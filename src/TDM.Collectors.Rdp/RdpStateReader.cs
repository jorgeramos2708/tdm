using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32;
using System.ServiceProcess;
using TDM.Core;

namespace TDM.Collectors.Rdp;

internal static class RdpStateReader
{
    private const string RdpTcpKey = @"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp";

    public static RdpSnapshot CaptureLightweight()
        => CaptureCore(includeCertificate: false);

    public static RdpSnapshot Capture()
        => CaptureCore(includeCertificate: true);

    private static RdpSnapshot CaptureCore(bool includeCertificate)
    {
        var limitations = new List<string>();
        var service = GetTermServiceStatus();
        var port = GetConfiguredPort();
        var listener = port.IsAvailable
            ? IsTcpPortListening(port.Value)
            : ProbeResult<bool>.Unavailable("El puerto configurado no pudo leerse; no es seguro comprobar el listener con un puerto asumido.");
        var sessions = WtsSessionReader.GetSessions();

        AddLimitation(limitations, "TermService", service);
        AddLimitation(limitations, "Puerto RDP", port);
        AddLimitation(limitations, "Listener TCP", listener);
        AddLimitation(limitations, "Sesiones WTS", sessions);

        ProbeResult<string?> thumbprint = ProbeResult<string?>.Available(null);
        ProbeResult<X509Certificate2?> certificate = ProbeResult<X509Certificate2?>.Available(null);
        if (includeCertificate)
        {
            thumbprint = ReadThumbprintValue("SSLCertificateSHA1Hash");
            AddLimitation(limitations, "Huella de certificado RDP", thumbprint);
            if (thumbprint.IsAvailable && !string.IsNullOrWhiteSpace(thumbprint.Value))
            {
                certificate = FindRdpCertificate(thumbprint.Value);
                AddLimitation(limitations, "Almacén de certificados RDP", certificate);
            }
        }

        var cert = certificate.IsAvailable ? certificate.Value : null;
        return new RdpSnapshot(
            service.IsAvailable ? service.Value ?? "Desconocido" : "No evaluado",
            port.IsAvailable ? port.Value : 0,
            listener.IsAvailable && listener.Value,
            sessions.IsAvailable ? sessions.Value ?? [] : [],
            thumbprint.IsAvailable ? NormalizeThumbprint(thumbprint.Value) : null,
            certificate.IsAvailable && cert is not null,
            cert is null ? null : new DateTimeOffset(cert.NotAfter),
            cert?.Subject)
        {
            TermServiceEvaluated = service.IsAvailable,
            PortConfigurationEvaluated = port.IsAvailable,
            ListenerEvaluated = listener.IsAvailable,
            SessionsEvaluated = sessions.IsAvailable,
            CertificateConfigurationEvaluated = !includeCertificate || thumbprint.IsAvailable,
            CertificateStoreEvaluated = !includeCertificate || (thumbprint.IsAvailable && (string.IsNullOrWhiteSpace(thumbprint.Value) || certificate.IsAvailable)),
            CoverageLimitations = limitations
        };
    }

    private static ProbeResult<string> GetTermServiceStatus()
    {
        try
        {
            using var sc = new ServiceController("TermService");
            return ProbeResult<string>.Available(sc.Status.ToString());
        }
        catch (InvalidOperationException ex) { return ProbeResult<string>.Unavailable(ex.Message); }
        catch (UnauthorizedAccessException ex) { return ProbeResult<string>.AccessDenied(ex.Message); }
        catch (Exception ex) { return ProbeResult<string>.Error(ex.Message); }
    }

    private static ProbeResult<int> GetConfiguredPort()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(RdpTcpKey, writable: false);
            if (key is null) return ProbeResult<int>.Available(3389);
            var value = key.GetValue("PortNumber");
            var port = value switch
            {
                int i when i is >= 1 and <= 65535 => i,
                long l when l is >= 1 and <= 65535 => (int)l,
                string s when int.TryParse(s, out var p) && p is >= 1 and <= 65535 => p,
                null => 3389,
                _ => 0
            };
            return port > 0
                ? ProbeResult<int>.Available(port)
                : ProbeResult<int>.Error("PortNumber contiene un valor no válido.");
        }
        catch (UnauthorizedAccessException ex) { return ProbeResult<int>.AccessDenied(ex.Message); }
        catch (Exception ex) { return ProbeResult<int>.Error(ex.Message); }
    }

    private static ProbeResult<string?> ReadThumbprintValue(string name)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(RdpTcpKey, writable: false);
            if (key is null) return ProbeResult<string?>.Available(null);
            var value = key.GetValue(name);
            var text = value switch
            {
                byte[] bytes => Convert.ToHexString(bytes),
                string raw => raw,
                _ => value?.ToString()
            };
            return ProbeResult<string?>.Available(text);
        }
        catch (UnauthorizedAccessException ex) { return ProbeResult<string?>.AccessDenied(ex.Message); }
        catch (Exception ex) { return ProbeResult<string?>.Error(ex.Message); }
    }

    private static ProbeResult<bool> IsTcpPortListening(int port)
    {
        try
        {
            var listening = IPGlobalProperties.GetIPGlobalProperties()
                .GetActiveTcpListeners()
                .Any(ep => ep.Port == port);
            return ProbeResult<bool>.Available(listening);
        }
        catch (UnauthorizedAccessException ex) { return ProbeResult<bool>.AccessDenied(ex.Message); }
        catch (Exception ex) { return ProbeResult<bool>.Error(ex.Message); }
    }

    private static ProbeResult<X509Certificate2?> FindRdpCertificate(string? thumbprint)
    {
        var normalized = NormalizeThumbprint(thumbprint);
        if (string.IsNullOrWhiteSpace(normalized)) return ProbeResult<X509Certificate2?>.Available(null);

        var readableStore = false;
        var errors = new List<string>();
        foreach (var storeName in new[] { "Remote Desktop", "My" })
        {
            try
            {
                using var store = new X509Store(storeName, StoreLocation.LocalMachine);
                store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
                readableStore = true;
                var found = store.Certificates
                    .Cast<X509Certificate2>()
                    .FirstOrDefault(c => string.Equals(NormalizeThumbprint(c.Thumbprint), normalized, StringComparison.OrdinalIgnoreCase));
                if (found is not null) return ProbeResult<X509Certificate2?>.Available(found);
            }
            catch (UnauthorizedAccessException ex) { errors.Add($"{storeName}: acceso denegado ({ex.Message})"); }
            catch (Exception ex) { errors.Add($"{storeName}: {ex.Message}"); }
        }

        if (readableStore) return ProbeResult<X509Certificate2?>.Available(null);
        return errors.Any(e => e.Contains("acceso denegado", StringComparison.OrdinalIgnoreCase))
            ? ProbeResult<X509Certificate2?>.AccessDenied(string.Join(" | ", errors))
            : ProbeResult<X509Certificate2?>.Unavailable(errors.Count == 0 ? "No hay almacenes RDP legibles." : string.Join(" | ", errors));
    }

    private static string? NormalizeThumbprint(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        return new string(value.Where(Uri.IsHexDigit).ToArray()).ToUpperInvariant();
    }

    private static void AddLimitation<T>(List<string> limitations, string source, ProbeResult<T> result)
    {
        if (!result.IsUnavailable) return;
        limitations.Add($"{source}: {result.StatusText}{(string.IsNullOrWhiteSpace(result.Detail) ? string.Empty : $" - {result.Detail}")}");
    }
}

internal static class WtsSessionReader
{
    private static readonly IntPtr WTS_CURRENT_SERVER_HANDLE = IntPtr.Zero;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WTS_SESSION_INFO
    {
        public int SessionId;
        public IntPtr pWinStationName;
        public WTS_CONNECTSTATE_CLASS State;
    }

    private enum WTS_CONNECTSTATE_CLASS
    {
        Active,
        Connected,
        ConnectQuery,
        Shadow,
        Disconnected,
        Idle,
        Listen,
        Reset,
        Down,
        Init
    }

    [DllImport("Wtsapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool WTSEnumerateSessionsW(
        IntPtr hServer,
        int Reserved,
        int Version,
        out IntPtr ppSessionInfo,
        out int pCount);

    [DllImport("Wtsapi32.dll")]
    private static extern void WTSFreeMemory(IntPtr pMemory);

    public static ProbeResult<IReadOnlyList<RdpSessionInfo>> GetSessions()
    {
        var results = new List<RdpSessionInfo>();
        IntPtr buffer = IntPtr.Zero;

        try
        {
            if (!WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, out buffer, out var count))
            {
                var error = Marshal.GetLastWin32Error();
                return ProbeResult<IReadOnlyList<RdpSessionInfo>>.Unavailable($"WTSEnumerateSessionsW error {error}.");
            }

            var size = Marshal.SizeOf<WTS_SESSION_INFO>();
            var current = buffer;
            for (var i = 0; i < count; i++)
            {
                var info = Marshal.PtrToStructure<WTS_SESSION_INFO>(current);
                var station = Marshal.PtrToStringUni(info.pWinStationName) ?? string.Empty;
                results.Add(new RdpSessionInfo(info.SessionId, station, info.State.ToString()));
                current = IntPtr.Add(current, size);
            }
            return ProbeResult<IReadOnlyList<RdpSessionInfo>>.Available(results);
        }
        catch (UnauthorizedAccessException ex) { return ProbeResult<IReadOnlyList<RdpSessionInfo>>.AccessDenied(ex.Message); }
        catch (Exception ex) { return ProbeResult<IReadOnlyList<RdpSessionInfo>>.Error(ex.Message); }
        finally
        {
            if (buffer != IntPtr.Zero) WTSFreeMemory(buffer);
        }
    }
}
