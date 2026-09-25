using System.Diagnostics;
using System.Security.Cryptography;
using Microsoft.Win32;
using TDM.Core;
using TDM.Models;

namespace TDM.Collectors.Windows;

/// <summary>
/// Captura un inventario longitudinal, acotado y de solo lectura, de configuraciones y
/// binarios Windows/RDP que son relevantes para TSplus. No intenta escanear todo Windows:
/// registra fuentes críticas conocidas para poder comparar cambios entre muestras.
/// </summary>
public sealed class WindowsLongitudinalStateCollector : IReadOnlyCollector
{
    private const long MaxHashBytes = 64L * 1024 * 1024;
    private readonly bool _calculateHashes;

    public WindowsLongitudinalStateCollector(bool calculateHashes = false) => _calculateHashes = calculateHashes;

    public string Nombre => _calculateHashes
        ? "Historial Windows / integridad crítica"
        : "Historial Windows / configuración crítica";

    public Task<CollectorResult> CollectAsync(DiagnosticContext context, CancellationToken cancellationToken = default)
    {
        var events = new List<DiagnosticEvent>();
        var findings = new List<DiagnosticFinding>();
        var now = DateTimeOffset.Now;
        var attempted = 0;
        var available = 0;

        foreach (var item in RegistryTargets())
        {
            cancellationToken.ThrowIfCancellationRequested();
            attempted++;
            var read = ReadRegistry(item.Path, item.ValueName);
            if (read.Available) available++;
            events.Add(new DiagnosticEvent(
                now,
                "Windows Registry",
                item.Component,
                DiagnosticLayer.Windows,
                DiagnosticSeverity.Informativo,
                "WINDOWS_LONGITUDINAL_CONFIG_STATE",
                read.Available
                    ? $"Estado longitudinal de {item.Component}: {item.ValueName}."
                    : $"No fue posible leer {item.ValueName} para el historial longitudinal.",
                Evidencia:
                [
                    new EvidenceItem("Ruta", item.Path),
                    new EvidenceItem("Nombre", item.ValueName),
                    new EvidenceItem("Valor", read.Available ? read.Value : "NO EVALUADO"),
                    new EvidenceItem("Cobertura", read.Available ? "Disponible" : read.Detail)
                ]));
        }

        foreach (var path in CriticalWindowsFiles())
        {
            cancellationToken.ThrowIfCancellationRequested();
            attempted++;
            var state = ReadFileState(path, _calculateHashes);
            if (state.Available) available++;
            events.Add(new DiagnosticEvent(
                now,
                "Windows Filesystem",
                Path.GetFileName(path),
                DiagnosticLayer.Windows,
                DiagnosticSeverity.Informativo,
                "WINDOWS_LONGITUDINAL_LIBRARY_STATE",
                state.Exists
                    ? $"Estado longitudinal del binario crítico {Path.GetFileName(path)}."
                    : $"No se encontró el binario crítico esperado {Path.GetFileName(path)}.",
                Archivo: path,
                Evidencia:
                [
                    new EvidenceItem("Archivo", path),
                    new EvidenceItem("Presente", state.Exists ? "Sí" : "No"),
                    new EvidenceItem("Tamaño", state.Length.ToString()),
                    new EvidenceItem("Última modificación UTC", state.LastWriteUtc),
                    new EvidenceItem("Versión", state.Version),
                    new EvidenceItem("SHA-256", state.Hash),
                    new EvidenceItem("Cobertura", state.Available ? "Disponible" : state.Detail)
                ]));
            if (state.Available && state.Exists && DateTimeOffset.TryParse(state.LastWriteUtc, out var modifiedAt))
            {
                var windowEnd = context.HoraIncidente ?? now;
                var windowStart = windowEnd - context.Lookback;
                if (modifiedAt >= windowStart && modifiedAt <= windowEnd)
                {
                    events.Add(new DiagnosticEvent(
                        modifiedAt,
                        "Windows Filesystem",
                        Path.GetFileName(path),
                        DiagnosticLayer.Windows,
                        DiagnosticSeverity.Informativo,
                        "WINDOWS_FILE_MODIFICATION_EVIDENCE",
                        "El metadato actual del archivo indica una modificación dentro de la ventana analizada.",
                        Archivo: path,
                        Evidencia:
                        [
                            new EvidenceItem("Archivo", path),
                            new EvidenceItem("Última modificación UTC", modifiedAt.ToString("O")),
                            new EvidenceItem("Versión actual", state.Version),
                            new EvidenceItem("Limitación", "LastWriteTime es evidencia de modificación del archivo actual; no reconstruye por sí solo su contenido anterior")
                        ]));
                }
            }
        }

        var coverage = attempted == 0 ? "No disponible" : available == attempted ? "Completa" : available > 0 ? "Parcial" : "No disponible";
        events.Add(new DiagnosticEvent(
            now,
            "TDM",
            "Historial Windows crítico",
            DiagnosticLayer.Windows,
            coverage == "Completa" ? DiagnosticSeverity.Informativo : DiagnosticSeverity.Advertencia,
            "WINDOWS_LONGITUDINAL_COVERAGE",
            $"Cobertura del inventario longitudinal Windows: {coverage} ({available}/{attempted}).",
            Evidencia:
            [
                new EvidenceItem("Cobertura", coverage),
                new EvidenceItem("Fuentes disponibles", available.ToString()),
                new EvidenceItem("Fuentes intentadas", attempted.ToString()),
                new EvidenceItem("Hashes", _calculateHashes ? "Sí; archivos <= 64 MiB" : "No; muestra de estado"),
                new EvidenceItem("Alcance", "Configuraciones y binarios Windows/RDP críticos; no representa todos los archivos del sistema")
            ]));

        return Task.FromResult(new CollectorResult(findings, events));
    }

    private static IEnumerable<(string Path, string ValueName, string Component)> RegistryTargets()
    {
        yield return (@"SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections", "RDP / acceso");
        yield return (@"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp", "UserAuthentication", "RDP / NLA");
        yield return (@"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp", "SecurityLayer", "RDP / SecurityLayer");
        yield return (@"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp", "MinEncryptionLevel", "RDP / cifrado");
        yield return (@"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp", "PortNumber", "RDP / puerto");
        yield return (@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "Userinit", "Winlogon / Userinit");
        foreach (var service in new[] { "TermService", "UmRdpService", "SessionEnv", "RpcSs", "EventLog", "Spooler", "Winmgmt" })
            yield return ($@"SYSTEM\CurrentControlSet\Services\{service}", "ImagePath", $"Servicio {service} / ImagePath");
    }

    private static (bool Available, string Value, string Detail) ReadRegistry(string path, string valueName)
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var key = baseKey.OpenSubKey(path, writable: false);
            if (key is null) return (true, "<clave ausente>", "Disponible");
            var value = key.GetValue(valueName, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
            return value is null
                ? (true, "<no configurado>", "Disponible")
                : (true, NormalizeRegistryValue(value), "Disponible");
        }
        catch (UnauthorizedAccessException ex) { return (false, string.Empty, "Acceso denegado: " + ex.Message); }
        catch (Exception ex) { return (false, string.Empty, "Error de lectura: " + ex.Message); }
    }

    private static string NormalizeRegistryValue(object value)
        => value switch
        {
            string[] items => string.Join(";", items),
            byte[] bytes => Convert.ToHexString(bytes.AsSpan(0, Math.Min(bytes.Length, 64))) + (bytes.Length > 64 ? "…" : string.Empty),
            _ => Convert.ToString(value, System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty
        };

    private static IEnumerable<string> CriticalWindowsFiles()
    {
        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var system32 = Path.Combine(windows, "System32");
        yield return Path.Combine(system32, "termsrv.dll");
        yield return Path.Combine(system32, "rdpcorets.dll");
        yield return Path.Combine(system32, "rdpwsx.dll");
        yield return Path.Combine(system32, "winlogon.exe");
        yield return Path.Combine(system32, "userinit.exe");
        yield return Path.Combine(system32, "svchost.exe");
        yield return Path.Combine(system32, "spoolsv.exe");
        yield return Path.Combine(system32, "wbem", "WmiPrvSE.exe");
    }

    private static FileState ReadFileState(string path, bool hash)
    {
        try
        {
            var file = new FileInfo(path);
            if (!file.Exists) return new(true, false, 0, "N/D", "N/D", "N/D", "Disponible");
            var version = "N/D";
            try { version = FileVersionInfo.GetVersionInfo(path).FileVersion ?? "N/D"; } catch { }
            var sha = "No calculado";
            if (hash)
            {
                if (file.Length <= MaxHashBytes)
                {
                    using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                    sha = Convert.ToHexString(SHA256.HashData(stream));
                }
                else sha = "Omitido (>64 MiB)";
            }
            return new(true, true, file.Length, file.LastWriteTimeUtc.ToString("O"), version, sha, "Disponible");
        }
        catch (UnauthorizedAccessException ex) { return new(false, File.Exists(path), 0, "N/D", "N/D", "N/D", "Acceso denegado: " + ex.Message); }
        catch (IOException ex) { return new(false, File.Exists(path), 0, "N/D", "N/D", "N/D", "Error de E/S: " + ex.Message); }
        catch (Exception ex) { return new(false, File.Exists(path), 0, "N/D", "N/D", "N/D", "Error de lectura: " + ex.Message); }
    }

    private sealed record FileState(bool Available, bool Exists, long Length, string LastWriteUtc, string Version, string Hash, string Detail);
}
