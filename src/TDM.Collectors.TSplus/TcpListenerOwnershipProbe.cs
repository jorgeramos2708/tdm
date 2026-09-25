using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;

namespace TDM.Collectors.TSplus;

internal enum TcpListenerOwnershipState
{
    ExpectedProcess,
    NoListener,
    OtherProcess,
    OwnerUnknown,
    NotEvaluated
}

internal sealed record TcpListenerOwnershipResult(
    TcpListenerOwnershipState State,
    int Port,
    IReadOnlyList<int> Pids,
    IReadOnlyList<string> Processes,
    string Detail)
{
    public string EvidenceText => State switch
    {
        TcpListenerOwnershipState.ExpectedProcess => $"Listener TSplus compatible · {Detail}",
        TcpListenerOwnershipState.NoListener => "No se observó listener TCP",
        TcpListenerOwnershipState.OtherProcess => $"CONFLICTO · {Detail}",
        TcpListenerOwnershipState.OwnerUnknown => $"NO EVALUADO completamente · {Detail}",
        _ => $"NO EVALUADO · {Detail}"
    };
}

/// <summary>
/// Consulta la tabla TCP OWNER_PID de Windows para diferenciar un puerto realmente atendido
/// por el runtime esperado de un puerto ocupado por otro proceso. Sólo lectura.
/// </summary>
internal static class TcpListenerOwnershipProbe
{
    private const uint ErrorInsufficientBuffer = 122;
    private const int AfInet = 2;
    private const int AfInet6 = 23;

    public static TcpListenerOwnershipResult Probe(int port, string installRoot, string? configuredExecutable)
    {
        if (!OperatingSystem.IsWindows())
            return new(TcpListenerOwnershipState.NotEvaluated, port, [], [], "La inspección de PID del listener requiere Windows.");

        try
        {
            var pids = QueryPids(AfInet, port).Concat(QueryPids(AfInet6, port)).Distinct().OrderBy(x => x).ToList();
            if (pids.Count == 0)
                return new(TcpListenerOwnershipState.NoListener, port, [], [], "Sin PID propietario para el puerto configurado.");

            var expectedName = string.IsNullOrWhiteSpace(configuredExecutable)
                ? null
                : Path.GetFileNameWithoutExtension(configuredExecutable);
            var processLabels = new List<string>();
            var anyExpected = false;
            var anyUnknown = false;
            var allClearlyOther = true;

            foreach (var pid in pids)
            {
                try
                {
                    using var process = Process.GetProcessById(pid);
                    var name = process.ProcessName;
                    string? imagePath = null;
                    try { imagePath = process.MainModule?.FileName; } catch { }
                    processLabels.Add(string.IsNullOrWhiteSpace(imagePath) ? $"{name} (PID {pid})" : $"{name} (PID {pid}) · {imagePath}");

                    var nameMatches = !string.IsNullOrWhiteSpace(expectedName)
                                      && name.Equals(expectedName, StringComparison.OrdinalIgnoreCase);
                    var pathMatches = !string.IsNullOrWhiteSpace(imagePath)
                                      && IsUnderRoot(imagePath, installRoot);
                    // S5: un runtime genérico (java/javaw) coincide por nombre con cualquier java del
                    // sistema; para él se exige ruta bajo installRoot. Un nombre propio (html5service)
                    // sí valida por nombre. Sin ruta legible no se afirma: queda OwnerUnknown.
                    var nameIsGenericRuntime = !string.IsNullOrWhiteSpace(expectedName)
                        && (expectedName.Equals("java", StringComparison.OrdinalIgnoreCase)
                            || expectedName.Equals("javaw", StringComparison.OrdinalIgnoreCase));
                    if ((nameMatches && !nameIsGenericRuntime) || pathMatches)
                    {
                        anyExpected = true;
                        allClearlyOther = false;
                    }
                    else if (string.IsNullOrWhiteSpace(imagePath))
                    {
                        anyUnknown = true;
                        allClearlyOther = false;
                    }
                }
                catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception or NotSupportedException)
                {
                    _ = ex;
                    processLabels.Add($"PID {pid} · propietario no legible");
                    anyUnknown = true;
                    allClearlyOther = false;
                }
            }

            var detail = string.Join(" | ", processLabels);
            if (anyExpected)
                return new(TcpListenerOwnershipState.ExpectedProcess, port, pids, processLabels, detail);
            if (allClearlyOther)
                return new(TcpListenerOwnershipState.OtherProcess, port, pids, processLabels, detail);
            if (anyUnknown)
                return new(TcpListenerOwnershipState.OwnerUnknown, port, pids, processLabels, detail);
            return new(TcpListenerOwnershipState.OwnerUnknown, port, pids, processLabels, detail);
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException or NotSupportedException)
        {
            return new(TcpListenerOwnershipState.NotEvaluated, port, [], [], ex.Message);
        }
    }

    private static bool IsUnderRoot(string candidate, string root)
    {
        if (string.IsNullOrWhiteSpace(candidate) || string.IsNullOrWhiteSpace(root)) return false;
        try
        {
            var fullCandidate = Path.GetFullPath(candidate).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            var fullRoot = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar;
            return fullCandidate.StartsWith(fullRoot, StringComparison.OrdinalIgnoreCase);
        }
        catch { return false; }
    }

    private static IEnumerable<int> QueryPids(int addressFamily, int targetPort)
    {
        var size = 0;
        var first = GetExtendedTcpTable(IntPtr.Zero, ref size, true, addressFamily, TcpTableClass.OwnerPidListener, 0);
        if (first != 0 && first != ErrorInsufficientBuffer)
            throw new System.ComponentModel.Win32Exception((int)first);
        if (size <= sizeof(uint)) yield break;

        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            var result = GetExtendedTcpTable(buffer, ref size, true, addressFamily, TcpTableClass.OwnerPidListener, 0);
            if (result != 0) throw new System.ComponentModel.Win32Exception((int)result);

            var count = Marshal.ReadInt32(buffer);
            var current = IntPtr.Add(buffer, sizeof(uint));
            if (addressFamily == AfInet)
            {
                var rowSize = Marshal.SizeOf<MibTcpRowOwnerPid>();
                for (var i = 0; i < count; i++)
                {
                    var row = Marshal.PtrToStructure<MibTcpRowOwnerPid>(current);
                    if (Port(row.LocalPort) == targetPort && row.OwningPid > 0 && row.OwningPid <= int.MaxValue)
                        yield return (int)row.OwningPid;
                    current = IntPtr.Add(current, rowSize);
                }
            }
            else
            {
                var rowSize = Marshal.SizeOf<MibTcp6RowOwnerPid>();
                for (var i = 0; i < count; i++)
                {
                    var row = Marshal.PtrToStructure<MibTcp6RowOwnerPid>(current);
                    if (Port(row.LocalPort) == targetPort && row.OwningPid > 0 && row.OwningPid <= int.MaxValue)
                        yield return (int)row.OwningPid;
                    current = IntPtr.Add(current, rowSize);
                }
            }
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    private static int Port(uint networkOrder)
        => unchecked((ushort)IPAddress.NetworkToHostOrder((short)(networkOrder & 0xFFFF)));

    private enum TcpTableClass
    {
        OwnerPidListener = 3
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcpRowOwnerPid
    {
        public uint State;
        public uint LocalAddr;
        public uint LocalPort;
        public uint RemoteAddr;
        public uint RemotePort;
        public uint OwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcp6RowOwnerPid
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] LocalAddr;
        public uint LocalScopeId;
        public uint LocalPort;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] RemoteAddr;
        public uint RemoteScopeId;
        public uint RemotePort;
        public uint State;
        public uint OwningPid;
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr tcpTable,
        ref int size,
        [MarshalAs(UnmanagedType.Bool)] bool order,
        int ipVersion,
        TcpTableClass tableClass,
        uint reserved);
}
