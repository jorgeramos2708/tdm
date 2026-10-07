using System.Runtime.InteropServices;
using TDM.Models;

namespace TDM.Collectors.Windows;

/// <summary>
/// Gobernador ultraligero para el monitor integrado de la GUI.
/// Lee CPU mediante GetSystemTimes y memoria mediante GlobalMemoryStatusEx.
/// No usa WMI, no cambia prioridades y no modifica Windows.
/// </summary>
public static class ResourceLoadGuard
{
    private static readonly object Sync = new();
    private static ulong? _previousIdle;
    private static ulong? _previousKernel;
    private static ulong? _previousUser;

    // Estado independiente para la vista Tiempo real. Evita que el refresco visual de 5 s
    // altere la ventana de cálculo de CPU que usa el gobernador del monitor 30/60 s.
    private static readonly object DisplaySync = new();
    private static ulong? _displayPreviousIdle;
    private static ulong? _displayPreviousKernel;
    private static ulong? _displayPreviousUser;

    public sealed record Snapshot(
        DateTimeOffset Timestamp,
        double? CpuPercent,
        double? MemoryFreePercent,
        ulong? MemoryTotalBytes,
        bool ShouldDefer,
        bool AllowsIntensiveSampling,
        string Summary,
        // F33 (H8): contadores de la guía oficial 9 (MEMORYSTATUSEX) — Available MBytes
        // (ullAvailPhys) y % Committed Bytes In Use ((TotalPageFile-AvailPageFile)/TotalPageFile).
        ulong? MemoryAvailableBytes = null,
        double? MemoryCommittedPercent = null);

    public static Snapshot Capture(ResourceDetectionThresholds? thresholds = null)
    {
        var memory = ReadMemory();
        return BuildSnapshot(ReadCpuPercent(), memory.FreePercent, memory.TotalBytes, thresholds ?? ResourceDetectionThresholds.Default,
            memory.AvailableBytes, memory.CommittedPercent);
    }

    /// <summary>
    /// Muestra ultraligera e independiente para la vista Tiempo real de Observabilidad.
    /// Sólo lee GetSystemTimes + GlobalMemoryStatusEx; no ejecuta collectors, WMI, Event Log
    /// ni lecturas de archivos TSplus.
    /// </summary>
    public static Snapshot CaptureDisplay(ResourceDetectionThresholds? thresholds = null)
    {
        var memory = ReadMemory();
        return BuildSnapshot(ReadDisplayCpuPercent(), memory.FreePercent, memory.TotalBytes, thresholds ?? ResourceDetectionThresholds.Default,
            memory.AvailableBytes, memory.CommittedPercent);
    }

    private static Snapshot BuildSnapshot(double? cpu, double? memoryFree, ulong? memoryTotalBytes, ResourceDetectionThresholds thresholds,
        ulong? memoryAvailableBytes, double? memoryCommittedPercent)
    {
        // El monitor debe ceder ante un servidor bajo presión. Los umbrales provienen de la
        // configuración operativa (Fase 29, C1); con los valores por defecto el comportamiento
        // es idéntico al histórico: aplazo con CPU >= 85 o memoria libre <= 10 %, y muestreo
        // intensivo sólo con CPU < 70 y memoria libre >= 20 %. El diagnóstico manual no se
        // bloquea por esta regla.
        var memoryFreeCritical = 100d - thresholds.MemoryUsedCriticalPercent;
        var memoryFreeWarning = 100d - thresholds.MemoryUsedWarningPercent;
        var shouldDefer = (cpu.HasValue && cpu.Value >= thresholds.CpuCriticalPercent)
                          || (memoryFree.HasValue && memoryFree.Value <= memoryFreeCritical);

        // El modo de 30 s sólo se habilita cuando hay margen suficiente. En caso contrario el
        // monitor permanece a 60 s aunque exista un cambio reciente.
        var allowsIntensive = cpu.HasValue && memoryFree.HasValue
                              && cpu.Value < thresholds.CpuWarningPercent
                              && memoryFree.Value >= memoryFreeWarning;

        var cpuText = cpu.HasValue ? $"CPU {cpu.Value:0}%" : "CPU N/D";
        var memText = memoryFree.HasValue ? $"memoria libre {memoryFree.Value:0.0}%" : "memoria N/D";
        var state = shouldDefer
            ? "muestra aplazada por protección de recursos"
            : (!cpu.HasValue || !memoryFree.HasValue)
                ? "cobertura de recursos parcial; muestreo intensivo deshabilitado"
                : "recursos disponibles";
        return new Snapshot(DateTimeOffset.Now, cpu, memoryFree, memoryTotalBytes, shouldDefer, allowsIntensive,
            $"{state} · {cpuText} · {memText}", memoryAvailableBytes, memoryCommittedPercent);
    }

    private static double? ReadCpuPercent()
    {
        try
        {
            if (!GetSystemTimes(out var idle, out var kernel, out var user)) return null;
            var idleValue = idle.ToUInt64();
            var kernelValue = kernel.ToUInt64();
            var userValue = user.ToUInt64();

            lock (Sync)
            {
                if (!_previousIdle.HasValue || !_previousKernel.HasValue || !_previousUser.HasValue)
                {
                    _previousIdle = idleValue;
                    _previousKernel = kernelValue;
                    _previousUser = userValue;
                    return null;
                }

                var idleDelta = idleValue - _previousIdle.Value;
                var kernelDelta = kernelValue - _previousKernel.Value;
                var userDelta = userValue - _previousUser.Value;
                _previousIdle = idleValue;
                _previousKernel = kernelValue;
                _previousUser = userValue;

                var total = kernelDelta + userDelta;
                if (total == 0) return null;
                var busy = total > idleDelta ? total - idleDelta : 0;
                return Math.Clamp(busy * 100d / total, 0d, 100d);
            }
        }
        catch { return null; }
    }


    private static double? ReadDisplayCpuPercent()
    {
        try
        {
            if (!GetSystemTimes(out var idle, out var kernel, out var user)) return null;
            var idleValue = idle.ToUInt64();
            var kernelValue = kernel.ToUInt64();
            var userValue = user.ToUInt64();

            lock (DisplaySync)
            {
                if (!_displayPreviousIdle.HasValue || !_displayPreviousKernel.HasValue || !_displayPreviousUser.HasValue)
                {
                    _displayPreviousIdle = idleValue;
                    _displayPreviousKernel = kernelValue;
                    _displayPreviousUser = userValue;
                    return null;
                }

                var idleDelta = idleValue - _displayPreviousIdle.Value;
                var kernelDelta = kernelValue - _displayPreviousKernel.Value;
                var userDelta = userValue - _displayPreviousUser.Value;
                _displayPreviousIdle = idleValue;
                _displayPreviousKernel = kernelValue;
                _displayPreviousUser = userValue;

                var total = kernelDelta + userDelta;
                if (total == 0) return null;
                var busy = total > idleDelta ? total - idleDelta : 0;
                return Math.Clamp(busy * 100d / total, 0d, 100d);
            }
        }
        catch { return null; }
    }

    private static (double? FreePercent, ulong? TotalBytes, ulong? AvailableBytes, double? CommittedPercent) ReadMemory()
    {
        try
        {
            var status = new MemoryStatusEx
            {
                Length = (uint)Marshal.SizeOf<MemoryStatusEx>()
            };
            if (!GlobalMemoryStatusEx(ref status)) return (null, null, null, null);
            var freePercent = Math.Clamp(100d - status.MemoryLoad, 0d, 100d);
            var totalBytes = status.TotalPhys > 0 ? status.TotalPhys : (ulong?)null;
            var availableBytes = status.AvailPhys;
            // % Committed Bytes In Use (Memory Targets doc 9): commited = TotalPageFile - AvailPageFile.
            double? committedPercent = status.TotalPageFile > 0
                ? Math.Clamp((status.TotalPageFile - status.AvailPageFile) * 100d / status.TotalPageFile, 0d, 100d)
                : null;
            return (freePercent, totalBytes, availableBytes, committedPercent);
        }
        catch { return (null, null, null, null); }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeFileTime
    {
        public uint Low;
        public uint High;
        public readonly ulong ToUInt64() => ((ulong)High << 32) | Low;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    private struct MemoryStatusEx
    {
        public uint Length;
        public uint MemoryLoad;
        public ulong TotalPhys;
        public ulong AvailPhys;
        public ulong TotalPageFile;
        public ulong AvailPageFile;
        public ulong TotalVirtual;
        public ulong AvailVirtual;
        public ulong AvailExtendedVirtual;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetSystemTimes(out NativeFileTime idleTime, out NativeFileTime kernelTime, out NativeFileTime userTime);

    [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GlobalMemoryStatusEx(ref MemoryStatusEx buffer);
}
