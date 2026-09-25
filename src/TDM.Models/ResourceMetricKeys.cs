namespace TDM.Models;

/// <summary>
/// Contrato estable para métricas numéricas persistidas por TDM.
/// Las claves Metric.* son datos, no texto de presentación: los analizadores deben
/// consumirlas antes de recurrir a parsers de compatibilidad con versiones antiguas.
/// </summary>
public static class ResourceMetricKeys
{
    public const string CpuPercent = "Metric.Cpu.Percent";
    public const string MemoryFreePercent = "Metric.Memory.FreePercent";
    public const string MemoryFreeBytes = "Metric.Memory.FreeBytes";
    public const string MemoryTotalBytes = "Metric.Memory.TotalBytes";

    public const string TcpEphemeralUsed = "Metric.Tcp.EphemeralUsed";
    public const string TcpEphemeralCapacity = "Metric.Tcp.EphemeralCapacity";
    public const string TcpEphemeralUsagePercent = "Metric.Tcp.EphemeralUsagePercent";
    public const string TcpTimeWait = "Metric.Tcp.TimeWait";
    public const string TcpEstablished = "Metric.Tcp.Established";

    public static string DiskFreePercent(string drive) => $"Metric.Disk.{NormalizeDrive(drive)}.FreePercent";
    public static string DiskFreeBytes(string drive) => $"Metric.Disk.{NormalizeDrive(drive)}.FreeBytes";
    public static string DiskTotalBytes(string drive) => $"Metric.Disk.{NormalizeDrive(drive)}.TotalBytes";

    public static string ProcessRamMb(string processName, int pid) => $"Metric.Process.{NormalizeSegment(processName)}.{pid}.RamMb";
    public static string ProcessHandles(string processName, int pid) => $"Metric.Process.{NormalizeSegment(processName)}.{pid}.Handles";
    public static string ProcessThreads(string processName, int pid) => $"Metric.Process.{NormalizeSegment(processName)}.{pid}.Threads";

    private static string NormalizeDrive(string value)
    {
        if (string.IsNullOrWhiteSpace(value)) return "UNKNOWN";
        var trimmed = value.Trim();
        var c = trimmed.FirstOrDefault(char.IsLetterOrDigit);
        return c == default ? "UNKNOWN" : char.ToUpperInvariant(c).ToString();
    }

    private static string NormalizeSegment(string value)
    {
        if (string.IsNullOrWhiteSpace(value)) return "unknown";
        var chars = value.Trim().Select(c => char.IsLetterOrDigit(c) ? c : '_').ToArray();
        var normalized = new string(chars).Trim('_');
        return string.IsNullOrWhiteSpace(normalized) ? "unknown" : normalized;
    }
}
