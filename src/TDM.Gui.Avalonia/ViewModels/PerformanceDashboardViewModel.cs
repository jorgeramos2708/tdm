using CommunityToolkit.Mvvm.ComponentModel;
using TDM.Collectors.Windows;
using TDM.Persistence;

namespace TDM.Gui.Avalonia.ViewModels;

public partial class PerformanceDashboardViewModel : ObservableObject
{
    [ObservableProperty] private string _cpuValue = "N/D";
    [ObservableProperty] private string _memoryValue = "N/D";
    [ObservableProperty] private string _networkReceiveValue = "↓ N/D Mbps";
    [ObservableProperty] private string _networkSendValue = "↑ N/D Mbps";
    [ObservableProperty] private IReadOnlyList<double> _cpuSeries = Array.Empty<double>();
    [ObservableProperty] private IReadOnlyList<double> _memorySeries = Array.Empty<double>();
    [ObservableProperty] private IReadOnlyList<double> _networkRxSeries = Array.Empty<double>();
    [ObservableProperty] private IReadOnlyList<double> _networkTxSeries = Array.Empty<double>();
    [ObservableProperty] private IReadOnlyList<string> _timeLabels = Array.Empty<string>();
    [ObservableProperty] private double _networkMaximum = 1d;
    [ObservableProperty] private double _networkWarning = 0.7d;
    [ObservableProperty] private double _networkCritical = 0.85d;
    [ObservableProperty] private double? _cpuWarningThreshold;
    [ObservableProperty] private double? _cpuCriticalThreshold;
    [ObservableProperty] private double? _memoryWarningThreshold;
    [ObservableProperty] private double? _memoryCriticalThreshold;
    [ObservableProperty] private IReadOnlyList<MetricRow> _topProcesses = Array.Empty<MetricRow>();
    [ObservableProperty] private IReadOnlyList<MetricRow> _disks = Array.Empty<MetricRow>();

    public void Apply(IReadOnlyList<ObservabilitySample> samples, LightweightProcessDiskSnapshot? liveResources = null)
    {
        if (samples.Count == 0)
        {
            Reset();
            ApplyLiveResources(liveResources);
            return;
        }

        var latest = samples[^1];
        var latestProcessSample = samples.LastOrDefault(s => s.ProcessRamMb.Count > 0) ?? latest;
        var latestDiskSample = samples.LastOrDefault(s => s.DiskFreePercent.Count > 0) ?? latest;
        var thresholds = SupportMonitoringSettings.Default.Thresholds;
        CpuWarningThreshold = thresholds.CpuWarning;
        CpuCriticalThreshold = thresholds.CpuCritical;
        MemoryWarningThreshold = thresholds.MemoryUsedWarning;
        MemoryCriticalThreshold = thresholds.MemoryUsedCritical;

        var cpuSample = samples.LastOrDefault(s => s.CpuPercent.HasValue) ?? latest;
        var memorySample = samples.LastOrDefault(s => s.MemoryFreePercent.HasValue) ?? latest;
        var networkRxSample = samples.LastOrDefault(s => s.NetworkReceiveMbps.HasValue) ?? latest;
        var networkTxSample = samples.LastOrDefault(s => s.NetworkSendMbps.HasValue) ?? latest;
        CpuValue = cpuSample.CpuPercent.HasValue ? $"{cpuSample.CpuPercent.Value:0.0}%" : "N/D";
        MemoryValue = memorySample.MemoryFreePercent.HasValue ? $"{100d - memorySample.MemoryFreePercent.Value:0.0}% usada" : "N/D";
        NetworkReceiveValue = networkRxSample.NetworkReceiveMbps.HasValue
            ? $"↓ {networkRxSample.NetworkReceiveMbps.Value:0.00} Mbps"
            : "↓ N/D Mbps";
        NetworkSendValue = networkTxSample.NetworkSendMbps.HasValue
            ? $"↑ {networkTxSample.NetworkSendMbps.Value:0.00} Mbps"
            : "↑ N/D Mbps";

        var chartSamples = DashboardRules.ChartSamples(samples);
        CpuSeries = DashboardRules.ContinuousSeries(chartSamples, s => s.CpuPercent);
        MemorySeries = DashboardRules.ContinuousSeries(chartSamples, s => s.MemoryFreePercent.HasValue ? 100d - s.MemoryFreePercent.Value : null);
        NetworkRxSeries = DashboardRules.ContinuousSeries(chartSamples, s => s.NetworkReceiveMbps);
        NetworkTxSeries = DashboardRules.ContinuousSeries(chartSamples, s => s.NetworkSendMbps);
        TimeLabels = chartSamples.Select(s => s.Timestamp.ToLocalTime().ToString("dd/MM HH:mm:ss")).ToArray();

        NetworkMaximum = Math.Max(1d, samples
            .SelectMany(s => new[] { s.NetworkReceiveMbps, s.NetworkSendMbps })
            .Where(v => v.HasValue)
            .Select(v => v!.Value)
            .DefaultIfEmpty(0d)
            .Max() * 1.15d);
        NetworkWarning = Math.Max(0.1d, NetworkMaximum * 0.70d);
        NetworkCritical = Math.Max(NetworkWarning + 0.1d, NetworkMaximum * 0.85d);

        ApplyPersistedResources(latestProcessSample, latestDiskSample);
        ApplyLiveResources(liveResources);
    }

    private void ApplyPersistedResources(ObservabilitySample processSample, ObservabilitySample diskSample)
    {
        var topProcesses = processSample.ProcessRamMb
            .OrderByDescending(x => x.Value)
            .Take(8)
            .Select(x =>
            {
                processSample.ProcessHandles.TryGetValue(x.Key, out var handles);
                processSample.ProcessThreads.TryGetValue(x.Key, out var threads);
                return new MetricRow(x.Key, $"{x.Value:0} MB", $"Handles {handles:0} · Threads {threads:0}", DashboardPalette.Cyan);
            })
            .ToList();
        if (topProcesses.Count > 0)
            TopProcesses = topProcesses;

        var disks = diskSample.DiskFreePercent
            .OrderBy(x => x.Value)
            .Select(x => new MetricRow(
                x.Key,
                $"{x.Value:0.0}% libre",
                diskSample.DiskFreeBytes.TryGetValue(x.Key, out var bytes) ? $"{bytes / 1024d / 1024d / 1024d:0.0} GB disponibles" : "Espacio disponible no informado",
                x.Value <= 5 ? DashboardPalette.Danger : x.Value <= 10 ? DashboardPalette.Warn : DashboardPalette.Good))
            .ToList();
        if (disks.Count > 0)
            Disks = disks;
    }

    public void ApplyLiveResources(LightweightProcessDiskSnapshot? liveResources)
    {
        if (liveResources is { Processes.Count: > 0 })
        {
            TopProcesses = liveResources.Processes
                .OrderByDescending(x => x.RamMb)
                .Take(8)
                .Select(x => new MetricRow(
                    $"{x.Name}[PID {x.Pid}]",
                    $"{x.RamMb:0} MB",
                    $"Handles {x.Handles} · Threads {x.Threads}",
                    DashboardPalette.Cyan))
                .ToList();
        }
        else if (TopProcesses.Count == 0)
        {
            TopProcesses = new[]
            {
                new MetricRow(
                    "Esperando procesos",
                    "N/D",
                    "La captura ligera se actualiza automáticamente cada 5 s",
                    DashboardPalette.Muted)
            };
        }

        if (liveResources is { Disks.Count: > 0 })
        {
            Disks = liveResources.Disks
                .OrderBy(x => x.FreePercent)
                .Select(x => new MetricRow(
                    NormalizeDriveName(x.Drive),
                    $"{x.FreePercent:0.0}% libre",
                    $"{x.FreeBytes / 1024d / 1024d / 1024d:0.0} GB disponibles",
                    x.FreePercent <= 5 ? DashboardPalette.Danger : x.FreePercent <= 10 ? DashboardPalette.Warn : DashboardPalette.Good))
                .ToList();
        }
        else if (Disks.Count == 0)
        {
            Disks = new[]
            {
                new MetricRow(
                    "Esperando discos",
                    "N/D",
                    "La captura ligera se actualiza automáticamente cada 5 s",
                    DashboardPalette.Muted)
            };
        }
    }

    private static string NormalizeDriveName(string value)
    {
        if (string.IsNullOrWhiteSpace(value)) return "N/D";
        var trimmed = value.Trim();
        return trimmed.EndsWith("\\", StringComparison.Ordinal) ? trimmed[..^1] : trimmed;
    }

    private void Reset()
    {
        CpuValue = MemoryValue = "N/D";
        NetworkReceiveValue = "↓ N/D Mbps";
        NetworkSendValue = "↑ N/D Mbps";
        CpuSeries = MemorySeries = NetworkRxSeries = NetworkTxSeries = Array.Empty<double>();
        TimeLabels = Array.Empty<string>();
        NetworkMaximum = 1d;
        NetworkWarning = 0.7d;
        NetworkCritical = 0.85d;
        var thresholds = SupportMonitoringSettings.Default.Thresholds;
        CpuWarningThreshold = thresholds.CpuWarning;
        CpuCriticalThreshold = thresholds.CpuCritical;
        MemoryWarningThreshold = thresholds.MemoryUsedWarning;
        MemoryCriticalThreshold = thresholds.MemoryUsedCritical;
        TopProcesses = Array.Empty<MetricRow>();
        Disks = Array.Empty<MetricRow>();
    }
}
