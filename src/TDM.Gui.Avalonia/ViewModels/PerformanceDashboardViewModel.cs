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

        CpuValue = latest.CpuPercent.HasValue ? $"{latest.CpuPercent.Value:0.0}%" : "N/D";
        MemoryValue = latest.MemoryFreePercent.HasValue ? $"{100d - latest.MemoryFreePercent.Value:0.0}% usada" : "N/D";
        NetworkReceiveValue = latest.NetworkReceiveMbps.HasValue
            ? $"↓ {latest.NetworkReceiveMbps.Value:0.00} Mbps"
            : "↓ N/D Mbps";
        NetworkSendValue = latest.NetworkSendMbps.HasValue
            ? $"↑ {latest.NetworkSendMbps.Value:0.00} Mbps"
            : "↑ N/D Mbps";

        var chartSamples = DashboardRules.ChartSamples(samples);
        CpuSeries = chartSamples.Select(s => s.CpuPercent ?? double.NaN).ToArray();
        MemorySeries = chartSamples.Select(s => s.MemoryFreePercent.HasValue ? 100d - s.MemoryFreePercent.Value : double.NaN).ToArray();
        NetworkRxSeries = chartSamples.Select(s => s.NetworkReceiveMbps.GetValueOrDefault()).ToArray();
        NetworkTxSeries = chartSamples.Select(s => s.NetworkSendMbps.GetValueOrDefault()).ToArray();
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
        TopProcesses = Array.Empty<MetricRow>();
        Disks = Array.Empty<MetricRow>();
    }
}
