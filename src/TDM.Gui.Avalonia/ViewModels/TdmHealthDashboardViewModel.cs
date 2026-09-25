using System.Text;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using TDM.Persistence;

namespace TDM.Gui.Avalonia.ViewModels;

public partial class TdmHealthDashboardViewModel : ObservableObject
{
    [ObservableProperty] private string _monitorMode = "N/D";
    [ObservableProperty] private string _frequency = "N/D";
    [ObservableProperty] private string _samples = "0";
    [ObservableProperty] private string _deferred = "0";
    [ObservableProperty] private string _timeouts = "0";
    [ObservableProperty] private string _cpu = "N/D";
    [ObservableProperty] private string _ram = "N/D";
    [ObservableProperty] private string _handles = "0";
    [ObservableProperty] private string _threads = "0";
    [ObservableProperty] private string _jsonl = "0 B";
    [ObservableProperty] private string _slowestCollector = "N/D";
    [ObservableProperty] private string _slowestCollectorMs = "0 ms";
    [ObservableProperty] private string _diagnosticDuration = "0 ms";
    [ObservableProperty] private IReadOnlyList<double> _durationSeries = Array.Empty<double>();
    [ObservableProperty] private IReadOnlyList<double> _cpuSeries = Array.Empty<double>();
    [ObservableProperty] private IReadOnlyList<double> _ramSeries = Array.Empty<double>();
    [ObservableProperty] private IReadOnlyList<double> _handlesSeries = Array.Empty<double>();
    [ObservableProperty] private IReadOnlyList<double> _threadsSeries = Array.Empty<double>();
    [ObservableProperty] private double _durationMaximum = 1000;
    [ObservableProperty] private double _cpuMemoryMaximum = 100;
    [ObservableProperty] private double _processCountMaximum = 50;
    [ObservableProperty] private double? _cpuWarningThreshold = 3;
    [ObservableProperty] private double? _cpuCriticalThreshold = 7;
    [ObservableProperty] private double? _memoryWarningThreshold;
    [ObservableProperty] private double? _memoryCriticalThreshold;
    [ObservableProperty] private IReadOnlyList<string> _timeLabels = Array.Empty<string>();
    [ObservableProperty] private string _detailTitle = "Salud de TDM";
    [ObservableProperty] private string _detailText = "Selecciona Ver detalle para la telemetría completa del monitor.";
    [ObservableProperty] private bool _isDetailVisible;
    private string _healthFullDetail = "Sin datos de salud de TDM.";

    public void Apply(IReadOnlyList<ObservabilitySample> samples)
        => Apply(samples, SupportMonitoringSettings.Default.Thresholds);

    public void Apply(IReadOnlyList<ObservabilitySample> samples, SupportThresholds? thresholds)
    {
        thresholds ??= SupportMonitoringSettings.Default.Thresholds;
        if (samples.Count == 0)
        {
            Reset(thresholds);
            return;
        }

        var latest = samples[^1];
        MonitorMode = latest.MonitorMode;
        Frequency = latest.MonitorIntervalSeconds > 0 ? $"{latest.MonitorIntervalSeconds} seg" : "N/D";
        Samples = samples.Count(x => x.SampleKind.Contains("monitor", StringComparison.OrdinalIgnoreCase)).ToString();
        Deferred = latest.DeferredSamples.ToString();
        Timeouts = latest.CollectorTimeouts.ToString();
        Cpu = latest.TdmCpuPercent.HasValue ? $"{latest.TdmCpuPercent.Value:0.0}%" : "N/D";
        var physicalMemoryBytes = samples.LastOrDefault(x => x.MemoryTotalBytes is > 0)?.MemoryTotalBytes;
        var latestMemoryPercent = TdmMemoryPercent(latest.TdmWorkingSetMb, latest.MemoryTotalBytes ?? physicalMemoryBytes);
        CpuWarningThreshold = Math.Clamp(thresholds.TdmCpuWarning, 0d, 100d);
        CpuCriticalThreshold = Math.Clamp(thresholds.TdmCpuCritical, 0d, 100d);
        MemoryWarningThreshold = Math.Clamp(thresholds.TdmMemoryWarningPercent, 0d, 100d);
        MemoryCriticalThreshold = Math.Clamp(thresholds.TdmMemoryCriticalPercent, 0d, 100d);
        Ram = latestMemoryPercent.HasValue ? $"{latestMemoryPercent.Value:0.0}%" : "N/D";
        Handles = latest.TdmHandleCount.ToString();
        Threads = latest.TdmThreadCount.ToString();
        Jsonl = DashboardRules.FormatBytes(latest.ObservabilityBytes);
        SlowestCollector = latest.SlowestCollector;
        SlowestCollectorMs = $"{latest.SlowestCollectorMs:0} ms";
        DiagnosticDuration = $"{latest.DiagnosticDurationMs:0} ms";

        var chartSamples = DashboardRules.ChartSamples(samples);
        DurationSeries = chartSamples.Select(x => x.DiagnosticDurationMs).ToArray();
        CpuSeries = DashboardRules.ContinuousSeries(chartSamples, x => x.TdmCpuPercent);
        RamSeries = DashboardRules.ContinuousSeries(chartSamples, x => TdmMemoryPercent(x.TdmWorkingSetMb, x.MemoryTotalBytes ?? physicalMemoryBytes));
        HandlesSeries = chartSamples.Select(x => (double)x.TdmHandleCount).ToArray();
        ThreadsSeries = chartSamples.Select(x => (double)x.TdmThreadCount).ToArray();
        TimeLabels = chartSamples.Select(x => x.Timestamp.ToLocalTime().ToString("dd/MM HH:mm:ss")).ToArray();

        DurationMaximum = Math.Max(1000, samples.Max(x => x.DiagnosticDurationMs) * 1.15);
        CpuMemoryMaximum = 100;
        ProcessCountMaximum = Math.Max(50, samples.Max(x => Math.Max(x.TdmHandleCount, x.TdmThreadCount)) * 1.15);
        _healthFullDetail = BuildHealthDetail(latest, samples, thresholds);
        RefreshVisibleDetail();
    }

    [RelayCommand] private void ShowHealthDetail() => ShowDetail("Salud de TDM", _healthFullDetail);
    [RelayCommand] private void CloseDetail() => IsDetailVisible = false;

    private void ShowDetail(string title, string text)
    {
        DetailTitle = title;
        DetailText = text;
        IsDetailVisible = true;
    }

    private void RefreshVisibleDetail()
    {
        if (IsDetailVisible && DetailTitle.Equals("Salud de TDM", StringComparison.Ordinal))
            DetailText = _healthFullDetail;
    }

    private string BuildHealthDetail(ObservabilitySample latest, IReadOnlyList<ObservabilitySample> samples, SupportThresholds thresholds)
    {
        var builder = new StringBuilder();
        builder.Append($"Modo de monitoreo: {MonitorMode} · Frecuencia: {Frequency} · Muestras: {Samples} · Diferidas: {Deferred} · Timeouts: {Timeouts}.");
        builder.AppendLine();
        builder.Append($"Bitácora (JSONL): {Jsonl} · Colector más lento: {SlowestCollector} ({SlowestCollectorMs}) · Duración de muestra: {DiagnosticDuration}.");
        builder.AppendLine();
        builder.Append($"CPU TDM: {Cpu} (advertencia ≥ {thresholds.TdmCpuWarning:0.0}%, crítico ≥ {thresholds.TdmCpuCritical:0.0}%)");
        builder.Append($" · Memoria TDM: {Ram} (advertencia ≥ {thresholds.TdmMemoryWarningPercent:0.0}%, crítico ≥ {thresholds.TdmMemoryCriticalPercent:0.0}%).");
        builder.AppendLine();
        builder.Append($"Recursos abiertos: {Handles} (advertencia ≥ {thresholds.TdmHandlesWarning}, crítico ≥ {thresholds.TdmHandlesCritical})");
        builder.Append($" — {StateLabel(latest.TdmHandleCount, thresholds.TdmHandlesWarning, thresholds.TdmHandlesCritical)}.");
        builder.Append($" Hilos: {Threads} (advertencia ≥ {thresholds.TdmThreadsWarning}, crítico ≥ {thresholds.TdmThreadsCritical})");
        builder.Append($" — {StateLabel(latest.TdmThreadCount, thresholds.TdmThreadsWarning, thresholds.TdmThreadsCritical)}.");
        if (samples.Count > 0)
        {
            builder.AppendLine();
            builder.Append($"Duración en la ventana: media {samples.Average(x => x.DiagnosticDurationMs):0} ms · máxima {samples.Max(x => x.DiagnosticDurationMs):0} ms.");
        }
        return builder.ToString().TrimEnd();
    }

    private static string StateLabel(int value, int warning, int critical)
        => value >= critical ? "Crítico" : value >= warning ? "Advertencia" : "Normal";

    private void Reset(SupportThresholds thresholds)
    {
        MonitorMode = Frequency = Cpu = Ram = "N/D";
        Samples = Deferred = Timeouts = Handles = Threads = "0";
        Jsonl = "0 B";
        SlowestCollector = "N/D";
        SlowestCollectorMs = DiagnosticDuration = "0 ms";
        DurationSeries = CpuSeries = RamSeries = HandlesSeries = ThreadsSeries = Array.Empty<double>();
        TimeLabels = Array.Empty<string>();
        DurationMaximum = 1000;
        CpuMemoryMaximum = 100;
        ProcessCountMaximum = 50;
        CpuWarningThreshold = Math.Clamp(thresholds.TdmCpuWarning, 0d, 100d);
        CpuCriticalThreshold = Math.Clamp(thresholds.TdmCpuCritical, 0d, 100d);
        MemoryWarningThreshold = Math.Clamp(thresholds.TdmMemoryWarningPercent, 0d, 100d);
        MemoryCriticalThreshold = Math.Clamp(thresholds.TdmMemoryCriticalPercent, 0d, 100d);
        _healthFullDetail = "Sin datos de salud de TDM.";
        RefreshVisibleDetail();
    }

    private static double? TdmMemoryPercent(double workingSetMb, double? totalPhysicalBytes)
    {
        if (!totalPhysicalBytes.HasValue || totalPhysicalBytes.Value <= 0) return null;
        return Math.Clamp(workingSetMb * 1024d * 1024d * 100d / totalPhysicalBytes.Value, 0d, 100d);
    }
}
