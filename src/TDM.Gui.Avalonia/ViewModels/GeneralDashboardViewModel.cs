using CommunityToolkit.Mvvm.ComponentModel;
using TDM.Persistence;

namespace TDM.Gui.Avalonia.ViewModels;

public partial class GeneralDashboardViewModel : ObservableObject
{
    [ObservableProperty] private string _moduleState = "NO EVALUADO";
    [ObservableProperty] private string _moduleDetail = "sin salud modular";
    [ObservableProperty] private global::Avalonia.Media.IBrush _moduleAccent = DashboardPalette.Muted;
    [ObservableProperty] private string _cpu = "N/D";
    [ObservableProperty] private global::Avalonia.Media.IBrush _cpuAccent = DashboardPalette.Muted;
    [ObservableProperty] private string _memoryFree = "N/D";
    [ObservableProperty] private global::Avalonia.Media.IBrush _memoryAccent = DashboardPalette.Muted;
    [ObservableProperty] private string _criticalSignals = "0";
    [ObservableProperty] private string _crashLoops = "0";
    [ObservableProperty] private string _coverage = "N/D";
    [ObservableProperty] private IReadOnlyList<double> _cpuSeries = Array.Empty<double>();
    [ObservableProperty] private IReadOnlyList<double> _memoryUsedSeries = Array.Empty<double>();
    [ObservableProperty] private IReadOnlyList<ModuleRow> _modules = Array.Empty<ModuleRow>();

    public void Apply(IReadOnlyList<ObservabilitySample> samples)
    {
        if (samples.Count == 0) { Reset(); return; }
        var latest = samples[^1];
        var thresholds = SupportMonitoringSettings.Default.Thresholds;
        var moduleSample = samples.LastOrDefault(x => x.ModuleHealth.Count > 0) ?? latest;
        var cpuSample = samples.LastOrDefault(x => x.CpuPercent.HasValue) ?? latest;
        var memorySample = samples.LastOrDefault(x => x.MemoryFreePercent.HasValue) ?? latest;
        var scoreSample = samples.LastOrDefault(x => x.CoverageScore.HasValue) ?? latest;
        var module = DashboardRules.OverallModuleHealth(moduleSample.ModuleHealth);
        ModuleState = module.Label;
        ModuleDetail = module.Detail;
        ModuleAccent = module.Brush;
        Cpu = cpuSample.CpuPercent.HasValue ? $"{cpuSample.CpuPercent.Value:0.0}%" : "N/D";
        CpuAccent = DashboardRules.MetricBrush(cpuSample.CpuPercent, thresholds.CpuWarning, thresholds.CpuCritical);
        MemoryFree = memorySample.MemoryFreePercent.HasValue ? $"{memorySample.MemoryFreePercent.Value:0.0}%" : "N/D";
        MemoryAccent = DashboardRules.ReverseMetricBrush(memorySample.MemoryFreePercent, 100d - thresholds.MemoryUsedWarning, 100d - thresholds.MemoryUsedCritical);
        CriticalSignals = (scoreSample.CriticalFindings + scoreSample.ErrorFindings).ToString();
        CrashLoops = scoreSample.CrashLoops.ToString();
        Coverage = scoreSample.CoverageScore.HasValue ? $"{scoreSample.CoverageScore}%" : "N/D";
        var chartSamples = DashboardRules.ChartSamples(samples);
        CpuSeries = DashboardRules.ContinuousSeries(chartSamples, x => x.CpuPercent);
        MemoryUsedSeries = DashboardRules.ContinuousSeries(chartSamples, x => x.MemoryFreePercent.HasValue ? 100d - x.MemoryFreePercent.Value : null);
        Modules = moduleSample.ModuleHealth
            .OrderByDescending(x => DashboardRules.HealthRank(x.Value))
            .ThenBy(x => x.Key, StringComparer.OrdinalIgnoreCase)
            .Select(x =>
            {
                var state = DashboardRules.HealthState(x.Value);
                return new ModuleRow(DashboardRules.CompactModuleName(x.Key), state.Label, DashboardRules.NormalizeHealthDetail(DashboardRules.NormalizeDisplayName(x.Value)), state.Brush);
            })
            .ToList();
    }

    private void Reset()
    {
        ModuleState = "NO EVALUADO"; ModuleDetail = "sin salud modular"; ModuleAccent = DashboardPalette.Muted;
        Cpu = MemoryFree = Coverage = "N/D"; CpuAccent = MemoryAccent = DashboardPalette.Muted;
        CriticalSignals = CrashLoops = "0"; CpuSeries = MemoryUsedSeries = Array.Empty<double>(); Modules = Array.Empty<ModuleRow>();
    }
}
