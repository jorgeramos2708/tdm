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
        var module = DashboardRules.OverallModuleHealth(latest.ModuleHealth);
        ModuleState = module.Label;
        ModuleDetail = module.Detail;
        ModuleAccent = module.Brush;
        Cpu = latest.CpuPercent.HasValue ? $"{latest.CpuPercent.Value:0.0}%" : "N/D";
        CpuAccent = DashboardRules.MetricBrush(latest.CpuPercent, 85, 95);
        MemoryFree = latest.MemoryFreePercent.HasValue ? $"{latest.MemoryFreePercent.Value:0.0}%" : "N/D";
        MemoryAccent = DashboardRules.ReverseMetricBrush(latest.MemoryFreePercent, 20, 10);
        CriticalSignals = (latest.CriticalFindings + latest.ErrorFindings).ToString();
        CrashLoops = latest.CrashLoops.ToString();
        Coverage = latest.CoverageScore.HasValue ? $"{latest.CoverageScore}%" : "N/D";
        var chartSamples = DashboardRules.ChartSamples(samples);
        CpuSeries = DashboardRules.ContinuousSeries(chartSamples, x => x.CpuPercent);
        MemoryUsedSeries = DashboardRules.ContinuousSeries(chartSamples, x => x.MemoryFreePercent.HasValue ? 100d - x.MemoryFreePercent.Value : null);
        Modules = latest.ModuleHealth
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
