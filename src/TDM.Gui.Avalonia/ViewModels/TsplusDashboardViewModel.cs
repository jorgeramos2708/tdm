using CommunityToolkit.Mvvm.ComponentModel;
using TDM.Persistence;

namespace TDM.Gui.Avalonia.ViewModels;

public partial class TsplusDashboardViewModel : ObservableObject
{
    private static readonly string[] Groups =
    [
        "RDP / Remote Access Core", "Web / HTML5 / Web Portal", "Aplicaciones publicadas",
        "Sesiones / perfiles / logon", "Farm / Gateway / Load Balancing / Reverse Proxy",
        "Universal Printer", "Virtual Printer", "Two-Factor Authentication (2FA)", "Advanced Security"
    ];

    [ObservableProperty] private string _overall = "NO EVALUADO";
    [ObservableProperty] private string _overallDetail = "sin salud modular";
    [ObservableProperty] private global::Avalonia.Media.IBrush _overallAccent = DashboardPalette.Muted;
    [ObservableProperty] private IReadOnlyList<ModuleRow> _modules = Array.Empty<ModuleRow>();

    public void Apply(IReadOnlyList<ObservabilitySample> samples)
    {
        if (samples.Count == 0) { Overall = "NO EVALUADO"; OverallDetail = "sin datos"; OverallAccent = DashboardPalette.Muted; Modules = Array.Empty<ModuleRow>(); return; }
        var latest = samples[^1];
        var overall = DashboardRules.OverallModuleHealth(latest.ModuleHealth);
        Overall = DashboardRules.CompactSlashes(overall.Label);
        OverallDetail = DashboardRules.CompactSlashes(overall.Detail);
        OverallAccent = overall.Brush;
        Modules = Groups.Select(group =>
        {
            var state = DashboardRules.ModuleStateFor(latest.ModuleHealth, group);
            return new ModuleRow(
                DashboardRules.CompactSlashes(DashboardRules.CompactModuleName(group)),
                DashboardRules.CompactSlashes(state.Label),
                DashboardRules.CompactSlashes(DashboardRules.NormalizeDisplayName(state.Detail)),
                state.Brush);
        }).ToList();
    }
}
