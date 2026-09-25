using CommunityToolkit.Mvvm.ComponentModel;
using TDM.Persistence;

namespace TDM.Gui.Avalonia.ViewModels;

public partial class CausalityDashboardViewModel : ObservableObject
{
    [ObservableProperty] private string _currentOrigin = "INDETERMINADO";
    [ObservableProperty] private string _originator = "Sin originador confirmado";
    [ObservableProperty] private global::Avalonia.Media.IBrush _originAccent = DashboardPalette.Muted;
    [ObservableProperty] private string _tsplusCount = "0";
    [ObservableProperty] private string _windowsCount = "0";
    [ObservableProperty] private string _externalCount = "0";
    [ObservableProperty] private string _indeterminateCount = "0";
    [ObservableProperty] private string _lastCausalMoment = "Sin instante causal disponible";
    [ObservableProperty] private IReadOnlyList<CausalRow> _originators = Array.Empty<CausalRow>();

    public void Apply(IReadOnlyList<ObservabilitySample> samples)
    {
        var diagnostic = samples
            .Where(x => x.SampleKind.Equals("diagnostic", StringComparison.OrdinalIgnoreCase) && !string.IsNullOrWhiteSpace(x.CausalOrigin))
            .ToList();
        var latest = diagnostic.LastOrDefault();
        CurrentOrigin = latest?.CausalOrigin ?? "INDETERMINADO";
        Originator = latest?.Originator ?? "Sin originador confirmado";
        OriginAccent = DashboardRules.OriginBrush(CurrentOrigin);
        TsplusCount = diagnostic.Count(x => string.Equals(x.CausalOrigin, "TSPLUS", StringComparison.OrdinalIgnoreCase)).ToString();
        WindowsCount = diagnostic.Count(x => string.Equals(x.CausalOrigin, "WINDOWS", StringComparison.OrdinalIgnoreCase)).ToString();
        ExternalCount = diagnostic.Count(x => string.Equals(x.CausalOrigin, "EXTERNO", StringComparison.OrdinalIgnoreCase)).ToString();
        IndeterminateCount = diagnostic.Count(x => !string.Equals(x.CausalOrigin, "TSPLUS", StringComparison.OrdinalIgnoreCase)
                                                && !string.Equals(x.CausalOrigin, "WINDOWS", StringComparison.OrdinalIgnoreCase)
                                                && !string.Equals(x.CausalOrigin, "EXTERNO", StringComparison.OrdinalIgnoreCase)).ToString();
        LastCausalMoment = latest is null ? "Sin instante causal disponible" : $"{latest.Timestamp.ToLocalTime():dd/MM/yyyy HH:mm:ss} · {CurrentOrigin} · {Originator}";
        Originators = diagnostic
            .Where(x => !string.IsNullOrWhiteSpace(x.Originator))
            .GroupBy(x => x.Originator!, StringComparer.OrdinalIgnoreCase)
            .Select(g => new CausalRow(g.Key, g.Last().CausalOrigin ?? "INDETERMINADO", g.Count().ToString(), DashboardRules.OriginBrush(g.Last().CausalOrigin)))
            .OrderByDescending(x => int.TryParse(x.Count, out var count) ? count : 0)
            .ThenBy(x => x.Name, StringComparer.OrdinalIgnoreCase)
            .Take(12)
            .ToList();
    }
}
