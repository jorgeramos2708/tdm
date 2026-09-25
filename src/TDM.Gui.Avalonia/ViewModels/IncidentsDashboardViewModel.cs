using CommunityToolkit.Mvvm.ComponentModel;
using TDM.Persistence;

namespace TDM.Gui.Avalonia.ViewModels;

public partial class IncidentsDashboardViewModel : ObservableObject
{
    [ObservableProperty] private string _total = "0";
    [ObservableProperty] private string _critical = "0";
    [ObservableProperty] private string _errors = "0";
    [ObservableProperty] private string _affectedComponents = "0";
    [ObservableProperty] private IReadOnlyList<IncidentRow> _incidents = Array.Empty<IncidentRow>();

    public void Apply(IReadOnlyList<ObservabilitySample> samples)
    {
        var incidents = DashboardRules.UniqueOperationalIncidents(samples);
        Total = incidents.Count.ToString();
        Critical = incidents.Count(x => IsCritical(x.Severity)).ToString();
        Errors = incidents.Count(x => x.Severity.Equals("Error", StringComparison.OrdinalIgnoreCase)).ToString();
        AffectedComponents = incidents.Select(x => x.Component).Where(x => !string.IsNullOrWhiteSpace(x)).Distinct(StringComparer.OrdinalIgnoreCase).Count().ToString();
        Incidents = incidents.Take(60).Select(ToRow).ToList();
    }

    private static IncidentRow ToRow(ObservabilityIncident incident)
        => new(
            incident.Timestamp.ToLocalTime().ToString("dd/MM HH:mm:ss"),
            incident.Severity,
            FriendlyKind(incident.Kind),
            DashboardRules.SanitizeVisibleText(incident.Component),
            CompactSummary(incident.Summary),
            IsCritical(incident.Severity) ? DashboardPalette.Danger :
                incident.Severity.Equals("Error", StringComparison.OrdinalIgnoreCase) ? DashboardPalette.Error : DashboardPalette.Warn);

    private static string FriendlyKind(string kind)
        => kind.ToUpperInvariant() switch
        {
            "APPLICATION_CRASH" => "Crash de aplicación",
            "DOTNET_UNHANDLED_EXCEPTION" => "Excepción .NET no controlada",
            "WER_REPORT" => "Reporte de error de Windows",
            "SERVICE_TERMINATION" => "Servicio detenido inesperadamente",
            "SERVICE_START_FAILURE" => "Falla al iniciar servicio",
            _ => kind.Replace('_', ' ')
        };

    private static string CompactSummary(string? summary)
    {
        var value = DashboardRules.SanitizeVisibleText(summary);
        value = string.Join(' ', value.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));
        return value.Length <= 280 ? value : value[..277].TrimEnd() + "...";
    }

    private static bool IsCritical(string severity)
        => severity.Equals("Critico", StringComparison.OrdinalIgnoreCase) || severity.Equals("Crítico", StringComparison.OrdinalIgnoreCase);
}
