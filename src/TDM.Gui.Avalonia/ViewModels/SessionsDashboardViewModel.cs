using CommunityToolkit.Mvvm.ComponentModel;
using TDM.Persistence;

namespace TDM.Gui.Avalonia.ViewModels;

public partial class SessionsDashboardViewModel : ObservableObject
{
    [ObservableProperty] private string _activeValue = "0";
    [ObservableProperty] private string _disconnectedValue = "0";
    [ObservableProperty] private string _coverage = "No evaluado";
    [ObservableProperty] private string _logonFailures = "0";
    [ObservableProperty] private string _nlaFailures = "0";
    [ObservableProperty] private IReadOnlyList<IncidentRow> _sessionIncidents = Array.Empty<IncidentRow>();

    public void Apply(IReadOnlyList<ObservabilitySample> samples)
    {
        if (samples.Count == 0)
        {
            ActiveValue = DisconnectedValue = LogonFailures = NlaFailures = "0";
            Coverage = "No evaluado";
            SessionIncidents = Array.Empty<IncidentRow>();
            return;
        }

        var latest = samples[^1];
        ActiveValue = latest.ActiveSessions.ToString();
        DisconnectedValue = latest.DisconnectedSessions.ToString();
        Coverage = latest.SessionCoverage;
        LogonFailures = latest.LogonFailures.ToString();
        NlaFailures = latest.NlaFailures.ToString();
        SessionIncidents = DashboardRules.UniqueOperationalIncidents(samples)
            .Where(DashboardRules.IsSessionIncident)
            .Take(30)
            .Select(ToRow)
            .ToList();
    }

    private static IncidentRow ToRow(ObservabilityIncident incident)
        => new(
            incident.Timestamp.ToLocalTime().ToString("HH:mm:ss"),
            incident.Severity,
            incident.Kind,
            incident.Component,
            incident.Summary,
            SeverityBrush(incident.Severity));

    private static global::Avalonia.Media.IBrush SeverityBrush(string severity)
        => severity.Equals("Critico", StringComparison.OrdinalIgnoreCase) || severity.Equals("Crítico", StringComparison.OrdinalIgnoreCase)
            ? DashboardPalette.Danger
            : severity.Equals("Error", StringComparison.OrdinalIgnoreCase)
                ? DashboardPalette.Error
                : DashboardPalette.Warn;
}
