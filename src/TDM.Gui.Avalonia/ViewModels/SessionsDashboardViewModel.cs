using System.Text;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using TDM.Persistence;

namespace TDM.Gui.Avalonia.ViewModels;

public partial class SessionsDashboardViewModel : ObservableObject
{
    [ObservableProperty] private string _activeValue = "0";
    [ObservableProperty] private string _disconnectedValue = "0";
    [ObservableProperty] private string _coverage = "No evaluado";
    [ObservableProperty] private string _logonFailures = "No evaluado";
    [ObservableProperty] private string _nlaFailures = "No evaluado";
    [ObservableProperty] private IReadOnlyList<IncidentRow> _sessionIncidents = Array.Empty<IncidentRow>();
    [ObservableProperty] private string _detailTitle = "Sesiones";
    [ObservableProperty] private string _detailText = "Selecciona Ver detalle para el resumen de sesiones.";
    [ObservableProperty] private bool _isDetailVisible;
    private string _sessionsFullDetail = "Sin datos de sesiones.";
    private IReadOnlyList<IncidentRow> _sessionRows = Array.Empty<IncidentRow>();

    public void Apply(IReadOnlyList<ObservabilitySample> samples)
    {
        if (samples.Count == 0)
        {
            ActiveValue = DisconnectedValue = "0";
            LogonFailures = NlaFailures = "No evaluado";
            Coverage = "No evaluado";
            SessionIncidents = Array.Empty<IncidentRow>();
            _sessionRows = Array.Empty<IncidentRow>();
            _sessionsFullDetail = "Sin datos de sesiones en la ventana observable.";
            RefreshVisibleDetail();
            return;
        }

        var latest = samples[^1];
        var sessionSample = DashboardRules.LastSessionSample(samples);
        var sessionSource = sessionSample ?? latest;
        var sessionsEvaluated = sessionSample != null;
        ActiveValue = sessionSource.ActiveSessions.ToString();
        DisconnectedValue = sessionSource.DisconnectedSessions.ToString();
        Coverage = sessionsEvaluated ? sessionSource.SessionCoverage : "No evaluado";
        LogonFailures = sessionsEvaluated ? sessionSource.LogonFailures.ToString() : "No evaluado";
        NlaFailures = sessionsEvaluated ? sessionSource.NlaFailures.ToString() : "No evaluado";
        _sessionRows = DashboardRules.UniqueOperationalIncidents(samples)
            .Where(DashboardRules.IsSessionIncident)
            .Select(ToRow)
            .ToList();
        SessionIncidents = _sessionRows.Take(30).ToList();
        _sessionsFullDetail = BuildSessionsDetail(sessionSource, sessionsEvaluated);
        RefreshVisibleDetail();
    }

    [RelayCommand] private void ShowSessionsDetail() => ShowDetail("Sesiones", _sessionsFullDetail);
    [RelayCommand] private void CloseDetail() => IsDetailVisible = false;

    private void ShowDetail(string title, string text)
    {
        DetailTitle = title;
        DetailText = text;
        IsDetailVisible = true;
    }

    private void RefreshVisibleDetail()
    {
        if (IsDetailVisible && DetailTitle.Equals("Sesiones", StringComparison.Ordinal))
            DetailText = _sessionsFullDetail;
    }

    private string BuildSessionsDetail(ObservabilitySample source, bool failuresEvaluated)
    {
        var builder = new StringBuilder();
        builder.Append($"Activas: {ActiveValue} · Desconectadas: {DisconnectedValue} · Cobertura: {Coverage}.");
        builder.AppendLine();
        builder.Append(failuresEvaluated
            ? $"Fallos de inicio de sesión (última muestra): logon {source.LogonFailures} · NLA {source.NlaFailures}."
            : "Fallos de inicio de sesión: No evaluado (el colector de sesiones no aportó datos).");
        if (_sessionRows.Count == 0)
        {
            builder.AppendLine();
            builder.Append("Sin incidencias de sesión en la ventana observable.");
            return builder.ToString().TrimEnd();
        }

        builder.AppendLine();
        builder.AppendLine("Sesiones con incidencia (revisar en este orden):");
        foreach (var incident in _sessionRows.Take(10))
        {
            builder.Append($"• {incident.Time} · {incident.Severity} · {incident.Kind} · {incident.Component}");
            builder.Append($" — {incident.Summary}");
            builder.AppendLine();
        }
        if (_sessionRows.Count > 10)
            builder.Append($"… y {_sessionRows.Count - 10} incidencia(s) más en la ventana.");
        return builder.ToString().TrimEnd();
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
