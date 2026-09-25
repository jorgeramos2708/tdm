using System.Text;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using TDM.Persistence;

namespace TDM.Gui.Avalonia.ViewModels;

public partial class IncidentsDashboardViewModel : ObservableObject
{
    [ObservableProperty] private string _total = "No evaluado";
    [ObservableProperty] private string _critical = "No evaluado";
    [ObservableProperty] private string _errors = "No evaluado";
    [ObservableProperty] private string _affectedComponents = "No evaluado";
    [ObservableProperty] private IReadOnlyList<IncidentRow> _incidents = Array.Empty<IncidentRow>();
    [ObservableProperty] private string _detailTitle = "Incidentes";
    [ObservableProperty] private string _detailText = "Selecciona Ver detalle para el resumen de incidentes.";
    [ObservableProperty] private bool _isDetailVisible;
    private string _incidentsFullDetail = "Sin incidentes en la ventana.";
    private IReadOnlyList<ObservabilityIncident> _allIncidents = [];

    public void Apply(IReadOnlyList<ObservabilitySample> samples)
    {
        if (samples.Count == 0)
        {
            Total = Critical = Errors = AffectedComponents = "No evaluado";
            Incidents = Array.Empty<IncidentRow>();
            _allIncidents = [];
            _incidentsFullDetail = "Sin datos de incidentes en la ventana observable.";
            RefreshVisibleDetail();
            return;
        }

        var incidents = DashboardRules.UniqueOperationalIncidents(samples);
        _allIncidents = incidents;
        Total = incidents.Count.ToString();
        Critical = incidents.Count(x => IsCritical(x.Severity)).ToString();
        Errors = incidents.Count(x => x.Severity.Equals("Error", StringComparison.OrdinalIgnoreCase)).ToString();
        AffectedComponents = incidents.Select(x => x.Component).Where(x => !string.IsNullOrWhiteSpace(x)).Distinct(StringComparer.OrdinalIgnoreCase).Count().ToString();
        Incidents = incidents.Take(60).Select(ToRow).ToList();
        _incidentsFullDetail = BuildIncidentsDetail(incidents);
        RefreshVisibleDetail();
    }

    [RelayCommand] private void ShowIncidentsDetail() => ShowDetail("Incidentes", _incidentsFullDetail);
    [RelayCommand] private void CloseDetail() => IsDetailVisible = false;

    private void ShowDetail(string title, string text)
    {
        DetailTitle = title;
        DetailText = text;
        IsDetailVisible = true;
    }

    private void RefreshVisibleDetail()
    {
        if (IsDetailVisible && DetailTitle.Equals("Incidentes", StringComparison.Ordinal))
            DetailText = _incidentsFullDetail;
    }

    private string BuildIncidentsDetail(IReadOnlyList<ObservabilityIncident> incidents)
    {
        if (incidents.Count == 0) return "Sin incidentes en la ventana observable.";
        var builder = new StringBuilder();
        builder.Append($"Total: {Total}. Críticos: {Critical}. Error: {Errors}. Componentes afectados: {AffectedComponents}.");
        var byKind = incidents
            .GroupBy(x => x.Kind, StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(g => g.Count())
            .Take(6)
            .Select(g => $"{FriendlyKind(g.Key)}: {g.Count()}");
        builder.AppendLine();
        builder.AppendLine($"Por tipo: {string.Join(" · ", byKind)}.");

        var review = incidents
            .Where(x => IsCritical(x.Severity) || x.Severity.Equals("Error", StringComparison.OrdinalIgnoreCase))
            .ToList();
        if (review.Count == 0) review = incidents.ToList();
        builder.AppendLine("Elementos a revisar (críticos y errores primero):");
        foreach (var incident in review.Take(15))
        {
            builder.Append($"• {incident.Timestamp.ToLocalTime():dd/MM HH:mm} · {SeverityLabel(incident.Severity)}");
            builder.Append($" · {FriendlyKind(incident.Kind)} · {DashboardRules.SanitizeVisibleText(incident.Component)}");
            builder.Append($" — {CompactSummary(incident.Summary)}");
            builder.AppendLine();
        }
        if (review.Count > 15)
            builder.Append($"… y {review.Count - 15} incidente(s) más en la ventana.");
        return builder.ToString().TrimEnd();
    }

    private static string SeverityLabel(string severity)
        => IsCritical(severity) ? "Crítico" : severity;

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
