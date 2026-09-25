using System.Text;
using Avalonia.Media;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using TDM.Persistence;

namespace TDM.Gui.Avalonia.ViewModels;

public partial class SupportDashboardViewModel : ObservableObject
{
    private const string ServicesDetailTitle = "Servicios y dependencias";
    private const string ModulesDetailTitle = "Módulos TSplus";
    [ObservableProperty] private string _serviceValue = "N/D";
    [ObservableProperty] private double _serviceFraction;
    [ObservableProperty] private string _serviceDetail = "sin datos";
    [ObservableProperty] private string _serviceExtra = string.Empty;
    [ObservableProperty] private IBrush _serviceAccent = DashboardPalette.Muted;
    [ObservableProperty] private IBrush _serviceHealthyAccent = DashboardPalette.Muted;
    [ObservableProperty] private string _moduleValue = "N/D";
    [ObservableProperty] private double _moduleFraction;
    [ObservableProperty] private string _moduleDetail = "sin datos";
    [ObservableProperty] private string _moduleExtra = string.Empty;
    [ObservableProperty] private IBrush _moduleAccent = DashboardPalette.Muted;
    [ObservableProperty] private IBrush _moduleHealthyAccent = DashboardPalette.Muted;
    [ObservableProperty] private string _sessionValue = "0";
    [ObservableProperty] private string _sessionSummary = "Sin incidentes de sesión";
    [ObservableProperty] private string _sessionCounts = "Activas: 0 · Desconectadas: 0";
    [ObservableProperty] private string _sessionCoverage = "Cobertura: No evaluado";
    [ObservableProperty] private IBrush _sessionAccent = DashboardPalette.Muted;
    [ObservableProperty] private IBrush _sessionIncidentAccent = DashboardPalette.Muted;
    [ObservableProperty] private string _incidentValue = "0";
    [ObservableProperty] private int _criticalIncidents;
    [ObservableProperty] private int _errorIncidents;
    [ObservableProperty] private string _incidentSummary = "Sin incidentes en la ventana";
    [ObservableProperty] private string _detailTitle = "Detalle";
    [ObservableProperty] private string _detailText = "Selecciona Ver detalle en una tarjeta.";
    [ObservableProperty] private bool _isDetailVisible;
    private string _servicesFullDetail = "Sin datos de servicios o dependencias.";
    private string _modulesFullDetail = "Sin datos de módulos TSplus.";
    private string _sessionsFullDetail = "Sin datos de sesiones.";
    private string _incidentsFullDetail = "Sin incidentes en la ventana.";
    private IReadOnlyList<ObservabilityIncident> _incidents = [];
    private IReadOnlyList<ObservabilityIncident> _sessionIncidents = [];

    public void Apply(IReadOnlyList<ObservabilitySample> samples)
    {
        if (samples.Count == 0)
        {
            Reset();
            return;
        }

        var latest = samples[^1];
        var incidents = DashboardRules.UniqueOperationalIncidents(samples);
        var serviceSample = samples.LastOrDefault(x => x.ServiceStates is { Count: > 0 });
        var dependencySample = samples.LastOrDefault(x => x.DependencyStates is { Count: > 0 });
        var moduleSample = samples.LastOrDefault(x => x.ModuleHealth.Count > 0);
        var operational = DashboardRules.TsplusOperationalStates(serviceSample?.ServiceStates, dependencySample?.DependencyStates);
        var services = operational.Services;
        var dependencies = operational.Dependencies;

        var serviceLevels = services.ToDictionary(x => x.Key, x => DashboardRules.OperationalStateLevel(x.Value), StringComparer.OrdinalIgnoreCase);
        var dependencyLevels = dependencies.ToDictionary(x => x.Key, x => DashboardRules.OperationalStateLevel(x.Value), StringComparer.OrdinalIgnoreCase);

        var healthyServices = serviceLevels.Count(x => x.Value == 1);
        var healthyDependencies = dependencyLevels.Count(x => x.Value == 1);
        var reviewServices = serviceLevels.Count(x => x.Value is 0 or 2);
        var reviewDependencies = dependencyLevels.Count(x => x.Value is 0 or 2);
        var stoppedServices = serviceLevels.Count(x => x.Value >= 3);
        var stoppedDependencies = dependencyLevels.Count(x => x.Value >= 3);

        var total = services.Count + dependencies.Count;
        var healthy = healthyServices + healthyDependencies;
        var review = reviewServices + reviewDependencies;
        var stopped = stoppedServices + stoppedDependencies;
        var affected = review + stopped;

        var stoppedNames = services
            .Where(x => DashboardRules.OperationalStateLevel(x.Value) >= 3)
            .Select(x => $"Servicio {DashboardRules.SanitizeVisibleText(x.Key)} ({DescribeState(x.Value)})")
            .Concat(dependencies
                .Where(x => DashboardRules.OperationalStateLevel(x.Value) >= 3)
                .Select(x => $"Dependencia {DashboardRules.SanitizeVisibleText(x.Key)} ({DescribeState(x.Value)})"))
            .ToList();
        var reviewNames = services
            .Where(x => DashboardRules.OperationalStateLevel(x.Value) is 0 or 2)
            .Select(x => $"Servicio {DashboardRules.SanitizeVisibleText(x.Key)} ({DescribeState(x.Value)})")
            .Concat(dependencies
                .Where(x => DashboardRules.OperationalStateLevel(x.Value) is 0 or 2)
                .Select(x => $"Dependencia {DashboardRules.SanitizeVisibleText(x.Key)} ({DescribeState(x.Value)})"))
            .ToList();

        ServiceValue = total == 0 ? "N/D" : $"{healthy}/{total}";
        ServiceFraction = total == 0 ? 0d : affected / (double)total;
        ServiceDetail = total == 0 ? "sin datos"
            : affected == 0 ? "sin incidencias"
            : stopped > 0 && review > 0 ? $"{stopped} detenido(s) · {review} revisar"
            : stopped > 0 ? (stopped == 1 ? "1 detenido" : $"{stopped} detenidos")
            : $"{review} revisar";
        ServiceExtra = total == 0
            ? string.Empty
            : $"Servicios {healthyServices}/{services.Count} · Dependencias {healthyDependencies}/{dependencies.Count}";
        ServiceAccent = total == 0 ? DashboardPalette.Muted : stopped > 0 ? DashboardPalette.Warn : review > 0 ? DashboardPalette.Warn : DashboardPalette.Good;
        ServiceHealthyAccent = total == 0 ? DashboardPalette.Muted : DashboardPalette.Good;
        _servicesFullDetail = total == 0
            ? "Sin datos de servicios o dependencias."
            : $"Saludables/neutrales: {healthy}/{total}. Servicios: {healthyServices}/{services.Count}; detenidos: {stoppedServices}; revisar: {reviewServices}. " +
              $"Dependencias: {healthyDependencies}/{dependencies.Count}; detenidas: {stoppedDependencies}; revisar: {reviewDependencies}. " +
              (stoppedNames.Count == 0 ? "No hay elementos detenidos. " : $"Elementos detenidos: {string.Join(", ", stoppedNames)}. ") +
              (reviewNames.Count == 0 ? "No hay elementos pendientes de revisión." : $"Pendientes de revisión: {string.Join(", ", reviewNames)}.");

        var modules = moduleSample?.ModuleHealth ?? new Dictionary<string, string>();
        var criticalModules = modules
            .Where(x => DashboardRules.HealthRank(x.Value) >= 4)
            .Select(x => DashboardRules.CompactModuleName(x.Key))
            .ToList();
        var errorModules = modules
            .Where(x => DashboardRules.HealthRank(x.Value) == 3)
            .Select(x => DashboardRules.CompactModuleName(x.Key))
            .ToList();
        var affectedModules = criticalModules.Concat(errorModules).ToList();
        var criticalLabel = criticalModules.Count == 1 ? "1 crítico" : $"{criticalModules.Count} críticos";

        ModuleValue = modules.Count == 0 ? "N/D" : $"{affectedModules.Count}/{modules.Count}";
        ModuleFraction = modules.Count == 0 ? 0d : affectedModules.Count / (double)modules.Count;
        ModuleDetail = modules.Count == 0
            ? "sin datos"
            : $"{criticalLabel} · {errorModules.Count} con error";
        ModuleExtra = modules.Count == 0
            ? string.Empty
            : affectedModules.Count == 0 ? "Sin módulos con error" : string.Join(", ", affectedModules.Take(2));
        ModuleAccent = modules.Count == 0
            ? DashboardPalette.Muted
            : criticalModules.Count > 0 ? DashboardPalette.Danger
            : errorModules.Count > 0 ? DashboardPalette.Error
            : DashboardPalette.Good;
        ModuleHealthyAccent = modules.Count == 0 ? DashboardPalette.Muted : DashboardPalette.Good;
        _modulesFullDetail = modules.Count == 0
            ? "Sin datos de módulos TSplus."
            : $"Módulos con error o estado crítico: {affectedModules.Count}/{modules.Count}. " +
              $"Críticos: {criticalModules.Count}. Con error: {errorModules.Count}. " +
              (affectedModules.Count == 0 ? "No hay módulos afectados." : $"Módulos afectados: {string.Join(", ", affectedModules)}.") +
              (affectedModules.Count == 0
                  ? string.Empty
                  : $" Estados: {string.Join(" · ", modules
                      .Where(x => affectedModules.Contains(DashboardRules.CompactModuleName(x.Key)))
                      .Select(x => $"{DashboardRules.CompactModuleName(x.Key)}: {DashboardRules.NormalizeHealthDetail(x.Value)}"))}.");

        var sessionIncidents = incidents.Where(DashboardRules.IsSessionIncident).ToList();
        SessionValue = (latest.ActiveSessions + latest.DisconnectedSessions).ToString();
        SessionSummary = sessionIncidents.Count switch
        {
            0 => "Sin incidentes de sesión",
            1 => "1 incidente de sesión",
            _ => $"{sessionIncidents.Count} incidentes de sesión"
        };
        SessionCounts = $"Activas: {latest.ActiveSessions} · Desconectadas: {latest.DisconnectedSessions}";
        SessionCoverage = $"Cobertura: {latest.SessionCoverage}";
        SessionAccent = DashboardPalette.Cyan;
        SessionIncidentAccent = sessionIncidents.Count > 0 ? DashboardPalette.Error : DashboardPalette.Good;

        CriticalIncidents = incidents.Count(x => x.Severity.Equals("Critico", StringComparison.OrdinalIgnoreCase) || x.Severity.Equals("Crítico", StringComparison.OrdinalIgnoreCase));
        ErrorIncidents = incidents.Count(x => x.Severity.Equals("Error", StringComparison.OrdinalIgnoreCase));
        IncidentValue = incidents.Count.ToString();
        IncidentSummary = incidents.Count == 0
            ? "Sin incidentes en la ventana"
            : string.Join(" · ", incidents.GroupBy(x => x.Kind, StringComparer.OrdinalIgnoreCase).OrderByDescending(g => g.Count()).Take(2).Select(g => $"{g.Key}: {g.Count()}"));

        _incidents = incidents;
        _sessionIncidents = sessionIncidents;
        _sessionsFullDetail = BuildSessionsDetail();
        _incidentsFullDetail = BuildIncidentsDetail();
        RefreshVisibleDetail();
    }

    [RelayCommand] private void ShowServicesDetail() => ShowDetail(ServicesDetailTitle, _servicesFullDetail);
    [RelayCommand] private void ShowModulesDetail() => ShowDetail(ModulesDetailTitle, _modulesFullDetail);
    [RelayCommand] private void ShowSessionsDetail() => ShowDetail("Sesiones", _sessionsFullDetail);
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
        if (!IsDetailVisible) return;
        if (DetailTitle.Equals(ServicesDetailTitle, StringComparison.Ordinal)) DetailText = _servicesFullDetail;
        else if (DetailTitle.Equals(ModulesDetailTitle, StringComparison.Ordinal)) DetailText = _modulesFullDetail;
        else if (DetailTitle.Equals("Sesiones", StringComparison.Ordinal)) DetailText = _sessionsFullDetail;
        else if (DetailTitle.Equals("Incidentes", StringComparison.Ordinal)) DetailText = _incidentsFullDetail;
    }

    private string BuildSessionsDetail()
    {
        var builder = new StringBuilder();
        builder.Append($"Total observadas: {SessionValue}. {SessionCounts}. {SessionSummary}. {SessionCoverage}.");
        if (_sessionIncidents.Count == 0)
        {
            builder.AppendLine();
            builder.Append("Sin incidencias de sesión en la ventana observable.");
            return builder.ToString();
        }

        builder.AppendLine();
        builder.AppendLine("Sesiones con incidencia (revisar en este orden):");
        foreach (var incident in _sessionIncidents.Take(10))
        {
            builder.Append($"• {incident.Timestamp.ToLocalTime():dd/MM HH:mm} · {SeverityLabel(incident.Severity)}");
            builder.Append($" · {DescribeSubject(incident)} · {incident.Kind}");
            builder.Append($" — {incident.Summary}");
            builder.AppendLine();
        }
        if (_sessionIncidents.Count > 10)
            builder.Append($"… y {_sessionIncidents.Count - 10} incidencia(s) más en la ventana.");
        return builder.ToString().TrimEnd();
    }

    private string BuildIncidentsDetail()
    {
        var builder = new StringBuilder();
        builder.Append($"Total: {IncidentValue}. Críticos: {CriticalIncidents}. Error: {ErrorIncidents}. {IncidentSummary}");
        if (_incidents.Count == 0) return builder.ToString();

        var byKind = _incidents
            .GroupBy(x => x.Kind, StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(g => g.Count())
            .Take(6)
            .Select(g => $"{g.Key}: {g.Count()}");
        builder.AppendLine();
        builder.AppendLine($"Por tipo: {string.Join(" · ", byKind)}.");

        var review = _incidents
            .Where(x => x.Severity.Equals("Critico", StringComparison.OrdinalIgnoreCase)
                     || x.Severity.Equals("Crítico", StringComparison.OrdinalIgnoreCase)
                     || x.Severity.Equals("Error", StringComparison.OrdinalIgnoreCase))
            .ToList();
        if (review.Count == 0) review = _incidents.ToList();
        builder.AppendLine("Elementos a revisar (servicios, procesos y sesiones afectados):");
        foreach (var incident in review.Take(15))
        {
            builder.Append($"• {incident.Timestamp.ToLocalTime():dd/MM HH:mm} · {SeverityLabel(incident.Severity)}");
            builder.Append($" · {incident.Kind} · {DescribeSubject(incident)}");
            builder.Append($" — {incident.Summary}");
            builder.AppendLine();
        }
        if (review.Count > 15)
            builder.Append($"… y {review.Count - 15} elemento(s) más en la ventana.");
        return builder.ToString().TrimEnd();
    }

    private static string DescribeSubject(ObservabilityIncident incident)
        => string.IsNullOrWhiteSpace(incident.Subject)
            ? DashboardRules.SanitizeVisibleText(incident.Component)
            : DashboardRules.SanitizeVisibleText(incident.Subject);

    private static string DescribeState(string state)
        => DashboardRules.LocalizeOperationalText(state);

    private static string SeverityLabel(string severity)
        => severity.Equals("Critico", StringComparison.OrdinalIgnoreCase) ? "Crítico" : severity;

    private void Reset()
    {
        ServiceValue = ModuleValue = "N/D";
        ServiceFraction = ModuleFraction = 0d;
        ServiceDetail = ModuleDetail = "sin datos";
        ServiceExtra = ModuleExtra = string.Empty;
        ServiceAccent = ServiceHealthyAccent = ModuleAccent = ModuleHealthyAccent = SessionAccent = SessionIncidentAccent = DashboardPalette.Muted;
        _servicesFullDetail = "Sin datos de servicios o dependencias.";
        _modulesFullDetail = "Sin datos de módulos TSplus.";
        _incidents = [];
        _sessionIncidents = [];
        _sessionsFullDetail = "Sin datos de sesiones.";
        _incidentsFullDetail = "Sin incidentes en la ventana.";
        SessionValue = IncidentValue = "0";
        SessionSummary = "Sin incidentes de sesión";
        SessionCounts = "Activas: 0 · Desconectadas: 0";
        SessionCoverage = "Cobertura: No evaluado";
        CriticalIncidents = ErrorIncidents = 0;
        IncidentSummary = "Sin incidentes en la ventana";
        RefreshVisibleDetail();
    }
}
