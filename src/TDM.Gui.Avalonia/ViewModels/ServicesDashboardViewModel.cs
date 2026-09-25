using CommunityToolkit.Mvvm.ComponentModel;
using TDM.Persistence;

namespace TDM.Gui.Avalonia.ViewModels;

public partial class ServicesDashboardViewModel : ObservableObject
{
    [ObservableProperty] private string _serviceSummary = "Sin datos";
    [ObservableProperty] private string _dependencySummary = "Sin datos";
    [ObservableProperty] private IReadOnlyList<StateRow> _services = Array.Empty<StateRow>();
    [ObservableProperty] private IReadOnlyList<StateRow> _dependencies = Array.Empty<StateRow>();

    public void Apply(IReadOnlyList<ObservabilitySample> samples)
    {
        if (samples.Count == 0)
        {
            ServiceSummary = DependencySummary = "Sin datos";
            Services = Dependencies = Array.Empty<StateRow>();
            return;
        }

        // Las muestras de 5 s son ligeras; conservar el último conjunto de estados
        // de servicios/dependencias evita que una muestra ligera vacíe el mapa SCM.
        var serviceSample = samples.LastOrDefault(x => x.ServiceStates is { Count: > 0 });
        var dependencySample = samples.LastOrDefault(x => x.DependencyStates is { Count: > 0 });
        var operational = DashboardRules.TsplusOperationalStates(serviceSample?.ServiceStates, dependencySample?.DependencyStates);
        var services = operational.Services;
        var dependencies = operational.Dependencies;

        Services = BuildRows(services, dependencyRows: false);
        Dependencies = BuildRows(dependencies, dependencyRows: true);

        ServiceSummary = BuildSummary(services);
        DependencySummary = BuildSummary(dependencies);
    }

    private static IReadOnlyList<StateRow> BuildRows(IReadOnlyDictionary<string, string> states, bool dependencyRows)
        => states
            // Lo que requiere intervención aparece primero; dentro de cada estado se
            // mantiene una agrupación estable TSplus → Windows → General.
            .OrderBy(x => StateRank(x.Value))
            .ThenBy(x => OriginRank(dependencyRows ? ClassifyDependencyOrigin(x.Key) : ClassifyOrigin(x.Key)))
            .ThenBy(x => x.Key, StringComparer.OrdinalIgnoreCase)
            .Select(x =>
            {
                var origin = dependencyRows ? ClassifyDependencyOrigin(x.Key) : ClassifyOrigin(x.Key);
                var presentation = PresentState(x.Value);
                return new StateRow(
                    DashboardRules.NormalizeDisplayName(x.Key),
                    origin,
                    presentation.Label,
                    presentation.Accent,
                    DashboardRules.OriginBrush(origin));
            })
            .ToList();

    private static int StateRank(string? state)
    {
        var p = PresentState(state);
        return p.Label switch
        {
            "Detenido" => 0,
            "Revisar" => 1,
            "No evaluado" => 2,
            "Bajo demanda" => 3,
            "No requerido" => 4,
            "Complementario" => 5,
            "En ejecución" => 6,
            _ => 7
        };
    }

    private static (string Label, global::Avalonia.Media.IBrush Accent) PresentState(string? state)
    {
        var value = state ?? string.Empty;
        if (value.Contains("Complementario", StringComparison.OrdinalIgnoreCase))
            return ("Complementario", DashboardPalette.Muted);
        if (value.Contains("No evaluado", StringComparison.OrdinalIgnoreCase) ||
            value.Contains("Unknown", StringComparison.OrdinalIgnoreCase) ||
            value.Contains("N/D", StringComparison.OrdinalIgnoreCase))
            return ("No evaluado", DashboardPalette.Warn);
        if (value.Contains("Bajo demanda", StringComparison.OrdinalIgnoreCase))
            return ("Bajo demanda", DashboardPalette.Good);
        if (value.Contains("No requerido", StringComparison.OrdinalIgnoreCase) ||
            (value.Contains("Deshabilitado", StringComparison.OrdinalIgnoreCase) && !value.Contains("requerido", StringComparison.OrdinalIgnoreCase)))
            return ("No requerido", DashboardPalette.Muted);
        if (DashboardRules.IsRunningState(value))
            return ("En ejecución", DashboardPalette.Good);
        if (value.Contains("Condicional", StringComparison.OrdinalIgnoreCase))
            return ("Revisar", DashboardPalette.Warn);
        if (value.Contains("Stopped", StringComparison.OrdinalIgnoreCase) || value.Contains("Failed", StringComparison.OrdinalIgnoreCase) ||
            value.Contains("Error", StringComparison.OrdinalIgnoreCase) || value.Contains("No operativo", StringComparison.OrdinalIgnoreCase))
            return ("Detenido", DashboardPalette.Warn);
        if (value.Contains("Parcial", StringComparison.OrdinalIgnoreCase) || value.Contains("Advertencia", StringComparison.OrdinalIgnoreCase) ||
            value.Contains("Pending", StringComparison.OrdinalIgnoreCase) || value.Contains("Paused", StringComparison.OrdinalIgnoreCase))
            return ("Revisar", DashboardPalette.Warn);
        return ("No evaluado", DashboardPalette.Warn);
    }

    private static string ClassifyDependencyOrigin(string name)
    {
        var separator = name.IndexOf('→');
        if (separator > 0 && separator < name.Length - 1)
            return ClassifyOrigin(name[(separator + 1)..].Trim());
        return ClassifyOrigin(name);
    }

    private static int OriginRank(string origin)
        => origin.Equals("TSplus", StringComparison.OrdinalIgnoreCase) ? 0
            : origin.Equals("Windows", StringComparison.OrdinalIgnoreCase) ? 1
            : 2;


    private static string ClassifyOrigin(string name)
    {
        if (string.IsNullOrWhiteSpace(name)) return "General";

        // TSplus primero: una relación como "RemoteSupport... → RpcSs" debe seguir
        // identificándose como originada por un servicio TSplus.
        var tsplus = new[]
        {
            "TSplus", "RemoteSupport", "ServerMonitoring", "Advanced Security", "TSplus-Security",
            "Application Publishing", "APSC", "WebPortal", "HTML5", "TwoFactor", "Two Factor", "UniversalPrinter", "Universal Printer"
        };
        if (tsplus.Any(term => name.Contains(term, StringComparison.OrdinalIgnoreCase))) return "TSplus";

        var windows = new[]
        {
            "TermService", "UmRdpService", "SessionEnv", "TermServLicensing", "Tssdis", "RDMS", "TSGateway",
            "RpcSs", "RpcEptMapper", "DcomLaunch", "EventLog", "Winmgmt", "Schedule", "SENS",
            "BFE", "MpsSvc", "Nsi", "Dnscache", "NlaSvc", "Dhcp", "Netman", "iphlpsvc",
            "WinHttpAutoProxySvc", "LanmanWorkstation", "LanmanServer", "ProfSvc", "UserManager",
            "gpsvc", "SamSs", "CryptSvc", "KeyIso", "W32Time", "Netlogon", "Spooler",
            "RDP/Listener", "Red/Gateway"
        };
        if (windows.Any(term => name.Contains(term, StringComparison.OrdinalIgnoreCase))) return "Windows";
        return "General";
    }

    private static string BuildSummary(IReadOnlyDictionary<string, string> states)
    {
        if (states.Count == 0) return "Sin datos";
        var labels = states.Values.Select(x => PresentState(x).Label).ToList();
        var running = labels.Count(x => x == "En ejecución");
        var stopped = labels.Count(x => x == "Detenido");
        var review = labels.Count(x => x is "Revisar" or "No evaluado");
        var demand = labels.Count(x => x is "Bajo demanda" or "No requerido");
        var complementary = labels.Count(x => x == "Complementario");
        return $"{running} en ejecución · {stopped} detenidos · {review} revisar · {demand} bajo demanda/no requerido · {complementary} complementarios";
    }
}
