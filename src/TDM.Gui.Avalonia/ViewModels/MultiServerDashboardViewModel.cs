using CommunityToolkit.Mvvm.ComponentModel;
using TDM.Persistence;

namespace TDM.Gui.Avalonia.ViewModels;

public partial class MultiServerDashboardViewModel : ObservableObject
{
    [ObservableProperty] private string _coordinator = Environment.MachineName;
    [ObservableProperty] private string _total = "0";
    [ObservableProperty] private string _online = "0";
    [ObservableProperty] private string _degraded = "0";
    [ObservableProperty] private string _offline = "0";
    [ObservableProperty] private IReadOnlyList<FederationRow> _nodes = Array.Empty<FederationRow>();

    public void Apply(string coordinator, IReadOnlyList<FederationNodeStatus> statuses)
    {
        Coordinator = string.IsNullOrWhiteSpace(coordinator) ? Environment.MachineName : coordinator;
        Total = statuses.Count.ToString();
        Online = statuses.Count(x => x.Connectivity.Equals("EN LÍNEA", StringComparison.OrdinalIgnoreCase)).ToString();
        Degraded = statuses.Count(x => x.Health.Equals("DEGRADADO", StringComparison.OrdinalIgnoreCase) || x.Connectivity.Equals("ATRASADO", StringComparison.OrdinalIgnoreCase)).ToString();
        Offline = statuses.Count(x => x.Connectivity.Equals("SIN DATOS", StringComparison.OrdinalIgnoreCase) || x.Connectivity.Equals("NO ACCESIBLE", StringComparison.OrdinalIgnoreCase)).ToString();
        Nodes = statuses.Select(x => new FederationRow(
            x.Node.DisplayName, x.Node.Group, x.Node.Role, x.Connectivity, x.Health,
            x.CpuPercent.HasValue ? $"{x.CpuPercent.Value:0.0}%" : "N/D",
            x.MemoryUsedPercent.HasValue ? $"{x.MemoryUsedPercent.Value:0.0}%" : "N/D",
            x.ActiveSessions.ToString(), x.Incidents.ToString(), x.Detail,
            x.Health.Equals("FALLA", StringComparison.OrdinalIgnoreCase) ? DashboardPalette.Error :
            x.Connectivity.Equals("SIN DATOS", StringComparison.OrdinalIgnoreCase) || x.Connectivity.Equals("NO ACCESIBLE", StringComparison.OrdinalIgnoreCase) ? DashboardPalette.Muted :
            x.Health.Equals("DEGRADADO", StringComparison.OrdinalIgnoreCase) || x.Connectivity.Equals("ATRASADO", StringComparison.OrdinalIgnoreCase) ? DashboardPalette.Warn : DashboardPalette.Good)).ToList();
    }
}
