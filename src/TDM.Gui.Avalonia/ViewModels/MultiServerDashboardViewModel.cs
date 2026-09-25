using System.Text;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
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
    [ObservableProperty] private string _detailTitle = "Servidores/Granja";
    [ObservableProperty] private string _detailText = "Selecciona Ver detalle para el estado de la granja.";
    [ObservableProperty] private bool _isDetailVisible;
    private string _nodesFullDetail = "Sin datos de nodos en la granja.";
    private IReadOnlyList<FederationNodeStatus> _statuses = [];

    public void Apply(string coordinator, IReadOnlyList<FederationNodeStatus> statuses)
    {
        Coordinator = string.IsNullOrWhiteSpace(coordinator) ? Environment.MachineName : coordinator;
        _statuses = statuses;
        Total = statuses.Count.ToString();
        var offlineNodes = statuses.Where(IsOffline).ToList();
        var reachable = statuses.Where(x => !IsOffline(x)).ToList();
        var degradedNodes = reachable.Where(IsDegraded).ToList();
        var onlineNodes = reachable.Where(x => !IsDegraded(x)).ToList();
        Online = onlineNodes.Count.ToString();
        Degraded = degradedNodes.Count.ToString();
        Offline = offlineNodes.Count.ToString();
        Nodes = statuses.Select(x => new FederationRow(
            x.Node.DisplayName, x.Node.Group, x.Node.Role, x.Connectivity, x.Health,
            x.CpuPercent.HasValue ? $"{x.CpuPercent.Value:0.0}%" : "N/D",
            x.MemoryUsedPercent.HasValue ? $"{x.MemoryUsedPercent.Value:0.0}%" : "N/D",
            x.ActiveSessions.ToString(), x.Incidents.ToString(), x.Detail,
            x.Health.Equals("FALLA", StringComparison.OrdinalIgnoreCase) ? DashboardPalette.Error :
            IsOffline(x) ? DashboardPalette.Muted :
            IsDegraded(x) ? DashboardPalette.Warn : DashboardPalette.Good)).ToList();
        _nodesFullDetail = BuildNodesDetail();
        RefreshVisibleDetail();
    }

    [RelayCommand] private void ShowNodesDetail() => ShowDetail("Servidores/Granja", _nodesFullDetail);
    [RelayCommand] private void CloseDetail() => IsDetailVisible = false;

    private void ShowDetail(string title, string text)
    {
        DetailTitle = title;
        DetailText = text;
        IsDetailVisible = true;
    }

    private void RefreshVisibleDetail()
    {
        if (IsDetailVisible && DetailTitle.Equals("Servidores/Granja", StringComparison.Ordinal))
            DetailText = _nodesFullDetail;
    }

    private string BuildNodesDetail()
    {
        if (_statuses.Count == 0) return "Sin nodos configurados en la granja.";
        var thresholds = SupportMonitoringSettings.Default.Thresholds;
        var builder = new StringBuilder();
        builder.Append($"Nodos: {Total} · En línea: {Online} · Degradados: {Degraded} · Sin datos: {Offline}.");
        builder.AppendLine();
        builder.AppendLine("Estado por nodo (salud · conectividad · antigüedad · reloj):");
        foreach (var node in _statuses.Take(20))
        {
            builder.Append($"• {DashboardRules.SanitizeVisibleText(node.Node.DisplayName)} — salud: {node.Health} · conectividad: {node.Connectivity}");
            if (node.CpuPercent.HasValue) builder.Append($" · CPU {node.CpuPercent.Value:0.0}%");
            builder.Append($" · sesiones {node.ActiveSessions} · incidentes {node.Incidents}");
            builder.Append($" · última muestra hace {node.AgeSeconds:0} s");
            builder.Append($" · reloj {node.ClockFileDeltaSeconds:+0.0;-0.0} s");
            if (node.AgeSeconds >= thresholds.NodeOfflineSeconds) builder.Append(" [SIN DATOS]");
            else if (node.AgeSeconds >= thresholds.NodeStaleWarningSeconds) builder.Append(" [MUESTRA ANTIGUA]");
            if (Math.Abs(node.ClockFileDeltaSeconds) >= thresholds.ClockDriftWarningSeconds) builder.Append(" [DESFASE DE RELOJ]");
            builder.AppendLine();
        }
        if (_statuses.Count > 20)
            builder.Append($"… y {_statuses.Count - 20} nodo(s) más.");
        return builder.ToString().TrimEnd();
    }

    private static bool IsOffline(FederationNodeStatus status)
        => status.Connectivity.Equals("SIN DATOS", StringComparison.OrdinalIgnoreCase)
           || status.Connectivity.Equals("NO ACCESIBLE", StringComparison.OrdinalIgnoreCase);

    private static bool IsDegraded(FederationNodeStatus status)
        => status.Connectivity.Equals("ATRASADO", StringComparison.OrdinalIgnoreCase)
           || status.Health.Equals("DEGRADADO", StringComparison.OrdinalIgnoreCase)
           || status.Health.Equals("FALLA", StringComparison.OrdinalIgnoreCase);
}
