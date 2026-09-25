using System.Net.NetworkInformation;
using TDM.Core;
using TDM.Models;

namespace TDM.Collectors.Network;

/// <summary>
/// Estado básico de interfaces/gateway para el monitor continuo. No ejecuta netstat ni resuelve procesos.
/// </summary>
public sealed class LightweightNetworkStateCollector : IReadOnlyCollector
{
    public string Nombre => "Red ligera";

    public Task<CollectorResult> CollectAsync(DiagnosticContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var adapters = NetworkInterface.GetAllNetworkInterfaces()
            .Where(x => x.NetworkInterfaceType != NetworkInterfaceType.Loopback)
            .ToList();
        var active = adapters.Where(x => x.OperationalStatus == OperationalStatus.Up).ToList();
        var hasGateway = false;
        var gatewayReadFailures = 0;
        foreach (var adapter in active)
        {
            try
            {
                if (adapter.GetIPProperties().GatewayAddresses.Any(g => !g.Address.Equals(System.Net.IPAddress.Any) && !g.Address.Equals(System.Net.IPAddress.IPv6Any)))
                    hasGateway = true;
            }
            catch { gatewayReadFailures++; }
        }
        var gatewayEvaluated = hasGateway || gatewayReadFailures == 0;

        var severity = context.Sistema.TsplusDetectado && active.Count == 0
            ? DiagnosticSeverity.Error
            : gatewayEvaluated ? DiagnosticSeverity.Informativo : DiagnosticSeverity.Advertencia;
        var evt = new DiagnosticEvent(
            DateTimeOffset.Now,
            "NetworkInformation",
            "Pila de red",
            DiagnosticLayer.Red,
            severity,
            DiagnosticEventTypes.NetworkState,
            $"Adaptadores activos={active.Count}; gateway={(gatewayEvaluated ? (hasGateway ? "Sí" : "No") : "No evaluado")}",
            Evidencia:
            [
                new EvidenceItem("Adaptadores activos", active.Count.ToString()),
                new EvidenceItem("Gateway disponible", gatewayEvaluated ? (hasGateway ? "Sí" : "No") : "No evaluado"),
                new EvidenceItem("Cobertura", gatewayEvaluated ? "Completa" : "Parcial"),
                new EvidenceItem("Cobertura monitor", gatewayEvaluated
                    ? "NetworkInterface; sin netstat/procesos"
                    : $"NetworkInterface; {gatewayReadFailures} adaptador(es) sin propiedades IP legibles; sin netstat/procesos")
            ]);

        return Task.FromResult(new CollectorResult([], [evt]));
    }
}
