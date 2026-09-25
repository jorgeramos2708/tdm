using System.Diagnostics;
using System.ServiceProcess;
using TDM.Core;
using TDM.Models;

namespace TDM.Collectors.TSplus;

public sealed class TsplusInventoryCollector : IReadOnlyCollector
{
    public string Nombre => "Inventario TSplus";

    public Task<CollectorResult> CollectAsync(DiagnosticContext context, CancellationToken cancellationToken = default)
    {
        var findings = new List<DiagnosticFinding>();
        var events = new List<DiagnosticEvent>();

        if (!context.Sistema.TsplusDetectado)
        {
            events.Add(new DiagnosticEvent(
                DateTimeOffset.Now, "TDM", "TSplus", DiagnosticLayer.Tsplus,
                DiagnosticSeverity.Informativo, "TSPLUS_NOT_DETECTED",
                "No se detectó una instalación de TSplus Remote Access en este equipo."));
            return Task.FromResult(new CollectorResult(findings, events));
        }

        var evidence = new List<EvidenceItem>
        {
            new("Ruta", context.Sistema.TsplusRuta ?? "N/D"),
            new("Versión", context.Sistema.TsplusVersion ?? "N/D")
        };

        var servicesProbe = TsplusServiceSnapshotReader.Read(cancellationToken);
        var relatedServices = servicesProbe.IsAvailable
            ? DiscoverRelatedServices(servicesProbe.Value ?? new Dictionary<string, (string DisplayName, ServiceControllerStatus Status)>())
            : [];
        evidence.Add(new EvidenceItem("Servicios relacionados encontrados", servicesProbe.IsAvailable ? relatedServices.Count.ToString() : "No evaluado"));
        evidence.Add(new EvidenceItem("Cobertura de servicios", servicesProbe.IsAvailable ? "Disponible" : $"Parcial: {servicesProbe.StatusText}"));
        foreach (var service in relatedServices.Take(20))
            evidence.Add(new EvidenceItem($"Servicio:{service.Name}", $"{service.DisplayName} = {service.Status}"));

        if (servicesProbe.IsUnavailable)
        {
            findings.Add(new DiagnosticFinding(
                "TSPLUS-INVENTORY-SERVICE-COVERAGE", "Inventario TSplus / servicios", DiagnosticSeverity.Advertencia,
                "No fue posible consultar los servicios relacionados con TSplus.",
                "La cobertura queda como no evaluada y TDM no interpreta el conteo como cero servicios instalados.",
                [new EvidenceItem("Estado de lectura", servicesProbe.StatusText), new EvidenceItem("Detalle", servicesProbe.Detail ?? "Sin detalle adicional")],
                ConfidenceLevel.Confirmada, Capa: DiagnosticLayer.Windows));
        }

        var relatedProcesses = DiscoverRelatedProcesses(context.Sistema.TsplusRuta);
        evidence.Add(new EvidenceItem("Procesos relacionados encontrados", relatedProcesses.Count.ToString()));
        foreach (var process in relatedProcesses.Take(20))
            evidence.Add(new EvidenceItem($"Proceso:{process.Name}", $"PID {process.Pid}"));

        events.Add(new DiagnosticEvent(
            DateTimeOffset.Now, "TDM", "TSplus", DiagnosticLayer.Tsplus,
            DiagnosticSeverity.Informativo, "TSPLUS_INVENTORY",
            "Inventario de TSplus capturado en modo de solo lectura.",
            Evidencia: evidence));

        foreach (var service in relatedServices.Where(s => s.Status != ServiceControllerStatus.Running))
        {
            findings.Add(new DiagnosticFinding(
                $"TSPLUS-SVC-{service.Name}", service.DisplayName,
                DiagnosticSeverity.Advertencia,
                "Se detectó un servicio relacionado con TSplus que no está en ejecución.",
                "TDM solamente consultó el estado del servicio; no intentó iniciarlo ni modificarlo.",
                [new EvidenceItem("Servicio", service.Name), new EvidenceItem("Estado", service.Status.ToString())],
                ConfidenceLevel.Media,
                Capa: DiagnosticLayer.Tsplus));
        }

        return Task.FromResult(new CollectorResult(findings, events));
    }

    private static List<(string Name, string DisplayName, ServiceControllerStatus Status)> DiscoverRelatedServices(
        IReadOnlyDictionary<string, (string DisplayName, ServiceControllerStatus Status)> services)
    {
        var result = new List<(string, string, ServiceControllerStatus)>();
        foreach (var item in services)
        {
            var text = $"{item.Key} {item.Value.DisplayName}";
            if (IsTsplusRelated(text)) result.Add((item.Key, item.Value.DisplayName, item.Value.Status));
        }
        return result;
    }

    private static bool IsTsplusRelated(string text) =>
        text.Contains("TSplus", StringComparison.OrdinalIgnoreCase)
        || text.Contains("Application Publishing", StringComparison.OrdinalIgnoreCase);

    private static List<(string Name, int Pid)> DiscoverRelatedProcesses(string? installPath)
    {
        var result = new List<(string, int)>();
        foreach (var process in Process.GetProcesses())
        {
            try
            {
                using (process)
                {
                    var name = process.ProcessName;
                    var relatedByName = name.Contains("tsplus", StringComparison.OrdinalIgnoreCase)
                        || name.Equals("logonsession", StringComparison.OrdinalIgnoreCase);
                    var relatedByPath = false;
                    try
                    {
                        var file = process.MainModule?.FileName;
                        relatedByPath = !string.IsNullOrWhiteSpace(file)
                            && !string.IsNullOrWhiteSpace(installPath)
                            && file.StartsWith(installPath, StringComparison.OrdinalIgnoreCase);
                    }
                    catch { }

                    if (relatedByName || relatedByPath) result.Add((name, process.Id));
                }
            }
            catch { }
        }
        return result;
    }
}
