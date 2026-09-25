using System.ServiceProcess;
using TDM.Core;
using TDM.Models;

namespace TDM.Collectors.TSplus;

/// <summary>
/// Snapshot operativo reducido para el monitor continuo. Sólo SCM y metadatos de unos pocos
/// archivos principales; no parsea logs, no hace hashes y no recorre directorios.
/// </summary>
public sealed class LightweightTsplusStateCollector : IReadOnlyCollector
{
    public string Nombre => "TSplus ligero";

    public Task<CollectorResult> CollectAsync(DiagnosticContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var events = new List<DiagnosticEvent>();
        if (!context.Sistema.TsplusDetectado || string.IsNullOrWhiteSpace(context.Sistema.TsplusRuta))
            return Task.FromResult(new CollectorResult([], events));

        var root = context.Sistema.TsplusRuta!;
        var servicesProbe = SnapshotRelevantServices();
        var services = servicesProbe.IsAvailable ? servicesProbe.Value ?? new Dictionary<string, (string Display, string Status)>(StringComparer.OrdinalIgnoreCase) : new Dictionary<string, (string Display, string Status)>(StringComparer.OrdinalIgnoreCase);
        var term = ServiceState(services, "TermService");
        var aps = FirstServiceState(services, "APSC", "Application Publishing");
        var coveragePartial = servicesProbe.IsUnavailable;
        var operational = !coveragePartial && term == "Running" && (aps is null || aps == "Running");

        // P0: el monitor continuo debe detectar directamente la indisponibilidad de servicios
        // TSplus críticos. En particular, Web Portal no puede depender del catálogo reducido de
        // nombres conocidos ni esperar a un diagnóstico completo para aparecer como incidente.
        if (!coveragePartial)
        {
            foreach (var item in services.Where(x => TsplusServiceClassifier.Classify(x.Key, x.Value.Display) == TsplusProduct.RemoteAccess))
            {
                var isRunning = item.Value.Status.Equals("Running", StringComparison.OrdinalIgnoreCase);
                var role = item.Value.Display.Contains("Web Portal", StringComparison.OrdinalIgnoreCase)
                    || item.Key.Contains("WebPortal", StringComparison.OrdinalIgnoreCase)
                    || item.Value.Display.Contains("HTML5", StringComparison.OrdinalIgnoreCase)
                    ? "Web / HTML5 / Web Portal"
                    : "Remote Access / servicio TSplus";
                events.Add(new DiagnosticEvent(
                    DateTimeOffset.Now,
                    "Service Control Manager",
                    item.Value.Display,
                    DiagnosticLayer.Tsplus,
                    isRunning ? DiagnosticSeverity.Informativo : DiagnosticSeverity.Critico,
                    "SERVICE_STATE",
                    $"Estado actual: {item.Value.Status}",
                    Evidencia:
                    [
                        new EvidenceItem("Servicio", item.Key),
                        new EvidenceItem("Nombre visible", item.Value.Display),
                        new EvidenceItem("Estado", item.Value.Status),
                        new EvidenceItem("Proveedor", "TSplus/relacionado"),
                        new EvidenceItem("Rol", role),
                        new EvidenceItem("Requerida ahora", "Sí"),
                        new EvidenceItem("Origen de lectura", "Service Control Manager")
                    ],
                    Producto: TsplusProduct.RemoteAccess));
            }
        }

        events.Add(new DiagnosticEvent(
            DateTimeOffset.Now,
            "TDM",
            "TSplus Remote Access",
            DiagnosticLayer.Tsplus,
            coveragePartial ? DiagnosticSeverity.Advertencia : operational ? DiagnosticSeverity.Informativo : DiagnosticSeverity.Error,
            "TSPLUS_PRODUCT_STATE",
            coveragePartial ? "No fue posible evaluar de forma confiable los servicios básicos de Remote Access." : operational ? "Dependencias básicas de Remote Access disponibles." : "Una dependencia básica de Remote Access cambió de estado.",
            Evidencia:
            [
                new EvidenceItem("Producto", "Remote Access"),
                new EvidenceItem("TermService", coveragePartial ? "No evaluado" : term ?? "No localizado"),
                new EvidenceItem("APSC", coveragePartial ? "No evaluado" : aps ?? "No localizado"),
                new EvidenceItem("Operación observada", coveragePartial ? "No evaluado" : operational ? "Operativo según dependencias básicas" : "Degradado"),
                new EvidenceItem("Cobertura monitor", coveragePartial ? $"Parcial: {servicesProbe.StatusText}" : "SCM + metadatos; sin logs/Registro profundo")
            ],
            Producto: TsplusProduct.RemoteAccess));

        AddFile(events, "Web / HTML5", "settings.js", Path.Combine(root, "Clients", "www", "software", "html5", "settings.js"));
        AddFile(events, "Aplicaciones", "AppControl.ini", Path.Combine(root, "UserDesktop", "files", "AppControl.ini"));
        AddFile(events, "Farm / Gateway", "balance.bin", Path.Combine(root, "Clients", "webserver", "balance.bin"));

        if (!coveragePartial)
        {
            AddOptionalProductState(events, services, TsplusProduct.AdvancedSecurity, "Advanced Security", "AdvancedSecurity", "TSplus-Security");
            AddOptionalProductState(events, services, TsplusProduct.ServerMonitoring, "Server Monitoring", "ServerMonitoring", "TSplus-ServerMonitoring");
        }

        return Task.FromResult(new CollectorResult([], events));
    }

    private static ProbeResult<IReadOnlyDictionary<string, (string Display, string Status)>> SnapshotRelevantServices()
    {
        var probe = TsplusServiceSnapshotReader.Read();
        if (!probe.IsAvailable)
        {
            return probe.State switch
            {
                ProbeState.AccessDenied => ProbeResult<IReadOnlyDictionary<string, (string Display, string Status)>>.AccessDenied(probe.Detail ?? "Acceso denegado al Service Control Manager."),
                ProbeState.Unavailable => ProbeResult<IReadOnlyDictionary<string, (string Display, string Status)>>.Unavailable(probe.Detail ?? "Service Control Manager no disponible."),
                _ => ProbeResult<IReadOnlyDictionary<string, (string Display, string Status)>>.Error(probe.Detail ?? "Error al consultar Service Control Manager.")
            };
        }

        var output = new Dictionary<string, (string Display, string Status)>(StringComparer.OrdinalIgnoreCase);
        foreach (var item in probe.Value ?? new Dictionary<string, (string DisplayName, ServiceControllerStatus Status)>())
        {
            var name = item.Key;
            var display = item.Value.DisplayName;
            if (TsplusServiceClassifier.IsRelated(name, display)
                || TsplusServiceClassifier.IsRelatedIncludingImagePath(name, display, out _ )
                || name.Equals("TermService", StringComparison.OrdinalIgnoreCase)
                || name.Contains("APSC", StringComparison.OrdinalIgnoreCase)
                || display.Contains("TSplus", StringComparison.OrdinalIgnoreCase)
                || name.Contains("ServerMonitoring", StringComparison.OrdinalIgnoreCase)
                || display.Contains("Server Monitoring", StringComparison.OrdinalIgnoreCase)
                || name.Contains("AdvancedSecurity", StringComparison.OrdinalIgnoreCase)
                || display.Contains("Advanced Security", StringComparison.OrdinalIgnoreCase))
                output[name] = (display, item.Value.Status.ToString());
        }
        return ProbeResult<IReadOnlyDictionary<string, (string Display, string Status)>>.Available(output);
    }

    private static string? ServiceState(IReadOnlyDictionary<string, (string Display, string Status)> services, string exact)
        => services.TryGetValue(exact, out var service) ? service.Status : null;

    private static string? FirstServiceState(IReadOnlyDictionary<string, (string Display, string Status)> services, params string[] tokens)
    {
        foreach (var item in services)
        {
            if (tokens.Any(t => item.Key.Contains(t, StringComparison.OrdinalIgnoreCase)
                                || item.Value.Display.Contains(t, StringComparison.OrdinalIgnoreCase)))
                return item.Value.Status;
        }
        return null;
    }

    private static void AddOptionalProductState(List<DiagnosticEvent> events, IReadOnlyDictionary<string, (string Display, string Status)> services,
        TsplusProduct product, string productName, params string[] tokens)
    {
        var matches = services.Where(x => tokens.Any(t => x.Key.Contains(t, StringComparison.OrdinalIgnoreCase) || x.Value.Display.Contains(t, StringComparison.OrdinalIgnoreCase))).ToList();
        if (matches.Count == 0) return;
        var running = matches.Any(x => x.Value.Status.Equals("Running", StringComparison.OrdinalIgnoreCase));
        events.Add(new DiagnosticEvent(
            DateTimeOffset.Now, "TDM", productName, DiagnosticLayer.Tsplus,
            running ? DiagnosticSeverity.Informativo : DiagnosticSeverity.Advertencia,
            "TSPLUS_PRODUCT_STATE",
            running ? $"{productName}: servicio relacionado Running." : $"{productName}: servicios relacionados no están Running.",
            Evidencia:
            [
                new EvidenceItem("Producto", productName),
                new EvidenceItem("Servicios relacionados", string.Join(" | ", matches.Select(x => $"{x.Key}={x.Value.Status}"))),
                new EvidenceItem("Operación observada", running ? "Servicio principal disponible" : "Degradado")
            ],
            Producto: product));
    }

    private static void AddFile(List<DiagnosticEvent> events, string module, string name, string path)
    {
        try
        {
            var existsProbe = FileSystemProbe.File(path);
            var exists = existsProbe.IsAvailable;
            var evidence = new List<EvidenceItem>
            {
                new("Módulo", module),
                new("Archivo", path),
                new("Estado", exists ? "Presente" : "No presente")
            };
            if (exists)
            {
                var fi = new FileInfo(path);
                evidence.Add(new EvidenceItem("Tamaño", fi.Length.ToString()));
                evidence.Add(new EvidenceItem("Última escritura UTC", fi.LastWriteTimeUtc.ToString("O")));
            }
            events.Add(new DiagnosticEvent(
                DateTimeOffset.Now, "TDM", $"{module} / {name}", DiagnosticLayer.Tsplus,
                DiagnosticSeverity.Informativo, "TSPLUS_MODULE_CRITICAL_FILE_STATE",
                $"{name}: {(exists ? "presente" : "no presente")}; sólo metadatos.",
                Archivo: path, Evidencia: evidence, Producto: TsplusProduct.RemoteAccess));
        }
        catch
        {
            // El monitor continuo no escala un error de metadatos a una falla funcional.
        }
    }
}
