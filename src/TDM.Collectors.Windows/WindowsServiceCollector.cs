using System.ServiceProcess;
using TDM.Core;
using TDM.Models;

namespace TDM.Collectors.Windows;

public sealed class WindowsServiceCollector : IReadOnlyCollector
{
    public string Nombre => "Servicios Windows/RDP/TSplus";

    public Task<CollectorResult> CollectAsync(DiagnosticContext context, CancellationToken cancellationToken = default)
    {
        var findings = new List<DiagnosticFinding>();
        var events = new List<DiagnosticEvent>();
        var serviceNames = DiscoverServiceNames();

        foreach (var name in serviceNames)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                using var sc = new ServiceController(name);
                var status = sc.Status;
                var display = SafeDisplayName(sc);
                var tsplusRelated = TsplusServiceClassifier.IsRelatedIncludingImagePath(name, display, out var imagePath);
                var product = tsplusRelated ? TsplusServiceClassifier.Classify(name, display, imagePath) : TsplusProduct.Ninguno;
                var complementary = product is TsplusProduct.AdvancedSecurity or TsplusProduct.ServerMonitoring or TsplusProduct.RemoteSupport or TsplusProduct.TwoFactorAuthentication;
                var catalog = WindowsServiceCatalog.Find(name);
                var startMode = WindowsServiceCatalog.ReadStartMode(name);
                var autoStart = startMode.Equals("Automático", StringComparison.OrdinalIgnoreCase);
                var requiredNow = (catalog?.RequiredWhenTsplus == true && context.Sistema.TsplusDetectado)
                                  || (tsplusRelated && !complementary && autoStart);
                var presentationState = WindowsServiceCatalog.PresentationState(status, startMode, requiredNow);
                var layer = name.Equals("TermService", StringComparison.OrdinalIgnoreCase) ||
                            name.Equals("UmRdpService", StringComparison.OrdinalIgnoreCase) ||
                            name.Equals("SessionEnv", StringComparison.OrdinalIgnoreCase) ||
                            name.Equals("TermServLicensing", StringComparison.OrdinalIgnoreCase) ||
                            name.Equals("Tssdis", StringComparison.OrdinalIgnoreCase) ||
                            name.Equals("RDMS", StringComparison.OrdinalIgnoreCase) ||
                            name.Equals("TSGateway", StringComparison.OrdinalIgnoreCase)
                    ? DiagnosticLayer.Rdp
                    : tsplusRelated ? DiagnosticLayer.Tsplus : catalog?.Area == "Red" ? DiagnosticLayer.Red : DiagnosticLayer.Windows;

                var shouldWarn = WindowsServiceCatalog.ShouldWarnWhenStopped(status, startMode, requiredNow);
                var stoppedSeverity = catalog?.RequiredWhenTsplus == true && requiredNow
                    ? DiagnosticSeverity.Critico
                    : DiagnosticSeverity.Advertencia;
                events.Add(new DiagnosticEvent(
                    DateTimeOffset.Now,
                    "Service Control Manager",
                    display,
                    layer,
                    shouldWarn ? stoppedSeverity : DiagnosticSeverity.Informativo,
                    "SERVICE_STATE",
                    $"Estado actual: {status}",
                    Evidencia:
                    [
                        new EvidenceItem("Servicio", name),
                        new EvidenceItem("Nombre visible", display),
                        new EvidenceItem("Estado", status.ToString()),
                        new EvidenceItem("Estado presentación", presentationState),
                        new EvidenceItem("Inicio", startMode),
                        new EvidenceItem("Proveedor", tsplusRelated ? "TSplus/relacionado" : "Windows"),
                        new EvidenceItem("Área", tsplusRelated ? "TSplus" : catalog?.Area ?? "Windows"),
                        new EvidenceItem("Rol", complementary ? "Complementario" : tsplusRelated ? "Remote Access / núcleo" : catalog?.Area ?? "Windows")
                    ],
                    Producto: product));

                if (shouldWarn)
                {
                    findings.Add(new DiagnosticFinding(
                        $"SVC-{Sanitize(name)}", display, stoppedSeverity,
                        $"El servicio {display} no está en ejecución cuando debería estar disponible.",
                        "Se detectó el estado actual mediante Service Control Manager en modo lectura. Para servicios Windows bajo demanda, TDM no considera falla un estado detenido si su inicio es Manual. Los servicios TSplus se descubren dinámicamente por nombre, nombre visible o ImagePath.",
                        [new EvidenceItem("Estado", status.ToString()), new EvidenceItem("Inicio", startMode), new EvidenceItem("Servicio", name)],
                        ConfidenceLevel.Alta,
                        Capa: layer));
                }
            }
            catch (InvalidOperationException ex)
            {
                findings.Add(new DiagnosticFinding(
                    $"SVC-{Sanitize(name)}-READ", name, DiagnosticSeverity.Advertencia,
                    "No se pudo consultar el servicio.",
                    "La fuente queda NO EVALUADA para este servicio: " + ex.Message,
                    [new EvidenceItem("Servicio", name), new EvidenceItem("Cobertura", "No evaluado")], ConfidenceLevel.Media,
                    Capa: DiagnosticLayer.Windows));
            }
        }

        return Task.FromResult(new CollectorResult(findings, events));
    }

    private static IReadOnlyList<string> DiscoverServiceNames()
    {
        ServiceController[] services;
        try { services = ServiceController.GetServices(); }
        catch
        {
            return WindowsServiceCatalog.Targets
                .Where(x => x.RequiredWhenTsplus)
                .Select(x => x.Name)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(x => x, StringComparer.OrdinalIgnoreCase)
                .ToList();
        }

        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            foreach (var service in services)
            {
                var display = SafeDisplayName(service);
                if (WindowsServiceCatalog.IsRelevant(service.ServiceName) ||
                    TsplusServiceClassifier.IsRelatedIncludingImagePath(service.ServiceName, display, out _))
                    names.Add(service.ServiceName);
            }
        }
        finally
        {
            foreach (var service in services) service.Dispose();
        }

        return names.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToList();
    }

    private static string SafeDisplayName(ServiceController service)
    {
        try { return string.IsNullOrWhiteSpace(service.DisplayName) ? service.ServiceName : service.DisplayName; }
        catch { return service.ServiceName; }
    }

    private static string Sanitize(string value) => new(value.Where(char.IsLetterOrDigit).Select(char.ToUpperInvariant).Take(32).ToArray());
}
