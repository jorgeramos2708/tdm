using System.ServiceProcess;
using TDM.Core;
using TDM.Models;

namespace TDM.Collectors.Windows;

/// <summary>
/// Construye en modo de solo lectura el grafo real de dependencias SCM para servicios
/// Windows/RDP y servicios relacionados con TSplus descubiertos dinámicamente.
/// No cambia estados ni configuración de servicios.
/// </summary>
public sealed class ServiceDependencyGraphCollector : IReadOnlyCollector
{
    public string Nombre => "Dependencias reales de servicios Windows/TSplus";

    private const int MaxServices = 320;
    private const int MaxDepth = 4;

    public Task<CollectorResult> CollectAsync(DiagnosticContext context, CancellationToken cancellationToken = default)
    {
        var findings = new List<DiagnosticFinding>();
        var events = new List<DiagnosticEvent>();
        var coverage = new List<EvidenceItem>();

        ServiceController[] all;
        try
        {
            all = ServiceController.GetServices();
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            findings.Add(new DiagnosticFinding(
                "SERVICE-GRAPH-NOT-EVALUATED", "Dependencias de servicios", DiagnosticSeverity.Advertencia,
                "No fue posible construir el grafo real de dependencias del Service Control Manager.",
                "TDM conserva esta fuente como NO EVALUADA; no interpreta la ausencia del grafo como servicios saludables.",
                [new EvidenceItem("Error", ex.Message)], ConfidenceLevel.Confirmada, Capa: DiagnosticLayer.Windows));
            events.Add(new DiagnosticEvent(DateTimeOffset.Now, "Service Control Manager", "Grafo de dependencias",
                DiagnosticLayer.Windows, DiagnosticSeverity.Advertencia, "SERVICE_DEPENDENCY_COVERAGE",
                "Grafo SCM no evaluado.", Evidencia: [new EvidenceItem("Cobertura", "No evaluado"), new EvidenceItem("Error", ex.Message)]));
            return Task.FromResult(new CollectorResult(findings, events));
        }

        try
        {
            var matchingTargets = all
                .Where(s => WindowsServiceCatalog.IsRelevant(s.ServiceName)
                         || IsTsplusService(s.ServiceName, SafeDisplayName(s)))
                .ToList();
            var targets = matchingTargets.Take(MaxServices).ToList();
            var truncated = matchingTargets.Count > MaxServices;
            if (truncated)
                coverage.Add(new EvidenceItem("Inventario SCM", $"Parcial: {matchingTargets.Count} servicios objetivo; límite de seguridad={MaxServices}"));

            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var target in targets)
            {
                cancellationToken.ThrowIfCancellationRequested();
                AuditService(target.ServiceName, context, findings, events, coverage, seen, cancellationToken);
            }

            var partialCoverage = truncated || coverage.Any(x => x.Valor.Contains("No evaluado", StringComparison.OrdinalIgnoreCase) || x.Valor.Contains("Parcial", StringComparison.OrdinalIgnoreCase));
            events.Add(new DiagnosticEvent(
                DateTimeOffset.Now, "Service Control Manager", "Cobertura de dependencias",
                DiagnosticLayer.Windows, partialCoverage ? DiagnosticSeverity.Advertencia : DiagnosticSeverity.Informativo, "SERVICE_DEPENDENCY_COVERAGE",
                partialCoverage
                    ? "TDM recorrió el grafo SCM con cobertura parcial; una o más relaciones/estados no pudieron evaluarse."
                    : "TDM recorrió dependencias y dependientes reales del SCM para servicios Windows/RDP y servicios TSplus descubiertos.",
                Evidencia:
                [
                    new EvidenceItem("Cobertura", partialCoverage ? "Parcial" : "Disponible"),
                    new EvidenceItem("Servicios objetivo", targets.Count.ToString()),
                    new EvidenceItem("Servicios/nodos inspeccionados", seen.Count.ToString()),
                    new EvidenceItem("Profundidad máxima", MaxDepth.ToString()),
                    .. coverage.Take(80)
                ]));
        }
        finally
        {
            foreach (var service in all) service.Dispose();
        }

        return Task.FromResult(new CollectorResult(findings, events));
    }

    private static void AuditService(
        string serviceName,
        DiagnosticContext context,
        List<DiagnosticFinding> findings,
        List<DiagnosticEvent> events,
        List<EvidenceItem> coverage,
        HashSet<string> seen,
        CancellationToken ct)
    {
        if (!seen.Add(serviceName) || seen.Count > MaxServices) return;
        ct.ThrowIfCancellationRequested();

        try
        {
            using var sc = new ServiceController(serviceName);
            var display = SafeDisplayName(sc);
            var status = sc.Status;
            var tsplus = TsplusServiceClassifier.IsRelatedIncludingImagePath(serviceName, display, out var imagePath);

            var dependencyRead = ReadNames(() => sc.ServicesDependedOn);
            var dependentRead = ReadNames(() => sc.DependentServices);
            var dependencies = dependencyRead.Names;
            var dependents = dependentRead.Names;
            if (!dependencyRead.Available) coverage.Add(new EvidenceItem($"{serviceName} / dependencias", "No evaluado: " + dependencyRead.Error));
            if (!dependentRead.Available) coverage.Add(new EvidenceItem($"{serviceName} / dependientes", "No evaluado: " + dependentRead.Error));
            var layer = serviceName.Equals("TermService", StringComparison.OrdinalIgnoreCase) ||
                        serviceName.Equals("UmRdpService", StringComparison.OrdinalIgnoreCase) ||
                        serviceName.Equals("SessionEnv", StringComparison.OrdinalIgnoreCase) ||
                        serviceName.Equals("TermServLicensing", StringComparison.OrdinalIgnoreCase) ||
                        serviceName.Equals("Tssdis", StringComparison.OrdinalIgnoreCase) ||
                        serviceName.Equals("RDMS", StringComparison.OrdinalIgnoreCase) ||
                        serviceName.Equals("TSGateway", StringComparison.OrdinalIgnoreCase)
                ? DiagnosticLayer.Rdp
                : tsplus ? DiagnosticLayer.Tsplus : DiagnosticLayer.Windows;

            var product = tsplus ? TsplusServiceClassifier.Classify(serviceName, display, imagePath) : TsplusProduct.Ninguno;
            var catalog = WindowsServiceCatalog.Find(serviceName);
            var complementary = product is TsplusProduct.AdvancedSecurity or TsplusProduct.ServerMonitoring or TsplusProduct.RemoteSupport or TsplusProduct.TwoFactorAuthentication;
            var startMode = WindowsServiceCatalog.ReadStartMode(serviceName);
            var requiredNow = (catalog?.RequiredWhenTsplus == true && context.Sistema.TsplusDetectado) || (tsplus && !complementary);
            var presentationState = WindowsServiceCatalog.PresentationState(status, startMode, requiredNow);
            // El grafo no redefine la semántica del estado: usa exactamente la misma
            // política que WindowsServiceCollector. Un servicio TSplus Manual/Trigger
            // detenido no es una falla por sí mismo.
            var serviceWarning = WindowsServiceCatalog.ShouldWarnWhenStopped(status, startMode, requiredNow);

            events.Add(new DiagnosticEvent(
                DateTimeOffset.Now, "Service Control Manager", display, layer,
                serviceWarning ? (requiredNow ? DiagnosticSeverity.Critico : DiagnosticSeverity.Advertencia) : DiagnosticSeverity.Informativo,
                "SERVICE_STATE", $"Estado actual: {status}",
                Evidencia:
                [
                    new EvidenceItem("Servicio", serviceName),
                    new EvidenceItem("Nombre visible", display),
                    new EvidenceItem("Estado", status.ToString()),
                    new EvidenceItem("Estado presentación", presentationState),
                    new EvidenceItem("Inicio", startMode),
                    new EvidenceItem("Proveedor", tsplus ? "TSplus/relacionado" : "Windows"),
                    new EvidenceItem("Área", tsplus ? "TSplus" : catalog?.Area ?? "Windows"),
                    new EvidenceItem("Detección", tsplus && !TsplusServiceClassifier.IsRelated(serviceName, display) ? "ImagePath SCM" : "Nombre/servicio"),
                    new EvidenceItem("ImagePath", string.IsNullOrWhiteSpace(imagePath) ? "N/D" : imagePath)
                ], Producto: product));

            foreach (var dep in dependencies)
            {
                var state = ReadStatus(dep);
                if (!state.HasValue) coverage.Add(new EvidenceItem($"{serviceName} → {dep}", "No evaluado: estado de dependencia no legible"));
                events.Add(new DiagnosticEvent(
                    DateTimeOffset.Now, "Service Control Manager", $"{serviceName} → {dep}",
                    layer,
                    state is null ? DiagnosticSeverity.Advertencia
                        : WindowsServiceCatalog.ShouldWarnWhenStopped(state.Value, WindowsServiceCatalog.ReadStartMode(dep),
                            requiredNow: IsCriticalForIncident(serviceName, product, context))
                            ? DiagnosticSeverity.Advertencia
                            : DiagnosticSeverity.Informativo,
                    "SERVICE_DEPENDENCY_STATE",
                    $"{serviceName} depende de {dep}; estado observado: {state?.ToString() ?? "NO EVALUADO"}.",
                    Evidencia:
                    [
                        new EvidenceItem("Servicio", serviceName),
                        new EvidenceItem("Estado servicio", status.ToString()),
                        new EvidenceItem("Dependencia", dep),
                        new EvidenceItem("Estado dependencia", state?.ToString() ?? "No evaluado"),
                        new EvidenceItem("Relación", "ServicesDependedOn")
                    ], Producto: product));

                var dependencyStartMode = WindowsServiceCatalog.ReadStartMode(dep);
                var dependencyExpectedRunning = WindowsServiceCatalog.ShouldWarnWhenStopped(
                    state ?? ServiceControllerStatus.Stopped, dependencyStartMode,
                    requiredNow: IsCriticalForIncident(serviceName, product, context));
                if (state.HasValue && state != ServiceControllerStatus.Running
                                   && dependencyExpectedRunning
                                   && IsCriticalForIncident(serviceName, product, context))
                {
                    findings.Add(new DiagnosticFinding(
                        $"SERVICE-DEPENDENCY-{Sanitize(serviceName)}-{Sanitize(dep)}",
                        serviceName, DiagnosticSeverity.Advertencia,
                        $"Una dependencia real del servicio {serviceName} no está en ejecución y requiere correlación.",
                        "La relación fue obtenida directamente del Service Control Manager. El estado detenido por sí solo no se considera causa: debe correlacionarse con modo de inicio, falla SCM y síntoma funcional.",
                        [new EvidenceItem("Servicio", serviceName), new EvidenceItem("Dependencia", dep), new EvidenceItem("Estado", state.ToString()!), new EvidenceItem("Inicio dependencia", dependencyStartMode)],
                        ConfidenceLevel.Media, Capa: layer));
                }
            }

            foreach (var dependent in dependents)
            {
                var dependentState = ReadStatus(dependent);
                if (!dependentState.HasValue) coverage.Add(new EvidenceItem($"{dependent} ← {serviceName}", "No evaluado: estado de servicio dependiente no legible"));
                events.Add(new DiagnosticEvent(
                    DateTimeOffset.Now, "Service Control Manager", $"{dependent} ← {serviceName}",
                    layer,
                    DiagnosticSeverity.Informativo,
                    "SERVICE_DEPENDENT_STATE",
                    $"{dependent} declara dependencia sobre {serviceName}; estado observado: {dependentState?.ToString() ?? "NO EVALUADO"}.",
                    Evidencia:
                    [
                        new EvidenceItem("Servicio", serviceName),
                        new EvidenceItem("Dependiente", dependent),
                        new EvidenceItem("Estado dependiente", dependentState?.ToString() ?? "No evaluado"),
                        new EvidenceItem("Relación", "DependentServices")
                    ], Producto: product));
            }

            TraverseDependencies(serviceName, 0, seen, events, coverage, ct);
            coverage.Add(new EvidenceItem(serviceName, $"{status}; dependencias={dependencies.Count}; dependientes={dependents.Count}"));
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception or System.TimeoutException)
        {
            coverage.Add(new EvidenceItem(serviceName, "No evaluado: " + ex.Message));
        }
    }

    private static void TraverseDependencies(string root, int depth, HashSet<string> seen, List<DiagnosticEvent> events, List<EvidenceItem> coverage, CancellationToken ct)
    {
        if (depth >= MaxDepth)
        {
            coverage.Add(new EvidenceItem($"{root} / profundidad", $"Parcial: límite de profundidad SCM={MaxDepth} alcanzado"));
            return;
        }
        if (seen.Count >= MaxServices)
        {
            coverage.Add(new EvidenceItem("Inventario SCM", $"Parcial: límite de nodos SCM={MaxServices} alcanzado durante el recorrido"));
            return;
        }
        ServiceNamesRead read;
        ServiceController? sc = null;
        try
        {
            sc = new ServiceController(root);
            read = ReadNames(() => sc.ServicesDependedOn);
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception or System.TimeoutException)
        {
            coverage.Add(new EvidenceItem($"{root} / profundidad {depth + 1}", "No evaluado: " + ex.Message));
            sc?.Dispose();
            return;
        }
        finally
        {
            sc?.Dispose();
        }
        if (!read.Available)
        {
            coverage.Add(new EvidenceItem($"{root} / profundidad {depth + 1}", "No evaluado: " + read.Error));
            return;
        }

        foreach (var dep in read.Names)
        {
            ct.ThrowIfCancellationRequested();
            if (!seen.Add(dep)) continue;
            var state = ReadStatus(dep);
            var rootState = ReadStatus(root);
            if (!state.HasValue) coverage.Add(new EvidenceItem($"{root} → {dep}", "No evaluado: estado de dependencia no legible"));
            events.Add(new DiagnosticEvent(DateTimeOffset.Now, "Service Control Manager", $"{root} → {dep}",
                DiagnosticLayer.Windows, state == ServiceControllerStatus.Running ? DiagnosticSeverity.Informativo : DiagnosticSeverity.Advertencia,
                "SERVICE_DEPENDENCY_STATE", $"Dependencia SCM nivel {depth + 1}: {dep} = {state?.ToString() ?? "NO EVALUADO"}.",
                Evidencia: [new EvidenceItem("Servicio origen", root), new EvidenceItem("Estado servicio", rootState?.ToString() ?? "No evaluado"), new EvidenceItem("Dependencia", dep), new EvidenceItem("Profundidad", (depth + 1).ToString()), new EvidenceItem("Estado", state?.ToString() ?? "No evaluado")]));
            TraverseDependencies(dep, depth + 1, seen, events, coverage, ct);
            if (seen.Count >= MaxServices) break;
        }
    }

    private static ServiceNamesRead ReadNames(Func<ServiceController[]> factory)
    {
        try
        {
            var values = factory();
            try
            {
                return new ServiceNamesRead(
                    values.Select(x => x.ServiceName).Where(x => !string.IsNullOrWhiteSpace(x)).Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
                    true, null);
            }
            finally { foreach (var value in values) value.Dispose(); }
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception or System.TimeoutException)
        {
            return new ServiceNamesRead([], false, ex.Message);
        }
    }

    private sealed record ServiceNamesRead(List<string> Names, bool Available, string? Error);

    private static ServiceControllerStatus? ReadStatus(string name)
    {
        try { using var sc = new ServiceController(name); return sc.Status; }
        catch { return null; }
    }

    private static string SafeDisplayName(ServiceController sc)
    {
        try { return string.IsNullOrWhiteSpace(sc.DisplayName) ? sc.ServiceName : sc.DisplayName; }
        catch { return sc.ServiceName; }
    }

    private static bool IsTsplusService(string name, string display)
        => TsplusServiceClassifier.IsRelatedIncludingImagePath(name, display, out _);

    private static bool IsCriticalForIncident(string name, TsplusProduct product, DiagnosticContext context)
    {
        if (name.Equals("TermService", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("RpcSs", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("Spooler", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("ProfSvc", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("SessionEnv", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("UmRdpService", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("Netlogon", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("Dnscache", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("W32Time", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("DcomLaunch", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("Winmgmt", StringComparison.OrdinalIgnoreCase))
            return true;

        // El servicio TSplus en sí mismo sigue siendo relevante; no elevamos por defecto
        // cualquier dependencia de segundo/tercer nivel sólo porque Remote Access esté instalado.
        return product == TsplusProduct.RemoteAccess && context.Sistema.TsplusDetectado && IsTsplusServiceName(name);
    }

    private static bool IsTsplusServiceName(string name)
        => TsplusServiceClassifier.IsRelatedIncludingImagePath(name, name, out _);

    private static string Sanitize(string value) => new(value.Where(char.IsLetterOrDigit).Select(char.ToUpperInvariant).Take(28).ToArray());
}
