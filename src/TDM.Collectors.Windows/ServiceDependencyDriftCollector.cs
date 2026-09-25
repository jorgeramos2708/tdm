using System.ServiceProcess;
using TDM.Core;
using TDM.Models;

namespace TDM.Collectors.Windows;

/// <summary>
/// Diff temporal del grafo de dependencias SCM: captura snapshot del grafo real
/// y lo compara contra la ejecución anterior. Reporta qué dependencias/estados
/// cambiaron. Solo lectura + cursor durable; nunca modifica servicios.
/// Sin línea base previa la crea y lo declara (primera ejecución no es drift).
/// </summary>
public sealed class ServiceDependencyDriftCollector : IReadOnlyCollector
{
    public string Nombre => "Deriva de dependencias SCM";

    private const string BaselineKey = "scm-graph-baseline";
    private const int MaxServices = 320;
    private const int MaxDepth = 4;
    private const int MaxFindings = 20;

    private sealed record GraphBaselineState(Dictionary<string, ServiceNode> Nodes, DateTimeOffset SavedAt);
    private sealed record ServiceNode(
        string DisplayName,
        ServiceControllerStatus Status,
        string StartMode,
        List<string> Dependencies,
        List<string> Dependents,
        bool IsTsplus);

    public Task<CollectorResult> CollectAsync(DiagnosticContext context, CancellationToken cancellationToken = default)
    {
        var findings = new List<DiagnosticFinding>();
        var events = new List<DiagnosticEvent>();
        var evidence = new List<EvidenceItem>();

        ServiceController[] all;
        try
        {
            all = ServiceController.GetServices();
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            findings.Add(new DiagnosticFinding(
                "SCM-GRAPH-DRIFT-COVERAGE", "Deriva de dependencias SCM", DiagnosticSeverity.Advertencia,
                "No fue posible obtener el inventario SCM para evaluar la deriva.",
                ex.Message, [new EvidenceItem("Cobertura", "No evaluado"), new EvidenceItem("Error", ex.Message)],
                ConfidenceLevel.Confirmada, Capa: DiagnosticLayer.Windows));
            return Task.FromResult(new CollectorResult(findings, events));
        }

        var currentNodes = new Dictionary<string, ServiceNode>(StringComparer.OrdinalIgnoreCase);
        var coverage = new List<EvidenceItem>();

        try
        {
            var targets = all
                .Where(s => WindowsServiceCatalog.IsRelevant(s.ServiceName)
                         || IsTsplusService(s.ServiceName, SafeDisplayName(s)))
                .Take(MaxServices)
                .ToList();

            foreach (var target in targets)
            {
                var sc = new ServiceController(target.ServiceName);
                var display = SafeDisplayName(sc);
                var status = sc.Status;
                var deps = ReadNames(() => sc.ServicesDependedOn).Names;
                var dependents = ReadNames(() => sc.DependentServices).Names;
                var tsplus = TsplusServiceClassifier.IsRelatedIncludingImagePath(target.ServiceName, SafeDisplayName(target), out _);
                var layer = target.ServiceName.Equals("TermService", StringComparison.OrdinalIgnoreCase) ||
                            target.ServiceName.Equals("UmRdpService", StringComparison.OrdinalIgnoreCase) ||
                            target.ServiceName.Equals("SessionEnv", StringComparison.OrdinalIgnoreCase) ||
                            target.ServiceName.Equals("TermServLicensing", StringComparison.OrdinalIgnoreCase) ||
                            target.ServiceName.Equals("Tssdis", StringComparison.OrdinalIgnoreCase) ||
                            target.ServiceName.Equals("RDMS", StringComparison.OrdinalIgnoreCase) ||
                            target.ServiceName.Equals("TSGateway", StringComparison.OrdinalIgnoreCase)
                    ? DiagnosticLayer.Rdp
                    : target.ServiceName.Equals("TermService", StringComparison.OrdinalIgnoreCase) ? DiagnosticLayer.Rdp : (target.ServiceName.StartsWith("TSplus", StringComparison.OrdinalIgnoreCase) ? DiagnosticLayer.Tsplus : DiagnosticLayer.Windows);

                var startMode = WindowsServiceCatalog.ReadStartMode(target.ServiceName);
                currentNodes[target.ServiceName] = new ServiceNode(
                    SafeDisplayName(target), sc.Status, WindowsServiceCatalog.ReadStartMode(target.ServiceName),
                    deps, ReadNames(() => sc.DependentServices).Names, target.ServiceName.StartsWith("TSplus", StringComparison.OrdinalIgnoreCase));
            }

            // Cargar baseline
            if (!CollectorCursorStore.TryLoad<GraphBaselineState>(BaselineKey, out var baseline, out _) || baseline?.Nodes is null)
            {
                CollectorCursorStore.TrySave(BaselineKey, new GraphBaselineState(currentNodes, DateTimeOffset.Now), out _);
                events.Add(new DiagnosticEvent(
                    DateTimeOffset.Now, "Service Control Manager", "Grafo SCM",
                    DiagnosticLayer.Windows, DiagnosticSeverity.Informativo, "SCM_GRAPH_BASELINE_INITIALIZED",
                    "Se guardó la línea base inicial del grafo de dependencias SCM; la próxima ejecución comparará contra ella.",
                    Evidencia: [new EvidenceItem("Nodos", currentNodes.Count.ToString())]));
                return Task.FromResult(new CollectorResult(findings, events));
            }

            // Comparar
            var added = currentNodes.Keys.Except(baseline.Nodes.Keys, StringComparer.OrdinalIgnoreCase).Take(8).ToList();
            var removed = baseline.Nodes.Keys.Except(currentNodes.Keys, StringComparer.OrdinalIgnoreCase).Take(8).ToList();
            var changed = new List<string>();

            foreach (var kv in currentNodes)
            {
                if (!baseline.Nodes.TryGetValue(kv.Key, out var prev)) continue;
                var changes = new List<string>();
                if (!prev.Status.Equals(currentNodes[kv.Key].Status))
                    changes.Add($"Estado: {prev.Status} → {currentNodes[kv.Key].Status}");
                if (!prev.StartMode.Equals(currentNodes[kv.Key].StartMode))
                    changes.Add($"Inicio: {prev.StartMode} → {currentNodes[kv.Key].StartMode}");
                if (!prev.Dependencies.SequenceEqual(currentNodes[kv.Key].Dependencies, StringComparer.OrdinalIgnoreCase))
                    changes.Add($"Dependencias: [{string.Join(", ", prev.Dependencies)}] → [{string.Join(", ", currentNodes[kv.Key].Dependencies)}]");
                if (!prev.Dependents.SequenceEqual(currentNodes[kv.Key].Dependents, StringComparer.OrdinalIgnoreCase))
                    changes.Add($"Dependientes: [{string.Join(", ", prev.Dependents)}] → [{string.Join(", ", currentNodes[kv.Key].Dependents)}]");
                if (changes.Count > 0)
                    changed.Add($"{kv.Key}: {string.Join("; ", changes)}");
            }

            if (added.Count + removed.Count + changed.Count > 0)
            {
                var driftEvidence = new List<EvidenceItem>
                {
                    new("Servicios agregados", added.Count == 0 ? "Ninguno" : string.Join(" | ", added.Take(8))),
                    new("Servicios eliminados", removed.Count == 0 ? "Ninguno" : string.Join(" | ", removed.Take(8))),
                    new("Cambios de estado/inicio/dependencias", changed.Count == 0 ? "Ninguno" : string.Join(" | ", changed.Take(8)))
                };

                findings.Add(new DiagnosticFinding(
                    "SCM-GRAPH-DRIFT",
                    "Grafo de dependencias SCM",
                    DiagnosticSeverity.Advertencia,
                    $"Se detectaron cambios en el grafo de dependencias SCM ({added.Count + removed.Count + changed.Count} cambios).",
                    "Un cambio en el grafo de dependencias puede preceder o coincidir con incidentes. Valide si hubo instalación/desinstalación, cambio de modo de inicio o falla de dependencia antes de atribuir el incidente a otra capa.",
                    driftEvidence,
                    ConfidenceLevel.Media,
                    Capa: DiagnosticLayer.Windows));
            }
            else
            {
                events.Add(new DiagnosticEvent(
                    DateTimeOffset.Now, "Service Control Manager", "Grafo SCM",
                    DiagnosticLayer.Windows, DiagnosticSeverity.Informativo, "SCM_GRAPH_STABLE",
                    "El grafo de dependencias SCM coincide con la muestra anterior.",
                    Evidencia: [new EvidenceItem("Nodos", currentNodes.Count.ToString())]));
            }

            CollectorCursorStore.TrySave(BaselineKey, new GraphBaselineState(currentNodes, DateTimeOffset.Now), out _);
            return Task.FromResult(new CollectorResult(findings, events));
        }
        finally
        {
            foreach (var service in all) service.Dispose();
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

    private static bool IsTsplusService(string name, string display)
        => name.StartsWith("TSplus", StringComparison.OrdinalIgnoreCase) ||
           name.Equals("TermService", StringComparison.OrdinalIgnoreCase) ||
           name.Equals("UmRdpService", StringComparison.OrdinalIgnoreCase) ||
           name.Equals("SessionEnv", StringComparison.OrdinalIgnoreCase) ||
           name.Equals("TermServLicensing", StringComparison.OrdinalIgnoreCase) ||
           name.Equals("Tssdis", StringComparison.OrdinalIgnoreCase) ||
           name.Equals("RDMS", StringComparison.OrdinalIgnoreCase) ||
           name.Equals("TSGateway", StringComparison.OrdinalIgnoreCase);

    private static string SafeDisplayName(ServiceController sc)
    {
        try { return string.IsNullOrWhiteSpace(sc.DisplayName) ? sc.ServiceName : sc.DisplayName; }
        catch { return sc.ServiceName; }
    }
}