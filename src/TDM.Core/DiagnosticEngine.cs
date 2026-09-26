using System.Diagnostics;
using TDM.Models;

namespace TDM.Core;

public sealed class DiagnosticEngine
{
    private readonly IReadOnlyList<IReadOnlyCollector> _collectors;
    private readonly DiagnosticExecutionPolicy _policy;
    private readonly CollectorCircuitBreaker _circuitBreaker;

    public DiagnosticEngine(
        IEnumerable<IReadOnlyCollector> collectors,
        TimeSpan? collectorTimeout = null,
        int maxRawEvents = 50_000)
        : this(collectors, collectorTimeout.HasValue
            ? DiagnosticExecutionPolicy.Uniform(collectorTimeout.Value, maxRawEvents)
            : DiagnosticExecutionPolicy.ProductionDefault with { MaxRawEvents = Math.Max(1_000, maxRawEvents) })
    {
    }

    public DiagnosticEngine(IEnumerable<IReadOnlyCollector> collectors, DiagnosticExecutionPolicy policy)
        : this(collectors, policy, new CollectorCircuitBreaker())
    {
    }

    public DiagnosticEngine(IEnumerable<IReadOnlyCollector> collectors, DiagnosticExecutionPolicy policy, CollectorCircuitBreaker circuitBreaker)
    {
        ArgumentNullException.ThrowIfNull(collectors);
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentNullException.ThrowIfNull(circuitBreaker);
        _collectors = collectors.ToList();
        _policy = policy.Normalize();
        _circuitBreaker = circuitBreaker;
    }

    public IReadOnlyList<CollectorStatus> GetCircuitBreakerStatuses() => _circuitBreaker.GetAllStatuses();

    public async Task<DiagnosticReport> RunAsync(DiagnosticContext context, CancellationToken ct = default)
    {
        var inicio = DateTimeOffset.Now;
        var totalWatch = Stopwatch.StartNew();
        var memoryBefore = GC.GetTotalMemory(false);
        var findings = new List<DiagnosticFinding>();
        var events = new List<DiagnosticEvent>();
        var collectorMetrics = new List<(string Name, double Ms, string Status)>();
        var collectorErrors = 0;
        var collectorTimeouts = 0;
        var budgetExhausted = false;
        var collectorsOmittedByBudget = 0;

        for (var collectorIndex = 0; collectorIndex < _collectors.Count; collectorIndex++)
        {
            ct.ThrowIfCancellationRequested();
            var collector = _collectors[collectorIndex];

            // Circuit breaker: skip collector if open
            if (_circuitBreaker.IsOpen(collector.Nombre))
            {
                collectorMetrics.Add((collector.Nombre, 0, "CIRCUIT_OPEN"));
                findings.Add(new DiagnosticFinding(
                    $"COLLECTOR-CIRCUIT-OPEN-{SanitizeId(collector.Nombre)}",
                    collector.Nombre,
                    DiagnosticSeverity.Advertencia,
                    "Collector deshabilitado temporalmente por fallos repetidos (circuit breaker).",
                    $"El collector {collector.Nombre} excedió el umbral de fallos consecutivos y se omite en este ciclo. Se reintentará automáticamente tras el timeout de recuperación.",
                    [new EvidenceItem("Collector", collector.Nombre), new EvidenceItem("Estado", "Circuit Open")],
                    ConfidenceLevel.Confirmada));
                continue;
            }

            var remainingBudget = _policy.OverallTimeout - totalWatch.Elapsed;
            if (remainingBudget <= TimeSpan.Zero)
            {
                budgetExhausted = true;
                collectorsOmittedByBudget = _collectors.Count - collectorIndex;
                break;
            }

            var configuredTimeout = _policy.TimeoutFor(collector);
            var budgetLimitedTimeout = remainingBudget <= configuredTimeout;
            var effectiveTimeout = configuredTimeout <= remainingBudget ? configuredTimeout : remainingBudget;
            var watch = Stopwatch.StartNew();
            try
            {
                var result = await CollectorExecutionBoundary
                    .RunAsync(collector, context, effectiveTimeout, ct)
                    .ConfigureAwait(false);
                findings.AddRange(result.Hallazgos);
                events.AddRange(result.Eventos);
                collectorMetrics.Add((collector.Nombre, watch.Elapsed.TotalMilliseconds, "OK"));
                _circuitBreaker.RecordSuccess(collector.Nombre);
            }
            catch (TimeoutException)
            {
                collectorTimeouts++;
                collectorMetrics.Add((collector.Nombre, watch.Elapsed.TotalMilliseconds, "TIMEOUT"));
                _circuitBreaker.RecordFailure(collector.Nombre, new TimeoutException($"Collector {collector.Nombre} timed out after {effectiveTimeout.TotalSeconds:0}s"));
                findings.Add(new DiagnosticFinding(
                    $"COLLECTOR-TIMEOUT-{SanitizeId(collector.Nombre)}",
                    collector.Nombre,
                    DiagnosticSeverity.Advertencia,
                    "Una fuente de diagnóstico excedió el tiempo máximo de lectura.",
                    $"TDM dejó de esperar esta comprobación después de {effectiveTimeout.TotalSeconds:0} segundos para mantener disponible la aplicación. Si la API subyacente no coopera con cancelación, TDM evita volver a lanzar ese mismo collector hasta que la ejecución anterior finalice.",
                    [new EvidenceItem("Collector", collector.Nombre), new EvidenceItem("Límite", $"{effectiveTimeout.TotalSeconds:0} s"), new EvidenceItem("Presupuesto restante", $"{Math.Max(0, (_policy.OverallTimeout - totalWatch.Elapsed).TotalSeconds):0} s")],
                    ConfidenceLevel.Confirmada));

                // Si el límite efectivo fue recortado por el presupuesto global, el timeout
                // también representa agotamiento del diagnóstico, aunque éste sea el último collector.
                if (budgetLimitedTimeout || totalWatch.Elapsed >= _policy.OverallTimeout)
                {
                    budgetExhausted = true;
                    collectorsOmittedByBudget = Math.Max(0, _collectors.Count - (collectorIndex + 1));
                    break;
                }
            }
            catch (CollectorStillRunningException ex)
            {
                collectorTimeouts++;
                collectorMetrics.Add((collector.Nombre, watch.Elapsed.TotalMilliseconds, "DEFERRED"));
                _circuitBreaker.RecordFailure(collector.Nombre, ex);
                findings.Add(new DiagnosticFinding(
                    $"COLLECTOR-DEFERRED-{SanitizeId(collector.Nombre)}",
                    collector.Nombre,
                    DiagnosticSeverity.Advertencia,
                    "TDM aplazó una fuente que todavía finaliza una lectura anterior.",
                    ex.Message,
                    [new EvidenceItem("Collector", collector.Nombre), new EvidenceItem("Protección", "No se crean ejecuciones duplicadas de un collector bloqueado")],
                    ConfidenceLevel.Confirmada));
            }
            catch (CollectorExecutionCapacityException ex)
            {
                collectorTimeouts++;
                collectorMetrics.Add((collector.Nombre, watch.Elapsed.TotalMilliseconds, "CAPACITY-DEFERRED"));
                _circuitBreaker.RecordFailure(collector.Nombre, ex);
                findings.Add(new DiagnosticFinding(
                    $"COLLECTOR-CAPACITY-{SanitizeId(collector.Nombre)}",
                    collector.Nombre,
                    DiagnosticSeverity.Advertencia,
                    "TDM limitó collectors bloqueados para proteger los recursos del servidor.",
                    ex.Message,
                    [new EvidenceItem("Collector", collector.Nombre), new EvidenceItem("Collectors aún finalizando", ex.InFlight.ToString()), new EvidenceItem("Límite", "8")],
                    ConfidenceLevel.Confirmada));
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                collectorErrors++;
                collectorMetrics.Add((collector.Nombre, watch.Elapsed.TotalMilliseconds, "ERROR"));
                _circuitBreaker.RecordFailure(collector.Nombre, ex);
                findings.Add(new DiagnosticFinding(
                    $"COLLECTOR-{SanitizeId(collector.Nombre)}",
                    collector.Nombre,
                    DiagnosticSeverity.Advertencia,
                    "No fue posible completar una comprobación de solo lectura.",
                    ex.Message,
                    [new EvidenceItem("Collector", collector.Nombre)],
                    ConfidenceLevel.Media));
            }

            if (totalWatch.Elapsed >= _policy.OverallTimeout && collectorIndex + 1 < _collectors.Count)
            {
                budgetExhausted = true;
                collectorsOmittedByBudget = _collectors.Count - (collectorIndex + 1);
                break;
            }
        }

        if (budgetExhausted)
        {
            findings.Add(new DiagnosticFinding(
                "DIAGNOSTIC-BUDGET-EXHAUSTED",
                "Motor de diagnóstico",
                DiagnosticSeverity.Advertencia,
                "El diagnóstico alcanzó su tiempo máximo y terminó con cobertura parcial.",
                collectorsOmittedByBudget > 0
                    ? $"TDM detuvo la espera de nuevas fuentes al alcanzar {_policy.OverallTimeout.TotalSeconds:0} segundos. Las fuentes omitidas quedan como no evaluadas; no se interpretan como sanas."
                    : $"TDM alcanzó el presupuesto global de {_policy.OverallTimeout.TotalSeconds:0} segundos durante la última fuente. El diagnóstico queda marcado con cobertura parcial por tiempo.",
                [new EvidenceItem("Presupuesto", $"{_policy.OverallTimeout.TotalSeconds:0} s"), new EvidenceItem("Collectors omitidos", collectorsOmittedByBudget.ToString())],
                ConfidenceLevel.Confirmada));
        }

        var rawEventCount = events.Count;
        if (events.Count > _policy.MaxRawEvents)
        {
            var causal = events.Where(e => e.Severidad != DiagnosticSeverity.Informativo).OrderByDescending(OrderingTime).Take((int)(_policy.MaxRawEvents * 0.8));
            var contextEvents = events.Where(e => e.Severidad == DiagnosticSeverity.Informativo).OrderByDescending(OrderingTime).Take(_policy.MaxRawEvents - (int)(_policy.MaxRawEvents * 0.8));
            events = causal.Concat(contextEvents).OrderBy(OrderingTime).ToList();
            findings.Add(new DiagnosticFinding(
                "TDM-EVENT-VOLUME-LIMIT",
                "Motor de diagnóstico",
                DiagnosticSeverity.Advertencia,
                "El volumen bruto de eventos superó el límite de protección del diagnóstico.",
                $"Se recibieron {rawEventCount} observaciones. TDM conservó prioritariamente señales no informativas y contexto reciente hasta {_policy.MaxRawEvents} eventos para proteger memoria y tiempo de respuesta.",
                [new EvidenceItem("Eventos brutos", rawEventCount.ToString()), new EvidenceItem("Eventos conservados", events.Count.ToString())],
                ConfidenceLevel.Confirmada));
        }

        events = IdentityIncidentPromoter.Promote(events).ToList();
        var normalizedEvents = Deduplicate(events);

        totalWatch.Stop();
        var fin = DateTimeOffset.Now;
        // RC15 mantiene una ventana temporal estricta por ejecución. En GUI, la recolección base es 4 h y luego se refiltra en memoria.
        // Para análisis "últimos N", el límite
        // superior es el final real del escaneo; se descarta evidencia fechada anterior
        // al periodo seleccionado que algún collector haya podido leer durante la ejecución.
        var periodoFin = context.HoraIncidente ?? fin;
        var periodoInicio = periodoFin - context.Lookback;
        var strictEvents = normalizedEvents
            .Where(e => e.Timestamp is DateTimeOffset eventTime
                ? eventTime >= periodoInicio && eventTime <= periodoFin
                : IsNonTemporalContext(e))
            .OrderBy(OrderingTime)
            .ToList();
        var strictFindings = findings
            .Where(f => DiagnosticTimeWindow.IsFindingInside(f, periodoInicio, periodoFin))
            .ToList();

        return new DiagnosticReport(
            context.Sistema,
            strictFindings,
            strictEvents,
            inicio,
            fin)
        {
            Lookback = context.Lookback,
            LookbackSolicitado = context.Lookback,
            PeriodoAnalizadoInicio = periodoInicio,
            PeriodoAnalizadoFin = periodoFin,
            EvidenciaDisponibleLookback = context.Lookback,
            PeriodoEvidenciaInicio = periodoInicio,
            PeriodoEvidenciaFin = periodoFin,
            RendimientoDiagnostico = BuildPerformanceAssessment(totalWatch.Elapsed.TotalMilliseconds, collectorMetrics, collectorErrors, collectorTimeouts, rawEventCount, strictEvents.Count, strictFindings.Count, memoryBefore, GC.GetTotalMemory(false), budgetExhausted, collectorsOmittedByBudget, _policy.OverallTimeout)
        };
    }

    private static DiagnosticPerformanceAssessment BuildPerformanceAssessment(
        double totalMs,
        IReadOnlyList<(string Name, double Ms, string Status)> metrics,
        int errors,
        int timeouts,
        int rawEvents,
        int normalizedEvents,
        int findings,
        long memoryBefore,
        long memoryAfter,
        bool budgetExhausted,
        int collectorsOmittedByBudget,
        TimeSpan overallBudget)
    {
        var slowest = metrics.OrderByDescending(x => x.Ms).FirstOrDefault();
        var summary = budgetExhausted
            ? collectorsOmittedByBudget > 0
                ? $"Diagnóstico completado con cobertura parcial: se agotó el presupuesto global y se omitieron {collectorsOmittedByBudget} fuente(s)."
                : "Diagnóstico completado con cobertura parcial: la última fuente consumió el presupuesto global disponible."
            : timeouts > 0
                ? $"Diagnóstico completado con {timeouts} fuente(s) cancelada(s) por timeout; revisar cobertura."
                : errors > 0
                    ? $"Diagnóstico completado con {errors} collector(es) con error controlado."
                    : "Diagnóstico completado sin errores/timeout de collectors.";
        return new DiagnosticPerformanceAssessment(
            totalMs, metrics.Count, errors, timeouts, slowest.Name ?? "N/D", slowest.Ms, rawEvents, normalizedEvents, findings, memoryBefore, memoryAfter, summary)
        {
            PresupuestoAgotado = budgetExhausted,
            CollectorsOmitidosPorPresupuesto = collectorsOmittedByBudget,
            PresupuestoTotalMs = overallBudget.TotalMilliseconds
        };
    }

    private static string SanitizeId(string value)
    {
        if (string.IsNullOrWhiteSpace(value)) return "UNKNOWN";
        var chars = value.Select(ch => char.IsLetterOrDigit(ch) ? char.ToUpperInvariant(ch) : '-').ToArray();
        return new string(chars).Trim('-');
    }


    private static List<DiagnosticEvent> Deduplicate(List<DiagnosticEvent> events)
    {
        var output = new List<DiagnosticEvent>();
        var duplicateIndex = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var werIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var e in events.OrderBy(OrderingTime))
        {
            if (e.Tipo == "WER_REPORT")
            {
                var reportId = e.Evidencia?.FirstOrDefault(x => x.Clave.Equals("Report ID", StringComparison.OrdinalIgnoreCase))?.Valor;
                if (!string.IsNullOrWhiteSpace(reportId) && !werIds.Add(reportId)) continue;
            }

            var key = DiagnosticEventIdentity.Resolve(e);
            if (key is not null && duplicateIndex.TryGetValue(key, out var existingIndex))
            {
                var existing = output[existingIndex];
                if (Specificity(e) > Specificity(existing)) output[existingIndex] = e;
                continue;
            }

            if (key is not null) duplicateIndex[key] = output.Count;
            output.Add(e);
        }
        return output;
    }

    private static DateTimeOffset OrderingTime(DiagnosticEvent e)
        => e.Timestamp ?? e.IngestedAt ?? DateTimeOffset.MinValue;

    private static bool IsNonTemporalContext(DiagnosticEvent e)
        => !e.Timestamp.HasValue
           && (e.IngestedAt.HasValue || e.Tipo == "UNDATED_LOG_EVIDENCE")
           && !DiagnosticEventCatalog.IsFunctionalIncident(e);

    private static int Specificity(DiagnosticEvent e)
    {
        var score = e.Evidencia?.Count ?? 0;
        if (e.Producto is not TsplusProduct.Ninguno and not TsplusProduct.Desconocido) score += 3;
        if (e.Tipo is not "WINDOWS_EVENT" and not "WINDOWS_FORENSIC_EVENT") score += 10;
        if (e.Tipo is "APPLICATION_CRASH" or "DOTNET_UNHANDLED_EXCEPTION" or "SERVICE_TERMINATION" or "SERVICE_START_FAILURE") score += 8;
        return score;
    }
}
