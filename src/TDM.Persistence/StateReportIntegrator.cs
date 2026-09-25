using TDM.Models;

namespace TDM.Persistence;

/// <summary>
/// Integra el journal local de TDM con el reporte. Las transiciones históricas se pueden
/// incorporar antes de la correlación causal; la persistencia de la ejecución actual se
/// realiza después del análisis para no convertir la propia observación en una causa.
/// </summary>
public static class StateReportIntegrator
{
    public static async Task<DiagnosticReport> RecordAndEnrichAsync(
        DiagnosticReport report,
        string toolVersion,
        CancellationToken ct = default,
        string channel = "diagnostic",
        string? rootPath = null,
        string? baselineRootPath = null,
        RecordResult? preRecordedResult = null)
    {
        var events = report.Eventos.ToList();
        var findings = report.Hallazgos.ToList();
        var anchor = report.PeriodoAnalizadoFin != default ? report.PeriodoAnalizadoFin : report.Fin;
        try
        {
            var store = new LocalStateStore(rootPath);
            var snapshot = preRecordedResult?.Snapshot ?? StateSnapshotBuilder.Build(report, toolVersion);
            var result = preRecordedResult ?? await store.RecordAsync(snapshot, channel, ct);

            if (!string.IsNullOrWhiteSpace(baselineRootPath))
            {
                var baselineStore = new LocalStateStore(baselineRootPath);
                if (!Path.GetFullPath(baselineStore.RootPath).Equals(Path.GetFullPath(result.RootPath), StringComparison.OrdinalIgnoreCase))
                {
                    var sharedBaseline = await baselineStore.LoadBaselineAsync(ct).ConfigureAwait(false);
                    if (sharedBaseline is not null)
                    {
                        result = result with
                        {
                            BaselineDifferences = LocalStateStore.CompareBaseline(sharedBaseline, snapshot),
                            BaselinePath = baselineStore.BaselinePath
                        };
                    }
                }
            }

            var trends = await ResourceTrendAnalyzer.UpdateAndAnalyzeAsync(snapshot, result.RootPath, ct);
            events.AddRange(trends.Events);
            findings.AddRange(trends.Findings.Where(f => !findings.Any(existing => existing.Id.Equals(f.Id, StringComparison.OrdinalIgnoreCase))));

            var historical = await new HistoricalTelemetryStore(result.RootPath).UpdateAndAnalyzeAsync(snapshot, ct);
            events.AddRange(historical.Events);
            findings.AddRange(historical.Findings.Where(f => !findings.Any(existing => existing.Id.Equals(f.Id, StringComparison.OrdinalIgnoreCase))));

            events.Add(new DiagnosticEvent(
                anchor,
                "TDM",
                "Historial local TDM",
                DiagnosticLayer.Desconocida,
                DiagnosticSeverity.Informativo,
                "TDM_LOCAL_HISTORY_STATUS",
                "TDM guardó una muestra compacta de estado en su almacén local; no se modificó Windows ni TSplus.",
                Evidencia:
                [
                    new EvidenceItem("Almacén", result.RootPath),
                    new EvidenceItem("Formato", "JSON/JSONL; sin motor de base de datos"),
                    new EvidenceItem("Canal", channel),
                    new EvidenceItem("Transiciones detectadas", result.Transitions.Count.ToString()),
                    new EvidenceItem("Baseline sano", result.BaselinePath is null ? "No configurado" : "Disponible"),
                    new EvidenceItem("Diferencias contra baseline", result.BaselineDifferences.Count.ToString())
                ]));

            foreach (var transition in result.Transitions.Take(100))
            {
                events.Add(new DiagnosticEvent(
                    transition.Timestamp > anchor ? anchor : transition.Timestamp,
                    "TDM State Journal",
                    transition.Component,
                    ParseLayer(transition.Layer),
                    DiagnosticSeverity.Informativo,
                    "TDM_STATE_TRANSITION",
                    $"Cambio de estado observado: {Compact(transition.PreviousValue)} → {Compact(transition.CurrentValue)}",
                    Evidencia:
                    [
                        new EvidenceItem("Tipo", transition.Type),
                        new EvidenceItem("Estado anterior", transition.PreviousValue),
                        new EvidenceItem("Estado actual", transition.CurrentValue),
                        new EvidenceItem("Severidad actual", transition.CurrentSeverity)
                    ],
                    Producto: ParseProduct(transition.Product)));
            }

            if (result.BaselinePath is not null)
            {
                events.Add(new DiagnosticEvent(
                    anchor,
                    "TDM Baseline",
                    "Baseline sano persistente",
                    DiagnosticLayer.Desconocida,
                    DiagnosticSeverity.Informativo,
                    "TDM_PERSISTENT_BASELINE_STATUS",
                    result.BaselineDifferences.Count == 0
                        ? "El estado comparable coincide con el baseline sano en las observaciones disponibles."
                        : $"Se observaron {result.BaselineDifferences.Count} diferencia(s) respecto al baseline sano. Una diferencia no implica por sí sola una falla.",
                    Evidencia:
                    [
                        new EvidenceItem("Archivo baseline", result.BaselinePath),
                        new EvidenceItem("Diferencias", result.BaselineDifferences.Count.ToString()),
                        new EvidenceItem("Criterio", "Sólo estados estables comparables; ausencia de evidencia no se interpreta como cambio")
                    ]));

                foreach (var difference in result.BaselineDifferences.Take(100))
                {
                    events.Add(new DiagnosticEvent(
                        anchor,
                        "TDM Baseline",
                        difference.Component,
                        DiagnosticLayer.Desconocida,
                        DiagnosticSeverity.Informativo,
                        "TDM_BASELINE_DIFFERENCE",
                        "Diferencia observada respecto al baseline sano; requiere contexto antes de considerarse anomalía.",
                        Evidencia:
                        [
                            new EvidenceItem("Tipo", difference.Type),
                            new EvidenceItem("Baseline", difference.PreviousValue),
                            new EvidenceItem("Actual", difference.CurrentValue),
                            new EvidenceItem("Severidad del estado actual", difference.CurrentSeverity)
                        ]));
                }
            }
        }
        catch (Exception ex)
        {
            events.Add(new DiagnosticEvent(
                anchor,
                "TDM",
                "Historial local TDM",
                DiagnosticLayer.Desconocida,
                DiagnosticSeverity.Advertencia,
                "TDM_LOCAL_HISTORY_UNAVAILABLE",
                "No fue posible actualizar el historial local propio de TDM. El diagnóstico de Windows/TSplus continúa siendo válido con la evidencia recopilada.",
                Evidencia: [new EvidenceItem("Detalle", ex.Message)]));
        }

        return report with
        {
            Hallazgos = findings.OrderByDescending(f => f.Severidad).ToList(),
            Eventos = events.OrderBy(e => e.Timestamp ?? DateTimeOffset.MaxValue).ToList()
        };
    }

    public static DiagnosticReport AddTransitionsFromRecordResult(DiagnosticReport report, RecordResult result, string channel)
    {
        if (result.Transitions.Count == 0) return report;
        var events = report.Eventos.ToList();
        foreach (var transition in result.Transitions.Take(1000))
        {
            var eventType = channel switch
            {
                "forensic-monitor" => "TDM_FORENSIC_STATE_TRANSITION",
                "integrity-monitor" => "TDM_INTEGRITY_STATE_TRANSITION",
                _ => "TDM_MONITOR_STATE_TRANSITION"
            };
            // P05: dedup por cambio físico (timestamp+componente+anterior→actual) en cualquier
            // canal, no solo intra-tipo: service-monitor y forensic-monitor observan los mismos servicios.
            if (events.Any(e => SamePhysicalTransition(e, transition)))
                continue;
            events.Add(new DiagnosticEvent(
                transition.Timestamp,
                "TDM Monitor Journal",
                transition.Component,
                ParseLayer(transition.Layer),
                DiagnosticSeverity.Informativo,
                eventType,
                $"Cambio de estado observado por TDM: {Compact(transition.PreviousValue)} → {Compact(transition.CurrentValue)}",
                Evidencia:
                [
                    new EvidenceItem("Tipo", transition.Type),
                    new EvidenceItem("Estado anterior", transition.PreviousValue),
                    new EvidenceItem("Estado actual", transition.CurrentValue),
                    new EvidenceItem("Canal", channel),
                    new EvidenceItem("Origen de evidencia", "Journal longitudinal TDM")
                ],
                Producto: ParseProduct(transition.Product)));
        }
        return report with { Eventos = events.OrderBy(e => e.Timestamp ?? DateTimeOffset.MaxValue).ToList() };
    }

    public static async Task<DiagnosticReport> AddRecentMonitorTransitionsAsync(
        DiagnosticReport report,
        DateTimeOffset from,
        DateTimeOffset to,
        CancellationToken ct = default,
        string? rootPath = null)
    {
        try
        {
            var store = new LocalStateStore(rootPath);
            var channels = new[] { "monitor", "service-monitor", "forensic-monitor", "integrity-monitor" };
            var collected = new List<(StateTransition Transition, string Channel)>();
            foreach (var channel in channels)
            {
                var items = await store.ReadRecentTransitionsAsync(from, to, channel, ct).ConfigureAwait(false);
                collected.AddRange(items.Select(x => (x, channel)));
            }

            var transitions = collected
                .OrderBy(x => x.Transition.Timestamp)
                .ThenBy(x => x.Transition.Key, StringComparer.OrdinalIgnoreCase)
                .ToList();
            if (transitions.Count == 0) return report;

            var events = report.Eventos.ToList();
            foreach (var item in transitions.TakeLast(1000))
            {
                var transition = item.Transition;
                var eventType = item.Channel switch
                {
                    "forensic-monitor" => "TDM_FORENSIC_STATE_TRANSITION",
                    "integrity-monitor" => "TDM_INTEGRITY_STATE_TRANSITION",
                    _ => "TDM_MONITOR_STATE_TRANSITION"
                };
                // P05: dedup cross-canal por cambio físico (ver SamePhysicalTransition).
                if (events.Any(e => SamePhysicalTransition(e, transition)))
                    continue;

                var source = item.Channel switch
                {
                    "forensic-monitor" => "TDM Forensic Journal",
                    "integrity-monitor" => "TDM Integrity Journal",
                    _ => "TDM Monitor Journal"
                };
                events.Add(new DiagnosticEvent(
                    transition.Timestamp,
                    source,
                    transition.Component,
                    ParseLayer(transition.Layer),
                    DiagnosticSeverity.Informativo,
                    eventType,
                    $"Cambio histórico observado por TDM: {Compact(transition.PreviousValue)} → {Compact(transition.CurrentValue)}",
                    Evidencia:
                    [
                        new EvidenceItem("Tipo", transition.Type),
                        new EvidenceItem("Estado anterior", transition.PreviousValue),
                        new EvidenceItem("Estado actual", transition.CurrentValue),
                        new EvidenceItem("Canal", item.Channel),
                        new EvidenceItem("Origen de evidencia", "Journal longitudinal TDM")
                    ],
                    Producto: ParseProduct(transition.Product)));
            }

            return report with { Eventos = events.OrderBy(e => e.Timestamp ?? DateTimeOffset.MaxValue).ToList() };
        }
        catch
        {
            return report;
        }
    }

    /// <summary>
    /// Declara de forma verificable cuánto historial propio existe realmente. Seleccionar
    /// "3 días" no se convierte en una afirmación de 72 h si TDM fue instalado después o
    /// si hubo huecos de captura.
    /// </summary>
    public static async Task<DiagnosticReport> AddHistoricalCoverageAsync(
        DiagnosticReport report,
        DateTimeOffset from,
        DateTimeOffset to,
        CancellationToken ct = default,
        string? rootPath = null,
        string? secondaryRootPath = null)
    {
        try
        {
            var stores = new List<LocalStateStore> { new(rootPath) };
            if (!string.IsNullOrWhiteSpace(secondaryRootPath))
            {
                var secondary = new LocalStateStore(secondaryRootPath);
                if (!stores.Any(x => Path.GetFullPath(x.RootPath).Equals(Path.GetFullPath(secondary.RootPath), StringComparison.OrdinalIgnoreCase)))
                    stores.Add(secondary);
            }

            async Task<List<PersistentStateSnapshot>> ReadAcrossAsync(string channel)
            {
                var all = new List<PersistentStateSnapshot>();
                foreach (var store in stores)
                    all.AddRange(await store.ReadRecentSnapshotsAsync(from, to, channel, ct).ConfigureAwait(false));
                return all.GroupBy(x => $"{x.Machine}|{x.CapturedAt:O}|{x.ToolVersion}", StringComparer.OrdinalIgnoreCase)
                    .Select(g => g.First()).OrderBy(x => x.CapturedAt).ToList();
            }

            var service = await ReadAcrossAsync("service-monitor").ConfigureAwait(false);
            var legacy = await ReadAcrossAsync("monitor").ConfigureAwait(false);
            var forensic = await ReadAcrossAsync("forensic-monitor").ConfigureAwait(false);
            var integrity = await ReadAcrossAsync("integrity-monitor").ConfigureAwait(false);

            // La cadencia por sí sola no basta para declarar cobertura. Cada muestra debe
            // contener observaciones del dominio que pretende cubrir; de lo contrario un
            // collector bloqueado por permisos podría producir snapshots vacíos y aparentar
            // continuidad que en realidad no existe.
            var servicesAssessment = AssessWindow(
                service.Concat(legacy).Concat(forensic), from, to, TimeSpan.FromMinutes(6),
                snapshot => HasObservationType(snapshot, "SERVICE_STATE"));

            var windowsConfig = AssessWindow(
                forensic, from, to, TimeSpan.FromMinutes(6),
                snapshot => HasAnyObservationType(snapshot,
                    "WINDOWS_LONGITUDINAL_CONFIG_STATE", "WINDOWS_RDP_POLICY_STATE",
                    "WINDOWS_TSPLUS_WINLOGON_INTEGRATION", "WINDOWS_RDS_ROLE_COMPATIBILITY"));
            var tsplusConfig = report.Sistema.TsplusDetectado
                ? AssessWindow(
                    forensic, from, to, TimeSpan.FromMinutes(6),
                    snapshot => HasAnyObservationType(snapshot,
                        "TSPLUS_LONGITUDINAL_CONFIG_STATE", "TSPLUS_CONFIG_ARTIFACT_STATE",
                        "TSPLUS_APPCONTROL_STATE", "TSPLUS_WEB_SETTINGS_JS_STATE",
                        "TSPLUS_WEB_SETTINGS_STATE", "TSPLUS_WEB_BALANCE_STATE",
                        "TSPLUS_FARM_CONFIGURATION_STATE"))
                : new HistoryAssessment(true, "No aplica; TSplus Remote Access no detectado");
            var configAssessment = CombineAssessments("Windows", windowsConfig, "TSplus", tsplusConfig);

            var windowsIntegrity = AssessWindow(
                integrity, from, to, TimeSpan.FromMinutes(25),
                snapshot => HasObservationType(snapshot, "WINDOWS_LONGITUDINAL_LIBRARY_STATE"));
            var tsplusIntegrity = report.Sistema.TsplusDetectado
                ? AssessWindow(
                    integrity, from, to, TimeSpan.FromMinutes(25),
                    snapshot => HasAnyObservationType(snapshot,
                        "TSPLUS_LONGITUDINAL_LIBRARY_STATE", "TSPLUS_MODULE_CRITICAL_FILE_STATE"))
                : new HistoryAssessment(true, "No aplica; TSplus Remote Access no detectado");
            var integrityAssessment = CombineAssessments("Windows", windowsIntegrity, "TSplus", tsplusIntegrity);

            var complete = servicesAssessment.Complete && configAssessment.Complete && integrityAssessment.Complete;
            var status = complete ? "Completa" : "Parcial";

            var events = report.Eventos.ToList();
            events.Add(new DiagnosticEvent(
                to,
                "TDM",
                "Cobertura histórica longitudinal",
                DiagnosticLayer.Desconocida,
                complete ? DiagnosticSeverity.Informativo : DiagnosticSeverity.Advertencia,
                "TDM_FORENSIC_HISTORY_COVERAGE",
                complete
                    ? "TDM dispone de continuidad longitudinal propia para la ventana solicitada."
                    : "La ventana solicitada excede o contiene huecos respecto al historial longitudinal propio disponible; TDM no presentará la parte ausente como evidencia observada.",
                Evidencia:
                [
                    new EvidenceItem("Ventana solicitada", $"{from:O} → {to:O}"),
                    new EvidenceItem("Duración solicitada", FormatDuration(to - from)),
                    new EvidenceItem("Cobertura global", status),
                    new EvidenceItem("Servicios", servicesAssessment.Description),
                    new EvidenceItem("Configuración Windows/TSplus", configAssessment.Description),
                    new EvidenceItem("Archivos/librerías críticas", integrityAssessment.Description),
                    new EvidenceItem("Criterio", "Completa sólo si el journal cubre inicio/fin y no presenta huecos superiores a la tolerancia del canal")
                ]));

            var findings = report.Hallazgos.ToList();
            if (!complete && to - from >= TimeSpan.FromHours(1) && findings.All(f => f.Id != "TDM-HISTORICAL-COVERAGE-PARTIAL"))
            {
                findings.Add(new DiagnosticFinding(
                    "TDM-HISTORICAL-COVERAGE-PARTIAL",
                    "Historial longitudinal TDM",
                    DiagnosticSeverity.Advertencia,
                    "La cobertura histórica propia de TDM no abarca de forma continua toda la ventana seleccionada.",
                    "Event Viewer, WER y logs existentes todavía pueden aportar evidencia retrospectiva anterior, pero configuraciones, estados de servicios y hashes que TDM no observó previamente no pueden reconstruirse con certeza. Esta limitación se conserva para impedir falsas causas raíz.",
                    [
                        new EvidenceItem("Ventana solicitada", FormatDuration(to - from)),
                        new EvidenceItem("Servicios", servicesAssessment.Description),
                        new EvidenceItem("Configuración", configAssessment.Description),
                        new EvidenceItem("Integridad", integrityAssessment.Description)
                    ],
                    ConfidenceLevel.Confirmada));
            }

            return report with
            {
                Eventos = events.OrderBy(e => e.Timestamp ?? DateTimeOffset.MaxValue).ToList(),
                Hallazgos = findings.OrderByDescending(f => f.Severidad).ToList()
            };
        }
        catch (Exception ex)
        {
            var events = report.Eventos.ToList();
            events.Add(new DiagnosticEvent(
                to,
                "TDM",
                "Cobertura histórica longitudinal",
                DiagnosticLayer.Desconocida,
                DiagnosticSeverity.Advertencia,
                "TDM_FORENSIC_HISTORY_COVERAGE",
                "No fue posible verificar el journal longitudinal para toda la ventana solicitada.",
                Evidencia:
                [
                    new EvidenceItem("Cobertura global", "No disponible"),
                    new EvidenceItem("Detalle", ex.Message)
                ]));
            return report with { Eventos = events.OrderBy(e => e.Timestamp ?? DateTimeOffset.MaxValue).ToList() };
        }
    }

    private static HistoryAssessment AssessWindow(
        IEnumerable<PersistentStateSnapshot> source,
        DateTimeOffset from,
        DateTimeOffset to,
        TimeSpan maxGap,
        Func<PersistentStateSnapshot, bool>? qualifies = null)
    {
        var snapshots = source
            .Where(x => qualifies is null || qualifies(x))
            .OrderBy(x => x.CapturedAt)
            .ToList();
        if (snapshots.Count == 0) return new(false, "No disponible; 0 muestras válidas del dominio");
        var first = snapshots[0].CapturedAt;
        var last = snapshots[^1].CapturedAt;
        var largestGap = TimeSpan.Zero;
        for (var i = 1; i < snapshots.Count; i++)
        {
            var gap = snapshots[i].CapturedAt - snapshots[i - 1].CapturedAt;
            if (gap > largestGap) largestGap = gap;
        }

        var startCovered = first <= from + maxGap;
        var endCovered = last >= to - maxGap;
        var gapsCovered = snapshots.Count == 1 ? to - from <= maxGap : largestGap <= maxGap;
        var complete = startCovered && endCovered && gapsCovered;
        var description = $"{(complete ? "Completa" : "Parcial")}; muestras={snapshots.Count}; primera={first:O}; última={last:O}; hueco máx={FormatDuration(largestGap)}";
        return new(complete, description);
    }


    private static bool HasObservationType(PersistentStateSnapshot snapshot, string type)
        => snapshot.Observations.Any(x => x.Type.Equals(type, StringComparison.OrdinalIgnoreCase));

    private static bool HasAnyObservationType(PersistentStateSnapshot snapshot, params string[] types)
        => snapshot.Observations.Any(x => types.Any(type => x.Type.Equals(type, StringComparison.OrdinalIgnoreCase)));

    private static HistoryAssessment CombineAssessments(
        string leftName,
        HistoryAssessment left,
        string rightName,
        HistoryAssessment right)
        => new(
            left.Complete && right.Complete,
            $"{(left.Complete && right.Complete ? "Completa" : "Parcial")}; {leftName}: {left.Description}; {rightName}: {right.Description}");

    private static string FormatDuration(TimeSpan value)
    {
        if (value.TotalDays >= 1) return $"{value.TotalDays:0.##} días";
        if (value.TotalHours >= 1) return $"{value.TotalHours:0.##} h";
        if (value.TotalMinutes >= 1) return $"{value.TotalMinutes:0.##} min";
        return $"{Math.Max(0, value.TotalSeconds):0} s";
    }

    private sealed record HistoryAssessment(bool Complete, string Description);

    private static readonly string[] MonitorTransitionTypes =
    [
        // Q3: TDM_STATE_TRANSITION (RecordAndEnrich) también participa: sin él, el mismo cambio
        // físico aparece dos veces con distinto Tipo (pre-record + journal).
        "TDM_STATE_TRANSITION",
        "TDM_MONITOR_STATE_TRANSITION",
        "TDM_FORENSIC_STATE_TRANSITION",
        "TDM_INTEGRITY_STATE_TRANSITION"
    ];

    /// <summary>
    /// P05: dos eventos de transición de canales distintos representan el mismo cambio físico
    /// si coinciden timestamp, componente y valores anterior→actual. Evita duplicar en el
    /// historial un Running→Stopped visto por service-monitor y forensic-monitor.
    /// W2: el journal clampa el timestamp a `anchor` mientras el pre-record usa el CapturedAt
    /// raw (difieren ms/s del mismo ciclo); se acepta |Δ|≤5 s. Un flapping real queda a ≥60 s
    /// (cadencia de muestra), muy por encima de la tolerancia, así que no se colapsa.
    /// </summary>
    private static bool SamePhysicalTransition(DiagnosticEvent existing, StateTransition transition)
    {
        if (!MonitorTransitionTypes.Contains(existing.Tipo, StringComparer.OrdinalIgnoreCase)) return false;
        if (existing.Timestamp is not DateTimeOffset existingTs) return false;
        if ((existingTs - transition.Timestamp).Duration() > TimeSpan.FromSeconds(5)) return false;
        if (!existing.Componente.Equals(transition.Component, StringComparison.OrdinalIgnoreCase)) return false;
        var old = existing.Evidencia?.FirstOrDefault(e => e.Clave.Equals("Estado anterior", StringComparison.OrdinalIgnoreCase))?.Valor;
        var @new = existing.Evidencia?.FirstOrDefault(e => e.Clave.Equals("Estado actual", StringComparison.OrdinalIgnoreCase))?.Valor;
        return string.Equals(old, transition.PreviousValue, StringComparison.Ordinal)
            && string.Equals(@new, transition.CurrentValue, StringComparison.Ordinal);
    }

    private static DiagnosticLayer ParseLayer(string value)
        => Enum.TryParse<DiagnosticLayer>(value, true, out var layer) ? layer : DiagnosticLayer.Desconocida;

    private static TsplusProduct ParseProduct(string value)
        => Enum.TryParse<TsplusProduct>(value, true, out var product) ? product : TsplusProduct.Ninguno;

    private static string Compact(string value)
        => value.Length <= 180 ? value : value[..180] + "…";
}
