using TDM.Correlation;
using TDM.Models;

namespace TDM.Application;

/// <summary>
/// Orquestación analítica única para GUI/CLI. No recopila evidencia ni persiste estado;
/// transforma un DiagnosticReport ya capturado en diagnóstico correlacionado.
/// </summary>
public static class DiagnosticWorkflow
{
    public static DiagnosticReport EnrichOperationalState(DiagnosticReport report)
    {
        ArgumentNullException.ThrowIfNull(report);
        return OperationalHealthAnalyzer.Enrich(report);
    }

    public static DiagnosticReport Analyze(
        DiagnosticReport report,
        bool includeGuidedResolution = false,
        IReadOnlyDictionary<string, (int Confirmadas, int Descartadas, double Tasa)>? verifiedHitRates = null)
    {
        ArgumentNullException.ThrowIfNull(report);
        report = EnrichOperationalState(report);
        var calibrated = DiagnosticPrecisionAnalyzer.Calibrate(report, RootCauseCorrelator.Analyze(report));
        // P0-aprendizaje: el historial verificado por el técnico ajusta puntajes con
        // guardarraíles (tope ±15, veto de evidencia primaria independiente). Se aplica sobre la
        // lista completa ANTES del recorte para que el ranking ajustado decida qué entra al top-8.
        // Sin historial el ranking usa solo evidencia actual: null no cambia ningún comportamiento previo.
        if (verifiedHitRates is { Count: > 0 })
            calibrated = VerifiedHistoryCalibrator.ApplyVerifiedHistory(calibrated, verifiedHitRates).ToList();
        // F34 (H4/H5): tras la reordenación de Calibrate, el podio final (puestos 1-3)
        // conserva la fuente oficial aunque el candidato haya ascendido desde una posición
        // bruta mayor a 3 (ToCandidate sólo cubre el ranking inicial).
        calibrated = RootCauseCorrelator.ApplyTopThreeGuidance(calibrated);
        // P14: recorte final post-calibración (el pool completo se calibra; el Take(8) es
        // sólo de presentación y FailurePatternAnalyzer sigue viendo la lista completa).
        var causes = calibrated.Take(8).ToList();
        // MEDIUM: el filtro de rol se aplica sobre la lista completa (antes del Take(8)); con ≥8
        // impactos directos saturando el top-8, el pool causal quedaba vacío y CausaRaizPrincipal
        // era null aunque existieran causas reales calculadas en los puestos 9-12.
        var causalCandidates = calibrated.Where(c => !c.RolCausal.Equals("IMPACTO_DIRECTO_SIN_CAUSA_DEL_PARO", StringComparison.OrdinalIgnoreCase)).ToList();
        RootCauseCandidate? primary = null;
        if (causalCandidates.Count == 1)
        {
            // P15: un único candidato Media/Baja sin evidencia primaria independiente no puede
            // declararse causa principal; se conserva como hipótesis y primary queda null.
            if (IsPrimaryEligible(causalCandidates[0]))
                primary = causalCandidates[0];
        }
        else if (causalCandidates.Count > 1 && causalCandidates[0].Puntaje - causalCandidates[1].Puntaje >= 5)
        {
            // R1: el mismo veto aplica al top multi-candidato: un Media sin independencia,
            // aunque saque 5 puntos, queda como hipótesis competitiva, no como causa principal.
            if (IsPrimaryEligible(causalCandidates[0]))
                primary = causalCandidates[0];
        }
        if (primary is not null && causes.All(c => !ReferenceEquals(c, primary)))
        {
            // La causa ganadora quedó fuera del recorte de 8 por saturación de impacto directo;
            // se incorpora a la presentación para que CausaRaizPrincipal esté siempre en CausasRaiz.
            causes.Add(primary);
        }
        report = report with { CausasRaiz = causes, CausaRaizPrincipal = primary };
        // B#19: los patrones de falla se calculan sobre la lista completa de candidatos
        // calibrados; el recorte Take(8) es sólo presentación del informe y no debe ocultar
        // recurrencias de candidatos fuera del top 8.
        report = report with { PatronesFalla = FailurePatternAnalyzer.Analyze(report with { CausasRaiz = calibrated }) };
        report = report with { Incidentes = IncidentClusterAnalyzer.Analyze(report) };
        report = report with { PrecisionDiagnostica = DiagnosticPrecisionAnalyzer.Analyze(report) };
        report = report with { ImpactoFuncional = FunctionalImpactAnalyzer.Analyze(report) };
        report = report with { PlanAccion = SafeActionPlanner.Build(report) };
        report = report with { CoberturaDiagnostica = DiagnosticCoverageAnalyzer.Analyze(report) };
        if (includeGuidedResolution)
            report = report with { ResolucionesGuiadas = TsplusGuidedTroubleshooter.AnalyzeAll(report) };
        report = report with { Tensiones = ReportConsistencyAnalyzer.Analyze(report) };
        return report;
    }

    private static bool IsPrimaryEligible(RootCauseCandidate candidate)
    {
        if (candidate.Confianza is ConfidenceLevel.Alta or ConfidenceLevel.Confirmada) return true;
        return candidate.Evidencia.Any(e =>
            e.Clave.Equals("Evidencia primaria independiente", StringComparison.OrdinalIgnoreCase) &&
            e.Valor.Equals("Sí", StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// F35 (M-05/M-09): cierra el pipeline DESPUÉS de los enriquecimientos post-motor
    /// (hallazgos y observaciones añadidos por estabilidad, divergencia, latido, clústeres
    /// o integración de estado). Sincroniza el recuento de rendimiento con las colecciones
    /// finales que se exportan y recalcula las tensiones para que sus números midan el
    /// reporte terminado, no el snapshot previo a los apéndices.
    /// </summary>
    public static DiagnosticReport SyncRecuentoAndTensions(DiagnosticReport report)
    {
        ArgumentNullException.ThrowIfNull(report);
        if (report.RendimientoDiagnostico is { } perf &&
            (perf.Hallazgos != report.Hallazgos.Count || perf.EventosNormalizados != report.Eventos.Count))
        {
            report = report with
            {
                RendimientoDiagnostico = perf with
                {
                    Hallazgos = report.Hallazgos.Count,
                    EventosNormalizados = report.Eventos.Count
                }
            };
        }
        return report with { Tensiones = ReportConsistencyAnalyzer.Analyze(report) };
    }
}
