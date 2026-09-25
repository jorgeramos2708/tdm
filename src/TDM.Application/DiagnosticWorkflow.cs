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
        // P14: recorte final post-calibración (la pre-selección amplia de 12 ya ocurrió en el correlador).
        var causes = calibrated.Take(8).ToList();
        // P0-aprendizaje: el historial verificado por el técnico ajusta puntajes con
        // guardarraíles (tope ±15, veto de evidencia primaria independiente). Sin historial
        // el ranking usa solo evidencia actual: null no cambia ningún comportamiento previo.
        if (verifiedHitRates is { Count: > 0 })
            causes = VerifiedHistoryCalibrator.ApplyVerifiedHistory(causes, verifiedHitRates).ToList();
        var causalCandidates = causes.Where(c => !c.RolCausal.Equals("IMPACTO_DIRECTO_SIN_CAUSA_DEL_PARO", StringComparison.OrdinalIgnoreCase)).ToList();
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
        report = report with { CausasRaiz = causes, CausaRaizPrincipal = primary };
        report = report with { PatronesFalla = FailurePatternAnalyzer.Analyze(report) };
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

    public static DiagnosticReport RefreshCoverageAndGuidedResolution(DiagnosticReport report)
    {
        ArgumentNullException.ThrowIfNull(report);
        return report with
        {
            CoberturaDiagnostica = DiagnosticCoverageAnalyzer.Analyze(report),
            ResolucionesGuiadas = TsplusGuidedTroubleshooter.AnalyzeAll(report)
        };
    }
}
