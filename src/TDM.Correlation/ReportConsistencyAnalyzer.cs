using TDM.Models;

namespace TDM.Correlation;

/// <summary>
/// Auto-chequeo de coherencia interna del reporte terminado: lista tensiones explícitas
/// que requieren lectura del técnico en vez de dejarlas implícitas (p. ej. "sin causa"
/// junto a hallazgos Error). Función pura sobre el reporte final; no puntúa ni propone
/// causas. Pineado por tests.
/// </summary>
public static class ReportConsistencyAnalyzer
{
    public static IReadOnlyList<string> Analyze(DiagnosticReport report)
    {
        ArgumentNullException.ThrowIfNull(report);
        var tensions = new List<string>();
        var serious = report.Hallazgos.Count(f => f.Severidad is DiagnosticSeverity.Error or DiagnosticSeverity.Critico);
        if (report.CausaRaizPrincipal is null && serious > 0)
            tensions.Add($"Hay {serious} hallazgo(s) Error/Crítico sin causa principal: la evidencia no forma cadena causal o la causa está fuera de cobertura.");
        var criticalIncomplete = report.CoberturaDiagnostica?.Fuentes
            .Any(x => x.Critica && x.Estado is not "Disponible" and not "No aplica") == true;
        if (report.CausaRaizPrincipal is { Confianza: ConfidenceLevel.Alta or ConfidenceLevel.Confirmada } && criticalIncomplete)
            tensions.Add("La causa principal tiene confianza alta con cobertura crítica parcial: las fuentes NO EVALUADAS no están descartadas.");
        if (report.ImpactoFuncional?.EstadoGeneral is FunctionalImpactState.Interrumpido or FunctionalImpactState.Degradado
            && report.CausaRaizPrincipal is null)
            tensions.Add($"Impacto funcional {report.ImpactoFuncional.EstadoGeneral} sin origen demostrado: impacto confirmado, causa no demostrada.");
        var principal = report.CausaRaizPrincipal;
        if (principal?.HoraIncidente.HasValue == true && report.PeriodoAnalizadoFin != default &&
            (principal.HoraIncidente.Value < report.PeriodoAnalizadoInicio || principal.HoraIncidente.Value > report.PeriodoAnalizadoFin))
            tensions.Add("La hora del incidente principal cae fuera de la ventana analizada: verifique la ventana antes de actuar.");
        if (report.PrecisionDiagnostica is { Score: < 40 } && principal is not null)
            tensions.Add($"Calidad diagnóstica baja ({report.PrecisionDiagnostica.Score}/100) con causa propuesta: valide manualmente antes de actuar.");
        if (report.Hallazgos.Any(f => f.Id.Equals("TDM-CAUSE-UNSTABLE", StringComparison.OrdinalIgnoreCase)) && principal is not null)
            tensions.Add("La causa principal tiene historial inestable entre muestras: tómese como hipótesis, no como veredicto.");
        return tensions;
    }
}
