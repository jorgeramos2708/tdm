using TDM.Core;
using TDM.Models;

namespace TDM.Correlation;

public static partial class RootCauseCorrelator
{
    /// <summary>
    /// C2 (auditoría de efectividad, Fase 30): el hallazgo crítico de recursos —emitido con
    /// los umbrales configurados desde la Fase 29— debe llegar al ranking como candidato de
    /// causa raíz; antes ninguna regla consumía el prefijo RESOURCE- y el pipeline
    /// detección → correlación → ranking se rompía. La afirmación de causalidad exige
    /// evidencia acompañante: una señal funcional independiente (IsCausalSignal) dentro de
    /// la ventana y ≤15 min del fin del análisis, mismo contrato conservador que Print
    /// Spooler/TermService. Sin ella el candidato se conserva como hipótesis Media, que la
    /// elegibilidad de causa principal no permite declarar primaria.
    /// </summary>
    private static void AddResourceExhaustionCandidates(DiagnosticReport report, List<CandidateDraft> drafts)
    {
        var exhaustion = report.Hallazgos
            .Where(f => f.Severidad == DiagnosticSeverity.Critico)
            .Where(f => f.Id.Equals("RESOURCE-MEMORY-CRITICAL", StringComparison.OrdinalIgnoreCase)
                     || f.Id.StartsWith("RESOURCE-DISK-CRITICAL-", StringComparison.OrdinalIgnoreCase))
            .ToList();
        if (exhaustion.Count == 0) return;

        var symptom = WindowedFunctionalSignal(report);
        var correlated = symptom is not null;

        foreach (var finding in exhaustion)
        {
            var isDisk = finding.Id.StartsWith("RESOURCE-DISK-CRITICAL-", StringComparison.OrdinalIgnoreCase);
            var id = isDisk
                ? $"ROOT-RESOURCE-DISK-EXHAUSTION-{SafeDependencyId(finding.Id[^1].ToString())}"
                : "ROOT-RESOURCE-MEMORY-EXHAUSTION";

            drafts.Add(new CandidateDraft(
                id,
                finding.Componente,
                DiagnosticLayer.Windows,
                correlated ? 93 : 76,
                correlated ? ConfidenceLevel.Alta : ConfidenceLevel.Media,
                isDisk
                    ? "Una unidad crítica para Windows/TSplus superó el umbral de espacio libre crítico configurado."
                    : "La memoria física superó el umbral de uso crítico configurado.",
                correlated
                    ? "TDM confirmó el hallazgo crítico con los umbrales configurados y observó además una señal funcional independiente dentro de la ventana (≤15 min del fin del análisis). La secuencia respalda investigar capacidad/recursos antes de modificar TSplus; la causalidad requiere confirmación manual: TDM no libera espacio, no ajusta memoria ni modifica cuotas."
                    : "TDM confirmó el hallazgo crítico con los umbrales configurados, pero no observó una señal funcional independiente en la ventana. Se conserva como hipótesis preventiva; sin un síntoma funcional no se afirma causalidad.",
                Merge(
                    finding.Evidencia,
                    new EvidenceItem("Señal funcional acompañante",
                        correlated ? $"{symptom!.Tipo} · {symptom.Componente}" : "No observada"),
                    new EvidenceItem("Ventana de correlación",
                        correlated
                            ? "Señal independiente dentro de la ventana y ≤15 min del fin"
                            : "Sin señal funcional en la ventana")),
                isDisk ? "MS-DISK-SPACE" : "MS-LOW-MEMORY",
                symptom?.Timestamp,
                "WINDOWS",
                TsplusProduct.RemoteAccess));
        }
    }

    /// <summary>
    /// Señal funcional independiente dentro del periodo analizado y cercana al fin.
    /// IsCausalSignal descarta eventos sintetizados por TDM, estados y telemetría, de modo
    /// que la elevación exige convergencia real y no la propia captura de recursos (cuyo
    /// evento es Fuente=TDM e Informativo/Advertencia).
    /// </summary>
    private static DiagnosticEvent? WindowedFunctionalSignal(DiagnosticReport report)
        => report.Eventos
            .Where(e => e.Timestamp.HasValue && e.Severidad != DiagnosticSeverity.Informativo)
            .Where(DiagnosticPrecisionAnalyzer.IsCausalSignal)
            .Where(e => DiagnosticTimeWindow.IsEventInside(report, e.Timestamp!.Value))
            .Where(e => IsNearAnalysisEnd(report, e, TimeSpan.FromMinutes(15)))
            .OrderByDescending(e => e.Timestamp)
            .FirstOrDefault();
}
