using TDM.Models;
using TDM.Core;

namespace TDM.Correlation;

/// <summary>
/// Anti-flapping de causa principal: si la causa cambia demasiado entre muestras
/// consecutivas, el top debe leerse como hipótesis competitivas, no como veredicto.
/// Función pura: el historial lo persiste el llamador (cursor) y lo pasa como lista
/// donde el último elemento es la muestra actual. Vacíos = "sin causa principal".
/// Reglas: ventana 6, mínimo 4 muestras no vacías, 3+ causas distintas = inestable.
/// P2-02: Threshold configurable via DiagnosticExecutionPolicy.CauseStabilityFlappingThreshold.
/// </summary>
public static class CauseStabilityAnalyzer
{
    public const int Window = 6;
    public const int MinSamples = 4;
    public const int DefaultMaxDistinct = 2;

    public static DiagnosticFinding? Analyze(
        IReadOnlyList<string> recentPrimaryIds,
        int window = Window,
        int? maxDistinct = null)
    {
        if (recentPrimaryIds.Count == 0 || window <= 0) return null;
        var seq = recentPrimaryIds
            .Skip(Math.Max(0, recentPrimaryIds.Count - window))
            .Where(s => !string.IsNullOrWhiteSpace(s))
            .ToList();
        if (seq.Count < MinSamples) return null;
        var distinct = seq.Distinct(StringComparer.OrdinalIgnoreCase).Count();
        var threshold = maxDistinct ?? DefaultMaxDistinct;
        if (distinct <= threshold) return null;
        return new DiagnosticFinding(
            "TDM-CAUSE-UNSTABLE",
            "Causa principal",
            DiagnosticSeverity.Advertencia,
            $"La causa principal cambió {distinct} veces en las últimas {seq.Count} muestras (umbral: {threshold}).",
            "Un top que rota entre candidatos indica evidencia dividida o síntomas superpuestos. Lea el top-3 como hipótesis competitivas y valide con el técnico antes de actuar sobre la causa #1.",
            [new EvidenceItem("Secuencia", string.Join(" -> ", seq)),
             new EvidenceItem("Causas distintas", distinct.ToString()),
             new EvidenceItem("Muestras", seq.Count.ToString()),
             new EvidenceItem("Umbral configurado", threshold.ToString())],
            ConfidenceLevel.Alta,
            Capa: DiagnosticLayer.Desconocida);
    }
}
