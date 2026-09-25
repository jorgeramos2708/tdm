using TDM.Models;

namespace TDM.Correlation;

public static partial class RootCauseCorrelator
{
    /// <summary>
    /// Post-pass configuración→síntoma: un ajuste TSplus que cambió dentro de los 30
    /// min previos al incidente suma hasta +6 al candidato TSplus afectado, con evidencia
    /// explícita. Solo rol CAUSA_CANDIDATA con hora de incidente (los marcadores de
    /// impacto directo no son causas y no se tocan). Acotado y declarado por diseño:
    /// la proximidad temporal no demuestra causalidad, solo prioriza al sospechoso.
    /// </summary>
    private static void ApplyConfigurationDriftProximity(DiagnosticReport report, List<CandidateDraft> drafts)
    {
        for (var i = 0; i < drafts.Count; i++)
        {
            var draft = drafts[i];
            if (draft.Layer != DiagnosticLayer.Tsplus) continue;
            if (!draft.CausalRole.Equals("CAUSA_CANDIDATA", StringComparison.OrdinalIgnoreCase)) continue;
            if (!draft.IncidentTime.HasValue) continue;
            var minutes = DriftProximityMatcher.MinutesBeforeIncident(
                report.Hallazgos, draft.IncidentTime.Value, DriftProximityMatcher.DefaultWindow);
            if (!minutes.HasValue) continue;
            var evidence = draft.Evidence.ToList();
            evidence.Add(new EvidenceItem("Cambio de configuración previo",
                $"Un ajuste de configuración cambió {minutes.Value} min antes del incidente (ventana 30 min, tope +{DriftProximityMatcher.MaxNudgePoints})."));
            drafts[i] = draft with
            {
                Score = Math.Min(100, draft.Score + DriftProximityMatcher.MaxNudgePoints),
                Evidence = evidence
            };
        }
    }
}
