using TDM.Models;

namespace TDM.Correlation;

/// <summary>
/// Cierra el loop de aprendizaje: ajusta el ranking de causas con el historial verificado
/// por el técnico (ver <see cref="TDM.Persistence.DiagnosticFeedbackStore"/>), sin tocar las
/// reglas del correlador. Función pura: no lee disco, no escribe estado.
/// Reglas (guardarraíles):
/// 1. Sin historial (null/vacío) la lista se devuelve intacta: el ranking usa solo evidencia actual.
/// 2. El ajuste escala con la muestra: ±15 puntos con 5+ veredictos, proporcional por debajo.
///    Una sola anécdota mueve como máximo ±3: no decide primarias.
/// 3. Tope duro de ±15 puntos y clamp 0..100.
/// 4. Veto de inversión: un historial de descartes NUNCA resta a un candidato con
///    "Evidencia primaria independiente = Sí". La evidencia dura prevalece sobre la reputación.
/// 5. Veto de adelantamiento: el feedback no puede hacer que un candidato sin evidencia
///    primaria independiente supere a uno que sí la tiene y venía por encima por puntaje
///    base. En empate se conserva el orden base (ordenamiento estable).
/// 6. Todo ajuste efectivo queda registrado como EvidenceItem ("Historial verificado por
///    técnico") para que el reporte muestre por qué cambió el puntaje. Un veto total
///    también se declara ("Historial verificado no aplicado...").
/// </summary>
public static class VerifiedHistoryCalibrator
{
    public const int MaxAdjustmentPoints = 15;
    public const int FullWeightSampleSize = 5;
    public static readonly TimeSpan DefaultLookback = TimeSpan.FromDays(90);

    private const string HistoryKey = "Historial verificado por técnico";
    private const string IndependentKey = "Evidencia primaria independiente";

    public static IReadOnlyList<RootCauseCandidate> ApplyVerifiedHistory(
        IReadOnlyList<RootCauseCandidate> candidates,
        IReadOnlyDictionary<string, (int Confirmadas, int Descartadas, double Tasa)>? hitRates)
    {
        if (candidates.Count == 0 || hitRates is null || hitRates.Count == 0) return candidates;

        // Puntajes ajustados antes del veto de adelantamiento.
        var adjusted = new List<(RootCauseCandidate Candidate, int Score, int BaseRank, string? Note)>(candidates.Count);
        var rank = 0;
        foreach (var candidate in candidates)
        {
            var delta = 0;
            string? note = null;
            if (hitRates.TryGetValue(candidate.Id, out var history))
            {
                var total = history.Confirmadas + history.Descartadas;
                if (total > 0)
                {
                    var weight = Math.Min(total / (double)FullWeightSampleSize, 1.0);
                    delta = (int)Math.Round((history.Tasa - 0.5) * 2 * MaxAdjustmentPoints * weight);
                    delta = Math.Clamp(delta, -MaxAdjustmentPoints, MaxAdjustmentPoints);
                    if (delta < 0 && HasIndependentPrimaryEvidence(candidate))
                    {
                        // Regla 4: veto de inversión. Se declara para auditoría del reporte.
                        note = $"{IndependentKey}: Sí; historial ({history.Confirmadas} confirmadas / {history.Descartadas} descartadas) no aplicado: la evidencia dura prevalece.";
                        delta = 0;
                    }
                    else if (delta != 0)
                    {
                        var sign = delta > 0 ? "+" : "";
                        note = $"{history.Confirmadas} confirmadas / {history.Descartadas} descartadas → ajuste {sign}{delta} (tope ±{MaxAdjustmentPoints}).";
                    }
                }
            }
            adjusted.Add((candidate, Math.Clamp(candidate.Puntaje + delta, 0, 100), rank, note));
            rank++;
        }

        // Regla 5: veto de adelantamiento por pares (base: el de arriba tiene evidencia
        // independiente y el de abajo no). Se recorta al empate; el orden estable conserva al de arriba.
        for (var i = 0; i < adjusted.Count; i++)
        {
            if (HasIndependentPrimaryEvidence(adjusted[i].Candidate)) continue;
            int? cap = null;
            for (var j = 0; j < adjusted.Count; j++)
            {
                if (i == j || !HasIndependentPrimaryEvidence(adjusted[j].Candidate)) continue;
                if (adjusted[j].BaseRank < adjusted[i].BaseRank)
                    cap = cap.HasValue ? Math.Min(cap.Value, adjusted[j].Score) : adjusted[j].Score;
            }
            if (cap.HasValue && adjusted[i].Score > cap.Value)
            {
                var entry = adjusted[i];
                entry.Score = cap.Value;
                entry.Note = (entry.Note is null ? "" : entry.Note + " ") +
                    $"Recortado a {cap.Value} para no superar por historial a un candidato con {IndependentKey.ToLowerInvariant()}.";
                adjusted[i] = entry;
            }
        }

        return adjusted
            .OrderByDescending(x => x.Score)
            .ThenBy(x => x.BaseRank)
            .Select((x, index) =>
            {
                var evidence = x.Candidate.Evidencia;
                if (!string.IsNullOrWhiteSpace(x.Note))
                {
                    var list = x.Candidate.Evidencia.ToList();
                    list.Add(new EvidenceItem(HistoryKey, x.Note!));
                    evidence = list;
                }
                return x.Candidate with { Puntaje = x.Score, Evidencia = evidence, Posicion = index + 1 };
            })
            .ToList();
    }

    internal static bool HasIndependentPrimaryEvidence(RootCauseCandidate candidate)
        => candidate.Evidencia.Any(e =>
            e.Clave.Equals(IndependentKey, StringComparison.OrdinalIgnoreCase) &&
            e.Valor.Equals("Sí", StringComparison.OrdinalIgnoreCase));
}
