using System.Globalization;
using TDM.Models;

namespace TDM.Correlation;

/// <summary>
/// Proximidad temporal configuración→síntoma: si un ajuste cambió poco antes del
/// incidente, es el primer sospechoso. Lee las horas que publica el collector de
/// deriva ("Horas de cambio (UTC)" = "archivo|ISO; ...") y devuelve los minutos
/// entre el cambio previo más cercano y el incidente, o null si ninguno precede
/// dentro de la ventana. Puro y pineado por tests.
/// </summary>
public static class DriftProximityMatcher
{
    public static readonly TimeSpan DefaultWindow = TimeSpan.FromMinutes(30);
    public const int MaxNudgePoints = 6;

    public static int? MinutesBeforeIncident(
        IReadOnlyList<DiagnosticFinding> findings,
        DateTimeOffset incident,
        TimeSpan window)
    {
        if (findings.Count == 0 || window <= TimeSpan.Zero) return null;
        int? best = null;
        foreach (var finding in findings)
        {
            if (!finding.Id.StartsWith("TSPLUS-CONFIG-DRIFT", StringComparison.OrdinalIgnoreCase)) continue;
            foreach (var item in finding.Evidencia)
            {
                if (!item.Clave.Equals("Horas de cambio (UTC)", StringComparison.OrdinalIgnoreCase)) continue;
                foreach (var part in item.Valor.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                {
                    var sep = part.LastIndexOf('|');
                    if (sep < 0) continue;
                    // L-05 (F35): cultura explícita; la escritora publica ISO-8601 con offset
                    // y el parseo implícito de CurrentCulture no es un contrato verificable.
                    if (!DateTimeOffset.TryParse(part[(sep + 1)..].Trim(), CultureInfo.InvariantCulture, DateTimeStyles.None, out var change)) continue;
                    var delta = incident - change;
                    if (delta < TimeSpan.Zero || delta > window) continue;
                    var minutes = (int)delta.TotalMinutes;
                    best = best.HasValue ? Math.Min(best.Value, minutes) : minutes;
                }
            }
        }
        return best;
    }
}
