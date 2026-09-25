using TDM.Models;

namespace TDM.Core;

/// <summary>
/// Regla única para decidir si un hallazgo fechado pertenece a una ventana visible.
/// Los hallazgos de estado actual sin timestamp se conservan.
/// </summary>
public static class DiagnosticTimeWindow
{
    private static readonly string[] TimestampKeys =
    [
        "Fecha", "Último registro", "Hora del incidente", "Primer evento", "Último evento"
    ];

    public static bool IsFindingInside(DiagnosticFinding finding, DateTimeOffset start, DateTimeOffset end)
    {
        var timestamps = finding.Evidencia
            .Where(e => TimestampKeys.Any(key => e.Clave.Equals(key, StringComparison.OrdinalIgnoreCase)))
            .Select(e => e.Valor)
            .Where(raw => !string.IsNullOrWhiteSpace(raw) && !raw.Equals("N/D", StringComparison.OrdinalIgnoreCase))
            .Select(raw => DateTimeOffset.TryParse(raw, out var timestamp) ? timestamp : (DateTimeOffset?)null)
            .Where(t => t.HasValue)
            .Select(t => t!.Value)
            .ToList();

        if (timestamps.Count == 0) return true;

        // Un hallazgo con intervalo Primer/Último evento pertenece a la ventana si
        // ambos intervalos se solapan. No se descarta por escoger accidentalmente
        // sólo el primer campo temporal disponible.
        var earliest = timestamps.Min();
        var latest = timestamps.Max();
        return latest >= start && earliest <= end;
    }
}
