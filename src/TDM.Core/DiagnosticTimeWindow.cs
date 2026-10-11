using System.Globalization;
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

    // L-12 (F35): sólo las claves que citan eventos concretos del pipeline; las demás
    // (Fecha, Último registro, Hora del incidente) describen estado/hito, no eventos del reporte.
    private static readonly string[] EventCitationKeys = ["Primer evento", "Último evento"];

    // H1: formatos exactos que emiten los productores de TimestampKeys ("dd/MM/yyyy HH:mm:ss"
    // en hallazgos de reglas/collectors, "O" round-trip ISO 8601 en Fecha/Último registro).
    // MS: un format string sólo es estable con cultura explícita ("O"/"o" es invariante por
    // definición; "d" cambia entre MM/dd y dd/MM según la cultura) — learn.microsoft.com/dotnet/
    // standard/base-types/standard-date-and-time-format-strings — y TryParseExact con array de
    // formatos exige coincidencia exacta — learn.microsoft.com/dotnet/api/system.datetimeoffset.tryparseexact.
    private static readonly string[] TimestampFormats =
    [
        "dd/MM/yyyy HH:mm:ss",
        "dd/MM/yyyy HH:mm:ss.fff",
        "dd/MM/yyyy",
        "O",
        "yyyy-MM-ddTHH:mm:ss",
        "yyyy-MM-dd"
    ];

    /// <summary>
    /// Regla única para decidir si un evento fechado pertenece al periodo analizado del
    /// reporte. Si el periodo no está declarado, el evento se conserva. Los eventos sin
    /// timestamp se evalúan fuera de esta regla.
    /// </summary>
    public static bool IsEventInside(DiagnosticReport report, DateTimeOffset timestamp)
        => (report.PeriodoAnalizadoInicio == default || timestamp >= report.PeriodoAnalizadoInicio)
           && (report.PeriodoAnalizadoFin == default || timestamp <= report.PeriodoAnalizadoFin);

    /// <summary>
    /// Timestamps que el hallazgo declara como cita de eventos concretos (Primer/Último
    /// evento), leídos con la regla de parseo única. Vacío si no declara ninguno legible.
    /// L-12 (F35): el auto-chequeo de coherencia los usa para detectar citas cuyo evento
    /// ya fue descartado por el recorte de la ventana analizada.
    /// </summary>
    public static IReadOnlyList<DateTimeOffset> DeclaredEventTimestamps(DiagnosticFinding finding)
    {
        ArgumentNullException.ThrowIfNull(finding);
        var timestamps = new List<DateTimeOffset>();
        foreach (var raw in DeclaredValues(finding, EventCitationKeys))
            if (TryParseTimestamp(raw, out var timestamp)) timestamps.Add(timestamp);
        return timestamps;
    }

    public static bool IsFindingInside(DiagnosticFinding finding, DateTimeOffset start, DateTimeOffset end)
    {
        var declared = DeclaredValues(finding, TimestampKeys);

        var timestamps = new List<DateTimeOffset>(declared.Count);
        foreach (var raw in declared)
        {
            if (TryParseTimestamp(raw, out var timestamp))
            {
                timestamps.Add(timestamp);
            }
            else if (LooksLikeTimestamp(raw))
            {
                // H1: una fecha declarada que no se puede leer no pertenece comprobablemente a la
                // ventana; antes el fallo de parse (TryParse sin cultura) la conservaba para siempre.
                return false;
            }
        }

        if (timestamps.Count == 0) return true;

        // Un hallazgo con intervalo Primer/Último evento pertenece a la ventana si
        // ambos intervalos se solapan. No se descarta por escoger accidentalmente
        // sólo el primer campo temporal disponible.
        var earliest = timestamps.Min();
        var latest = timestamps.Max();
        return latest >= start && earliest <= end;
    }

    private static List<string> DeclaredValues(DiagnosticFinding finding, string[] keys)
        => finding.Evidencia
            .Where(e => keys.Any(key => e.Clave.Equals(key, StringComparison.OrdinalIgnoreCase)))
            .Select(e => e.Valor)
            .Where(raw => !string.IsNullOrWhiteSpace(raw) && !raw.Equals("N/D", StringComparison.OrdinalIgnoreCase))
            .ToList();

    private static bool TryParseTimestamp(string raw, out DateTimeOffset timestamp)
    {
        if (DateTimeOffset.TryParseExact(raw, TimestampFormats, CultureInfo.InvariantCulture,
            DateTimeStyles.AllowWhiteSpaces, out timestamp))
            return true;
        // Forma ISO 8601 yyyy-MM-dd… (round-trip "O" y variantes sin fracciones/offset): se delega
        // al parseo general con InvariantCulture porque ISO no tiene ambigüedad de día/mes.
        // Las fechas con "/" no tienen fallback genérico: con cultura invariante "05/03" sería
        // siempre mes/día y reabriría la ambigüedad que H1 elimina.
        if (raw.Length >= 10 && raw[4] == '-' && raw[7] == '-')
            return DateTimeOffset.TryParse(raw, CultureInfo.InvariantCulture, DateTimeStyles.AllowWhiteSpaces, out timestamp);
        timestamp = default;
        return false;
    }

    private static bool LooksLikeTimestamp(string raw) =>
        raw.Length > 0 && raw[0] is >= '0' and <= '9' && (raw.Contains('/') || raw.Contains('-'));
}
