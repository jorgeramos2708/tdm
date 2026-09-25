using System.Globalization;

namespace TDM.Models;

/// <summary>
/// Resuelve una ventana temporal retrospectiva coherente para todos los collectors.
/// Si existe HoraIncidente, esa hora es el límite superior de la investigación;
/// Lookback siempre significa "N tiempo hacia atrás", nunca una ventana centrada.
/// </summary>
public readonly record struct DiagnosticWindowRange(DateTimeOffset Start, DateTimeOffset End)
{
    public bool Contains(DateTimeOffset timestamp) => timestamp >= Start && timestamp <= End;
}

public static class DiagnosticWindow
{
    public static DiagnosticWindowRange Resolve(DiagnosticContext context, DateTimeOffset? now = null)
    {
        ArgumentNullException.ThrowIfNull(context);
        var lookback = context.Lookback > TimeSpan.Zero ? context.Lookback : TimeSpan.FromMinutes(15);
        var end = context.HoraIncidente ?? now ?? DateTimeOffset.Now;
        return new DiagnosticWindowRange(end - lookback, end);
    }

    /// <summary>
    /// Cláusula XPath compatible con EventLogQuery usando tiempos UTC absolutos.
    /// Evita que una investigación histórica dependa de timediff(@SystemTime),
    /// que siempre se evalúa contra la hora actual del equipo.
    /// </summary>
    public static string EventLogTimeClause(DiagnosticContext context, DateTimeOffset? now = null)
    {
        var range = Resolve(context, now);
        return $"TimeCreated[@SystemTime >= '{FormatUtc(range.Start)}' and @SystemTime <= '{FormatUtc(range.End)}']";
    }

    public static string FormatUtc(DateTimeOffset value)
        => value.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'", CultureInfo.InvariantCulture);
}
