using TDM.Models;

namespace TDM.Correlation;

/// <summary>
/// Une incidentes ya correlacionados que comparten proceso, producto, excepción y componente funcional.
/// No fusiona productos distintos ni convierte recurrencia en causalidad.
/// </summary>
public static class FailurePatternAnalyzer
{
    public static IReadOnlyList<FailurePattern> Analyze(DiagnosticReport report)
    {
        var incidents = report.CausasRaiz
            .Where(c => c.Id == "ROOT-PROCESS-CRASH" && c.HoraIncidente.HasValue)
            .ToList();

        var groups = incidents
            .GroupBy(BuildSignature, StringComparer.OrdinalIgnoreCase)
            .Select(g => BuildPattern(g.ToList()))
            .OrderByDescending(p => p.Incidentes)
            .ThenByDescending(p => p.UltimaDeteccion)
            .ToList();

        return groups;
    }

    private static string BuildSignature(RootCauseCandidate c)
    {
        // R5: el origen clasificado NO forma parte de la firma: el mismo crash que flipa de
        // origen entre muestras partía el patrón en dos. El origen se conserva como evidencia.
        var semantic = EV(c, "Componente semántico");
        var exception = EV(c, "Tipo de excepción");
        if (semantic == "N/D") semantic = c.Componente;
        return $"{c.Producto}|{c.Componente}|{semantic}|{exception}";
    }

    private static FailurePattern BuildPattern(IReadOnlyList<RootCauseCandidate> items)
    {
        var ordered = items.OrderBy(c => c.HoraIncidente).ToList();
        var first = ordered[0];
        var firstTime = ordered[0].HoraIncidente!.Value;
        var lastTime = ordered[^1].HoraIncidente!.Value;
        TimeSpan? average = null;
        if (ordered.Count > 1)
        {
            var totalTicks = 0L;
            for (var i = 1; i < ordered.Count; i++)
                totalTicks += (ordered[i].HoraIncidente!.Value - ordered[i - 1].HoraIncidente!.Value).Ticks;
            average = TimeSpan.FromTicks(totalTicks / (ordered.Count - 1));
        }

        var semantic = EV(first, "Componente semántico");
        if (semantic == "N/D") semantic = first.Componente;
        var exception = EV(first, "Tipo de excepción");
        var ids = ordered.Select(x => EV(x, "ID incidente")).Where(x => x != "N/D").ToList();
        // U4: la firma ya no incluye el origen (R5); si el patrón fusionó orígenes distintos se
        // declara para no ocultar el conflicto que Calibrate penaliza por separado.
        var origins = ordered.Select(x => x.OrigenClasificado).Where(x => !string.IsNullOrWhiteSpace(x))
            .Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        var state = ordered.Any(x => x.Confianza == ConfidenceLevel.Confirmada) ? "CONFIRMADA"
            : ordered.Any(x => x.Confianza == ConfidenceLevel.Alta) ? "ALTAMENTE SUSTENTADA"
            : ordered.Any(x => x.Confianza == ConfidenceLevel.Media) ? "PROBABLE"
            : "INDETERMINADA";

        var evidence = new List<EvidenceItem>
        {
            new("Recurrencia del patrón en la ventana", ordered.Count > 1 ? "Sí" : "No"),
            new("Incidentes del patrón", ordered.Count.ToString()),
            new("Primera detección", firstTime.ToLocalTime().ToString("dd/MM/yyyy HH:mm:ss")),
            new("Última detección", lastTime.ToLocalTime().ToString("dd/MM/yyyy HH:mm:ss")),
            new("Intervalo promedio", average.HasValue ? FormatInterval(average.Value) : "No aplica"),
            new("Origen", origins.Count <= 1 ? first.OrigenClasificado : string.Join(" / ", origins)),
            new("Orígenes fusionados", origins.Count <= 1 ? "No" : "Sí; ver Origen"),
            new("Componente funcional", semantic),
            new("Tipo de excepción", exception)
        };

        var id = $"PATTERN-{first.Producto}-{Sanitize(first.Componente)}-{StableHash(BuildSignature(first)):X8}";
        return new FailurePattern(id, first.Producto, first.Componente, semantic, exception, first.OrigenClasificado,
            state, ordered.Count, firstTime, lastTime, average, ids, evidence);
    }

    private static string EV(RootCauseCandidate c, string key) =>
        c.Evidencia.FirstOrDefault(e => e.Clave.Equals(key, StringComparison.OrdinalIgnoreCase))?.Valor ?? "N/D";

    private static string FormatInterval(TimeSpan value) =>
        value.TotalHours >= 1 ? $"{(int)value.TotalHours} h {value.Minutes} min" : value.TotalMinutes >= 1 ? $"{(int)value.TotalMinutes} min {value.Seconds} s" : $"{value.TotalSeconds:F0} s";

    private static uint StableHash(string value)
    {
        const uint offset = 2166136261;
        const uint prime = 16777619;
        var hash = offset;
        foreach (var ch in value)
        {
            hash ^= char.ToUpperInvariant(ch);
            hash *= prime;
        }
        return hash;
    }

    private static string Sanitize(string value)
    {
        var chars = value.Where(char.IsLetterOrDigit).Take(24).ToArray();
        return chars.Length == 0 ? "component" : new string(chars);
    }
}
