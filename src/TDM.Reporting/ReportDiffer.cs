using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.Json;
using TDM.Models;

namespace TDM.Reporting;

/// <summary>
/// Diff día-a-día entre dos reportes TDM. Solo lectura; no modifica estado.
/// Compara: causas raíz (Id+Componente), hallazgos (Id), precision/cobertura scores, estado funcional.
/// </summary>
public static class ReportDiffer
{
    public sealed record DiffResult(
        DateTimeOffset PreviousTimestamp,
        DateTimeOffset CurrentTimestamp,
        IReadOnlyList<DiffItem> Changes,
        int PreviousFindings,
        int CurrentFindings,
        int PreviousCauses,
        int CurrentCauses,
        int PrecisionDelta,
        int CoverageDelta,
        FunctionalImpactState? PreviousImpact,
        FunctionalImpactState? CurrentImpact);

    public sealed record DiffItem(
        string Category,
        string Key,
        DiffKind Kind,
        string? PreviousValue = null,
        string? CurrentValue = null,
        string? Summary = null);

    public enum DiffKind { Added, Removed, Changed }

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false
    };

/// <summary>
    /// Calcula el diff entre el reporte anterior (si existe) y el actual.
    /// Retorna null si no hay reporte previo.
    /// </summary>
    public static DiffResult? Compute(DiagnosticReport previous, DiagnosticReport current)
    {
        if (previous is null) return null;

        var changes = new List<DiffItem>();

        // Causes: by stable composite key (Componente|Capa|OrigenClasificado) - P0-06
        // Id can change between runs; use stable identifiers
        var prevCauses = new Dictionary<string, RootCauseCandidate>(StringComparer.OrdinalIgnoreCase);
        foreach (var c in previous.CausasRaiz)
        {
            var key = StableCauseKey(c);
            prevCauses[key] = c;
        }
        var currCauses = new Dictionary<string, RootCauseCandidate>(StringComparer.OrdinalIgnoreCase);
        foreach (var c in current.CausasRaiz)
        {
            var key = StableCauseKey(c);
            currCauses[key] = c;
        }

        foreach (var kv in currCauses)
        {
            if (!prevCauses.ContainsKey(kv.Key))
            {
                var parts = kv.Key.Split('|');
                changes.Add(new DiffItem("Causa raíz", FormatCauseKey(parts), DiffKind.Added,
                    null, "Rank " + kv.Value.Puntaje + " / " + kv.Value.Confianza,
                    "Nueva causa raíz detectada en la muestra actual"));
            }
        }
        foreach (var kv in prevCauses)
        {
            if (!currCauses.ContainsKey(kv.Key))
            {
                var parts = kv.Key.Split('|');
                changes.Add(new DiffItem("Causa raíz", FormatCauseKey(parts), DiffKind.Removed,
                    "Rank " + kv.Value.Puntaje + " / " + kv.Value.Confianza, null,
                    "Causa raíz ya no presente en la muestra actual"));
            }
        }
        foreach (var kv in currCauses)
        {
            if (prevCauses.TryGetValue(kv.Key, out var prev) &&
                (prev.Puntaje != kv.Value.Puntaje || prev.Confianza != kv.Value.Confianza))
            {
                var parts = kv.Key.Split('|');
                changes.Add(new DiffItem("Causa raíz", FormatCauseKey(parts), DiffKind.Changed,
                    "Rank " + prev.Puntaje + " / " + prev.Confianza, "Rank " + kv.Value.Puntaje + " / " + kv.Value.Confianza,
                    "Cambio en ranking o confianza de causa existente"));
            }
}

        // Findings: by Id
        var prevFindings = previous.Hallazgos.ToDictionary(f => f.Id, StringComparer.OrdinalIgnoreCase);
        var currFindings = current.Hallazgos.ToDictionary(f => f.Id, StringComparer.OrdinalIgnoreCase);

        foreach (var kv in currFindings)
        {
            if (!prevFindings.ContainsKey(kv.Key))
            {
                changes.Add(new DiffItem("Hallazgo", kv.Key, DiffKind.Added,
                    null, kv.Value.Severidad + " / " + kv.Value.Confianza,
                    "Nuevo hallazgo: " + kv.Value.Resumen));
            }
        }
        foreach (var kv in prevFindings)
        {
            if (!currFindings.ContainsKey(kv.Key))
            {
                changes.Add(new DiffItem("Hallazgo", kv.Key, DiffKind.Removed,
                    kv.Value.Severidad + " / " + kv.Value.Confianza, null,
                    "Hallazgo ya no presente en la muestra actual"));
            }
        }
        foreach (var kv in currFindings)
        {
            if (prevFindings.TryGetValue(kv.Key, out var prev) &&
                (prev.Severidad != kv.Value.Severidad || prev.Confianza != kv.Value.Confianza))
            {
                changes.Add(new DiffItem("Hallazgo", kv.Key, DiffKind.Changed,
                    prev.Severidad + " / " + prev.Confianza, kv.Value.Severidad + " / " + kv.Value.Confianza,
                    "Cambio en severidad o confianza de hallazgo existente"));
            }
        }

        // Precision score
        var prevPrecision = previous.PrecisionDiagnostica?.Score ?? 0;
        var currPrecision = current.PrecisionDiagnostica?.Score ?? 0;
        if (prevPrecision != currPrecision)
        {
            changes.Add(new DiffItem("Calidad diagnóstica", "PrecisionScore", DiffKind.Changed,
                prevPrecision.ToString(), currPrecision.ToString(),
                "Score de precisión: " + prevPrecision + " \u2192 " + currPrecision));
        }

        // Coverage score
        var prevCoverage = previous.CoberturaDiagnostica?.Score ?? 0;
        var currCoverage = current.CoberturaDiagnostica?.Score ?? 0;
        if (prevCoverage != currCoverage)
        {
            changes.Add(new DiffItem("Cobertura", "CoverageScore", DiffKind.Changed,
                prevCoverage.ToString(), currCoverage.ToString(),
                "Score de cobertura: " + prevCoverage + " \u2192 " + currCoverage));
        }

        // Functional impact
        var prevImpact = previous.ImpactoFuncional?.EstadoGeneral;
        var currImpact = current.ImpactoFuncional?.EstadoGeneral;
        if (prevImpact != currImpact)
        {
            changes.Add(new DiffItem("Impacto funcional", "EstadoGeneral", DiffKind.Changed,
                prevImpact?.ToString() ?? "N/D", currImpact?.ToString() ?? "N/D",
                "Estado funcional: " + prevImpact + " \u2192 " + currImpact));
        }

return new DiffResult(
            previous.PeriodoAnalizadoFin,
            current.PeriodoAnalizadoFin,
            changes.OrderBy(c => c.Category).ThenBy(c => c.Key).ToList(),
            previous.Hallazgos.Count,
            current.Hallazgos.Count,
            previous.CausasRaiz.Count,
            current.CausasRaiz.Count,
            currPrecision - prevPrecision,
            currCoverage - prevCoverage,
            prevImpact,
            currImpact);
    }

    private static string StableCauseKey(RootCauseCandidate c)
        => $"{c.Componente}|{c.Capa}|{c.OrigenClasificado}";

    private static string FormatCauseKey(string[] parts)
        => parts.Length >= 3 ? $"{parts[0]} · {parts[1]} · {parts[2]}" : string.Join(" · ", parts);

    /// <summary>
    /// Serializa el diff a JSON compacto para incluir en el HTML.
    /// </summary>
    public static string ToJson(DiffResult diff) => JsonSerializer.Serialize(diff, JsonOpts);

    /// <summary>
    /// Tarjeta HTML del diff para inyectar antes del cierre del body del reporte.
    /// Todo el contenido dinámico va escapado; el marcado propio es ASCII.
    /// </summary>
    public static string ToHtmlCard(DiffResult diff)
    {
        ArgumentNullException.ThrowIfNull(diff);
        static string H(string? value) => WebUtility.HtmlEncode(value ?? "");
        var sb = new StringBuilder();
        sb.Append("<div class='card diff-card'><h2>Cambios desde el reporte anterior</h2>");
        sb.Append("<p class='muted'>Anterior: " + diff.PreviousTimestamp.ToLocalTime().ToString("dd/MM/yyyy HH:mm") +
            " | Actual: " + diff.CurrentTimestamp.ToLocalTime().ToString("dd/MM/yyyy HH:mm") +
            " | Hallazgos: " + diff.PreviousFindings + " -&gt; " + diff.CurrentFindings +
            " | Causas: " + diff.PreviousCauses + " -&gt; " + diff.CurrentCauses + "</p><ul>");
        foreach (var change in diff.Changes.Take(40))
        {
            sb.Append("<li><strong>" + H(change.Category) + ":</strong> " + H(change.Key) +
                " <span class='badge'>" + H(change.Kind.ToString()) + "</span>");
            if (!string.IsNullOrWhiteSpace(change.Summary))
                sb.Append("<br><span class='muted'>" + H(change.Summary) + "</span>");
            sb.Append("</li>");
        }
        if (diff.Changes.Count > 40)
            sb.Append("<li class='muted'>... y " + (diff.Changes.Count - 40) + " cambios mas (ver JSON).</li>");
        sb.Append("</ul></div>");
        return sb.ToString();
    }
}
