using TDM.Models;

namespace TDM.Core;

public static class DiagnosticEventIdentity
{
    public static string? Resolve(DiagnosticEvent e)
    {
        // La deduplicación temporal exige EventTime real. Evidencia sin fecha no se
        // colapsa ni se vuelve causal mediante IngestedAt.
        var effective = e.Timestamp;
        if (!effective.HasValue || DiagnosticEventCatalog.IsSnapshot(e.Tipo)) return null;

        // Preferir identificadores nativos evita colapsar eventos legítimos que ocurren
        // en el mismo segundo con el mismo mensaje. La heurística temporal queda sólo
        // como fallback para fuentes que no exponen RecordId/ReportId.
        var reportId = EvidenceReader.Value(e, "Report ID", "ReportId");
        if (!string.IsNullOrWhiteSpace(reportId) && !reportId.Equals("N/D", StringComparison.OrdinalIgnoreCase))
            return $"WER|{reportId}";

        var recordId = EvidenceReader.Value(e, "RecordId", "Record ID", "EventRecordId");
        if (!string.IsNullOrWhiteSpace(recordId) && !recordId.Equals("N/D", StringComparison.OrdinalIgnoreCase))
        {
            var channel = EvidenceReader.Value(e, "Log", "Canal", "Channel") ?? string.Empty;
            return $"EVT|{channel}|{e.Fuente}|{e.Codigo}|{recordId}";
        }

        var ts = effective.Value.ToUniversalTime();
        var rounded = new DateTimeOffset(ts.Year, ts.Month, ts.Day, ts.Hour, ts.Minute, ts.Second, TimeSpan.Zero);
        return $"FALLBACK|{rounded:O}|{e.Fuente}|{e.Codigo}|{NormalizeMessage(e.Mensaje)}";
    }

    public static string NormalizeMessage(string value)
    {
        if (string.IsNullOrWhiteSpace(value)) return string.Empty;
        var sb = new System.Text.StringBuilder(value.Length);
        var previousWhitespace = false;
        foreach (var ch in value)
        {
            if (char.IsWhiteSpace(ch))
            {
                if (!previousWhitespace) sb.Append(' ');
                previousWhitespace = true;
            }
            else
            {
                sb.Append(char.ToUpperInvariant(ch));
                previousWhitespace = false;
            }
        }
        return sb.ToString().Trim();
    }
}
