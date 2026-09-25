using System.Diagnostics.Eventing.Reader;
using System.Text.RegularExpressions;
using TDM.Core;
using TDM.Models;

namespace TDM.Collectors.Security;

public sealed class DefenderEventCollector : IReadOnlyCollector
{
    public string Nombre => "Microsoft Defender";
    private const string Channel = "Microsoft-Windows-Windows Defender/Operational";

    public Task<CollectorResult> CollectAsync(DiagnosticContext context, CancellationToken cancellationToken)
    {
        var findings = new List<DiagnosticFinding>();
        var events = new List<DiagnosticEvent>();
        var window = DiagnosticWindow.Resolve(context);
        var start = window.Start;
        var end = window.End;

        try
        {
            var timeClause = DiagnosticWindow.EventLogTimeClause(context);
            // S8: se agrega 1118 (remediación) como visibilidad informativa genérica, sin
            // atribuirle semántica de amenaza/acción: solo 1116/1117 elevan severidad.
            var query = new EventLogQuery(Channel, PathType.LogName, $"*[System[(EventID=1116 or EventID=1117 or EventID=1118 or EventID=5007) and {timeClause}]]")
            {
                ReverseDirection = true,
                TolerateQueryErrors = false
            };

            using var reader = new EventLogReader(query);
            for (EventRecord? record = reader.ReadEvent(); record is not null; record = reader.ReadEvent())
            {
                using (record)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if (!record.TimeCreated.HasValue) continue;
                    var ts = new DateTimeOffset(record.TimeCreated.Value);
                    if (ts < start || ts > end) continue;

                    var message = SafeFormat(record);
                    var severity = record.Id switch
                    {
                        1116 => DiagnosticSeverity.Advertencia,
                        1117 => DiagnosticSeverity.Advertencia,
                        5007 => DiagnosticSeverity.Informativo,
                        _ => DiagnosticSeverity.Informativo
                    };

                    var type = record.Id switch
                    {
                        1116 => "DEFENDER_THREAT_DETECTED",
                        1117 => "DEFENDER_ACTION_TAKEN",
                        5007 => "DEFENDER_CONFIGURATION_CHANGED",
                        _ => "DEFENDER_EVENT"
                    };

                    var path = ExtractLikelyPath(message);
                    events.Add(new DiagnosticEvent(
                        ts,
                        "Microsoft Defender Antivirus",
                        "Microsoft Defender",
                        DiagnosticLayer.Seguridad,
                        severity,
                        type,
                        message,
                        record.Id.ToString(),
                        path,
                        Evidencia:
                        [
                            new EvidenceItem("Event ID", record.Id.ToString()),
                            new EvidenceItem("Canal", Channel),
                            new EvidenceItem("Ruta detectada", path ?? "N/D")
                        ]));
                }
            }
        }
        catch (EventLogNotFoundException)
        {
            events.Add(new DiagnosticEvent(DateTimeOffset.Now, "TDM", "Microsoft Defender", DiagnosticLayer.Seguridad,
                DiagnosticSeverity.Informativo, "DEFENDER_LOG_NOT_AVAILABLE",
                "El canal operacional de Microsoft Defender no está disponible en este equipo."));
        }
        catch (UnauthorizedAccessException ex)
        {
            findings.Add(new DiagnosticFinding(
                "DEFENDER-ACCESS-DENIED",
                "Microsoft Defender",
                DiagnosticSeverity.Advertencia,
                "No fue posible leer el historial operacional de Microsoft Defender.",
                ex.Message,
                [new EvidenceItem("Canal", Channel)],
                ConfidenceLevel.Media,
                Capa: DiagnosticLayer.Seguridad));
        }
        catch (EventLogException ex)
        {
            // V5: lectura interrumpida a mitad de canal; lo ya leído se conserva y la
            // cobertura queda parcial en vez de perderse como COLLECTOR-ERROR.
            findings.Add(new DiagnosticFinding(
                "DEFENDER-COVERAGE-PARTIAL",
                "Microsoft Defender",
                DiagnosticSeverity.Advertencia,
                "La lectura del historial operacional de Microsoft Defender quedó parcial.",
                ex.Message,
                [new EvidenceItem("Canal", Channel), new EvidenceItem("Cobertura", "Parcial")],
                ConfidenceLevel.Media,
                Capa: DiagnosticLayer.Seguridad));
        }

        return Task.FromResult(new CollectorResult(findings, events));
    }

    private static string SafeFormat(EventRecord record)
    {
        try { return record.FormatDescription() ?? $"Evento Defender {record.Id}"; }
        catch { return $"Evento Defender {record.Id}"; }
    }

    private static string? ExtractLikelyPath(string message)
    {
        if (string.IsNullOrWhiteSpace(message)) return null;
        var matches = Regex.Matches(message, @"(?im)(?:Path|Ruta|Resources?|Recursos?)\s*:\s*(.+)$");
        foreach (Match match in matches)
        {
            var value = match.Groups[1].Value.Trim();
            if (!string.IsNullOrWhiteSpace(value)) return value;
        }
        return null;
    }
}
