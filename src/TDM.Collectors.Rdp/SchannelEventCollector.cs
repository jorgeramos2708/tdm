using System.Diagnostics.Eventing.Reader;
using TDM.Core;
using TDM.Models;

namespace TDM.Collectors.Rdp;

public sealed class SchannelEventCollector : IReadOnlyCollector
{
    public string Nombre => "Schannel / TLS";

    public Task<CollectorResult> CollectAsync(DiagnosticContext context, CancellationToken cancellationToken)
    {
        var events = new List<DiagnosticEvent>();
        var findings = new List<DiagnosticFinding>();
        var window = DiagnosticWindow.Resolve(context);
        var start = window.Start;
        var end = window.End;

        try
        {
            var timeClause = DiagnosticWindow.EventLogTimeClause(context);
            var query = new EventLogQuery("System", PathType.LogName,
                $"*[System[Provider[@Name='Schannel'] and (Level=1 or Level=2 or Level=3) and {timeClause}]]")
            {
                ReverseDirection = true,
                TolerateQueryErrors = false
            };
            using var reader = new EventLogReader(query);
            var max = context.Lookback.TotalHours switch
            {
                <= 4 => 500,
                <= 12 => 1_000,
                <= 24 => 2_000,
                _ => 4_000
            };
            for (var i = 0; i < max; i++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                using var record = reader.ReadEvent();
                if (record is null) break;
                if (!record.TimeCreated.HasValue) continue;
                var ts = new DateTimeOffset(record.TimeCreated.Value);
                if (ts > end) continue;
                if (ts < start) break;

                string message;
                try { message = record.FormatDescription() ?? "Evento Schannel sin descripción disponible."; }
                catch { message = "No fue posible obtener la descripción del evento Schannel."; }

                // S3: tipo estable de catálogo (antes "Event ID {id}", invisible para el
                // catálogo de incidentes, precisión y ledger) + capa Seguridad coherente con
                // WindowsEventCollector. El Id numérico se conserva en Código y evidencia.
                // V2: Fuente "Schannel" + RecordId + Canal "System" para que el dedup del engine
                // (EVT|Canal|Fuente|Codigo|RecordId) colapse esta emisión con la del forense y la base.
                events.Add(new DiagnosticEvent(
                    ts,
                    "Schannel",
                    "TLS / Schannel",
                    DiagnosticLayer.Seguridad,
                    record.Level switch
                    {
                        1 => DiagnosticSeverity.Critico,
                        2 => DiagnosticSeverity.Error,
                        3 => DiagnosticSeverity.Advertencia,
                        _ => DiagnosticSeverity.Informativo
                    },
                    "TLS_SCHANNEL_EVENT",
                    message,
                    record.Id.ToString(),
                    Evidencia: SchannelEvidence(record)
                ));
            }
        }
        catch (EventLogNotFoundException ex)
        {
            findings.Add(new DiagnosticFinding(
                "TLS-SCHANNEL-COVERAGE", "TLS / Schannel", DiagnosticSeverity.Advertencia,
                "No fue posible evaluar el registro Schannel.",
                "La cobertura TLS queda parcial; la ausencia de eventos no se interpreta como ausencia confirmada de fallas TLS.",
                [new EvidenceItem("Detalle", ex.Message)], ConfidenceLevel.Confirmada, Capa: DiagnosticLayer.Seguridad));
        }
        catch (UnauthorizedAccessException ex)
        {
            findings.Add(new DiagnosticFinding(
                "TLS-SCHANNEL-COVERAGE", "TLS / Schannel", DiagnosticSeverity.Advertencia,
                "No fue posible evaluar el registro Schannel por permisos insuficientes.",
                "La cobertura TLS queda parcial; la ausencia de eventos no se interpreta como ausencia confirmada de fallas TLS.",
                [new EvidenceItem("Detalle", ex.Message)], ConfidenceLevel.Confirmada, Capa: DiagnosticLayer.Seguridad));
        }
        catch (EventLogException ex)
        {
            // V5: con TolerateQueryErrors=false una lectura corrupta a mitad de canal lanzaba y
            // el engine la volvía COLLECTOR-ERROR perdiendo eventos ya leídos y cobertura.
            findings.Add(new DiagnosticFinding(
                "TLS-SCHANNEL-COVERAGE", "TLS / Schannel", DiagnosticSeverity.Advertencia,
                "La lectura Schannel se interrumpió y quedó parcial.",
                "Los eventos ya leídos se conservan; la cobertura TLS queda parcial y no se interpreta como ausencia de fallas.",
                [new EvidenceItem("Detalle", ex.Message)], ConfidenceLevel.Confirmada, Capa: DiagnosticLayer.Seguridad));
        }

        if (context.Sistema.TsplusDetectado && events.Count > 0)
        {
            var findingSeverity = events.Any(e => e.Severidad == DiagnosticSeverity.Critico)
                ? DiagnosticSeverity.Critico
                : events.Any(e => e.Severidad == DiagnosticSeverity.Error)
                    ? DiagnosticSeverity.Error
                    : DiagnosticSeverity.Advertencia;
            findings.Add(new DiagnosticFinding(
                "TLS-SCHANNEL-EVENTS",
                "TLS / Schannel",
                findingSeverity,
                $"Se detectaron {events.Count} eventos Schannel relevantes en la ventana analizada.",
                "Los eventos TLS deben correlacionarse con fallas RDP o TSplus antes de considerarse causa raíz.",
                [new EvidenceItem("Eventos Schannel", events.Count.ToString())],
                ConfidenceLevel.Media,
                "Microsoft Learn",
                "https://learn.microsoft.com/windows-server/security/tls/tls-registry-settings",
                "Revisar los eventos Schannel y la configuración/certificado TLS aplicable. TDM no modifica TLS ni certificados.",
                DiagnosticLayer.Seguridad));
        }

        return Task.FromResult(new CollectorResult(findings, events));
    }

    /// <summary>
    /// Parseo profundo sistemático: además de los identificadores nativos incluye fecha,
    /// Task/Opcode numéricos y sus nombres visibles (best-effort: requieren el proveedor de
    /// mensajes y pueden fallar). Da identidad exacta para correlación TLS por endpoint.
    /// </summary>
    private static IReadOnlyList<EvidenceItem> SchannelEvidence(EventRecord record)
    {
        var evidence = new List<EvidenceItem>
        {
            new("Canal", "System"),
            new("Provider", "Schannel"),
            new("Event ID Schannel", record.Id.ToString()),
            new("RecordId", record.RecordId?.ToString() ?? "N/D"),
            new("Fecha", record.TimeCreated?.ToString("O") ?? "N/D"),
            new("Opcode", record.Opcode?.ToString() ?? "N/D"),
            new("Categoría de tarea", record.Task?.ToString() ?? "N/D")
        };
        try
        {
            var opcodeName = record.OpcodeDisplayName;
            if (!string.IsNullOrWhiteSpace(opcodeName)) evidence.Add(new EvidenceItem("Opcode visible", opcodeName));
        }
        catch { }
        try
        {
            var taskName = record.TaskDisplayName;
            if (!string.IsNullOrWhiteSpace(taskName)) evidence.Add(new EvidenceItem("Tarea visible", taskName));
        }
        catch { }
        return evidence;
    }
}
