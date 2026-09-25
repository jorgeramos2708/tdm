using System.Diagnostics.Eventing.Reader;
using TDM.Core;
using TDM.Models;

namespace TDM.Collectors.Windows;

public sealed class WindowsEventCollector : IReadOnlyCollector
{
    public string Nombre => "Eventos de Windows";

    public Task<CollectorResult> CollectAsync(DiagnosticContext context, CancellationToken cancellationToken = default)
    {
        var findings = new List<DiagnosticFinding>();
        var events = new List<DiagnosticEvent>();
        var coverage = new List<EvidenceItem>();
        var window = DiagnosticWindow.Resolve(context);
        var timeClause = DiagnosticWindow.EventLogTimeClause(context);
        var relevantLimit = ResolveLimit(context.Lookback);
        var scanLimit = Math.Max(relevantLimit * 8, 2_000);
        var xpath = $"*[System[(Level=1 or Level=2) and {timeClause}]]";

        coverage.Add(new EvidenceItem("Ventana solicitada", $"{window.Start:O} → {window.End:O}"));

        foreach (var log in new[] { "System", "Application", "Security" })
        {
            try
            {
                var q = new EventLogQuery(log, PathType.LogName, xpath)
                {
                    ReverseDirection = true,
                    TolerateQueryErrors = false
                };
                using var reader = new EventLogReader(q);
                var relevant = 0;
                var scanned = 0;
                var limited = false;

                for (EventRecord? ev = reader.ReadEvent(); ev is not null; ev = reader.ReadEvent())
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    using (ev)
                    {
                        scanned++;
                        var provider = ev.ProviderName ?? "Desconocido";
                        if (!IsRelevant(provider, ev.Id))
                        {
                            if (scanned >= scanLimit) { limited = true; break; }
                            continue;
                        }

                        string message;
                        try { message = ev.FormatDescription() ?? "Sin descripción."; }
                        catch { message = "Descripción no disponible."; }

                        var layer = ClassifyLayer(provider);
                        var severity = ev.Level switch
                        {
                            1 => DiagnosticSeverity.Critico,
                            2 => DiagnosticSeverity.Error,
                            3 => DiagnosticSeverity.Advertencia,
                            _ => DiagnosticSeverity.Informativo
                        };
                        var timestamp = ev.TimeCreated is null
                            ? (DateTimeOffset?)null
                            : new DateTimeOffset(ev.TimeCreated.Value);

                        var evidence = new[]
                        {
                            new EvidenceItem("Log", log),
                            new EvidenceItem("EventId", ev.Id.ToString()),
                            new EvidenceItem("Provider", provider),
                            new EvidenceItem("RecordId", ev.RecordId?.ToString() ?? "N/D"),
                            new EvidenceItem("Fecha", ev.TimeCreated?.ToString("O") ?? "N/D"),
                            // Parseo profundo: Task/Opcode numéricos siempre disponibles; nombres
                            // visibles best-effort (requieren proveedor de mensajes).
                            new EvidenceItem("Opcode", ev.Opcode?.ToString() ?? "N/D"),
                            new EvidenceItem("Categoría de tarea", ev.Task?.ToString() ?? "N/D"),
                            new EvidenceItem("Opcode visible", SafeDisplay(() => ev.OpcodeDisplayName)),
                            new EvidenceItem("Tarea visible", SafeDisplay(() => ev.TaskDisplayName))
                        };

                        // V1+V2: mismo mapeo que el forense/incremental. Un 7009/7000 en la base ya no
                        // es WINDOWS_EVENT genérico (invisible a ledger/SCM), y Schannel usa el tipo
                        // de catálogo para que el dedup del engine colapse las tres emisiones.
                        var eventType = provider.Contains("Schannel", StringComparison.OrdinalIgnoreCase)
                            ? "TLS_SCHANNEL_EVENT"
                            : provider.Contains("Service Control Manager", StringComparison.OrdinalIgnoreCase) && ev.Id is 7031 or 7034
                                ? "SERVICE_TERMINATION"
                                : provider.Contains("Service Control Manager", StringComparison.OrdinalIgnoreCase) && ev.Id is 7000 or 7001 or 7009 or 7011 or 7023 or 7024
                                    ? "SERVICE_START_FAILURE"
                                    : "WINDOWS_EVENT";

                        // V2: para Schannel, usar Fuente="Schannel" + Canal="System" + RecordId
                        // para que el dedup del engine (EVT|Canal|Fuente|Codigo|RecordId) colapse
                        // con el forense y el Rdp.
                        var fuente = provider.Contains("Schannel", StringComparison.OrdinalIgnoreCase) ? "Schannel" : provider;
                        var canal = provider.Contains("Schannel", StringComparison.OrdinalIgnoreCase) ? "System" : log;
                        var eventTypeFinal = eventType;

                        events.Add(new DiagnosticEvent(
                            timestamp, fuente, provider, layer, severity,
                            eventTypeFinal, message, ev.Id.ToString(), Evidencia: evidence));

                        findings.Add(new DiagnosticFinding(
                            $"EVT-{log}-{ev.RecordId}", provider, severity,
                            $"Evento relevante detectado: ID {ev.Id}", message,
                            evidence, ConfidenceLevel.Media, Capa: layer));
                        relevant++;

                        if (relevant >= relevantLimit || scanned >= scanLimit)
                        {
                            limited = true;
                            break;
                        }
                    }
                }

                coverage.Add(new EvidenceItem(log,
                    limited
                        ? $"Parcial; relevantes={relevant}; examinados={scanned}; límites relevantes={relevantLimit}/examinados={scanLimit}"
                        : $"Disponible; relevantes={relevant}; examinados={scanned}"));
            }
            catch (EventLogNotFoundException)
            {
                coverage.Add(new EvidenceItem(log, "Canal no disponible"));
            }
            catch (UnauthorizedAccessException ex)
            {
                coverage.Add(new EvidenceItem(log, "Sin permisos de lectura"));
                findings.Add(new DiagnosticFinding(
                    $"EVT-{log}-ACCESS", "Event Log", DiagnosticSeverity.Advertencia,
                    $"No fue posible leer el registro {log}.", ex.Message,
                    [new EvidenceItem("Log", log)], ConfidenceLevel.Alta,
                    Capa: DiagnosticLayer.Windows));
            }
            catch (EventLogException ex)
            {
                coverage.Add(new EvidenceItem(log, $"No legible: {ex.Message}"));
                findings.Add(new DiagnosticFinding(
                    $"EVT-{log}-READ", "Event Log", DiagnosticSeverity.Advertencia,
                    $"No fue posible completar la lectura del registro {log}.",
                    "La fuente queda NO EVALUADA/parcial; la ausencia de eventos no se considera evidencia de salud.",
                    [new EvidenceItem("Log", log), new EvidenceItem("Detalle", ex.Message)],
                    ConfidenceLevel.Confirmada, Capa: DiagnosticLayer.Windows));
            }
        }

        var partial = coverage.Skip(1).Any(x =>
            x.Valor.StartsWith("Parcial", StringComparison.OrdinalIgnoreCase) ||
            x.Valor.StartsWith("Sin permisos", StringComparison.OrdinalIgnoreCase) ||
            x.Valor.StartsWith("No legible", StringComparison.OrdinalIgnoreCase));
        events.Add(new DiagnosticEvent(
            DateTimeOffset.Now,
            "TDM",
            "Cobertura de eventos Windows",
            DiagnosticLayer.Windows,
            partial ? DiagnosticSeverity.Advertencia : DiagnosticSeverity.Informativo,
            "WINDOWS_EVENT_COVERAGE",
            partial
                ? "La lectura base de eventos Windows quedó parcial; las ausencias no se interpretan como estado sano."
                : "La lectura base de eventos Windows se completó dentro de los límites configurados.",
            Evidencia: coverage));

        return Task.FromResult(new CollectorResult(findings, events));
    }

    private static int ResolveLimit(TimeSpan lookback)
        => lookback.TotalHours switch
        {
            <= 4 => 250,
            <= 12 => 500,
            <= 24 => 1_000,
            _ => 2_500
        };

    private static bool IsRelevant(string provider, int id)
    {
        string[] tokens =
        [
            "TerminalServices", "Service Control Manager", "Schannel", "Disk", "Ntfs",
            "RemoteDesktopServices", "Application Error", ".NET Runtime", "Windows Error Reporting"
        ];
        return tokens.Any(t => provider.Contains(t, StringComparison.OrdinalIgnoreCase))
            // P17: fallos de arranque SCM coherentes con IsCausalSignal y el canal incremental.
            || id is 41 or 51 or 55 or 1000 or 1001 or 1026 or 7000 or 7001 or 7009 or 7011 or 7023 or 7024 or 7031 or 7034;
    }

    private static DiagnosticLayer ClassifyLayer(string provider)
    {
        if (provider.Contains("TerminalServices", StringComparison.OrdinalIgnoreCase)
            || provider.Contains("RemoteDesktop", StringComparison.OrdinalIgnoreCase))
            return DiagnosticLayer.Rdp;

        if (provider.Contains("Schannel", StringComparison.OrdinalIgnoreCase))
            return DiagnosticLayer.Seguridad;

        return DiagnosticLayer.Windows;
    }

    private static string SafeDisplay(Func<string?> value)
    {
        try { return string.IsNullOrWhiteSpace(value()) ? "N/D" : value()!; }
        catch { return "N/D"; }
    }
}
