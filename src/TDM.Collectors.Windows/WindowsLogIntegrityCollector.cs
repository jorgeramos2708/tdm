using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using TDM.Core;
using TDM.Models;

namespace TDM.Collectors.Windows;

/// <summary>
/// Integridad del propio pipeline de evidencia: detecta vaciado/apagado de logs
/// (104/1100/1102), apagados sucios (6008) y auto-verifica el canal Application
/// extremo a extremo con un evento canario propio (lectura = pipeline vivo).
/// Solo lectura salvo el canario (un evento Information cada 10 min como máximo,
/// claramente marcado como diagnóstico). Cada query cumple el gate anti-Y1.
/// </summary>
public sealed class WindowsLogIntegrityCollector : IReadOnlyCollector
{
    public string Nombre => "Integridad de logs Windows";

    private const int MaxRecordsPerChannel = 200;
    private const int MaxFindings = 8;
    private const string CanarySource = "TDM Canary";
    private const string CanaryMarker = "TDM-SELFTEST-CANARY";
    private const string CursorKey = "tdm-canary-state";
    private static readonly TimeSpan WriteInterval = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan VerifyWindow = TimeSpan.FromMinutes(20);

    private sealed record CanaryState(DateTimeOffset LastWriteUtc, DateTimeOffset LastVerifiedUtc);
    private sealed record ChannelSpec(string Name, string Filter, DiagnosticLayer Layer);

    private static readonly ChannelSpec[] Channels =
    [
        new("System", "*[System[(EventID=104 or EventID=6008)]]", DiagnosticLayer.Windows),
        new("Security", "*[System[(EventID=1100 or EventID=1102)]]", DiagnosticLayer.Seguridad)
    ];

    public Task<CollectorResult> CollectAsync(DiagnosticContext context, CancellationToken cancellationToken = default)
    {
        var findings = new List<DiagnosticFinding>();
        var events = new List<DiagnosticEvent>();
        var coverage = new List<EvidenceItem>();
        var windowEnd = context.HoraIncidente ?? DateTimeOffset.Now;
        var windowStart = windowEnd - context.Lookback;
        var tamper = 0;

        foreach (var channel in Channels)
        {
            cancellationToken.ThrowIfCancellationRequested();
            // Sin filtro temporal en XPath: se lee de lo más reciente hacia atrás y se
            // corta al salir de la ventana (rompe barato cuando el canal está en calma).
            var xpath = channel.Filter;
            try
            {
                var query = new EventLogQuery(channel.Name, PathType.LogName, xpath) { ReverseDirection = true };
                using var reader = new EventLogReader(query);
                var read = 0;
                while (reader.ReadEvent() is { } record && findings.Count < MaxFindings)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    using (record)
                    {
                        if (read++ >= MaxRecordsPerChannel) break;
                        var time = record.TimeCreated?.ToUniversalTime();
                        if (time.HasValue && time.Value < windowStart.UtcDateTime) break;
                        var finding = ToTamperFinding(channel, record);
                        if (finding is not null) { findings.Add(finding); tamper++; }
                    }
                }
                coverage.Add(new EvidenceItem(channel.Name, "Disponible"));
            }
            catch (EventLogNotFoundException ex)
            {
                coverage.Add(new EvidenceItem(channel.Name, "Canal no disponible: " + ex.Message));
            }
            catch (UnauthorizedAccessException ex)
            {
                coverage.Add(new EvidenceItem(channel.Name, "Sin permisos de lectura: " + ex.Message));
            }
            catch (EventLogException ex)
            {
                coverage.Add(new EvidenceItem(channel.Name, "No legible: " + ex.Message));
            }
        }

        coverage.Add(CheckCanary(events, findings, cancellationToken));

        events.Add(new DiagnosticEvent(
            DateTimeOffset.Now, "TDM", "Integridad de logs Windows", DiagnosticLayer.Desconocida,
            DiagnosticSeverity.Informativo, "WINDOWS_LOG_INTEGRITY_COVERAGE",
            $"Integridad del pipeline de evidencia: {tamper} marcas de manipulación en ventana.",
            Evidencia: [.. coverage,
                new EvidenceItem("Marcas de manipulación", tamper.ToString()),
                new EvidenceItem("Hallazgos emitidos", findings.Count.ToString())]));
        return Task.FromResult(new CollectorResult(findings, events));
    }

    private static DiagnosticFinding? ToTamperFinding(ChannelSpec channel, EventRecord record)
    {
        var stamp = record.TimeCreated?.ToString("O") ?? "N/D";
        string? description = null;
        try { description = record.FormatDescription(); } catch (EventLogException) { }
        var evidence = new List<EvidenceItem>
        {
            new("Canal", channel.Name),
            new("EventID", record.Id.ToString()),
            new("Hora", stamp),
            new("Descripción", string.IsNullOrWhiteSpace(description) ? "N/D" : description.Trim())
        };
        return record.Id switch
        {
            104 or 1102 => new DiagnosticFinding(
                $"WINDOWS-LOG-CLEARED-{channel.Name}-{record.RecordId ?? record.Id}",
                $"Event Viewer / {channel.Name}",
                DiagnosticSeverity.Error,
                $"Se vació el log '{channel.Name}' dentro de la ventana analizada.",
                "Un vaciado de log borra evidencia y puede ser limpieza legítima (rotación manual) o manipulación. Todo lo anterior a esa hora en ese canal debe tratarse como perdido, no como sano.",
                evidence, ConfidenceLevel.Alta, Capa: channel.Layer),
            1100 => new DiagnosticFinding(
                $"WINDOWS-EVENTSERVICE-STOP-{record.RecordId ?? record.Id}",
                $"Event Viewer / {channel.Name}",
                DiagnosticSeverity.Advertencia,
                "El servicio de registro de eventos se detuvo dentro de la ventana.",
                "Mientras estuvo detenido, nada quedó registrado: la ausencia de eventos en ese intervalo no es evidencia de salud.",
                evidence, ConfidenceLevel.Alta, Capa: channel.Layer),
            6008 => new DiagnosticFinding(
                $"WINDOWS-UNEXPECTED-SHUTDOWN-{record.RecordId ?? record.Id}",
                "Sistema / apagado",
                DiagnosticSeverity.Advertencia,
                "El equipo se apagó de forma sucia dentro de la ventana analizada.",
                "Un apagado inesperado es el ancla temporal que explica paros de servicio y sesiones cortadas posteriores sin causa lógica propia.",
                evidence, ConfidenceLevel.Alta, Capa: channel.Layer),
            _ => null
        };
    }

    private EvidenceItem CheckCanary(List<DiagnosticEvent> events, List<DiagnosticFinding> findings, CancellationToken ct)
    {
        var now = DateTimeOffset.UtcNow;
        CollectorCursorStore.TryLoad<CanaryState>(CursorKey, out var state, out _);
        // Escritura acotada: como máximo una cada 10 min y solo con privilegio.
        if (state is null || now - state.LastWriteUtc > WriteInterval)
        {
            try
            {
                ct.ThrowIfCancellationRequested();
                EventLog.WriteEntry(CanarySource, $"{CanaryMarker} {now:O} (autoprueba TDM; ignorar)",
                    EventLogEntryType.Information);
                state = new CanaryState(now, state?.LastVerifiedUtc ?? DateTimeOffset.MinValue);
                CollectorCursorStore.TrySave(CursorKey, state, out _);
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException or Win32Exception or ArgumentException or InvalidOperationException or IOException)
            {
                return new EvidenceItem("Canario", "Sin privilegio de escritura; solo verificación de lectura.");
            }
        }
        // Verificación: el último canario debe ser legible en los últimos 20 min.
        var cutoff = now - VerifyWindow;
        try
        {
            var query = new EventLogQuery("Application", PathType.LogName,
                $"*[System[Provider[@Name='{CanarySource}'] and TimeCreated[@SystemTime>='{cutoff:O}']]]")
            { ReverseDirection = true };
            using var reader = new EventLogReader(query);
            using var record = reader.ReadEvent();
            if (record is not null)
            {
                var verified = new CanaryState(state?.LastWriteUtc ?? DateTimeOffset.MinValue, now);
                CollectorCursorStore.TrySave(CursorKey, verified, out _);
                events.Add(new DiagnosticEvent(DateTimeOffset.Now, "TDM", "Autoprueba de eventos",
                    DiagnosticLayer.Desconocida, DiagnosticSeverity.Informativo, "TDM_CANARY_OK",
                    "El canal Application se auto-verificó extremo a extremo (escritura y lectura del canario)."));
                return new EvidenceItem("Canario", "Verificado; pipeline de eventos vivo.");
            }
        }
        catch (EventLogNotFoundException) { return new EvidenceItem("Canario", "Canal Application no disponible."); }
        catch (UnauthorizedAccessException) { return new EvidenceItem("Canario", "Sin permisos de lectura."); }
        catch (EventLogException ex) { return new EvidenceItem("Canario", "No legible: " + ex.Message); }

        // Sin canario legible: solo es falla si se escribió uno recientemente.
        if (state is not null && state.LastWriteUtc >= cutoff)
        {
            findings.Add(new DiagnosticFinding(
                "TDM-CANARY-FAILURE",
                "Autoprueba de eventos",
                DiagnosticSeverity.Advertencia,
                "TDM escribió su evento canario pero no pudo leerlo de vuelta.",
                "El pipeline de Event Viewer no se auto-verifica: las lecturas de este ciclo podrían estar incompletas aunque no haya error explícito.",
                [new EvidenceItem("Escritura", state.LastWriteUtc.ToString("O")),
                 new EvidenceItem("Ventana de verificación", "20 min")],
                ConfidenceLevel.Alta,
                Capa: DiagnosticLayer.Desconocida));
            return new EvidenceItem("Canario", "Falla: escrito pero no legible.");
        }
        return new EvidenceItem("Canario", "Sin escritura reciente en ventana; no evaluado.");
    }
}
