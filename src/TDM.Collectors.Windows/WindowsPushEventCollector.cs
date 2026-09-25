using System.Diagnostics.Eventing.Reader;
using TDM.Core;
using TDM.Models;

namespace TDM.Collectors.Windows;

/// <summary>
/// Suscripci�n push a canales cr�ticos del Event Log (EvtSubscribe).
/// Elimina el gap de polling en r�fagas: los eventos se reciben en tiempo real.
/// Canales cubiertos: Security, System, TerminalServices-LocalSessionManager/Operational.
/// Se ejecuta como collector de larga duraci�n; emite eventos a un buffer compartido.
/// </summary>
public sealed class WindowsPushEventCollector : IReadOnlyCollector
{
    public string Nombre => "Eventos Windows push (EvtSubscribe)";

    private const int MaxBufferSize = 10000;
    private static readonly string[] PushChannels =
    [
        "Security",
        "System",
        "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
        "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
        "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational"
    ];

    private readonly object _bufferLock = new();
    private readonly Queue<DiagnosticEvent> _eventBuffer = new();
    private readonly CancellationTokenSource _cts = new();
    private readonly List<EventLogWatcher> _watchers = new();

    public Task<CollectorResult> CollectAsync(DiagnosticContext context, CancellationToken cancellationToken = default)
    {
        var findings = new List<DiagnosticFinding>();
        var events = new List<DiagnosticEvent>();
        var coverage = new List<EvidenceItem>();

        foreach (var channelName in PushChannels)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                var query = new EventLogQuery(channelName, PathType.LogName, "*") { ReverseDirection = false };
                var watcher = new EventLogWatcher(query);
                watcher.EventRecordWritten += (s, e) => OnEventRecordWritten(e, channelName);
                watcher.Enabled = true;
                _watchers.Add(watcher);
                coverage.Add(new EvidenceItem(channelName, "Suscripci�n activa"));
            }
            catch (EventLogNotFoundException)
            {
                coverage.Add(new EvidenceItem(channelName, "Canal no disponible en este SO"));
            }
            catch (UnauthorizedAccessException ex)
            {
                coverage.Add(new EvidenceItem(channelName, $"Sin permisos: {ex.Message}"));
            }
            catch (EventLogException ex)
            {
                coverage.Add(new EvidenceItem(channelName, $"Error suscripci�n: {ex.Message}"));
            }
        }

        // Devolver eventos bufferizados al finalizar el contexto
        // Nota: este collector se dise�a para vida larga; aqu� se devuelve lo acumulado hasta ahora
        lock (_bufferLock)
        {
            events.AddRange(_eventBuffer.Take(MaxBufferSize));
            _eventBuffer.Clear();
        }

        events.Add(new DiagnosticEvent(
            DateTimeOffset.Now, "TDM", "Push Event Subscription", DiagnosticLayer.Windows,
            DiagnosticSeverity.Informativo, "WINDOWS_PUSH_EVENT_COVERAGE",
            $"Canales suscritos: {_watchers.Count}/{PushChannels.Length}. Eventos en buffer: {_eventBuffer.Count}.",
            Evidencia: coverage));

        // Registrar cancelaci�n para limpiar watchers
        cancellationToken.Register(() => StopWatchers());

        return Task.FromResult(new CollectorResult(findings, events));
    }

    private void OnEventRecordWritten(EventRecordWrittenEventArgs e, string channelName)
    {
        try
        {
            if (e.EventRecord is null || e.EventException is not null) return;

            var record = e.EventRecord;
            DiagnosticLayer layer = GetLayer(channelName);

            var severity = record.Level switch
            {
                1 => DiagnosticSeverity.Critico,
                2 => DiagnosticSeverity.Error,
                3 => DiagnosticSeverity.Advertencia,
                4 => DiagnosticSeverity.Informativo,
                _ => DiagnosticSeverity.Informativo
            };

            // P0-fix: Safe enum conversion to avoid runtime crash on some .NET 8 environments
            // where typeof(EventTask)/EventOpcode may not be recognized as enum at runtime.
            string taskStr = SafeEnumToString(typeof(System.Diagnostics.Eventing.Reader.EventTask), record.Task, "Task");
            string opcodeStr = SafeEnumToString(typeof(System.Diagnostics.Eventing.Reader.EventOpcode), record.Opcode, "Opcode");
            var providerName = record.ProviderName ?? "Unknown";

            var evt = new DiagnosticEvent(
                record.TimeCreated ?? DateTimeOffset.Now,
                "EventLog Push",
                providerName,
                layer,
                severity,
                $"PUSH_{record.Id}",
                record.FormatDescription() ?? $"Evento {record.Id} de {providerName}",
                Codigo: record.Id.ToString(),
                Archivo: channelName,
                Evidencia: [new EvidenceItem("Canal", channelName), new EvidenceItem("Task", taskStr), new EvidenceItem("Opcode", opcodeStr)],
                Producto: TsplusProduct.Ninguno,
                IngestedAt: DateTimeOffset.Now);

            lock (_bufferLock)
            {
                _eventBuffer.Enqueue(evt);
                if (_eventBuffer.Count > MaxBufferSize)
                    _eventBuffer.Dequeue(); // Ring buffer
            }
        }
        catch (Exception ex)
        {
            // P0-fix: Defensive catch to prevent watcher crash on malformed events
            // Log internally (could be extended to emit a DiagnosticEvent for visibility)
            System.Diagnostics.Debug.WriteLine($"[WindowsPushEventCollector] Error processing event in {channelName}: {ex.Message}");
        }
    }

    private static DiagnosticLayer GetLayer(string channelName)
        => channelName.Equals("Security", StringComparison.OrdinalIgnoreCase)
            ? DiagnosticLayer.Seguridad
            : channelName.Contains("TerminalServices", StringComparison.OrdinalIgnoreCase) ? DiagnosticLayer.Rdp
            : DiagnosticLayer.Windows;

    /// <summary>
    /// P0-fix: Safe enum conversion for EventTask/EventOpcode.
    /// Some .NET 8 environments fail Enum.ToObject at runtime; this provides fallback.
    /// </summary>
    private static string SafeEnumToString(Type enumType, int? value, string fallbackPrefix)
    {
        if (!value.HasValue) return "N/D";
        try
        {
            if (!enumType.IsEnum) return $"{fallbackPrefix}0x{value.Value:X}";
            if (Enum.IsDefined(enumType, value.Value))
                return Enum.ToObject(enumType, value.Value)?.ToString() ?? $"0x{value.Value:X}";
            return $"0x{value.Value:X}";
        }
        catch
        {
            return $"0x{value.Value:X}";
        }
    }

    private void StopWatchers()
    {
        foreach (var watcher in _watchers)
        {
            try { watcher.Enabled = false; watcher.Dispose(); } catch { }
        }
        _watchers.Clear();
    }
}