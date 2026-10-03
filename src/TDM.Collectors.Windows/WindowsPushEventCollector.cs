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

    private static readonly object SharedLock = new();
    private static readonly Queue<DiagnosticEvent> SharedBuffer = new();
    private static readonly List<EventLogWatcher> SharedWatchers = new();
    private static readonly List<EvidenceItem> SharedCoverage = new();
    private static bool _subscribed;
    // MEDIUM F25: canales con resultado definitivo de suscripción (activa o fallo conocido);
    // sólo los fallos inesperados se reintentan en la próxima recolección.
    private static readonly HashSet<string> ResolvedChannels = new();

    public Task<CollectorResult> CollectAsync(DiagnosticContext context, CancellationToken cancellationToken = default)
    {
        var findings = new List<DiagnosticFinding>();
        var events = new List<DiagnosticEvent>();
        List<EvidenceItem> coverage;
        int subscribed;
        int drained;

        lock (SharedLock)
        {
            EnsureSubscribed();
            coverage = [.. SharedCoverage];
            subscribed = SharedWatchers.Count;
            drained = 0;
            while (SharedBuffer.Count > 0)
            {
                events.Add(SharedBuffer.Dequeue());
                drained++;
            }
        }

        events.Add(new DiagnosticEvent(
            DateTimeOffset.Now, "TDM", "Push Event Subscription", DiagnosticLayer.Windows,
            DiagnosticSeverity.Informativo, "WINDOWS_PUSH_EVENT_COVERAGE",
            $"Canales suscritos: {subscribed}/{PushChannels.Length}. Eventos en buffer: {drained}.",
            Evidencia: coverage));

        return Task.FromResult(new CollectorResult(findings, events));
    }

    private static void EnsureSubscribed()
    {
        if (_subscribed) return;

        var unexpected = false;

        foreach (var channelName in PushChannels)
        {
            // MEDIUM F25: los canales con resultado definitivo se saltan; se reintenta
            // sólo el canal cuyo último intento falló de forma inesperada.
            if (ResolvedChannels.Contains(channelName)) continue;

            EventLogWatcher? watcher = null;
            try
            {
                var query = new EventLogQuery(channelName, PathType.LogName, "*") { ReverseDirection = false };
                watcher = new EventLogWatcher(query);
                var channel = channelName;
                watcher.EventRecordWritten += (s, e) => OnEventRecordWritten(e, channel);
                watcher.Enabled = true;
                SharedWatchers.Add(watcher);
                watcher = null;
                SetCoverage(channelName, "Suscripción activa");
                ResolvedChannels.Add(channelName);
            }
            catch (EventLogNotFoundException)
            {
                DisposeWatcher(ref watcher);
                SetCoverage(channelName, "Canal no disponible en este SO");
                ResolvedChannels.Add(channelName);
            }
            catch (UnauthorizedAccessException ex)
            {
                DisposeWatcher(ref watcher);
                SetCoverage(channelName, $"Sin permisos: {ex.Message}");
                ResolvedChannels.Add(channelName);
            }
            catch (EventLogException ex)
            {
                DisposeWatcher(ref watcher);
                SetCoverage(channelName, $"Error suscripción: {ex.Message}");
                ResolvedChannels.Add(channelName);
            }
            catch (Exception ex)
            {
                // MEDIUM F25: fallo inesperado del ciclo de vida del watcher
                // (msdn microsoft.com/en-us/dotnet/api/system.diagnostics.eventing.reader.eventlogwatcher):
                // se marca el canal para reintento en la próxima recolección en lugar de
                // dejarlo pendiente de una suscripción que nunca se hará.
                DisposeWatcher(ref watcher);
                SetCoverage(channelName, $"Error suscripción: {ex.GetType().Name}: {ex.Message}");
                unexpected = true;
            }
        }

        // MEDIUM F25: el flag sólo se fija DESPUÉS de intentar todos los canales. Antes
        // estaba delante del foreach: una excepción inesperada abortaba el método con
        // _subscribed=true y push desactivado para siempre.
        _subscribed = !unexpected;
    }

    private static void DisposeWatcher(ref EventLogWatcher? watcher)
    {
        if (watcher is null) return;
        try { watcher.Enabled = false; watcher.Dispose(); } catch { }
        watcher = null;
    }

    private static void SetCoverage(string channelName, string value)
    {
        // SetCoverage idempotente: reemplaza la evidencia del canal en lugar de duplicarla.
        SharedCoverage.RemoveAll(c => c.Clave == channelName);
        SharedCoverage.Add(new EvidenceItem(channelName, value));
    }

    private static void OnEventRecordWritten(EventRecordWrittenEventArgs e, string channelName)
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

            lock (SharedLock)
            {
                SharedBuffer.Enqueue(evt);
                if (SharedBuffer.Count > MaxBufferSize)
                    SharedBuffer.Dequeue(); // Ring buffer
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

    public static void StopWatchers()
    {
        List<EventLogWatcher> watchers;
        lock (SharedLock)
        {
            watchers = [.. SharedWatchers];
            SharedWatchers.Clear();
            SharedBuffer.Clear();
            SharedCoverage.Clear();
            ResolvedChannels.Clear();
            _subscribed = false;
        }
        foreach (var watcher in watchers)
        {
            try { watcher.Enabled = false; watcher.Dispose(); } catch { }
        }
    }
}