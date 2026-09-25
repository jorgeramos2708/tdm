using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using TDM.Models;
using TDM.Persistence;

namespace TDM.Notifications;

/// <summary>
/// Autoridad anti-ruido. Emite apertura o escalamiento. Las recuperaciones se registran
/// en el estado interno, pero no generan alertas visibles.
/// El estado vive en ProgramData y sólo el servicio debe modificarlo.
/// </summary>
public sealed class NotificationDispatcher
{
    private readonly IReadOnlyList<INotificationSink> _sinks;
    private readonly JsonSerializerOptions _json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase, WriteIndented = true };
    private readonly SemaphoreSlim _gate = new(1, 1);
    public string StatePath { get; }

    public NotificationDispatcher(IEnumerable<INotificationSink> sinks, string? rootPath = null)
    {
        _sinks = sinks?.ToList() ?? throw new ArgumentNullException(nameof(sinks));
        var root = string.IsNullOrWhiteSpace(rootPath) ? TdmDataPaths.MachineRootPath : System.IO.Path.GetFullPath(rootPath);
        StatePath = System.IO.Path.Combine(root, "notifications", "dispatcher-state.json");
    }

    public async Task<IncidentNotification> SendOneShotAsync(AlertSignal signal, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(signal);
        var notification = ToNotification(signal, NotificationTransition.Opened, DateTimeOffset.Now);
        foreach (var sink in _sinks)
            await sink.SendAsync(notification, ct).ConfigureAwait(false);
        return notification;
    }

    public async Task<IReadOnlyList<IncidentNotification>> DispatchAsync(
        IEnumerable<AlertSignal> currentSignals,
        DateTimeOffset sampleTime,
        CancellationToken ct = default)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var prior = await LoadStateAsync(ct).ConfigureAwait(false);
            var priorActive = prior.Active.Values
                .Where(x => !string.IsNullOrWhiteSpace(x.Key))
                .GroupBy(x => NotificationSignalPolicy.CanonicalKey(x.Key), StringComparer.OrdinalIgnoreCase)
                .Select(g =>
                {
                    var selected = g
                        .OrderByDescending(x => SeverityRank(x.Severity))
                        .ThenByDescending(x => NotificationSignalPolicy.EvidencePreference(x.Key))
                        .First();
                    return selected with { Key = g.Key };
                })
                .ToDictionary(x => x.Key, StringComparer.OrdinalIgnoreCase);
            var current = currentSignals
                .Where(x => !string.IsNullOrWhiteSpace(x.Key))
                .GroupBy(x => NotificationSignalPolicy.CanonicalKey(x.Key), StringComparer.OrdinalIgnoreCase)
                .Select(g =>
                {
                    var selected = g
                        .OrderByDescending(x => SeverityRank(x.Severity))
                        .ThenByDescending(x => NotificationSignalPolicy.EvidencePreference(x.Key))
                        .ThenByDescending(x => x.Timestamp)
                        .First();
                    return selected with { Key = g.Key };
                })
                .ToDictionary(x => x.Key, StringComparer.OrdinalIgnoreCase);
            var active = new Dictionary<string, NotificationActiveState>(StringComparer.OrdinalIgnoreCase);
            var emitted = new List<IncidentNotification>();

            foreach (var signal in current.Values.OrderBy(x => x.Key, StringComparer.OrdinalIgnoreCase))
            {
                var transition = NotificationTransition.Opened;
                var shouldEmit = !priorActive.TryGetValue(signal.Key, out var old);
                if (old is not null)
                {
                    if (SeverityRank(signal.Severity) > SeverityRank(old.Severity))
                    {
                        transition = NotificationTransition.Escalated;
                        shouldEmit = true;
                    }
                }

                active[signal.Key] = new NotificationActiveState(
                    signal.Key,
                    signal.Severity,
                    TdmVisibleText.Sanitize(signal.Title),
                    TdmVisibleText.Sanitize(signal.Summary),
                    TdmVisibleText.Sanitize(signal.SourceKind),
                    string.IsNullOrWhiteSpace(signal.SourceId) ? signal.SourceId : TdmVisibleText.Sanitize(signal.SourceId));
                if (shouldEmit)
                    emitted.Add(ToNotification(signal, transition, sampleTime));
            }

            // FIX93: una condición que deja de estar activa se cierra en el estado interno,
            // pero no genera ninguna alerta visible de recuperación.

            foreach (var notification in emitted)
                foreach (var sink in _sinks)
                    await sink.SendAsync(notification, ct).ConfigureAwait(false);

            await SaveStateAsync(new NotificationDispatcherState(active), ct).ConfigureAwait(false);
            return emitted;
        }
        finally { _gate.Release(); }
    }

    private static IncidentNotification ToNotification(AlertSignal signal, NotificationTransition transition, DateTimeOffset sampleTime)
        => new(
            StableId(signal.Key, transition, sampleTime),
            sampleTime,
            transition,
            signal.Severity,
            TdmVisibleText.Sanitize(signal.Title),
            TdmVisibleText.Sanitize(signal.Summary),
            TdmVisibleText.Sanitize(signal.SourceKind),
            string.IsNullOrWhiteSpace(signal.SourceId) ? signal.SourceId : TdmVisibleText.Sanitize(signal.SourceId),
            signal.Severity);

    private async Task<NotificationDispatcherState> LoadStateAsync(CancellationToken ct)
    {
        if (!File.Exists(StatePath)) return EmptyState();
        try
        {
            await using var stream = new FileStream(StatePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete,
                16 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
            var state = await JsonSerializer.DeserializeAsync<NotificationDispatcherState>(stream, _json, ct).ConfigureAwait(false);
            if (state?.Active is null)
                return EmptyState();
            return new NotificationDispatcherState(
                state.Active.ToDictionary(x => x.Key, x => x.Value, StringComparer.OrdinalIgnoreCase));
        }
        catch (JsonException) { return EmptyState(); }
        catch (IOException) { return EmptyState(); }
        catch (UnauthorizedAccessException) { return EmptyState(); }
    }


    private static NotificationDispatcherState EmptyState()
        => new(new Dictionary<string, NotificationActiveState>(StringComparer.OrdinalIgnoreCase));

    private async Task SaveStateAsync(NotificationDispatcherState state, CancellationToken ct)
    {
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(StatePath)!);
        var tmp = StatePath + ".tmp-" + Guid.NewGuid().ToString("N");
        try
        {
            await using (var stream = new FileStream(tmp, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                16 * 1024, FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await JsonSerializer.SerializeAsync(stream, state, _json, ct).ConfigureAwait(false);
                await stream.FlushAsync(ct).ConfigureAwait(false);
                stream.Flush(true);
            }
            File.Move(tmp, StatePath, true);
        }
        finally { try { if (File.Exists(tmp)) File.Delete(tmp); } catch { } }
    }

    private static int SeverityRank(string? value)
        => value?.Trim().ToLowerInvariant() switch
        {
            "critico" or "crítico" => 4,
            "error" => 3,
            "advertencia" => 2,
            _ => 1
        };

    private static string StableId(string key, NotificationTransition transition, DateTimeOffset timestamp)
    {
        var payload = $"{key}|{transition}|{timestamp.ToUniversalTime():O}";
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(payload));
        return "NTF-" + Convert.ToHexString(hash)[..12];
    }
}
