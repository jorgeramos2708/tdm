using System.Text;
using System.IO;
using System.Text.Json;
using TDM.Notifications;

namespace TDM.Notifier.Avalonia;

internal sealed class JournalReader
{
    private sealed record ReaderState
    {
        public long CreationUtcTicks { get; init; }
        public long Offset { get; init; }
        public List<string> RecentIds { get; init; } = [];
    }

    private readonly JsonSerializerOptions _json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase, WriteIndented = true };
    private readonly string _journalPath;
    private readonly string _previousPath;
    private readonly string _statePath;
    private ReaderState _state = new();
    private bool _initialized;

    public JournalReader(string machineRoot, string userStateRoot)
    {
        _journalPath = Path.Combine(machineRoot, "notifications", "desktop-journal.jsonl");
        _previousPath = _journalPath + ".1";
        _statePath = Path.Combine(userStateRoot, "reader-state.json");
    }

    public async Task InitializeAsync(CancellationToken ct = default)
    {
        if (_initialized) return;
        Directory.CreateDirectory(Path.GetDirectoryName(_statePath)!);
        var loaded = await LoadStateAsync(ct).ConfigureAwait(false);
        if (loaded is not null)
        {
            _state = loaded with { RecentIds = loaded.RecentIds ?? [] };
        }
        else if (File.Exists(_journalPath))
        {
            // Primer inicio: no inundar la sesión con alertas históricas. Se empieza al final
            // del journal actual; cualquier alerta nueva o self-test sí se mostrará.
            var info = new FileInfo(_journalPath);
            _state = new ReaderState { CreationUtcTicks = info.CreationTimeUtc.Ticks, Offset = info.Length };
            await SaveStateAsync(ct).ConfigureAwait(false);
        }
        _initialized = true;
    }

    public async Task<IReadOnlyList<IncidentNotification>> ReadNewAsync(CancellationToken ct = default)
    {
        if (!_initialized) await InitializeAsync(ct).ConfigureAwait(false);
        if (!File.Exists(_journalPath)) return [];

        var info = new FileInfo(_journalPath);
        var creation = info.CreationTimeUtc.Ticks;
        var output = new List<IncidentNotification>();
        var recent = new HashSet<string>(_state.RecentIds, StringComparer.OrdinalIgnoreCase);
        var offset = _state.Offset;

        if (_state.CreationUtcTicks != 0 && creation != _state.CreationUtcTicks)
        {
            // El journal rotó. Completar primero cualquier línea que quedara en .1 a partir
            // del offset previo y luego continuar desde 0 en el archivo nuevo.
            if (File.Exists(_previousPath))
            {
                var previous = await ReadCompleteLinesAsync(_previousPath, offset, recent, ct).ConfigureAwait(false);
                output.AddRange(previous.Items);
            }
            offset = 0;
        }
        else if (info.Length < offset)
        {
            offset = 0;
        }

        var result = await ReadCompleteLinesAsync(_journalPath, offset, recent, ct).ConfigureAwait(false);
        output.AddRange(result.Items);
        var ids = recent.TakeLast(500).ToList();
        _state = new ReaderState { CreationUtcTicks = creation, Offset = result.NewOffset, RecentIds = ids };
        await SaveStateAsync(ct).ConfigureAwait(false);
        return output;
    }

    private async Task<(IReadOnlyList<IncidentNotification> Items, long NewOffset)> ReadCompleteLinesAsync(
        string path,
        long offset,
        HashSet<string> recent,
        CancellationToken ct)
    {
        var items = new List<IncidentNotification>();
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete,
            16 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
        if (offset < 0 || offset > stream.Length) offset = 0;
        stream.Seek(offset, SeekOrigin.Begin);
        var remaining = checked((int)Math.Min(int.MaxValue, stream.Length - offset));
        if (remaining <= 0) return (items, offset);
        var buffer = new byte[remaining];
        var read = 0;
        while (read < buffer.Length)
        {
            var n = await stream.ReadAsync(buffer.AsMemory(read, buffer.Length - read), ct).ConfigureAwait(false);
            if (n == 0) break;
            read += n;
        }
        if (read <= 0) return (items, offset);
        var lastNewLine = Array.LastIndexOf(buffer, (byte)'\n', read - 1, read);
        if (lastNewLine < 0) return (items, offset);

        var text = Encoding.UTF8.GetString(buffer, 0, lastNewLine + 1);
        foreach (var line in text.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            try
            {
                var item = JsonSerializer.Deserialize<IncidentNotification>(line, _json);
                if (item is null || item.Transition == NotificationTransition.Recovered) continue;
                if (recent.Add(item.Id)) items.Add(item);
            }
            catch (JsonException) { }
        }
        return (items, offset + lastNewLine + 1L);
    }

    private async Task<ReaderState?> LoadStateAsync(CancellationToken ct)
    {
        if (!File.Exists(_statePath)) return null;
        try
        {
            await using var stream = new FileStream(_statePath, FileMode.Open, FileAccess.Read, FileShare.Read,
                8 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
            return await JsonSerializer.DeserializeAsync<ReaderState>(stream, _json, ct).ConfigureAwait(false);
        }
        catch (JsonException) { return null; }
        catch (IOException) { return null; }
        catch (UnauthorizedAccessException) { return null; }
    }

    private async Task SaveStateAsync(CancellationToken ct)
    {
        var tmp = _statePath + ".tmp-" + Guid.NewGuid().ToString("N");
        try
        {
            await using (var stream = new FileStream(tmp, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                8 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan))
            {
                await JsonSerializer.SerializeAsync(stream, _state, _json, ct).ConfigureAwait(false);
                await stream.FlushAsync(ct).ConfigureAwait(false);
            }
            File.Move(tmp, _statePath, true);
        }
        finally { try { if (File.Exists(tmp)) File.Delete(tmp); } catch { } }
    }
}
