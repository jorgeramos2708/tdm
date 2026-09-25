using System.Text;
using System.Text.Json;
using TDM.Models;

namespace TDM.Persistence;

public sealed class LocalStateStore
{
    private static long _lastCleanupUtcTicks;
    private static readonly Lazy<string> CachedDefaultRoot = new(ResolveDefaultRootCore, LazyThreadSafetyMode.ExecutionAndPublication);
    public static string DefaultRootPath => CachedDefaultRoot.Value;
    private readonly JsonSerializerOptions _json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false
    };

    public string RootPath { get; }
    public int RetentionDays { get; }
    public string BaselinePath => Path.Combine(RootPath, "baseline", "healthy-baseline.json");
    public string LatestSnapshotPath => GetLatestSnapshotPath("diagnostic");

    public string GetLatestSnapshotPath(string channel)
    {
        var normalized = NormalizeChannel(channel);
        return normalized == "diagnostic"
            ? Path.Combine(RootPath, "state", "latest.json")
            : Path.Combine(RootPath, "state", $"latest-{normalized}.json");
    }

    public LocalStateStore(string? rootPath = null, int? retentionDays = null)
    {
        RootPath = string.IsNullOrWhiteSpace(rootPath) ? DefaultRootPath : Path.GetFullPath(rootPath);
        RetentionDays = Math.Clamp(retentionDays ?? ResolveRetentionDays(), 1, 365);
        EnsureLayout();
    }

    public Task<RecordResult> RecordAsync(PersistentStateSnapshot snapshot, CancellationToken ct = default)
        => RecordAsync(snapshot, "diagnostic", ct);

    public async Task<RecordResult> RecordAsync(PersistentStateSnapshot snapshot, string channel, CancellationToken ct = default)
    {
        var normalizedChannel = NormalizeChannel(channel);
        var latestSnapshotPath = GetLatestSnapshotPath(normalizedChannel);
        await using var gate = await AcquireStoreLockAsync(ct);
        var previous = await ReadSnapshotAsync(latestSnapshotPath, ct);
        var baseline = await ReadSnapshotAsync(BaselinePath, ct);

        // Un cambio de esquema de persistencia no es un cambio operativo del servidor.
        // Se adopta la nueva captura como punto de partida y se suprimen transiciones/drift artificiales.
        IReadOnlyList<StateTransition> transitions = previous is null || previous.SchemaVersion != snapshot.SchemaVersion
            ? Array.Empty<StateTransition>()
            : CompareTransitions(previous, snapshot);
        IReadOnlyList<BaselineDifference> baselineDifferences = baseline is null || baseline.SchemaVersion != snapshot.SchemaVersion
            ? Array.Empty<BaselineDifference>()
            : CompareBaseline(baseline, snapshot);

        var channelSuffix = normalizedChannel == "diagnostic" ? string.Empty : $"-{normalizedChannel}";
        var historyPath = Path.Combine(RootPath, "history", $"state{channelSuffix}-{snapshot.CapturedAt:yyyy-MM-dd}.jsonl");
        var transitionsPath = Path.Combine(RootPath, "history", $"transitions{channelSuffix}-{snapshot.CapturedAt:yyyy-MM-dd}.jsonl");

        var durable = normalizedChannel == "diagnostic";
        await AppendJsonLineAsync(historyPath, snapshot, durable, ct);
        foreach (var transition in transitions)
            await AppendJsonLineAsync(transitionsPath, transition, durable, ct);

        await WriteAtomicAsync(latestSnapshotPath, snapshot, pretty: durable, durable: durable, ct: ct);
        CleanupRetentionIfDue();

        return new RecordResult(
            snapshot,
            transitions,
            baselineDifferences,
            RootPath,
            historyPath,
            transitionsPath,
            latestSnapshotPath,
            baseline is null ? null : BaselinePath);
    }

    public async Task<IReadOnlyList<StateTransition>> ReadRecentTransitionsAsync(
        DateTimeOffset from,
        DateTimeOffset to,
        string channel = "monitor",
        CancellationToken ct = default)
    {
        var normalizedChannel = NormalizeChannel(channel);
        var suffix = normalizedChannel == "diagnostic" ? string.Empty : $"-{normalizedChannel}";
        var historyDir = Path.Combine(RootPath, "history");
        if (!Directory.Exists(historyDir)) return Array.Empty<StateTransition>();

        var output = new List<StateTransition>();
        foreach (var path in Directory.EnumerateFiles(historyDir, $"transitions{suffix}-*.jsonl").OrderBy(x => x, StringComparer.OrdinalIgnoreCase))
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete,
                    64 * 1024, FileOptions.SequentialScan);
                using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
                while (await reader.ReadLineAsync(ct) is { } line)
                {
                    if (string.IsNullOrWhiteSpace(line)) continue;
                    StateTransition? transition;
                    try { transition = JsonSerializer.Deserialize<StateTransition>(line, _json); }
                    catch (JsonException) { continue; }
                    if (transition is null || transition.Timestamp < from || transition.Timestamp > to) continue;
                    output.Add(transition);
                }
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }

        return output
            .OrderBy(x => x.Timestamp)
            .ThenBy(x => x.Key, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    public async Task<IReadOnlyList<PersistentStateSnapshot>> ReadRecentSnapshotsAsync(
        DateTimeOffset from,
        DateTimeOffset to,
        string channel = "monitor",
        CancellationToken ct = default)
    {
        if (to < from) (from, to) = (to, from);
        var normalizedChannel = NormalizeChannel(channel);
        var suffix = normalizedChannel == "diagnostic" ? string.Empty : $"-{normalizedChannel}";
        var historyDir = Path.Combine(RootPath, "history");
        if (!Directory.Exists(historyDir)) return Array.Empty<PersistentStateSnapshot>();

        var output = new List<PersistentStateSnapshot>();
        for (var day = from.Date; day <= to.Date; day = day.AddDays(1))
        {
            ct.ThrowIfCancellationRequested();
            var path = Path.Combine(historyDir, $"state{suffix}-{day:yyyy-MM-dd}.jsonl");
            if (!File.Exists(path)) continue;
            try
            {
                using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete,
                    64 * 1024, FileOptions.SequentialScan);
                using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
                while (await reader.ReadLineAsync(ct) is { } line)
                {
                    if (string.IsNullOrWhiteSpace(line)) continue;
                    PersistentStateSnapshot? snapshot;
                    try { snapshot = JsonSerializer.Deserialize<PersistentStateSnapshot>(line, _json); }
                    catch (JsonException) { continue; }
                    if (snapshot is null || snapshot.CapturedAt < from || snapshot.CapturedAt > to) continue;
                    output.Add(snapshot);
                }
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }

        return output.OrderBy(x => x.CapturedAt).ToList();
    }

    public async Task SaveBaselineAsync(PersistentStateSnapshot snapshot, bool replace = false, CancellationToken ct = default)
    {
        await using var gate = await AcquireStoreLockAsync(ct);
        if (File.Exists(BaselinePath) && !replace)
            throw new InvalidOperationException("Ya existe un baseline sano. Use --replace únicamente después de confirmar que el servidor está estable.");

        var filtered = snapshot with
        {
            Observations = snapshot.Observations.Where(o => o.BaselineEligible).ToList()
        };
        await WriteAtomicAsync(BaselinePath, filtered, pretty: true, durable: true, ct: ct);
    }

    public Task<PersistentStateSnapshot?> LoadBaselineAsync(CancellationToken ct = default)
        => ReadSnapshotAsync(BaselinePath, ct);

    public async Task<LocalStoreStatus> GetStatusAsync(CancellationToken ct = default)
    {
        var baseline = await ReadSnapshotAsync(BaselinePath, ct);
        var historyDir = Path.Combine(RootPath, "history");
        var history = Directory.Exists(historyDir) ? Directory.EnumerateFiles(historyDir, "state-*.jsonl").Count() : 0;
        var transitions = Directory.Exists(historyDir) ? Directory.EnumerateFiles(historyDir, "transitions-*.jsonl").Count() : 0;
        return new LocalStoreStatus(RootPath, LatestSnapshotPath, BaselinePath, baseline is not null, baseline?.CapturedAt,
            RetentionDays, history, transitions);
    }

    public static IReadOnlyList<StateTransition> CompareTransitions(PersistentStateSnapshot previous, PersistentStateSnapshot current)
    {
        if (previous.SchemaVersion != current.SchemaVersion) return Array.Empty<StateTransition>();
        var oldMap = previous.Observations.Where(o => o.TrackTransition)
            .ToDictionary(o => o.Key, StringComparer.OrdinalIgnoreCase);
        var output = new List<StateTransition>();
        foreach (var item in current.Observations.Where(o => o.TrackTransition))
        {
            if (!oldMap.TryGetValue(item.Key, out var old)) continue; // RC18.4 evita falsos "eliminados" si un collector quedó sin cobertura.
            if (string.Equals(old.Value, item.Value, StringComparison.Ordinal)) continue;
            output.Add(new StateTransition(current.CapturedAt, item.Key, item.Type, item.Component, item.Layer, item.Product,
                old.Value, item.Value, old.Severity, item.Severity));
        }
        return output;
    }

    public static IReadOnlyList<BaselineDifference> CompareBaseline(PersistentStateSnapshot baseline, PersistentStateSnapshot current)
    {
        if (baseline.SchemaVersion != current.SchemaVersion) return Array.Empty<BaselineDifference>();
        var oldMap = baseline.Observations.Where(o => o.BaselineEligible)
            .ToDictionary(o => o.Key, StringComparer.OrdinalIgnoreCase);
        var output = new List<BaselineDifference>();
        foreach (var item in current.Observations.Where(o => o.BaselineEligible))
        {
            if (!oldMap.TryGetValue(item.Key, out var old)) continue; // Ausencia de evidencia no se interpreta automáticamente como drift.
            if (string.Equals(old.Value, item.Value, StringComparison.Ordinal)) continue;
            output.Add(new BaselineDifference(item.Key, item.Type, item.Component, old.Value, item.Value, item.Severity));
        }
        return output;
    }

    private async Task<PersistentStateSnapshot?> ReadSnapshotAsync(string path, CancellationToken ct)
    {
        if (!File.Exists(path)) return null;
        try
        {
            await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete,
                64 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
            return await JsonSerializer.DeserializeAsync<PersistentStateSnapshot>(stream, _json, ct);
        }
        catch (JsonException)
        {
            // Un archivo truncado/corrupto no debe bloquear el diagnóstico actual.
            return null;
        }
    }

    private async Task AppendJsonLineAsync<T>(string path, T value, bool durable, CancellationToken ct)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var json = JsonSerializer.Serialize(value, _json) + Environment.NewLine;
        var bytes = Encoding.UTF8.GetBytes(json);
        var options = FileOptions.Asynchronous | (durable ? FileOptions.WriteThrough : FileOptions.SequentialScan);
        await using var stream = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.Read, 64 * 1024, options);
        await stream.WriteAsync(bytes, ct);
        await stream.FlushAsync(ct);
        if (durable) stream.Flush(flushToDisk: true);
    }

    private async Task WriteAtomicAsync<T>(string path, T value, bool pretty, bool durable, CancellationToken ct)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var temp = path + ".tmp-" + Guid.NewGuid().ToString("N");
        var options = new JsonSerializerOptions(_json) { WriteIndented = pretty };
        try
        {
            var fileOptions = FileOptions.Asynchronous | (durable ? FileOptions.WriteThrough : FileOptions.SequentialScan);
            await using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                64 * 1024, fileOptions))
            {
                await JsonSerializer.SerializeAsync(stream, value, options, ct);
                await stream.FlushAsync(ct);
                if (durable) stream.Flush(flushToDisk: true);
            }
            File.Move(temp, path, overwrite: true);
        }
        finally
        {
            try { if (File.Exists(temp)) File.Delete(temp); } catch { }
        }
    }

    private async Task<FileStream> AcquireStoreLockAsync(CancellationToken ct)
    {
        var lockPath = Path.Combine(RootPath, ".store.lock");
        Exception? last = null;
        for (var i = 0; i < 50; i++)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                return new FileStream(lockPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None, 1,
                    FileOptions.DeleteOnClose);
            }
            catch (IOException ex)
            {
                last = ex;
                await Task.Delay(100, ct);
            }
        }
        throw new IOException("No fue posible adquirir el bloqueo del almacén local TDM después de 5 segundos.", last);
    }

    private void CleanupRetentionIfDue()
    {
        var nowTicks = DateTime.UtcNow.Ticks;
        var last = Interlocked.Read(ref _lastCleanupUtcTicks);
        if (last != 0 && new TimeSpan(nowTicks - last) < TimeSpan.FromHours(6)) return;
        if (Interlocked.CompareExchange(ref _lastCleanupUtcTicks, nowTicks, last) != last) return;
        CleanupRetention();
    }

    private void CleanupRetention()
    {
        try
        {
            var historyDir = Path.Combine(RootPath, "history");
            if (!Directory.Exists(historyDir)) return;
            var cutoff = DateTime.UtcNow.Date.AddDays(-RetentionDays);
            foreach (var file in Directory.EnumerateFiles(historyDir, "*.jsonl"))
            {
                try
                {
                    var fi = new FileInfo(file);
                    if (fi.LastWriteTimeUtc < cutoff) fi.Delete();
                }
                catch { }
            }
        }
        catch { }
    }

    private void EnsureLayout()
    {
        Directory.CreateDirectory(RootPath);
        Directory.CreateDirectory(Path.Combine(RootPath, "baseline"));
        Directory.CreateDirectory(Path.Combine(RootPath, "state"));
        Directory.CreateDirectory(Path.Combine(RootPath, "history"));
    }

    private static string ResolveDefaultRootCore()
        => TdmDataPaths.ResolveWritableDefault();

    private static string NormalizeChannel(string? channel)
    {
        if (string.IsNullOrWhiteSpace(channel)) return "diagnostic";
        var chars = channel.Trim().ToLowerInvariant().Where(c => char.IsLetterOrDigit(c) || c is '-' or '_').ToArray();
        return chars.Length == 0 ? "diagnostic" : new string(chars);
    }

    private static int ResolveRetentionDays()
        => int.TryParse(Environment.GetEnvironmentVariable("TDM_HISTORY_RETENTION_DAYS"), out var days) ? days : 30;

    /// <summary>
    /// P1-06: Path for the latest exported diagnostic report (for diff fallback).
    /// </summary>
    public string LatestReportPath => Path.Combine(RootPath, "state", "latest-report.json");

    /// <summary>
    /// P1-06: Saves the latest exported diagnostic report for diff fallback.
    /// </summary>
    public async Task SaveLatestReportAsync(DiagnosticReport report, CancellationToken ct = default)
    {
        var path = LatestReportPath;
        var options = new System.Text.Json.JsonSerializerOptions
        {
            PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase,
            WriteIndented = true
        };
        var json = System.Text.Json.JsonSerializer.Serialize(report, options);
        await System.IO.File.WriteAllTextAsync(path, json, new System.Text.UTF8Encoding(false), ct);
    }

    /// <summary>
    /// P1-06: Loads the latest exported diagnostic report for diff fallback.
    /// Returns null if no report exists or deserialization fails.
    /// </summary>
    public async Task<DiagnosticReport?> LoadLatestReportAsync(CancellationToken ct = default)
    {
        var path = LatestReportPath;
        if (!File.Exists(path)) return null;
        try
        {
            var options = new System.Text.Json.JsonSerializerOptions
            {
                PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase,
                PropertyNameCaseInsensitive = true
            };
            var json = await File.ReadAllTextAsync(path, ct);
            return System.Text.Json.JsonSerializer.Deserialize<DiagnosticReport>(json, options);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Text.Json.JsonException)
        {
            return null;
        }
    }
}
