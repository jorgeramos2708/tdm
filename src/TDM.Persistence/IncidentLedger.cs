using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace TDM.Persistence;

public enum ManagedIncidentState { Active, Persistent, Recovered, Closed }

public sealed record ManagedIncident(
    string Id,
    DateTimeOffset StartedAt,
    DateTimeOffset LastSeenAt,
    DateTimeOffset? RecoveredAt,
    DateTimeOffset? ClosedAt,
    ManagedIncidentState State,
    string Severity,
    string Component,
    string Kind,
    string Summary,
    string? CausalOrigin,
    string? Originator,
    int Occurrences,
    string? TechnicianNote = null,
    string Node = "LOCAL");

public sealed class IncidentLedger
{
    private static readonly SemaphoreSlim ProcessGate = new(1, 1);
    private readonly JsonSerializerOptions _json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase, WriteIndented = false };
    public string Path { get; }

    public IncidentLedger(string? rootPath = null)
    {
        var root = string.IsNullOrWhiteSpace(rootPath) ? LocalStateStore.DefaultRootPath : rootPath;
        Path = System.IO.Path.Combine(root, "incidents", "incident-ledger.jsonl");
    }

    public async Task<IReadOnlyList<ManagedIncident>> ReadAsync(CancellationToken ct = default)
    {
        if (!File.Exists(Path)) return [];
        var items = new Dictionary<string, ManagedIncident>(StringComparer.OrdinalIgnoreCase);
        using var stream = new FileStream(Path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete,
            32 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
        using var reader = new StreamReader(stream, Encoding.UTF8);
        while (await reader.ReadLineAsync(ct) is { } line)
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            try
            {
                var item = JsonSerializer.Deserialize<ManagedIncident>(line, _json);
                if (item is not null && IsOperationalManagedIncident(item)) items[item.Id] = item;
            }
            catch (JsonException) { }
        }
        return items.Values.OrderByDescending(x => x.LastSeenAt).ToList();
    }

    public async Task<IReadOnlyList<ManagedIncident>> ReconcileAsync(
        IReadOnlyList<ObservabilityIncident> observed,
        DateTimeOffset sampleTime,
        SupportMonitoringSettings settings,
        string node = "LOCAL",
        CancellationToken ct = default)
    {
        await ProcessGate.WaitAsync(ct).ConfigureAwait(false);
        await using var processLock = await AcquireInterprocessLockAsync(ct).ConfigureAwait(false);
        try
        {
        var existing = (await ReadAsync(ct)).ToDictionary(x => x.Id, StringComparer.OrdinalIgnoreCase);
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var cooldown = TimeSpan.FromSeconds(Math.Max(30, settings.Thresholds.IncidentCooldownSeconds));
        // IncidentRecoveryConfirmSamples = muestras consecutivas (~60s c/u) sin el incidente para confirmar recuperación.
        var recoveryDelay = TimeSpan.FromSeconds(Math.Max(cooldown.TotalSeconds, settings.Thresholds.IncidentRecoveryConfirmSamples * 60.0));

foreach (var item in ObservabilityIncidentPolicy.Normalize(observed).OrderBy(x => x.Timestamp))
            {
                var key = Key(node, item.Component, item.Kind);
                var id = StableId(key, item.Timestamp);
                var candidate = settings.EnableIncidentAntiNoise
                    ? existing.Values
                        .Where(x => x.Node.Equals(node, StringComparison.OrdinalIgnoreCase)
                                 && x.Component.Equals(item.Component, StringComparison.OrdinalIgnoreCase)
                                 && x.Kind.Equals(item.Kind, StringComparison.OrdinalIgnoreCase)
                                 && x.State is ManagedIncidentState.Active or ManagedIncidentState.Persistent)
                        .OrderByDescending(x => x.LastSeenAt)
                        .FirstOrDefault(x => item.Timestamp - x.LastSeenAt <= cooldown)
                    : null;

                // P1-02: Kind inmutable - si el Kind cambia, NO reutilizar el incidente existente.
                // Esto evita contaminar VerifiedHistory con un Id que ahora representa otro tipo de fallo.
                // Si el Kind cambió, forzar creación de nuevo incidente (candidate = null).
                if (candidate is null && settings.EnableIncidentAntiNoise)
                {
                    var fallbackCandidate = existing.Values
                        .Where(x => x.Node.Equals(node, StringComparison.OrdinalIgnoreCase)
                                 && x.Component.Equals(item.Component, StringComparison.OrdinalIgnoreCase)
                                 && x.State is ManagedIncidentState.Active or ManagedIncidentState.Persistent)
                        .OrderByDescending(x => x.LastSeenAt)
                        .FirstOrDefault(x => item.Timestamp - x.LastSeenAt <= cooldown);
                    
                    // Solo usar fallback si el Kind NO cambió
                    if (fallbackCandidate is not null && fallbackCandidate.Kind.Equals(item.Kind, StringComparison.OrdinalIgnoreCase))
                    {
                        candidate = fallbackCandidate;
                    }
                    // Si el Kind cambió, candidate queda null y se creará nuevo incidente
                }

                if (candidate is null)
                {
                    candidate = new ManagedIncident(id, item.Timestamp, item.Timestamp, null, null,
                        ManagedIncidentState.Active, item.Severity, item.Component, item.Kind, item.Summary,
                        null, null, 1, null, node);
                }
                else
                {
                    candidate = candidate with
                    {
                        LastSeenAt = item.Timestamp,
                        State = candidate.Occurrences >= 1 ? ManagedIncidentState.Persistent : ManagedIncidentState.Active,
                        Severity = MaxSeverity(candidate.Severity, item.Severity),
                        Summary = item.Summary,
                        Occurrences = candidate.Occurrences + 1
                    };
                }
                existing[candidate.Id] = candidate;
                seen.Add(candidate.Id);
            }

        // Recuperación: si un incidente activo dejó de aparecer más allá del cooldown,
        // no se borra; se conserva como RECUPERADO para soporte.
        foreach (var pair in existing.ToArray())
        {
            var item = pair.Value;
            if (!item.Node.Equals(node, StringComparison.OrdinalIgnoreCase)) continue;
            if (item.State is not (ManagedIncidentState.Active or ManagedIncidentState.Persistent)) continue;
            if (seen.Contains(item.Id)) continue;
            if (sampleTime - item.LastSeenAt < recoveryDelay) continue;
            existing[pair.Key] = item with { State = ManagedIncidentState.Recovered, RecoveredAt = sampleTime };
        }

        await AppendSnapshotAsync(existing.Values, ct);
        return existing.Values.OrderByDescending(x => x.LastSeenAt).ToList();
        }
        finally { ProcessGate.Release(); }
    }

    public async Task AddNoteAsync(string id, string note, CancellationToken ct = default)
    {
        await ProcessGate.WaitAsync(ct).ConfigureAwait(false);
        await using var processLock = await AcquireInterprocessLockAsync(ct).ConfigureAwait(false);
        try
        {
            var existing = (await ReadAsync(ct)).ToDictionary(x => x.Id, StringComparer.OrdinalIgnoreCase);
            if (!existing.TryGetValue(id, out var item)) return;
            existing[id] = item with { TechnicianNote = string.IsNullOrWhiteSpace(note) ? null : note.Trim() };
            await AppendSnapshotAsync(existing.Values, ct);
        }
        finally { ProcessGate.Release(); }
    }

    public async Task CloseAsync(string id, CancellationToken ct = default)
    {
        await ProcessGate.WaitAsync(ct).ConfigureAwait(false);
        await using var processLock = await AcquireInterprocessLockAsync(ct).ConfigureAwait(false);
        try
        {
            var existing = (await ReadAsync(ct)).ToDictionary(x => x.Id, StringComparer.OrdinalIgnoreCase);
            if (!existing.TryGetValue(id, out var item)) return;
            existing[id] = item with { State = ManagedIncidentState.Closed, ClosedAt = DateTimeOffset.Now };
            await AppendSnapshotAsync(existing.Values, ct);
        }
        finally { ProcessGate.Release(); }
    }

    private async Task<FileStream> AcquireInterprocessLockAsync(CancellationToken ct)
    {
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(Path)!);
        var lockPath = Path + ".lock";
        for (var attempt = 0; attempt < 100; attempt++)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                return new FileStream(lockPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None,
                    1, FileOptions.Asynchronous | FileOptions.DeleteOnClose);
            }
            catch (IOException) when (attempt < 99)
            {
                await Task.Delay(50, ct).ConfigureAwait(false);
            }
        }
        throw new IOException("No fue posible adquirir el bloqueo interproceso del IncidentLedger.");
    }

    private async Task AppendSnapshotAsync(IEnumerable<ManagedIncident> items, CancellationToken ct)
    {
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(Path)!);
        var tmp = Path + ".tmp-" + Guid.NewGuid().ToString("N");
        try
        {
            await using (var stream = new FileStream(tmp, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                32 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan))
            await using (var writer = new StreamWriter(stream, new UTF8Encoding(false)))
            {
                var retentionCutoff = DateTimeOffset.Now.AddDays(-90);
                foreach (var item in items
                    .Where(x => x.LastSeenAt >= retentionCutoff || x.State is ManagedIncidentState.Active or ManagedIncidentState.Persistent)
                    .OrderByDescending(x => x.LastSeenAt)
                    .Take(2000)
                    .OrderBy(x => x.StartedAt))
                    await writer.WriteLineAsync(JsonSerializer.Serialize(item, _json).AsMemory(), ct);
                await writer.FlushAsync(ct);
            }
            File.Move(tmp, Path, true);
        }
        finally { try { if (File.Exists(tmp)) File.Delete(tmp); } catch { } }
    }

    private static bool IsOperationalManagedIncident(ManagedIncident item)
        => ObservabilityIncidentPolicy.IsOperationalIncident(
            item.Kind, item.Component, item.Severity, item.Summary);

    private static string Key(string node, string component, string kind) => $"{node}|{component}|{kind}".ToUpperInvariant();
    private static string StableId(string key, DateTimeOffset timestamp)
    {
        var normalized = timestamp.ToUniversalTime();
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes($"{key}|{normalized:O}"));
        return "INC-" + Convert.ToHexString(hash)[..12];
    }

    private static string MaxSeverity(string a, string b)
    {
        static int Rank(string s) => s.ToLowerInvariant() switch { "critico" or "crítico" => 4, "error" => 3, "advertencia" => 2, _ => 1 };
        return Rank(b) > Rank(a) ? b : a;
    }
}
