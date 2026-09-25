using System.Text.Json;

namespace TDM.Persistence;

public sealed record TdmServiceHeartbeat(
    DateTimeOffset Timestamp,
    string Version,
    string Status,
    int ProcessId,
    int MonitorIntervalSeconds,
    long CompletedSamples,
    int DeferredSamples,
    string? LastError = null);

public sealed class ServiceHeartbeatStore
{
    private readonly JsonSerializerOptions _json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase, WriteIndented = true };
    public string RootPath { get; }
    public string Path { get; }

    public ServiceHeartbeatStore(string? rootPath = null)
    {
        RootPath = string.IsNullOrWhiteSpace(rootPath) ? TdmDataPaths.MachineRootPath : System.IO.Path.GetFullPath(rootPath);
        Path = System.IO.Path.Combine(RootPath, "runtime", "service-heartbeat.json");
    }

    public async Task WriteAsync(TdmServiceHeartbeat heartbeat, CancellationToken ct = default)
    {
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(Path)!);
        var tmp = Path + ".tmp-" + Guid.NewGuid().ToString("N");
        try
        {
            await using (var stream = new FileStream(tmp, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                16 * 1024, FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await JsonSerializer.SerializeAsync(stream, heartbeat, _json, ct).ConfigureAwait(false);
                await stream.FlushAsync(ct).ConfigureAwait(false);
                stream.Flush(true);
            }
            File.Move(tmp, Path, true);
        }
        finally { try { if (File.Exists(tmp)) File.Delete(tmp); } catch { } }
    }

    public async Task<TdmServiceHeartbeat?> ReadAsync(CancellationToken ct = default)
    {
        if (!File.Exists(Path)) return null;
        try
        {
            await using var stream = new FileStream(Path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete,
                16 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
            return await JsonSerializer.DeserializeAsync<TdmServiceHeartbeat>(stream, _json, ct).ConfigureAwait(false);
        }
        catch (JsonException) { return null; }
        catch (IOException) { return null; }
        catch (UnauthorizedAccessException) { return null; }
    }

    // Q8: 150 s ≈ 2 ciclos de 60 s perdidos + margen. Con 3 min, dos ciclos caídos
    // seguían mostrándose "vivos" en GUI/telemetría/configuración.
    public static bool IsFresh(TdmServiceHeartbeat? heartbeat, TimeSpan? maxAge = null)
        => heartbeat is not null && DateTimeOffset.Now - heartbeat.Timestamp <= (maxAge ?? TimeSpan.FromSeconds(150));
}
