using System.Collections.Concurrent;
using System.Text;
using System.Text.Json;

namespace TDM.Persistence;

public sealed record FederationNode(
    string Id,
    string DisplayName,
    string Group,
    string Role,
    string ObservabilityRoot,
    bool Enabled = true,
    string Environment = "Producción");

public sealed record FederationConfiguration(
    string CoordinatorName,
    IReadOnlyList<FederationNode> Nodes)
{
    public static FederationConfiguration Empty { get; } = new(Environment.MachineName, []);
}

public sealed record FederationNodeStatus(
    FederationNode Node,
    string Connectivity,
    string Health,
    DateTimeOffset? LastSampleAt,
    double AgeSeconds,
    double? CpuPercent,
    double? MemoryUsedPercent,
    int ActiveSessions,
    int Incidents,
    string? CausalOrigin,
    string? Originator,
    double ClockFileDeltaSeconds,
    IReadOnlyDictionary<string, string> ServiceStates,
    IReadOnlyDictionary<string, string> DependencyStates,
    string Detail);

public sealed class FederationStore
{
    private readonly JsonSerializerOptions _json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase, WriteIndented = true };
    private readonly string _root;
    private const int MaxConcurrentNodeReads = 4;
    private readonly NonQueuingOperationLimiter _nodeReadLimiter = new(MaxConcurrentNodeReads);
    private readonly ConcurrentDictionary<string, Task<FederationNodeStatus>> _inflightNodeReads = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, DateTimeOffset> _nodeRetryAfter = new(StringComparer.OrdinalIgnoreCase);
    private static readonly TimeSpan NodeCircuitCooldown = TimeSpan.FromMinutes(2);
    public int InFlightNodeReads => _inflightNodeReads.Count;
    public int ActiveNodeReadSlots => _nodeReadLimiter.Active;
    public int OpenNodeCircuits => _nodeRetryAfter.Count(x => x.Value > DateTimeOffset.UtcNow);
    public string ConfigurationPath => Path.Combine(_root, "federation", "nodes.json");

    public FederationStore(string? rootPath = null)
    {
        _root = string.IsNullOrWhiteSpace(rootPath) ? LocalStateStore.DefaultRootPath : rootPath;
    }

    public async Task<FederationConfiguration> LoadConfigurationAsync(CancellationToken ct = default)
    {
        if (!File.Exists(ConfigurationPath)) return FederationConfiguration.Empty;
        try
        {
            await using var stream = new FileStream(ConfigurationPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete,
                16 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
            return await JsonSerializer.DeserializeAsync<FederationConfiguration>(stream, _json, ct) ?? FederationConfiguration.Empty;
        }
        catch (JsonException) { return FederationConfiguration.Empty; }
        catch (IOException) { return FederationConfiguration.Empty; }
        catch (UnauthorizedAccessException) { return FederationConfiguration.Empty; }
    }

    public async Task SaveConfigurationAsync(FederationConfiguration config, CancellationToken ct = default)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(ConfigurationPath)!);
        var normalized = config with
        {
            CoordinatorName = string.IsNullOrWhiteSpace(config.CoordinatorName) ? Environment.MachineName : config.CoordinatorName.Trim(),
            Nodes = config.Nodes
                .Where(x => !string.IsNullOrWhiteSpace(x.DisplayName) && !string.IsNullOrWhiteSpace(x.ObservabilityRoot))
                .GroupBy(x => x.Id, StringComparer.OrdinalIgnoreCase)
                .Select(g => g.Last())
                .ToList()
        };
        var tmp = ConfigurationPath + ".tmp-" + Guid.NewGuid().ToString("N");
        try
        {
            await using (var stream = new FileStream(tmp, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                16 * 1024, FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await JsonSerializer.SerializeAsync(stream, normalized, _json, ct);
                await stream.FlushAsync(ct);
                stream.Flush(true);
            }
            File.Move(tmp, ConfigurationPath, true);
        }
        finally { try { if (File.Exists(tmp)) File.Delete(tmp); } catch { } }
    }

    public async Task<IReadOnlyList<FederationNodeStatus>> ReadStatusesAsync(
        FederationConfiguration config,
        SupportThresholds thresholds,
        CancellationToken ct = default)
    {
        var nodes = config.Nodes.Where(x => x.Enabled).ToList();
        if (nodes.Count == 0) return [];
        var tasks = nodes.Select(node => ReadNodeBoundedAsync(node, thresholds, ct)).ToArray();
        var output = await Task.WhenAll(tasks);
        return output.OrderBy(x => x.Node.Group).ThenBy(x => x.Node.DisplayName).ToList();
    }


    private async Task<FederationNodeStatus> ReadNodeBoundedAsync(FederationNode node, SupportThresholds thresholds, CancellationToken ct)
    {
        var now = DateTimeOffset.UtcNow;
        if (_nodeRetryAfter.TryGetValue(node.Id, out var retryAfter) && retryAfter > now)
            return Empty(node, "NO ACCESIBLE", "SIN DATOS", $"Lectura suspendida temporalmente hasta {retryAfter.ToLocalTime():HH:mm:ss} después de un timeout previo. TDM no acumula nuevas lecturas UNC sobre el mismo nodo.");
        if (retryAfter != default) _nodeRetryAfter.TryRemove(node.Id, out _);

        Task<FederationNodeStatus> task;
        if (!_inflightNodeReads.TryGetValue(node.Id, out task!))
        {
            // No se crea una cola ilimitada detrás de APIs UNC bloqueadas. Si los cuatro
            // slots están ocupados, el nodo queda como aplazado y se reintentará en el
            // siguiente refresco en lugar de dejar otra operación esperando internamente.
            if (!_nodeReadLimiter.TryAcquire(out var slotLease) || slotLease is null)
                return Empty(node, "APLAZADO", "SIN DATOS", $"Lectura aplazada: TDM ya tiene {MaxConcurrentNodeReads} lecturas de servidor en curso. No se encola otra operación UNC para proteger el proceso.");

            var completion = new TaskCompletionSource<FederationNodeStatus>(TaskCreationOptions.RunContinuationsAsynchronously);
            if (!_inflightNodeReads.TryAdd(node.Id, completion.Task))
            {
                slotLease.Dispose();
                if (!_inflightNodeReads.TryGetValue(node.Id, out task!))
                    return Empty(node, "APLAZADO", "SIN DATOS", "La lectura quedó aplazada por una actualización concurrente del mismo servidor.");
            }
            else
            {
                task = completion.Task;
                _ = ExecuteReservedNodeReadAsync(node, thresholds, completion, slotLease);
            }
        }

        var timeout = TimeSpan.FromSeconds(Math.Clamp(thresholds.NodeReadTimeoutSeconds, 2, 30));
        var completed = await Task.WhenAny(task, Task.Delay(timeout, ct));
        if (completed == task) return await task.ConfigureAwait(false);
        ct.ThrowIfCancellationRequested();
        var blockedUntil = DateTimeOffset.UtcNow + NodeCircuitCooldown;
        _nodeRetryAfter[node.Id] = blockedUntil;
        return Empty(node, "NO ACCESIBLE", "SIN DATOS", $"Lectura del agregado excedió {timeout.TotalSeconds:0}s. Circuito temporal abierto hasta {blockedUntil.ToLocalTime():HH:mm:ss}; no se lanzarán lecturas repetidas mientras la fuente siga bloqueada.");
    }

    private async Task ExecuteReservedNodeReadAsync(
        FederationNode node,
        SupportThresholds thresholds,
        TaskCompletionSource<FederationNodeStatus> completion,
        IDisposable slotLease)
    {
        try
        {
            // File.Exists/metadata de una ruta UNC pueden bloquear en APIs del sistema;
            // se aíslan en un worker. El slot se reservó antes de crear este trabajo,
            // por lo que nunca existe una cola interna de lecturas UNC esperando turno.
            var result = await Task.Run(() => ReadNodeStatusAsync(node, thresholds, CancellationToken.None)).ConfigureAwait(false);
            completion.TrySetResult(result);
        }
        catch (Exception ex)
        {
            completion.TrySetResult(Empty(node, "NO ACCESIBLE", "SIN DATOS", $"Error controlado al leer el agregado del servidor: {ex.Message}"));
        }
        finally
        {
            if (_inflightNodeReads.TryGetValue(node.Id, out var current) && ReferenceEquals(current, completion.Task))
                _inflightNodeReads.TryRemove(node.Id, out _);
            // No cerrar aquí el circuito: si el caller ya agotó su timeout, el worker puede
            // terminar tarde y no debe borrar el cooldown de 2 minutos que protege nuevas UNC.
            // ReadNodeBoundedAsync elimina únicamente circuitos ya expirados.
            slotLease.Dispose();
        }
    }

    public async Task<IReadOnlyList<ObservabilitySample>> ReadNodeWindowAsync(FederationNode node, TimeSpan window, CancellationToken ct = default)
    {
        var path = ResolveWindowPath(node.ObservabilityRoot);
        if (!File.Exists(path)) return [];
        var samples = await ReadJsonLinesAsync(path, ct);
        if (samples.Count == 0) return [];
        var end = samples.Max(x => x.Timestamp);
        var start = end - (window <= TimeSpan.Zero ? TimeSpan.FromMinutes(15) : window > TimeSpan.FromHours(4) ? TimeSpan.FromHours(4) : window);
        return samples.Where(x => x.Timestamp >= start).OrderBy(x => x.Timestamp).TakeLast(720).ToList();
    }

    private async Task<FederationNodeStatus> ReadNodeStatusAsync(FederationNode node, SupportThresholds thresholds, CancellationToken ct)
    {
        var path = ResolveWindowPath(node.ObservabilityRoot);
        try
        {
            if (!File.Exists(path))
                return Empty(node, "NO ACCESIBLE", "SIN DATOS", "No existe o no es accesible el historial agregado de Observabilidad.");

            var samples = await ReadJsonLinesAsync(path, ct, 3);
            var latest = samples.LastOrDefault();
            if (latest is null) return Empty(node, "ACCESIBLE", "SIN DATOS", "El archivo existe, pero no contiene muestras válidas.");

            var age = Math.Max(0, (DateTimeOffset.Now - latest.Timestamp).TotalSeconds);
            var fileTime = new DateTimeOffset(File.GetLastWriteTimeUtc(path), TimeSpan.Zero);
            var fileDelta = Math.Abs((fileTime - latest.Timestamp.ToUniversalTime()).TotalSeconds);
            var connectivity = age >= thresholds.NodeOfflineSeconds ? "SIN DATOS" : age >= thresholds.NodeStaleWarningSeconds ? "ATRASADO" : "EN LÍNEA";
            double? memoryUsed = latest.MemoryFreePercent.HasValue ? 100d - latest.MemoryFreePercent.Value : null;
            var operationalIncidents = ObservabilityIncidentPolicy.Normalize(latest.Incidents);
            // Un incidente histórico conservado en el snapshot no debe mantener el nodo en FALLA para siempre.
            // Sólo los incidentes cercanos a la muestra más reciente se consideran activos para salud federada.
            var activeIncidents = operationalIncidents
                .Where(x => x.Timestamp >= latest.Timestamp - TimeSpan.FromMinutes(5)
                    && x.Timestamp <= latest.Timestamp + TimeSpan.FromMinutes(1))
                .ToList();
            var operationalFailure = HasOperationalFailure(latest.ServiceStates) || HasOperationalFailure(latest.DependencyStates);
            var critical = activeIncidents.Count > 0 || operationalFailure;
            // W4: excluir TDM-SNAPSHOT-STALE (causa TDM-interna, no TSplus) del warning federado
            var tdmStaleCount = latest.Incidents?.Count(i => i.Kind.Contains("SNAPSHOT_STALE", StringComparison.OrdinalIgnoreCase)) ?? 0;
            var warning = (latest.WarningFindings - tdmStaleCount) > 0 || latest.BaselineDifferences > 0 || fileDelta >= thresholds.ClockDriftWarningSeconds;
            var health = connectivity == "SIN DATOS" ? "SIN DATOS" : critical ? "FALLA" : warning ? "DEGRADADO" : "SALUDABLE";
            return new FederationNodeStatus(node, connectivity, health, latest.Timestamp, age, latest.CpuPercent, memoryUsed,
                latest.ActiveSessions, activeIncidents.Count, latest.CausalOrigin, latest.Originator, fileDelta,
                latest.ServiceStates ?? new Dictionary<string, string>(), latest.DependencyStates ?? new Dictionary<string, string>(),
                fileDelta >= thresholds.ClockDriftWarningSeconds ? $"Posible desfase reloj/archivo: {fileDelta:0}s" : "Agregado de TDM accesible");
        }
        catch (UnauthorizedAccessException ex) { return Empty(node, "NO ACCESIBLE", "SIN DATOS", "Permiso denegado: " + ex.Message); }
        catch (IOException ex) { return Empty(node, "NO ACCESIBLE", "SIN DATOS", "I/O: " + ex.Message); }
    }

    private static bool HasOperationalFailure(IReadOnlyDictionary<string, string>? states)
        => states?.Values.Any(state => ContainsOperationalFailure(state)) == true;

    private static bool ContainsOperationalFailure(string? state)
    {
        var value = state ?? string.Empty;
        return new[] { "Stopped", "Failed", "Error", "Crítico", "Critico", "No operativo", "Listening=No", "Activos=0" }
            .Any(marker => value.Contains(marker, StringComparison.OrdinalIgnoreCase));
    }

    private static FederationNodeStatus Empty(FederationNode node, string connectivity, string health, string detail)
        => new(node, connectivity, health, null, double.PositiveInfinity, null, null, 0, 0, null, null, 0,
            new Dictionary<string, string>(), new Dictionary<string, string>(), detail);

    private static string ResolveWindowPath(string root)
    {
        var trimmed = Environment.ExpandEnvironmentVariables(root.Trim());
        if (trimmed.EndsWith(".jsonl", StringComparison.OrdinalIgnoreCase)) return trimmed;
        return Path.Combine(trimmed, "state", "observability-window.jsonl");
    }

    private async Task<List<ObservabilitySample>> ReadJsonLinesAsync(string path, CancellationToken ct, int tailHint = 720)
    {
        var output = new List<ObservabilitySample>();
        const long maxTailBytes = 768L * 1024;
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete,
            32 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
        var start = Math.Max(0, stream.Length - maxTailBytes);
        if (start > 0) stream.Seek(start, SeekOrigin.Begin);
        using var reader = new StreamReader(stream, Encoding.UTF8, true, 32 * 1024);
        if (start > 0) _ = await reader.ReadLineAsync(ct); // descarta la primera línea posiblemente parcial del tail.
        while (await reader.ReadLineAsync(ct) is { } line)
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            try
            {
                var item = JsonSerializer.Deserialize<ObservabilitySample>(line, _json);
                if (item is not null) output.Add(item with { Incidents = ObservabilityIncidentPolicy.Normalize(item.Incidents) });
            }
            catch (JsonException) { }
        }
        return output.TakeLast(Math.Max(3, tailHint)).ToList();
    }
}
