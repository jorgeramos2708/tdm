using System.Collections.Concurrent;
using System.Diagnostics;
using TDM.Models;
using TDM.Persistence;

namespace TDM.Core;

/// <summary>
/// Health check endpoint para diagnóstico de estado del sistema TDM.
/// Reporta: stores, cursores, último ciclo, circuit breakers, memoria, uptime.
/// </summary>
public sealed class TdmHealthCheck
{
    private readonly string _rootPath;
    private readonly CollectorCircuitBreaker _circuitBreaker;
    private readonly ConcurrentDictionary<string, object> _lastCycleData = new();
    private readonly Stopwatch _uptime = Stopwatch.StartNew();

    public TdmHealthCheck(string rootPath, CollectorCircuitBreaker circuitBreaker)
    {
        _rootPath = rootPath;
        _circuitBreaker = circuitBreaker;
    }

    public void RecordCycleStart()
    {
        _lastCycleData["cycle_start"] = DateTimeOffset.UtcNow;
        _lastCycleData["cycle_status"] = "RUNNING";
    }

    public void RecordCycleEnd(bool success, string? error = null)
    {
        _lastCycleData["cycle_end"] = DateTimeOffset.UtcNow;
        _lastCycleData["cycle_status"] = success ? "OK" : "FAILED";
        if (error != null) _lastCycleData["cycle_error"] = error;
        _lastCycleData["cycle_duration_ms"] = _uptime.ElapsedMilliseconds;
    }

    public async Task<HealthCheckResult> CheckAsync(CancellationToken ct = default)
    {
        var checks = new List<HealthCheckItem>();

        // 1. Store accessibility
        checks.Add(await CheckStoresAsync(ct));

        // 2. Cursor store
        checks.Add(CheckCursors());

        // 3. Last cycle status
        checks.Add(CheckLastCycle());

        // 4. Circuit breakers
        checks.Add(CheckCircuitBreakers());

        // 5. Memory/GC
        checks.Add(CheckMemory());

        // 6. Disk space
        checks.Add(CheckDiskSpace());

        // 7. Uptime
        checks.Add(CheckUptime());

        var overall = checks.All(c => c.Status == HealthStatus.Healthy)
            ? HealthStatus.Healthy
            : checks.Any(c => c.Status == HealthStatus.Critical)
                ? HealthStatus.Critical
                : HealthStatus.Degraded;

        return new HealthCheckResult(
            overall,
            DateTimeOffset.UtcNow,
            _uptime.Elapsed,
            checks);
    }

    private async Task<HealthCheckItem> CheckStoresAsync(CancellationToken ct)
    {
        var storePaths = new[]
        {
            ("history", Path.Combine(_rootPath, "history")),
            ("baseline", Path.Combine(_rootPath, "baseline")),
            ("cursors", Path.Combine(_rootPath, "cursors")),
            ("settings", Path.Combine(_rootPath, "settings")),
            ("transitions", Path.Combine(_rootPath, "transitions"))
        };

        var issues = new List<string>();
        foreach (var (name, path) in storePaths)
        {
            try
            {
                if (!Directory.Exists(path))
                    Directory.CreateDirectory(path);

                // Test write
                var testFile = Path.Combine(path, $".health_{Guid.NewGuid():N}.tmp");
                await File.WriteAllTextAsync(testFile, "ok", ct);
                File.Delete(testFile);
            }
            catch (Exception ex)
            {
                issues.Add($"{name}: {ex.Message}");
            }
        }

        return new HealthCheckItem(
            "stores",
            issues.Count == 0 ? HealthStatus.Healthy : HealthStatus.Critical,
            issues.Count == 0 ? "Todos los stores accesibles" : string.Join("; ", issues));
    }

    private HealthCheckItem CheckCursors()
    {
        var cursorPath = Path.Combine(_rootPath, "cursors");
        try
        {
            if (!Directory.Exists(cursorPath))
                return new HealthCheckItem("cursors", HealthStatus.Degraded, "Directorio de cursors no existe (se creará al primer uso)");

            var files = Directory.GetFiles(cursorPath, "*.json*");
            return new HealthCheckItem("cursors", HealthStatus.Healthy, $"{files.Length} cursor(s) persistente(s)");
        }
        catch (Exception ex)
        {
            return new HealthCheckItem("cursors", HealthStatus.Critical, ex.Message);
        }
    }

    private HealthCheckItem CheckLastCycle()
    {
        if (!_lastCycleData.TryGetValue("cycle_end", out var endObj))
            return new HealthCheckItem("last_cycle", HealthStatus.Degraded, "Aún no se completó ningún ciclo");

        var end = (DateTimeOffset)endObj;
        var elapsed = DateTimeOffset.UtcNow - end;
        var status = _lastCycleData.TryGetValue("cycle_status", out var s) ? s?.ToString() : "UNKNOWN";
        var error = _lastCycleData.TryGetValue("cycle_error", out var e) ? e?.ToString() : null;

        var healthStatus = status == "OK" ? HealthStatus.Healthy : HealthStatus.Critical;
        var msg = $"Último ciclo: {status} hace {elapsed:hh\\:mm\\:ss}";
        if (error != null) msg += $" · error: {error}";

        return new HealthCheckItem("last_cycle", healthStatus, msg);
    }

    private HealthCheckItem CheckCircuitBreakers()
    {
        var statuses = _circuitBreaker.GetAllStatuses();
        var open = statuses.Count(s => s.IsOpen);
        var total = statuses.Count;

        if (total == 0)
            return new HealthCheckItem("circuit_breakers", HealthStatus.Healthy, "Sin collectors registrados");

        return new HealthCheckItem(
            "circuit_breakers",
            open > 0 ? HealthStatus.Degraded : HealthStatus.Healthy,
            $"{open}/{total} collectors con circuit open");
    }

    private HealthCheckItem CheckMemory()
    {
        var process = Process.GetCurrentProcess();
        var workingSetMb = process.WorkingSet64 / 1024 / 1024;
        var gcMemoryMb = GC.GetTotalMemory(false) / 1024 / 1024;

        var status = workingSetMb > 500 ? HealthStatus.Degraded : HealthStatus.Healthy;
        return new HealthCheckItem("memory", status, $"WS={workingSetMb}MB, GC={gcMemoryMb}MB, Gen0={GC.CollectionCount(0)}, Gen1={GC.CollectionCount(1)}, Gen2={GC.CollectionCount(2)}");
    }

    private HealthCheckItem CheckDiskSpace()
    {
        try
        {
            var drive = new DriveInfo(Path.GetPathRoot(_rootPath)!);
            var freeGb = drive.AvailableFreeSpace / 1024 / 1024 / 1024;
            var totalGb = drive.TotalSize / 1024 / 1024 / 1024;
            var freePct = totalGb > 0 ? (double)freeGb / totalGb * 100 : 0;

            var status = freePct < 5 ? HealthStatus.Critical : freePct < 10 ? HealthStatus.Degraded : HealthStatus.Healthy;
            return new HealthCheckItem("disk", status, $"{freeGb}/{totalGb} GB libres ({freePct:F1}%)");
        }
        catch (Exception ex)
        {
            return new HealthCheckItem("disk", HealthStatus.Degraded, ex.Message);
        }
    }

    private HealthCheckItem CheckUptime()
    {
        return new HealthCheckItem("uptime", HealthStatus.Healthy, $"{_uptime.Elapsed:dd\\.hh\\:mm\\:ss}");
    }
}

public sealed record HealthCheckResult(
    HealthStatus Overall,
    DateTimeOffset Timestamp,
    TimeSpan Uptime,
    IReadOnlyList<HealthCheckItem> Checks);

public sealed record HealthCheckItem(
    string Name,
    HealthStatus Status,
    string Detail);

public enum HealthStatus
{
    Healthy = 0,
    Degraded = 1,
    Critical = 2
}