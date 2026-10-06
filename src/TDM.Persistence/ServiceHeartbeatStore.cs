using System.Text.Json;
using TDM.Models;

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
    public static readonly TimeSpan DefaultFreshness = TimeSpan.FromSeconds(150);

    public static bool IsFresh(TdmServiceHeartbeat? heartbeat, TimeSpan? maxAge = null)
        => heartbeat is not null && DateTimeOffset.Now - heartbeat.Timestamp <= (maxAge ?? DefaultFreshness);

    /// <summary>
    /// C5 (auditoría de efectividad, Fase 31): estado declarable del latido del servicio.
    /// Sin archivo no hay servicio instalado (portable/no instalado) y no hay nada que
    /// declarar; con archivo fresco se expone el estado real (RUNNING/DEGRADED/STOPPED);
    /// rancio ⇒ STALLED, porque el monitoreo 24/7 no puede afirmarse vivo sin latido.
    /// </summary>
    public static string? DescribeStatus(TdmServiceHeartbeat? heartbeat, TimeSpan? maxAge = null)
        => heartbeat is null ? null
            : IsFresh(heartbeat, maxAge) ? heartbeat.Status
            : "STALLED";

    /// <summary>
    /// C5 (auditoría de efectividad, Fase 31): hallazgo Advertencia cuando el latido existe
    /// pero dejó de actualizarse. Deja el hueco del monitoreo 24/7 declarado en el informe
    /// (antes la ventana se leía como «sin novedad») y documenta cómo verificar la
    /// recuperación del servicio declarada por el instalador (sc failure/failureflag).
    /// </summary>
    public static DiagnosticFinding? StalledFinding(TdmServiceHeartbeat? heartbeat, DateTimeOffset now, TimeSpan? maxAge = null)
    {
        if (heartbeat is null || IsFresh(heartbeat, maxAge)) return null;
        var threshold = maxAge ?? DefaultFreshness;
        var age = now - heartbeat.Timestamp;
        return new DiagnosticFinding(
            "TDM-SERVICE-HEARTBEAT-STALLED",
            "TDM.Service",
            DiagnosticSeverity.Advertencia,
            "Monitoreo 24/7 STALLED: el latido del servicio dejó de actualizarse",
            $"La última señal del latido de TDM.Service tiene {age.TotalSeconds:F0} s y el umbral de frescura es {(int)threshold.TotalSeconds} s. El servicio sigue instalado pero su ciclo no escribe latido: TDM declara el hueco en lugar de leer la ventana como «sin novedad».",
            [
                new EvidenceItem("Última señal", heartbeat.Timestamp.ToLocalTime().ToString("dd/MM/yyyy HH:mm:ss")),
                new EvidenceItem("Edad del latido (s)", ((int)age.TotalSeconds).ToString()),
                new EvidenceItem("Umbral de frescura (s)", ((int)threshold.TotalSeconds).ToString()),
                new EvidenceItem("Estado en el latido", heartbeat.Status),
                new EvidenceItem("PID del proceso", heartbeat.ProcessId.ToString()),
                new EvidenceItem("Muestras completadas", heartbeat.CompletedSamples.ToString())
            ],
            ConfidenceLevel.Alta,
            FuenteOficial: "Microsoft — sc failure (acciones de recuperación del servicio)",
            UrlOficial: "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc742019(v=ws.11)",
            SolucionSugerida: "Reinicie TDM.Service y valide la recuperación declarada con «sc qfailure TDM.Service» (el instalador TDM configura sc failure y failureflag) y el latido en %ProgramData%\\TSplus Diagnostic Monitor\\Data\\runtime\\service-heartbeat.json; si el servicio ya no está instalado, elimine el archivo de latido obsoleto.",
            Capa: DiagnosticLayer.Desconocida);
    }
}
