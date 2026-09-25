using System.Text;
using System.Text.Json;
using TDM.Models;

namespace TDM.Persistence;

/// <summary>
/// Línea base adaptativa por máquina (algoritmo de Welford): aprende la media y varianza de
/// CPU (%) y memoria libre (%) observadas por TDM y detecta desvíos ≥3σ respecto a lo habitual
/// en ESTE equipo, en vez de depender solo de umbrales fijos globales. Sin memoria suficiente
/// (<see cref="MinSamples"/>) solo aprende, sin emitir hallazgos. Solo lectura/escritura de su
/// propio archivo; jamás modifica configuración del sistema.
/// </summary>
public sealed class AdaptiveBaselineStore
{
    public const int MinSamples = 20;
    private const double MinBandPp = 5.0;

    private readonly JsonSerializerOptions _json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase, WriteIndented = true };
    public string Path { get; }

    public AdaptiveBaselineStore(string? rootPath = null)
    {
        var root = string.IsNullOrWhiteSpace(rootPath) ? LocalStateStore.DefaultRootPath : rootPath;
        Path = System.IO.Path.Combine(root, "state", "adaptive-baseline.json");
    }

    private sealed record BaselineState(
        int Count,
        double MeanCpu,
        double M2Cpu,
        double MeanMemFree,
        double M2MemFree,
        DateTimeOffset UpdatedAt);

    /// <summary>
    /// Evalúa la muestra actual contra la línea base y luego la incorpora. Devuelve hallazgos
    /// solo cuando hay desvío anómalo con historial suficiente; en aprendizaje retorna vacío.
    /// </summary>
    public async Task<IReadOnlyList<DiagnosticFinding>> EvaluateAndUpdateAsync(
        double? cpuPercent,
        double? memoryFreePercent,
        CancellationToken ct = default)
    {
        var state = await LoadAsync(ct).ConfigureAwait(false);
        var findings = new List<DiagnosticFinding>();

        if (state.Count >= MinSamples)
        {
            var cpuAnomaly = CpuAnomaly(state, cpuPercent);
            if (cpuAnomaly is not null) findings.Add(cpuAnomaly);
            var memAnomaly = MemoryAnomaly(state, memoryFreePercent);
            if (memAnomaly is not null) findings.Add(memAnomaly);
        }

        var updated = state;
        if (IsValidPercent(cpuPercent) || IsValidPercent(memoryFreePercent))
        {
            updated = UpdateStats(state, cpuPercent, memoryFreePercent);
            await SaveAsync(updated, ct).ConfigureAwait(false);
        }

        return findings;
    }

    private static DiagnosticFinding? CpuAnomaly(BaselineState state, double? cpu)
    {
        if (!IsValidPercent(cpu)) return null;
        var v = cpu!.Value;
        var sigma = StdDev(state.M2Cpu, state.Count);
        var threshold = state.MeanCpu + Math.Max(3 * sigma, MinBandPp);
        if (v <= threshold) return null;
        var z = sigma > 0 ? (v - state.MeanCpu) / sigma : double.PositiveInfinity;
        return new DiagnosticFinding(
            "ADAPTIVE-BASELINE-CPU-ANOMALY",
            "CPU del servidor",
            DiagnosticSeverity.Advertencia,
            $"La CPU ({v:0.0}%) supera lo habitual en este equipo (media {state.MeanCpu:0.0}%, z={FormatZ(z)}).",
            "Desvío respecto a la línea base adaptativa local (algoritmo de Welford). No sustituye los umbrales globales configurados; indica comportamiento anómalo para ESTA máquina.",
            [
                new EvidenceItem("CPU actual (%)", v.ToString("0.0")),
                new EvidenceItem("Media histórica CPU (%)", state.MeanCpu.ToString("0.0")),
                new EvidenceItem("Desviación histórica (σ)", sigma.ToString("0.0")),
                new EvidenceItem("Muestras acumuladas", state.Count.ToString())
            ],
            ConfidenceLevel.Media,
            Capa: DiagnosticLayer.Windows);
    }

    private static DiagnosticFinding? MemoryAnomaly(BaselineState state, double? memFree)
    {
        if (!IsValidPercent(memFree)) return null;
        var v = memFree!.Value;
        var sigma = StdDev(state.M2MemFree, state.Count);
        var threshold = state.MeanMemFree - Math.Max(3 * sigma, MinBandPp);
        if (v >= threshold) return null;
        var z = sigma > 0 ? (state.MeanMemFree - v) / sigma : double.PositiveInfinity;
        return new DiagnosticFinding(
            "ADAPTIVE-BASELINE-MEMORY-ANOMALY",
            "Memoria del servidor",
            DiagnosticSeverity.Advertencia,
            $"La memoria libre ({v:0.0}%) está por debajo de lo habitual en este equipo (media {state.MeanMemFree:0.0}%, z={FormatZ(z)}).",
            "Desvío respecto a la línea base adaptativa local (algoritmo de Welford). No sustituye los umbrales globales configurados; indica comportamiento anómalo para ESTA máquina.",
            [
                new EvidenceItem("Memoria libre actual (%)", v.ToString("0.0")),
                new EvidenceItem("Media histórica libre (%)", state.MeanMemFree.ToString("0.0")),
                new EvidenceItem("Desviación histórica (σ)", sigma.ToString("0.0")),
                new EvidenceItem("Muestras acumuladas", state.Count.ToString())
            ],
            ConfidenceLevel.Media,
            Capa: DiagnosticLayer.Windows);
    }

    private static BaselineState UpdateStats(BaselineState state, double? cpu, double? memFree)
    {
        var count = state.Count + 1;
        var (meanCpu, m2Cpu) = Welford(state.Count, state.MeanCpu, state.M2Cpu, cpu);
        var (meanMem, m2Mem) = Welford(state.Count, state.MeanMemFree, state.M2MemFree, memFree);
        return new BaselineState(count, meanCpu, m2Cpu, meanMem, m2Mem, DateTimeOffset.Now);
    }

    private static (double Mean, double M2) Welford(int n, double mean, double m2, double? value)
    {
        if (!IsValidPercent(value)) return (mean, m2);
        var v = value!.Value;
        var next = n + 1;
        var delta = v - mean;
        var newMean = mean + delta / next;
        return (newMean, m2 + delta * (v - newMean));
    }

    private static double StdDev(double m2, int n) => n > 1 && m2 > 0 ? Math.Sqrt(m2 / (n - 1)) : 0d;
    private static bool IsValidPercent(double? v) => v.HasValue && double.IsFinite(v.Value) && v.Value >= 0 && v.Value <= 100;
    private static string FormatZ(double z) => double.IsInfinity(z) ? "∞" : z.ToString("0.0");

    private async Task<BaselineState> LoadAsync(CancellationToken ct)
    {
        if (!File.Exists(Path)) return new BaselineState(0, 0, 0, 0, 0, DateTimeOffset.Now);
        try
        {
            await using var stream = new FileStream(Path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete,
                16 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
            return await JsonSerializer.DeserializeAsync<BaselineState>(stream, _json, ct).ConfigureAwait(false)
                ?? new BaselineState(0, 0, 0, 0, 0, DateTimeOffset.Now);
        }
        catch (JsonException) { return new BaselineState(0, 0, 0, 0, 0, DateTimeOffset.Now); }
        catch (IOException) { return new BaselineState(0, 0, 0, 0, 0, DateTimeOffset.Now); }
        catch (UnauthorizedAccessException) { return new BaselineState(0, 0, 0, 0, 0, DateTimeOffset.Now); }
    }

    private async Task SaveAsync(BaselineState state, CancellationToken ct)
    {
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(Path)!);
        var tmp = Path + ".tmp-" + Guid.NewGuid().ToString("N");
        try
        {
            await using (var stream = new FileStream(tmp, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                16 * 1024, FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await JsonSerializer.SerializeAsync(stream, state, _json, ct).ConfigureAwait(false);
                await stream.FlushAsync(ct).ConfigureAwait(false);
                stream.Flush(true);
            }
            File.Move(tmp, Path, true);
        }
        finally { try { if (File.Exists(tmp)) File.Delete(tmp); } catch { } }
    }
}
