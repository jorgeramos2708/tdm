using System.Collections.Concurrent;
using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using TDM.Models;

namespace TDM.Persistence;

/// <summary>
/// Ventana caliente (2 h) de recursos y detección de tendencias de corto plazo.
/// Desde RC18.21 consume Metric.* como contrato primario; los regex sólo existen para
/// leer historial creado por versiones anteriores.
/// </summary>
public static partial class ResourceTrendAnalyzer
{
    private sealed record ResourceSample
    {
        public DateTimeOffset Timestamp { get; init; }
        public double? CpuPct { get; init; }
        public double? MemoryFreePct { get; init; }
        public IReadOnlyDictionary<string, double> ProcessRamMb { get; init; } = new Dictionary<string, double>();
        public IReadOnlyDictionary<string, double> ProcessHandles { get; init; } = new Dictionary<string, double>();
        public IReadOnlyDictionary<string, double> ProcessThreads { get; init; } = new Dictionary<string, double>();
    }

    private sealed class WindowState
    {
        public SemaphoreSlim Gate { get; } = new(1, 1);
        public List<ResourceSample> Samples { get; set; } = [];
        public bool Loaded { get; set; }
        public DateTimeOffset LastCompact { get; set; } = DateTimeOffset.MinValue;
    }

    private static readonly ConcurrentDictionary<string, WindowState> Windows = new(StringComparer.OrdinalIgnoreCase);
    private static readonly JsonSerializerOptions Json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
    private static readonly TimeSpan MaxWindow = TimeSpan.FromHours(2);
    private const int MaxSamples = 240;
    private const long CompactTriggerBytes = 4L * 1024 * 1024;

    public sealed record TrendResult(
        IReadOnlyList<DiagnosticFinding> Findings,
        IReadOnlyList<DiagnosticEvent> Events,
        string? WindowPath,
        int SampleCount);

    public static async Task<TrendResult> UpdateAndAnalyzeAsync(
        PersistentStateSnapshot snapshot,
        string rootPath,
        CancellationToken ct = default)
    {
        var current = Extract(snapshot);
        if (current is null) return new([], [], null, 0);

        var stateDir = Path.Combine(rootPath, "state");
        Directory.CreateDirectory(stateDir);
        var path = Path.Combine(stateDir, "resource-window.jsonl");
        var state = Windows.GetOrAdd(path, _ => new WindowState());
        await state.Gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (!state.Loaded)
            {
                state.Samples = await LoadInitialWindowAsync(path, Path.Combine(stateDir, "resource-window.json"), ct).ConfigureAwait(false);
                state.Loaded = true;
            }

            state.Samples.Add(current);
            Prune(state.Samples, current.Timestamp);
            await AppendJsonLineAsync(path, current, ct).ConfigureAwait(false);

            if (ShouldCompact(path, state, current.Timestamp))
            {
                await WriteAtomicJsonLinesAsync(path, state.Samples, ct).ConfigureAwait(false);
                state.LastCompact = current.Timestamp;
            }

            return Analyze(state.Samples, path);
        }
        finally
        {
            state.Gate.Release();
        }
    }

    private static void Prune(List<ResourceSample> samples, DateTimeOffset now)
    {
        var cutoff = now - MaxWindow;
        var pruned = samples
            .Where(x => x.Timestamp >= cutoff)
            .OrderBy(x => x.Timestamp)
            .GroupBy(x => x.Timestamp)
            .Select(g => g.Last())
            .TakeLast(MaxSamples)
            .ToList();
        samples.Clear();
        samples.AddRange(pruned);
    }

    private static bool ShouldCompact(string path, WindowState state, DateTimeOffset now)
    {
        try
        {
            if (!File.Exists(path) || new FileInfo(path).Length < CompactTriggerBytes) return false;
            return state.LastCompact == DateTimeOffset.MinValue || now - state.LastCompact >= TimeSpan.FromMinutes(30);
        }
        catch { return false; }
    }

    private static TrendResult Analyze(IReadOnlyList<ResourceSample> samples, string path)
    {
        var findings = new List<DiagnosticFinding>();
        var events = new List<DiagnosticEvent>();
        if (samples.Count < 3)
        {
            events.Add(StateEvent(samples, path, "Muestras insuficientes para calcular tendencia; se requieren al menos 3."));
            return new(findings, events, path, samples.Count);
        }

        var recent = samples.TakeLast(Math.Min(6, samples.Count)).ToList();
        var cpu = recent.Where(x => x.CpuPct.HasValue).Select(x => x.CpuPct!.Value).ToList();
        if (cpu.Count >= 3 && cpu.TakeLast(3).All(v => v >= 90))
        {
            findings.Add(new DiagnosticFinding(
                "RESOURCE-TREND-CPU-SUSTAINED",
                "CPU alta",
                DiagnosticSeverity.Advertencia,
                "TDM observó CPU elevada de forma sostenida en varias muestras consecutivas.",
                "La tendencia es preventiva y no se considera causa raíz sin errores/impacto temporal compatibles.",
                [new("Últimas muestras CPU", string.Join(" | ", cpu.TakeLast(6).Select(v => $"{v:0}%")))],
                ConfidenceLevel.Alta,
                Capa: DiagnosticLayer.Windows));
        }

        var memory = recent.Where(x => x.MemoryFreePct.HasValue).Select(x => x.MemoryFreePct!.Value).ToList();
        if (memory.Count >= 3)
        {
            var first = memory.First();
            var last = memory.Last();
            if (first - last >= 10 && last <= 20)
            {
                findings.Add(new DiagnosticFinding(
                    "RESOURCE-TREND-MEMORY-DOWN",
                    "Memoria libre",
                    DiagnosticSeverity.Advertencia,
                    "La memoria libre muestra una caída sostenida relevante entre las muestras recientes.",
                    "TDM detectó una reducción de al menos 10 puntos porcentuales y el valor actual está en 20% o menos. Debe correlacionarse con procesos y errores antes de atribuir causalidad.",
                    [new("Memoria libre inicial", $"{first:0.0}%"), new("Memoria libre actual", $"{last:0.0}%"), new("Muestras", string.Join(" | ", memory.Select(v => $"{v:0.0}%")))],
                    ConfidenceLevel.Alta,
                    Capa: DiagnosticLayer.Windows));
            }
        }

        foreach (var process in MetricNames(recent, x => x.ProcessRamMb))
        {
            var values = Values(recent, process, x => x.ProcessRamMb);
            if (values.Count < 3) continue;
            var first = values.First();
            var last = values.Last();
            if (last - first >= 256 && first > 0 && last >= first * 1.75)
            {
                findings.Add(new DiagnosticFinding(
                    $"RESOURCE-TREND-PROCESS-RAM-{Sanitize(process)}",
                    process,
                    DiagnosticSeverity.Advertencia,
                    "Un proceso relacionado con TSplus muestra crecimiento sostenido de memoria entre muestras recientes.",
                    "La tendencia puede orientar una investigación de fuga/presión de memoria, pero no demuestra por sí sola un defecto del proceso.",
                    [new("Proceso", process), new("RAM inicial", $"{first:0} MB"), new("RAM actual", $"{last:0} MB"), new("Muestras RAM", string.Join(" | ", values.Select(v => $"{v:0} MB")))],
                    ConfidenceLevel.Media,
                    Capa: DiagnosticLayer.Windows));
            }
        }

        foreach (var process in MetricNames(recent, x => x.ProcessHandles))
        {
            var values = Values(recent, process, x => x.ProcessHandles);
            if (values.Count < 3) continue;
            var first = values.First();
            var last = values.Last();
            if (first >= 100 && last - first >= 500 && last >= first * 1.5)
            {
                findings.Add(new DiagnosticFinding(
                    $"RESOURCE-TREND-PROCESS-HANDLES-{Sanitize(process)}",
                    process,
                    DiagnosticSeverity.Advertencia,
                    "Un proceso relacionado con TSplus muestra crecimiento sostenido de handles.",
                    "La señal puede anticipar una fuga de handles. Debe confirmarse con una ventana histórica mayor y evidencia del proceso antes de atribuir causalidad.",
                    [new("Handles iniciales", $"{first:0}"), new("Handles actuales", $"{last:0}")],
                    ConfidenceLevel.Media,
                    Capa: DiagnosticLayer.Windows));
            }
        }

        foreach (var process in MetricNames(recent, x => x.ProcessThreads))
        {
            var values = Values(recent, process, x => x.ProcessThreads);
            if (values.Count < 3) continue;
            var first = values.First();
            var last = values.Last();
            if (first >= 10 && last - first >= 50 && last >= first * 1.5)
            {
                findings.Add(new DiagnosticFinding(
                    $"RESOURCE-TREND-PROCESS-THREADS-{Sanitize(process)}",
                    process,
                    DiagnosticSeverity.Advertencia,
                    "Un proceso relacionado con TSplus muestra crecimiento sostenido de hilos.",
                    "La señal puede anticipar agotamiento de recursos o un patrón de fuga de threads. Requiere correlación antes de considerarse causal.",
                    [new("Hilos iniciales", $"{first:0}"), new("Hilos actuales", $"{last:0}")],
                    ConfidenceLevel.Media,
                    Capa: DiagnosticLayer.Windows));
            }
        }

        var summary = findings.Count == 0
            ? "No se detectó una tendencia preventiva sustentada en la ventana compacta de recursos."
            : $"Se detectaron {findings.Count} tendencia(s) preventiva(s) en recursos; requieren correlación antes de considerarse causa.";
        events.Add(StateEvent(samples, path, summary, findings.Count > 0 ? DiagnosticSeverity.Advertencia : DiagnosticSeverity.Informativo));
        return new(findings, events, path, samples.Count);
    }

    private static DiagnosticEvent StateEvent(IReadOnlyList<ResourceSample> samples, string path, string message,
        DiagnosticSeverity severity = DiagnosticSeverity.Informativo)
        => new(
            samples.LastOrDefault()?.Timestamp ?? DateTimeOffset.Now,
            "TDM",
            "Tendencia de recursos",
            DiagnosticLayer.Windows,
            severity,
            "TDM_RESOURCE_TREND",
            message,
            Evidencia:
            [
                new("Muestras conservadas", samples.Count.ToString(CultureInfo.InvariantCulture)),
                new("Ventana máxima", "2 horas / hasta 240 muestras"),
                new("Archivo TDM", path),
                new("Persistencia", "JSONL append-only; Metric.* como contrato primario"),
                new("Criterio", "Tendencia preventiva; no causa primaria automática")
            ]);

    private static ResourceSample? Extract(PersistentStateSnapshot snapshot)
    {
        var state = snapshot.Observations.LastOrDefault(x => x.Type.Equals(DiagnosticEventTypes.SystemResourceState, StringComparison.OrdinalIgnoreCase));
        if (state is null) return null;

        var typed = ParseTypedValues(state.Value);
        var cpu = Value(typed, ResourceMetricKeys.CpuPercent);
        var memory = Value(typed, ResourceMetricKeys.MemoryFreePercent);
        var processRam = ProcessValues(typed, "RamMb");
        var processHandles = ProcessValues(typed, "Handles");
        var processThreads = ProcessValues(typed, "Threads");

        // Compatibilidad: ventanas/snapshots anteriores no contenían Metric.*.
        if (!cpu.HasValue) cpu = TryPercent(CpuRegex(), state.Value);
        if (!memory.HasValue) memory = TryPercent(MemoryRegex(), state.Value);
        if (processRam.Count == 0)
        {
            foreach (Match match in ProcessRegex().Matches(state.Value))
            {
                var key = $"{match.Groups["name"].Value.Trim()}[PID {match.Groups["pid"].Value}]";
                if (TryNumber(match.Groups["ram"].Value, out var ram)) processRam[key] = ram;
            }
        }

        return new ResourceSample
        {
            Timestamp = snapshot.CapturedAt,
            CpuPct = cpu,
            MemoryFreePct = memory,
            ProcessRamMb = processRam,
            ProcessHandles = processHandles,
            ProcessThreads = processThreads
        };
    }

    internal static Dictionary<string, double> ParseTypedValues(string value)
    {
        var output = new Dictionary<string, double>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrWhiteSpace(value)) return output;
        foreach (var part in value.Split(" | ", StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var separator = part.IndexOf('=');
            if (separator <= 0) continue;
            var key = part[..separator].Trim();
            if (!key.StartsWith("Metric.", StringComparison.OrdinalIgnoreCase)) continue;
            if (TryNumber(part[(separator + 1)..].Trim(), out var number)) output[key] = number;
        }
        return output;
    }

    private static Dictionary<string, double> ProcessValues(IReadOnlyDictionary<string, double> typed, string suffix)
    {
        var output = new Dictionary<string, double>(StringComparer.OrdinalIgnoreCase);
        const string prefix = "Metric.Process.";
        foreach (var pair in typed.Where(x => x.Key.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)
                                               && x.Key.EndsWith("." + suffix, StringComparison.OrdinalIgnoreCase)))
        {
            var middle = pair.Key[prefix.Length..^(suffix.Length + 1)];
            var dot = middle.LastIndexOf('.');
            if (dot <= 0) continue;
            var process = middle[..dot].Replace('_', ' ');
            var pid = middle[(dot + 1)..];
            output[$"{process}[PID {pid}]"] = pair.Value;
        }
        return output;
    }

    private static double? Value(IReadOnlyDictionary<string, double> values, string key)
        => values.TryGetValue(key, out var result) ? result : null;

    private static double? TryPercent(Regex regex, string value)
    {
        var match = regex.Match(value);
        if (!match.Success) return null;
        return TryNumber(match.Groups["v"].Value, out var parsed) ? parsed : null;
    }

    private static bool TryNumber(string value, out double parsed)
        => double.TryParse(value.Replace(',', '.'), NumberStyles.Float, CultureInfo.InvariantCulture, out parsed);

    private static IEnumerable<string> MetricNames(IEnumerable<ResourceSample> samples, Func<ResourceSample, IReadOnlyDictionary<string, double>> selector)
        => samples.SelectMany(s => selector(s).Keys).Distinct(StringComparer.OrdinalIgnoreCase);

    private static List<double> Values(IEnumerable<ResourceSample> samples, string name, Func<ResourceSample, IReadOnlyDictionary<string, double>> selector)
        => samples.Select(s => selector(s).TryGetValue(name, out var v) ? (double?)v : null)
            .Where(v => v.HasValue)
            .Select(v => v!.Value)
            .ToList();

    private static async Task<List<ResourceSample>> LoadInitialWindowAsync(string path, string legacyPath, CancellationToken ct)
    {
        var output = new List<ResourceSample>();
        if (File.Exists(path))
            output.AddRange(await ReadJsonLinesAsync(path, ct).ConfigureAwait(false));
        else if (File.Exists(legacyPath))
        {
            try
            {
                await using var stream = new FileStream(legacyPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete,
                    32 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
                var legacy = await JsonSerializer.DeserializeAsync<List<ResourceSample>>(stream, Json, ct).ConfigureAwait(false);
                if (legacy is not null) output.AddRange(legacy);
            }
            catch (JsonException) { }
            catch (IOException) { }
        }
        Prune(output, DateTimeOffset.Now);
        return output;
    }

    private static async Task<List<ResourceSample>> ReadJsonLinesAsync(string path, CancellationToken ct)
    {
        var output = new List<ResourceSample>();
        try
        {
            await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete,
                32 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
            using var reader = new StreamReader(stream, Encoding.UTF8, true, 32 * 1024, false);
            while (await reader.ReadLineAsync(ct).ConfigureAwait(false) is { } line)
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                try
                {
                    var sample = JsonSerializer.Deserialize<ResourceSample>(line, Json);
                    if (sample is not null) output.Add(sample);
                }
                catch (JsonException) { }
            }
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
        return output;
    }

    private static async Task AppendJsonLineAsync(string path, ResourceSample sample, CancellationToken ct)
    {
        var payload = JsonSerializer.SerializeToUtf8Bytes(sample, Json);
        await using var stream = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.Read,
            16 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
        await stream.WriteAsync(payload, ct).ConfigureAwait(false);
        await stream.WriteAsync("\n"u8.ToArray(), ct).ConfigureAwait(false);
        await stream.FlushAsync(ct).ConfigureAwait(false);
    }

    private static async Task WriteAtomicJsonLinesAsync(string path, IReadOnlyList<ResourceSample> samples, CancellationToken ct)
    {
        var tmp = path + ".tmp-" + Guid.NewGuid().ToString("N");
        try
        {
            await using (var stream = new FileStream(tmp, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                32 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan))
            {
                foreach (var sample in samples.TakeLast(MaxSamples))
                {
                    var payload = JsonSerializer.SerializeToUtf8Bytes(sample, Json);
                    await stream.WriteAsync(payload, ct).ConfigureAwait(false);
                    await stream.WriteAsync("\n"u8.ToArray(), ct).ConfigureAwait(false);
                }
                await stream.FlushAsync(ct).ConfigureAwait(false);
            }
            File.Move(tmp, path, true);
        }
        finally
        {
            try { if (File.Exists(tmp)) File.Delete(tmp); } catch { }
        }
    }

    private static string Sanitize(string value)
        => new(value.Where(char.IsLetterOrDigit).Take(40).ToArray());

    [GeneratedRegex(@"CPU=Carga instantánea aproximada\s+(?<v>\d+(?:[\.,]\d+)?)%", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex CpuRegex();

    [GeneratedRegex(@"Memoria física=.*?\((?<v>\d+(?:[\.,]\d+)?)% libre\)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex MemoryRegex();

    [GeneratedRegex(@"(?<name>[A-Za-z0-9_.-]+)\[PID\s+(?<pid>\d+)\]\s+RAM=(?<ram>\d+(?:[\.,]\d+)?)\s+MB", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex ProcessRegex();
}
