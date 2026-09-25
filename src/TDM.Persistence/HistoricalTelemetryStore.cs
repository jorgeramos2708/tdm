using System.Collections.Concurrent;
using System.Globalization;
using System.Text;
using System.Text.Json;
using TDM.Models;

namespace TDM.Persistence;

/// <summary>
/// Segundo nivel de telemetría: conserva agregados horarios de baja resolución durante
/// 90 días. Complementa la ventana caliente de 2-4 horas y permite detectar degradaciones
/// lentas sin mantener muestras de alta resolución indefinidamente.
/// </summary>
public sealed class HistoricalTelemetryStore
{
    public sealed record MetricStats(
        int Count,
        double Min,
        double Max,
        double Average,
        double P50,
        double P95,
        double First,
        double Last);

    public sealed record HourlyTelemetry(
        DateTimeOffset HourStart,
        IReadOnlyDictionary<string, MetricStats> Metrics);

    private sealed record CurrentHour
    {
        public DateTimeOffset HourStart { get; init; }
        public Dictionary<string, List<double>> Metrics { get; init; } = new(StringComparer.OrdinalIgnoreCase);
    }

    private sealed class StoreState
    {
        public SemaphoreSlim Gate { get; } = new(1, 1);
        public bool Loaded { get; set; }
        public CurrentHour? Current { get; set; }
        public List<HourlyTelemetry> History { get; set; } = [];
        public int SamplesSinceCurrentPersist { get; set; }
        public DateTimeOffset LastCleanup { get; set; } = DateTimeOffset.MinValue;
    }

    public sealed record HistoricalTrendResult(
        IReadOnlyList<DiagnosticFinding> Findings,
        IReadOnlyList<DiagnosticEvent> Events,
        string HistoryPath,
        int HourCount);

    private static readonly ConcurrentDictionary<string, StoreState> States = new(StringComparer.OrdinalIgnoreCase);
    private static readonly JsonSerializerOptions Json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase, WriteIndented = false };
    private static readonly TimeSpan Retention = TimeSpan.FromDays(90);
    private const int MaxValuesPerMetricPerHour = 120;
    private const int CurrentPersistEverySamples = 5;

    private readonly string _stateDirectory;
    public string HistoryPath => Path.Combine(_stateDirectory, "historical-hourly.jsonl");
    public string CurrentHourPath => Path.Combine(_stateDirectory, "historical-current-hour.json");

    public HistoricalTelemetryStore(string rootPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(rootPath);
        _stateDirectory = Path.Combine(rootPath, "state");
        Directory.CreateDirectory(_stateDirectory);
    }

    public async Task<HistoricalTrendResult> UpdateAndAnalyzeAsync(PersistentStateSnapshot snapshot, CancellationToken ct = default)
    {
        var values = ExtractMetrics(snapshot);
        var state = States.GetOrAdd(HistoryPath, _ => new StoreState());
        await state.Gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (!state.Loaded)
            {
                state.History = await ReadHistoryAsync(ct).ConfigureAwait(false);
                state.Current = await ReadCurrentAsync(ct).ConfigureAwait(false);
                state.Loaded = true;
            }

            var hour = FloorHour(snapshot.CapturedAt);
            if (state.Current is not null && state.Current.HourStart != hour)
            {
                var finalized = Finalize(state.Current);
                if (finalized.Metrics.Count > 0)
                {
                    state.History.RemoveAll(x => x.HourStart == finalized.HourStart);
                    state.History.Add(finalized);
                    state.History = state.History.OrderBy(x => x.HourStart).ToList();
                    await AppendHourAsync(finalized, ct).ConfigureAwait(false);
                }
                state.Current = null;
                state.SamplesSinceCurrentPersist = 0;
            }

            state.Current ??= new CurrentHour { HourStart = hour };
            foreach (var pair in values)
            {
                if (!double.IsFinite(pair.Value)) continue;
                if (!state.Current.Metrics.TryGetValue(pair.Key, out var list))
                {
                    list = [];
                    state.Current.Metrics[pair.Key] = list;
                }
                list.Add(pair.Value);
                if (list.Count > MaxValuesPerMetricPerHour)
                    list.RemoveRange(0, list.Count - MaxValuesPerMetricPerHour);
            }

            state.SamplesSinceCurrentPersist++;
            if (state.SamplesSinceCurrentPersist >= CurrentPersistEverySamples)
            {
                await WriteCurrentAtomicAsync(state.Current, ct).ConfigureAwait(false);
                state.SamplesSinceCurrentPersist = 0;
            }

            var now = snapshot.CapturedAt;
            if (state.LastCleanup == DateTimeOffset.MinValue || now - state.LastCleanup >= TimeSpan.FromHours(6))
            {
                var cutoff = now - Retention;
                state.History = state.History.Where(x => x.HourStart >= cutoff).OrderBy(x => x.HourStart).ToList();
                await RewriteHistoryAsync(state.History, ct).ConfigureAwait(false);
                state.LastCleanup = now;
            }

            var currentSummary = Finalize(state.Current);
            return Analyze(state.History, currentSummary, snapshot.CapturedAt);
        }
        finally
        {
            state.Gate.Release();
        }
    }

    public async Task<IReadOnlyList<HourlyTelemetry>> ReadAsync(CancellationToken ct = default)
    {
        var history = await ReadHistoryAsync(ct).ConfigureAwait(false);
        var current = await ReadCurrentAsync(ct).ConfigureAwait(false);
        if (current is not null)
        {
            var finalized = Finalize(current);
            history.RemoveAll(x => x.HourStart == finalized.HourStart);
            history.Add(finalized);
        }
        return history.OrderBy(x => x.HourStart).ToList();
    }

    private HistoricalTrendResult Analyze(IReadOnlyList<HourlyTelemetry> history, HourlyTelemetry current, DateTimeOffset now)
    {
        var hours = history.Where(x => x.HourStart >= now - Retention).Append(current)
            .GroupBy(x => x.HourStart)
            .Select(g => g.Last())
            .OrderBy(x => x.HourStart)
            .ToList();
        var findings = new List<DiagnosticFinding>();

        foreach (var key in MetricKeys(hours, ".FreeBytes", "Metric.Disk."))
        {
            var points = MetricPoints(hours, key, TimeSpan.FromDays(14));
            if (points.Count < 6 || points[^1].Timestamp - points[0].Timestamp < TimeSpan.FromHours(6)) continue;
            var slopePerHour = LinearSlopePerHour(points);
            var currentFree = points[^1].Value;
            if (slopePerHour >= -1 || currentFree <= 0) continue;
            var daysRemaining = currentFree / (-slopePerHour * 24d);
            if (!double.IsFinite(daysRemaining) || daysRemaining > 30) continue;

            var drive = key.Split('.')[2];
            var severity = daysRemaining <= 3 ? DiagnosticSeverity.Critico : DiagnosticSeverity.Advertencia;
            findings.Add(new DiagnosticFinding(
                $"RESOURCE-HISTORICAL-DISK-{drive}",
                $"Disco {drive}:",
                severity,
                $"La tendencia histórica estima agotamiento del espacio libre en aproximadamente {daysRemaining:0.0} día(s) si continúa el ritmo actual.",
                "La proyección usa regresión lineal sobre agregados horarios recientes. Es una señal preventiva; cambios de carga o limpieza planificada pueden alterar la fecha real.",
                [
                    new("Espacio libre actual", FormatBytes(currentFree)),
                    new("Tendencia", $"{FormatBytes(Math.Abs(slopePerHour) * 24d)}/día de consumo"),
                    new("Horizonte estimado", $"{daysRemaining:0.0} días"),
                    new("Puntos horarios", points.Count.ToString(CultureInfo.InvariantCulture))
                ],
                ConfidenceLevel.Media,
                Capa: DiagnosticLayer.Windows));
        }

        foreach (var key in MetricKeys(hours, ".Handles", "Metric.Process."))
            AddGrowthFinding(findings, hours, key, "handles", minAbsoluteGrowth: 1000, minRatio: 1.5, TimeSpan.FromDays(7));
        foreach (var key in MetricKeys(hours, ".Threads", "Metric.Process."))
            AddGrowthFinding(findings, hours, key, "hilos", minAbsoluteGrowth: 100, minRatio: 1.5, TimeSpan.FromDays(7));

        var tcpPoints = MetricPoints(hours, ResourceMetricKeys.TcpEphemeralUsagePercent, TimeSpan.FromHours(12));
        if (tcpPoints.Count >= 3 && tcpPoints.TakeLast(3).All(x => x.Value >= 70))
        {
            findings.Add(new DiagnosticFinding(
                "RESOURCE-HISTORICAL-TCP-EPHEMERAL",
                "TCP / puertos efímeros",
                tcpPoints.TakeLast(3).All(x => x.Value >= 85) ? DiagnosticSeverity.Critico : DiagnosticSeverity.Advertencia,
                "La presión de puertos TCP efímeros se mantiene elevada en varios agregados horarios.",
                "Una presión sostenida es más relevante que una fotografía aislada y debe correlacionarse con timeouts/conexiones fallidas.",
                [new("Últimos agregados", string.Join(" | ", tcpPoints.TakeLast(6).Select(x => $"{x.Value:0.0}%")))],
                ConfidenceLevel.Media,
                Capa: DiagnosticLayer.Red));
        }

        var evt = new DiagnosticEvent(
            now,
            "TDM",
            "Telemetría histórica",
            DiagnosticLayer.Windows,
            findings.Count > 0 ? DiagnosticSeverity.Advertencia : DiagnosticSeverity.Informativo,
            "TDM_HISTORICAL_TELEMETRY",
            findings.Count == 0
                ? "La serie histórica horaria no presenta tendencias preventivas que superen los criterios actuales."
                : $"La serie histórica produjo {findings.Count} señal(es) preventiva(s) de largo plazo.",
            Evidencia:
            [
                new("Retención", "90 días"),
                new("Resolución", "agregado horario"),
                new("Horas disponibles", hours.Count.ToString(CultureInfo.InvariantCulture)),
                new("Archivo", HistoryPath),
                new("Estadísticos", "min/max/promedio/P50/P95/primero/último")
            ]);
        return new(findings, [evt], HistoryPath, hours.Count);
    }

    private static void AddGrowthFinding(
        ICollection<DiagnosticFinding> findings,
        IReadOnlyList<HourlyTelemetry> hours,
        string key,
        string label,
        double minAbsoluteGrowth,
        double minRatio,
        TimeSpan lookback)
    {
        var points = MetricPoints(hours, key, lookback);
        if (points.Count < 6) return;
        var first = points[0].Value;
        var last = points[^1].Value;
        if (first <= 0 || last - first < minAbsoluteGrowth || last < first * minRatio) return;
        var slope = LinearSlopePerHour(points);
        if (slope <= 0) return;

        var suffix = key.Split('.').TakeLast(3).ToArray();
        var process = suffix.Length >= 3 ? $"{suffix[0]}[PID {suffix[1]}]" : key;
        findings.Add(new DiagnosticFinding(
            $"RESOURCE-HISTORICAL-{label.ToUpperInvariant()}-{Sanitize(process)}",
            process,
            DiagnosticSeverity.Advertencia,
            $"La serie histórica muestra crecimiento sostenido de {label} en un proceso relacionado con TSplus.",
            "La tendencia se calcula sobre agregados horarios y busca fugas lentas que una ventana de dos horas puede no revelar.",
            [new("Inicial", $"{first:0}"), new("Actual", $"{last:0}"), new("Pendiente", $"{slope:0.0}/hora"), new("Puntos", points.Count.ToString(CultureInfo.InvariantCulture))],
            ConfidenceLevel.Media,
            Capa: DiagnosticLayer.Windows));
    }

    private static Dictionary<string, double> ExtractMetrics(PersistentStateSnapshot snapshot)
    {
        var state = snapshot.Observations.LastOrDefault(x => x.Type.Equals(DiagnosticEventTypes.SystemResourceState, StringComparison.OrdinalIgnoreCase));
        return state is null ? new Dictionary<string, double>(StringComparer.OrdinalIgnoreCase) : ResourceTrendAnalyzer.ParseTypedValues(state.Value);
    }

    private static HourlyTelemetry Finalize(CurrentHour current)
    {
        var metrics = current.Metrics
            .Where(x => x.Value.Count > 0)
            .ToDictionary(x => x.Key, x => Stats(x.Value), StringComparer.OrdinalIgnoreCase);
        return new HourlyTelemetry(current.HourStart, metrics);
    }

    private static MetricStats Stats(IReadOnlyList<double> values)
    {
        var ordered = values.OrderBy(x => x).ToArray();
        var avg = values.Average();
        return new MetricStats(values.Count, ordered[0], ordered[^1], avg,
            Percentile(ordered, 0.50), Percentile(ordered, 0.95), values[0], values[^1]);
    }

    private static double Percentile(IReadOnlyList<double> sorted, double p)
    {
        if (sorted.Count == 0) return 0;
        if (sorted.Count == 1) return sorted[0];
        var position = (sorted.Count - 1) * p;
        var lower = (int)Math.Floor(position);
        var upper = (int)Math.Ceiling(position);
        if (lower == upper) return sorted[lower];
        var fraction = position - lower;
        return sorted[lower] + (sorted[upper] - sorted[lower]) * fraction;
    }

    private sealed record MetricPoint(DateTimeOffset Timestamp, double Value);

    private static List<MetricPoint> MetricPoints(IReadOnlyList<HourlyTelemetry> hours, string key, TimeSpan lookback)
    {
        if (hours.Count == 0) return [];
        var end = hours[^1].HourStart;
        var start = end - lookback;
        return hours.Where(x => x.HourStart >= start && x.Metrics.ContainsKey(key))
            .Select(x => new MetricPoint(x.HourStart, x.Metrics[key].Average))
            .OrderBy(x => x.Timestamp)
            .ToList();
    }

    private static IEnumerable<string> MetricKeys(IReadOnlyList<HourlyTelemetry> hours, string suffix, string prefix)
        => hours.SelectMany(x => x.Metrics.Keys)
            .Where(x => x.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) && x.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
            .Distinct(StringComparer.OrdinalIgnoreCase);

    private static double LinearSlopePerHour(IReadOnlyList<MetricPoint> points)
    {
        if (points.Count < 2) return 0;
        var origin = points[0].Timestamp;
        var xs = points.Select(x => (x.Timestamp - origin).TotalHours).ToArray();
        var ys = points.Select(x => x.Value).ToArray();
        var meanX = xs.Average();
        var meanY = ys.Average();
        var numerator = 0d;
        var denominator = 0d;
        for (var i = 0; i < xs.Length; i++)
        {
            var dx = xs[i] - meanX;
            numerator += dx * (ys[i] - meanY);
            denominator += dx * dx;
        }
        return denominator <= 0 ? 0 : numerator / denominator;
    }

    private async Task<List<HourlyTelemetry>> ReadHistoryAsync(CancellationToken ct)
    {
        var output = new List<HourlyTelemetry>();
        if (!File.Exists(HistoryPath)) return output;
        try
        {
            await using var stream = new FileStream(HistoryPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete,
                32 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
            using var reader = new StreamReader(stream, Encoding.UTF8, true, 32 * 1024, false);
            while (await reader.ReadLineAsync(ct).ConfigureAwait(false) is { } line)
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                try
                {
                    var item = JsonSerializer.Deserialize<HourlyTelemetry>(line, Json);
                    if (item is not null) output.Add(item);
                }
                catch (JsonException) { }
            }
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
        return output.GroupBy(x => x.HourStart).Select(g => g.Last()).OrderBy(x => x.HourStart).ToList();
    }

    private async Task<CurrentHour?> ReadCurrentAsync(CancellationToken ct)
    {
        if (!File.Exists(CurrentHourPath)) return null;
        try
        {
            await using var stream = new FileStream(CurrentHourPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete,
                16 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
            return await JsonSerializer.DeserializeAsync<CurrentHour>(stream, Json, ct).ConfigureAwait(false);
        }
        catch (JsonException) { return null; }
        catch (IOException) { return null; }
        catch (UnauthorizedAccessException) { return null; }
    }

    private async Task AppendHourAsync(HourlyTelemetry hour, CancellationToken ct)
    {
        var payload = JsonSerializer.SerializeToUtf8Bytes(hour, Json);
        await using var stream = new FileStream(HistoryPath, FileMode.Append, FileAccess.Write, FileShare.Read,
            16 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
        await stream.WriteAsync(payload, ct).ConfigureAwait(false);
        await stream.WriteAsync("\n"u8.ToArray(), ct).ConfigureAwait(false);
        await stream.FlushAsync(ct).ConfigureAwait(false);
    }

    private Task WriteCurrentAtomicAsync(CurrentHour current, CancellationToken ct)
        => WriteAtomicJsonAsync(CurrentHourPath, current, ct);

    private async Task RewriteHistoryAsync(IReadOnlyList<HourlyTelemetry> history, CancellationToken ct)
    {
        var tmp = HistoryPath + ".tmp-" + Guid.NewGuid().ToString("N");
        try
        {
            await using (var stream = new FileStream(tmp, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                32 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan))
            {
                foreach (var item in history.OrderBy(x => x.HourStart))
                {
                    var payload = JsonSerializer.SerializeToUtf8Bytes(item, Json);
                    await stream.WriteAsync(payload, ct).ConfigureAwait(false);
                    await stream.WriteAsync("\n"u8.ToArray(), ct).ConfigureAwait(false);
                }
                await stream.FlushAsync(ct).ConfigureAwait(false);
            }
            File.Move(tmp, HistoryPath, true);
        }
        finally { try { if (File.Exists(tmp)) File.Delete(tmp); } catch { } }
    }

    private static async Task WriteAtomicJsonAsync<T>(string path, T value, CancellationToken ct)
    {
        var tmp = path + ".tmp-" + Guid.NewGuid().ToString("N");
        try
        {
            await using (var stream = new FileStream(tmp, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                16 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan))
            {
                await JsonSerializer.SerializeAsync(stream, value, Json, ct).ConfigureAwait(false);
                await stream.FlushAsync(ct).ConfigureAwait(false);
            }
            File.Move(tmp, path, true);
        }
        finally { try { if (File.Exists(tmp)) File.Delete(tmp); } catch { } }
    }

    private static DateTimeOffset FloorHour(DateTimeOffset value)
        => new(value.Year, value.Month, value.Day, value.Hour, 0, 0, value.Offset);

    private static string FormatBytes(double bytes)
    {
        var abs = Math.Abs(bytes);
        if (abs >= 1024d * 1024 * 1024) return $"{bytes / 1024d / 1024 / 1024:0.00} GB";
        if (abs >= 1024d * 1024) return $"{bytes / 1024d / 1024:0.00} MB";
        return $"{bytes / 1024d:0.00} KB";
    }

    private static string Sanitize(string value)
        => new(value.Where(char.IsLetterOrDigit).Take(48).ToArray());
}
