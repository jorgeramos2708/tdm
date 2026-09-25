using System.Text.Json;

namespace TDM.Persistence;

public sealed record SupportThresholds
{
    public double CpuWarning { get; init; } = 70;
    public double CpuCritical { get; init; } = 85;
    public double MemoryUsedWarning { get; init; } = 80;
    public double MemoryUsedCritical { get; init; } = 90;
    public int SessionWarning { get; init; } = 80;
    public int SessionCritical { get; init; } = 120;
    public int ServiceChangesWarning { get; init; } = 3;
    public int ServiceChangesCritical { get; init; } = 6;
    public double TdmCpuWarning { get; init; } = 3;
    public double TdmCpuCritical { get; init; } = 7;
    public double TdmMemoryWarningPercent { get; init; } = 5;
    public double TdmMemoryCriticalPercent { get; init; } = 10;
    public int TdmHandlesWarning { get; init; } = 2000;
    public int TdmHandlesCritical { get; init; } = 4000;
    public int TdmThreadsWarning { get; init; } = 80;
    public int TdmThreadsCritical { get; init; } = 150;
    public int IncidentCooldownSeconds { get; init; } = 120;
    public int IncidentRecoveryConfirmSamples { get; init; } = 2;
    public int ClockDriftWarningSeconds { get; init; } = 90;
    public int NodeStaleWarningSeconds { get; init; } = 150;
    public int NodeOfflineSeconds { get; init; } = 300;
    public int NodeReadTimeoutSeconds { get; init; } = 8;

    // P2-02: Flapping threshold for cause stability (2-5 distinct causes in window)
    public int CauseStabilityFlappingThreshold { get; init; } = 2;
    // P2: TSplus log limits (diagnostic full)
    public int MaxFilesPerDirectory { get; init; } = 400;
    public int MaxBytesPerFile { get; init; } = 64 * 1024 * 1024;
    public long MaxTotalBytes { get; init; } = 256L * 1024 * 1024;
    public int MaxEvents { get; init; } = 5000;
    // P2: TSplus incremental log limits
    public int MaxFilesPerDirectoryIncremental { get; init; } = 240;
    public int MaxBytesPerFileIncremental { get; init; } = 256 * 1024;
    public long MaxTotalBytesIncremental { get; init; } = 1024 * 1024;
    public int MaxEventsIncremental { get; init; } = 300;
}



public static class SupportThresholdsValidator
{
    public static IReadOnlyList<string> Validate(SupportThresholds? value)
    {
        var errors = new List<string>();
        if (value is null)
        {
            errors.Add("La configuración de umbrales está vacía.");
            return errors;
        }

        static bool BetweenDouble(double v, double min, double max) => double.IsFinite(v) && v >= min && v <= max;
        static bool BetweenInt(int v, int min, int max) => v >= min && v <= max;
        static void PairDouble(List<string> errors, string name, double warning, double critical, double min, double max)
        {
            if (!BetweenDouble(warning, min, max) || !BetweenDouble(critical, min, max))
                errors.Add($"{name}: los valores deben estar entre {min:0.##} y {max:0.##}.");
            else if (warning >= critical)
                errors.Add($"{name}: el nivel de aviso debe ser menor que el nivel alto.");
        }
        static void PairInt(List<string> errors, string name, int warning, int critical, int min, int max)
        {
            if (!BetweenInt(warning, min, max) || !BetweenInt(critical, min, max))
                errors.Add($"{name}: los valores deben estar entre {min} y {max}.");
            else if (warning >= critical)
                errors.Add($"{name}: el nivel de aviso debe ser menor que el nivel alto.");
        }

        PairDouble(errors, "CPU", value.CpuWarning, value.CpuCritical, 1, 100);
        PairDouble(errors, "Memoria usada", value.MemoryUsedWarning, value.MemoryUsedCritical, 1, 100);
        PairInt(errors, "Sesiones con problema", value.SessionWarning, value.SessionCritical, 1, 100000);
        PairInt(errors, "Cambios en servicios", value.ServiceChangesWarning, value.ServiceChangesCritical, 1, 10000);
        PairDouble(errors, "CPU de TDM", value.TdmCpuWarning, value.TdmCpuCritical, 0.1, 100);
        PairDouble(errors, "Memoria de TDM (%)", value.TdmMemoryWarningPercent, value.TdmMemoryCriticalPercent, 0.1, 100);
        PairInt(errors, "Handles de TDM", value.TdmHandlesWarning, value.TdmHandlesCritical, 100, 1000000);
        PairInt(errors, "Hilos de TDM", value.TdmThreadsWarning, value.TdmThreadsCritical, 1, 100000);

        if (!BetweenInt(value.IncidentCooldownSeconds, 10, 86400))
            errors.Add("Espera para repetir incidente: use un valor entre 10 y 86400 segundos.");
        if (!BetweenInt(value.IncidentRecoveryConfirmSamples, 1, 20))
            errors.Add("Confirmaciones para recuperación: use un valor entre 1 y 20.");
        if (!BetweenInt(value.ClockDriftWarningSeconds, 1, 86400))
            errors.Add("Desfase de reloj: use un valor entre 1 y 86400 segundos.");
        if (!BetweenInt(value.NodeStaleWarningSeconds, 30, 86400))
            errors.Add("Servidor atrasado: use un valor entre 30 y 86400 segundos.");
        if (!BetweenInt(value.NodeOfflineSeconds, 31, 604800))
            errors.Add("Servidor sin datos: use un valor entre 31 y 604800 segundos.");
        else if (value.NodeStaleWarningSeconds >= value.NodeOfflineSeconds)
            errors.Add("Servidores: 'atrasado' debe ocurrir antes que 'sin datos'.");
        if (!BetweenInt(value.NodeReadTimeoutSeconds, 2, 30))
            errors.Add("Tiempo máximo de lectura de servidor: use un valor entre 2 y 30 segundos.");

        if (!BetweenInt(value.CauseStabilityFlappingThreshold, 2, 5))
            errors.Add("Umbral de inestabilidad de causa (flapping): use un valor entre 2 y 5.");
        if (!BetweenInt(value.MaxFilesPerDirectory, 50, 2000))
            errors.Add("Máx. archivos por directorio (diagnóstico): use un valor entre 50 y 2000.");
        if (!BetweenInt(value.MaxBytesPerFile, 1024 * 1024, 512 * 1024 * 1024))
            errors.Add("Máx. bytes por archivo (diagnóstico): use un valor entre 1 MiB y 512 MiB.");
        if (!BetweenLong(value.MaxTotalBytes, 10L * 1024 * 1024, 2048L * 1024 * 1024))
            errors.Add("Presupuesto total de lectura (diagnóstico): use un valor entre 10 MiB y 2 GiB.");
        if (!BetweenInt(value.MaxEvents, 100, 50000))
            errors.Add("Máx. eventos (diagnóstico): use un valor entre 100 y 50000.");
        if (!BetweenInt(value.MaxFilesPerDirectoryIncremental, 50, 1000))
            errors.Add("Máx. archivos por directorio (incremental): use un valor entre 50 y 1000.");
        if (!BetweenInt(value.MaxBytesPerFileIncremental, 64 * 1024, 1024 * 1024))
            errors.Add("Máx. bytes por archivo (incremental): use un valor entre 64 KiB y 1 MiB.");
        if (!BetweenLong(value.MaxTotalBytesIncremental, 256L * 1024, 16L * 1024 * 1024))
            errors.Add("Presupuesto total de lectura (incremental): use un valor entre 256 KiB y 16 MiB.");
        if (!BetweenInt(value.MaxEventsIncremental, 50, 2000))
            errors.Add("Máx. eventos (incremental): use un valor entre 50 y 2000.");

        return errors;

        static bool BetweenLong(long v, long min, long max) => v >= min && v <= max;
    }

    public static bool IsValid(SupportThresholds? value)
        => Validate(value).Count == 0;
}

public sealed record SupportMonitoringSettings(
    SupportThresholds Thresholds,
    bool EnableIncidentAntiNoise = true,
    bool EnableSynchronizedCursor = true,
    bool EnableMultiServer = true)
{
    public static SupportMonitoringSettings Default { get; } = new(new SupportThresholds());
}

public sealed class SupportMonitoringSettingsStore
{
    private readonly JsonSerializerOptions _json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase, WriteIndented = true };
    public string Path { get; }

    public SupportMonitoringSettingsStore(string? rootPath = null)
    {
        var root = string.IsNullOrWhiteSpace(rootPath) ? LocalStateStore.DefaultRootPath : rootPath;
        Path = System.IO.Path.Combine(root, "settings", "support-monitoring.json");
    }

    public async Task<SupportMonitoringSettings> LoadAsync(CancellationToken ct = default)
    {
        if (!File.Exists(Path)) return SupportMonitoringSettings.Default;
        try
        {
            await using var stream = new FileStream(Path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete,
                16 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
            var loaded = await JsonSerializer.DeserializeAsync<SupportMonitoringSettings>(stream, _json, ct);
            if (loaded is null || !SupportThresholdsValidator.IsValid(loaded.Thresholds))
                return SupportMonitoringSettings.Default;
            return loaded;
        }
        catch (JsonException) { return SupportMonitoringSettings.Default; }
        catch (IOException) { return SupportMonitoringSettings.Default; }
        catch (UnauthorizedAccessException) { return SupportMonitoringSettings.Default; }
    }

    public async Task SaveAsync(SupportMonitoringSettings settings, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(settings);
        var errors = SupportThresholdsValidator.Validate(settings.Thresholds);
        if (errors.Count > 0)
            throw new ArgumentOutOfRangeException(nameof(settings), string.Join(" ", errors));

        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(Path)!);
        var tmp = Path + ".tmp-" + Guid.NewGuid().ToString("N");
        try
        {
            await using (var stream = new FileStream(tmp, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                16 * 1024, FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await JsonSerializer.SerializeAsync(stream, settings, _json, ct);
                await stream.FlushAsync(ct);
                stream.Flush(true);
            }
            File.Move(tmp, Path, true);
        }
        finally { try { if (File.Exists(tmp)) File.Delete(tmp); } catch { } }
    }
}
