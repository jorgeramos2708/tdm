using System.Diagnostics;
using TDM.Application;
using TDM.Collectors.TSplus;
using TDM.Collectors.Windows;
using TDM.Core;
using TDM.Models;
using TDM.Persistence;
using TDM.Reporting;

namespace TDM.Gui.Avalonia.Services;

public sealed record BaselineSaveResult(bool Success, string Message);

public sealed class DiagnosticExecutionService
{
    private const string ToolVersion = "1.0.0-rc.18.21.0";
    private readonly CollectorCircuitBreaker _circuitBreaker = new();
    private readonly LogService _logService = new();

    public IReadOnlyList<string> LookbackOptions { get; } =
    [
        "Tiempo real",
        "15 minutos",
        "30 minutos",
        "1 hora",
        "2 horas",
        "4 horas",
        "8 horas",
        "12 horas",
        "1 día",
        "2 días",
        "3 días"
    ];

public async Task<DiagnosticReport> RunAsync(string period, CancellationToken ct)
{
    _logService.Write(LogLevel.Information, "DIAGNOSTIC", "Engine", $"Iniciando diagnóstico: {period}");
    
    var lookback = LookbackForPeriod(period);
    var snapshot = SystemSnapshotReader.Capture();
    var tsplusProfile = TsplusReleaseCatalog.Resolve(snapshot);

    // Load operational configuration for diagnostic options
    var configService = new OperationalConfigurationService();
    var configSnapshot = await configService.LoadAsync(ct).ConfigureAwait(false);
    var thresholds = configSnapshot.Settings.Thresholds;

    var options = new DiagnosticOptions
    {
        MaxFilesPerDirectory = thresholds.MaxFilesPerDirectory,
        MaxBytesPerFile = thresholds.MaxBytesPerFile,
        MaxTotalBytes = thresholds.MaxTotalBytes,
        MaxEvents = thresholds.MaxEvents,
        EnableRdpEtw = false, // Auto-enabled by RdpEtwCollector when admin
        CauseStabilityFlappingThreshold = thresholds.CauseStabilityFlappingThreshold,
        MaxFilesPerDirectoryIncremental = thresholds.MaxFilesPerDirectoryIncremental,
        MaxBytesPerFileIncremental = thresholds.MaxBytesPerFileIncremental,
        MaxTotalBytesIncremental = thresholds.MaxTotalBytesIncremental,
        MaxEventsIncremental = thresholds.MaxEventsIncremental
    };

    var context = new DiagnosticContext(snapshot, lookback, TsplusProfile: tsplusProfile, Options: options);
    var engine = new DiagnosticEngine(CollectorCatalog.CreateFull(), DiagnosticExecutionPolicy.ForLookback(lookback), _circuitBreaker);

    _logService.Write(LogLevel.Information, "DIAGNOSTIC", "Engine", "Ejecutando motor de diagnóstico");
    var report = await engine.RunAsync(context, ct).ConfigureAwait(false);
    _logService.Write(LogLevel.Information, "DIAGNOSTIC", "Engine", $"Diagnóstico completado: {report.Hallazgos.Count} hallazgos, {report.Eventos.Count} eventos");

    // FIX42: el journal histórico se incorpora ANTES de correlacionar causas. De esta forma
    // un cambio de servicio/configuración/archivo observado por TDM puede correlacionarse
    // temporalmente con una falla posterior, sin convertir la muestra actual en causa.
    var monitorRoot = await ResolveMonitorRootAsync().ConfigureAwait(false);
    var diagnosticRoot = TdmDataPaths.ResolveWritableDefault();
    var from = report.PeriodoAnalizadoInicio == default ? report.Inicio - lookback : report.PeriodoAnalizadoInicio;
    var to = report.PeriodoAnalizadoFin == default ? report.Fin : report.PeriodoAnalizadoFin;
    var primaryHistoryRoot = monitorRoot ?? diagnosticRoot;
    report = await StateReportIntegrator.AddRecentMonitorTransitionsAsync(report, from, to, ct, primaryHistoryRoot).ConfigureAwait(false);
    if (!Path.GetFullPath(primaryHistoryRoot).Equals(Path.GetFullPath(diagnosticRoot), StringComparison.OrdinalIgnoreCase))
        report = await StateReportIntegrator.AddRecentMonitorTransitionsAsync(report, from, to, ct, diagnosticRoot).ConfigureAwait(false);
    report = await StateReportIntegrator.AddHistoricalCoverageAsync(report, from, to, ct, primaryHistoryRoot, diagnosticRoot).ConfigureAwait(false);
    // P0-aprendizaje: mismo historial verificado que usa el servicio (ventana 90 días).
    // Best-effort: sin archivo o sin acceso, el ranking usa solo evidencia actual.
    IReadOnlyDictionary<string, (int Confirmadas, int Descartadas, double Tasa)>? verifiedHitRates = null;
    try
    {
        var feedback = await new DiagnosticFeedbackStore(diagnosticRoot)
            .ReadAsync(from: DateTimeOffset.Now - TimeSpan.FromDays(90), ct: ct)
            .ConfigureAwait(false);
        if (feedback.Count > 0)
            verifiedHitRates = DiagnosticFeedbackStore.HitRateByCandidate(feedback);
    }
    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
    {
        _logService.Write(LogLevel.Warning, "DIAGNOSTIC", "Feedback", "Historial verificado no disponible", ex);
        _ = ex; // El diagnóstico manual no depende del historial verificado.
    }
    report = DiagnosticWorkflow.Analyze(report, includeGuidedResolution: true, verifiedHitRates: verifiedHitRates);

        // Divergencia servicio↔GUI: con servicio vivo y otra raíz, los historiales
        // (transiciones, feedback, cursores) se bifurcan. Best-effort y Advertencia
        // a propósito: no interfiere con el pase de tensiones (solo Error/Crítico).
        try
        {
            var heartbeat = await new ServiceHeartbeatStore(TdmDataPaths.MachineRootPath).ReadAsync(ct).ConfigureAwait(false);
            var divergence = StateRootDivergence.Evaluate(
                ServiceHeartbeatStore.IsFresh(heartbeat), diagnosticRoot, TdmDataPaths.MachineRootPath);
            if (divergence is not null)
                report = report with { Hallazgos = [.. report.Hallazgos, divergence] };
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _ = ex;
        }

        report = await StateReportIntegrator.RecordAndEnrichAsync(
            report,
            ToolVersion,
            ct,
            channel: "diagnostic-avalonia",
            rootPath: diagnosticRoot,
            baselineRootPath: monitorRoot).ConfigureAwait(false);

        // El diagnóstico completo contiene las métricas pesadas (procesos y discos).
        // Persistir una muestra de observabilidad permite que Rendimiento las muestre
        // inmediatamente y que sobrevivan a los refrescos visuales de 5 segundos.
        await PersistObservabilitySnapshotAsync(report, monitorRoot, diagnosticRoot, ct).ConfigureAwait(false);

        return report;
    }

    public BaselineEligibilityAssessment AssessBaseline(DiagnosticReport report)
    {
        var state = StateSnapshotBuilder.Build(report, ToolVersion);
        return BaselineEligibilityEvaluator.Evaluate(report, state);
    }

    public Task<ReportExportResult> ExportAsync(DiagnosticReport report, CancellationToken ct)
    {
        var documents = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        if (string.IsNullOrWhiteSpace(documents)) documents = AppContext.BaseDirectory;
        var directory = Path.Combine(documents, "TDM Reports");
        return ExportAsync(report, directory, ct);
    }

    public async Task<ReportExportResult> ExportAsync(DiagnosticReport report, string directory, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(directory))
            throw new ArgumentException("La carpeta de exportación no puede estar vacía.", nameof(directory));
        // Buscar reporte anterior más reciente en el mismo directorio para generar diff día-a-día
        DiagnosticReport? previousReport = null;
        try
        {
            var jsonFiles = Directory.GetFiles(directory, "TDM-*.json")
                .OrderByDescending(f => File.GetLastWriteTimeUtc(f))
                .ToArray();
            if (jsonFiles.Length >= 1)
            {
                var prevJson = File.ReadAllText(jsonFiles[0]);
                previousReport = System.Text.Json.JsonSerializer.Deserialize<DiagnosticReport>(prevJson, new System.Text.Json.JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            }
        }
        catch { /* Best-effort: si falla la lectura, se exporta sin diff */ }

        // P1-06: Fallback a LocalStateStore si no hay reporte previo en el directorio de exportación
        if (previousReport is null)
        {
            try
            {
                var store = new LocalStateStore();
                previousReport = await store.LoadLatestReportAsync(ct);
            }
            catch { /* Best-effort */ }
        }

        var result = await ReportExporter.ExportAsync(report, directory, ct, previousReport);
        
        // P1-06: Guardar el reporte exportado en LocalStateStore para futuros diffs
        try
        {
            var store = new LocalStateStore();
            await store.SaveLatestReportAsync(report, ct);
        }
        catch { /* Best-effort */ }

        return result;
    }

    public async Task<BaselineSaveResult> SaveBaselineAsync(DiagnosticReport report, CancellationToken ct)
    {
        var root = await ResolveMonitorRootAsync().ConfigureAwait(false) ?? TdmDataPaths.ResolveWritableDefault();
        var store = new LocalStateStore(root);
        var state = StateSnapshotBuilder.Build(report, ToolVersion);
        var assessment = BaselineEligibilityEvaluator.Evaluate(report, state);
        if (!assessment.Eligible)
            return new BaselineSaveResult(false, assessment.Reason);

        var existing = await store.LoadBaselineAsync(ct).ConfigureAwait(false);
        if (existing is not null)
            return new BaselineSaveResult(false,
                $"Ya existe un baseline sano en {store.BaselinePath}. Esta vista no lo reemplaza automáticamente; la sustitución requerirá confirmación explícita en una fase posterior.");

        await store.SaveBaselineAsync(state, replace: false, ct).ConfigureAwait(false);
        return new BaselineSaveResult(true,
            $"Baseline sano guardado · {state.Observations.Count(x => x.BaselineEligible)} observaciones · {store.BaselinePath}");
    }


    private static async Task PersistObservabilitySnapshotAsync(
        DiagnosticReport report,
        string? monitorRoot,
        string diagnosticRoot,
        CancellationToken ct)
    {
        var preferredRoot = string.IsNullOrWhiteSpace(monitorRoot) ? diagnosticRoot : monitorRoot;
        if (await TryRecordObservabilityAsync(preferredRoot!, report, ct).ConfigureAwait(false))
            return;

        if (!Path.GetFullPath(preferredRoot!).Equals(Path.GetFullPath(diagnosticRoot), StringComparison.OrdinalIgnoreCase))
            _ = await TryRecordObservabilityAsync(diagnosticRoot, report, ct).ConfigureAwait(false);
    }

    private static async Task<bool> TryRecordObservabilityAsync(string root, DiagnosticReport report, CancellationToken ct)
    {
        try
        {
            var store = new ObservabilityStore(root);
            var previous = (await store.ReadWindowAsync(TimeSpan.FromMinutes(15), ct).ConfigureAwait(false)).LastOrDefault();

            using var process = Process.GetCurrentProcess();
            process.Refresh();
            var runtime = new ObservabilityRuntimeState
            {
                MonitorIntervalSeconds = previous is { MonitorIntervalSeconds: > 0 } ? previous.MonitorIntervalSeconds : 5,
                MonitorMode = previous?.MonitorMode ?? "diagnóstico interactivo",
                DeferredSamples = previous?.DeferredSamples ?? 0,
                TdmWorkingSetMb = Math.Max(0d, process.WorkingSet64 / 1024d / 1024d),
                TdmCpuPercent = previous?.TdmCpuPercent,
                TdmHandleCount = Math.Max(0, process.HandleCount),
                TdmThreadCount = Math.Max(0, process.Threads.Count),
                ObservabilityBytes = store.WindowSizeBytes,
                NetworkReceiveMbps = previous?.NetworkReceiveMbps,
                NetworkSendMbps = previous?.NetworkSendMbps
            };

            await store.RecordAsync(report, "diagnostic-avalonia", runtime, ct).ConfigureAwait(false);
            return true;
        }
        catch (UnauthorizedAccessException)
        {
            return false;
        }
        catch (IOException)
        {
            return false;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            // La persistencia para dashboards es complementaria y nunca debe convertir
            // un diagnóstico ya completado en un fallo de ejecución.
            return false;
        }
    }

    private static async Task<string?> ResolveMonitorRootAsync()
    {
        if (PortableRuntime.IsEnabled) return null;
        try
        {
            var machine = TdmDataPaths.MachineRootPath;
            var heartbeat = await new ServiceHeartbeatStore(machine).ReadAsync().ConfigureAwait(false);
            if (ServiceHeartbeatStore.IsFresh(heartbeat) &&
                !string.Equals(heartbeat?.Status, "STOPPED", StringComparison.OrdinalIgnoreCase))
                return machine;

            // FIX42: si el servicio se detuvo después de haber acumulado historial, ese journal
            // sigue siendo evidencia válida. No lo descartamos sólo porque el heartbeat ya no
            // sea fresco; se usa en modo lectura y cualquier escritura posterior conserva fallback.
            var history = Path.Combine(machine, "history");
            if (Directory.Exists(history) && Directory.EnumerateFiles(history, "state-*.jsonl").Any())
                return machine;
        }
        catch
        {
            // Si ProgramData no es legible, el diagnóstico continúa con el store escribible por usuario.
        }
        return null;
    }

    /// <summary>
    /// Límite máximo de ejecución asociado a la opción seleccionada.
    /// Tiempo real funciona como cronómetro abierto hasta que el usuario lo detenga.
    /// Las ventanas fijas cancelan automáticamente el diagnóstico si todavía sigue activo
    /// al alcanzar la duración elegida.
    /// </summary>
    public static TimeSpan? ExecutionLimitForPeriod(string value)
        => value.Trim().ToLowerInvariant() switch
        {
            "tiempo real" => null,
            "15 minutos" => TimeSpan.FromMinutes(15),
            "30 minutos" => TimeSpan.FromMinutes(30),
            "1 hora" => TimeSpan.FromHours(1),
            "2 horas" => TimeSpan.FromHours(2),
            "4 horas" => TimeSpan.FromHours(4),
            "8 horas" => TimeSpan.FromHours(8),
            "12 horas" => TimeSpan.FromHours(12),
            "1 día" => TimeSpan.FromDays(1),
            "2 días" => TimeSpan.FromDays(2),
            "3 días" => TimeSpan.FromDays(3),
            _ => null
        };

    /// <summary>Ventana retrospectiva usada por el diagnóstico completo.</summary>
    public static TimeSpan LookbackForPeriod(string value)
        => value.Trim().ToLowerInvariant() switch
        {
            "15 minutos" => TimeSpan.FromMinutes(15),
            "30 minutos" => TimeSpan.FromMinutes(30),
            "1 hora" => TimeSpan.FromHours(1),
            "2 horas" => TimeSpan.FromHours(2),
            "4 horas" => TimeSpan.FromHours(4),
            "8 horas" => TimeSpan.FromHours(8),
            "12 horas" => TimeSpan.FromHours(12),
            "1 día" => TimeSpan.FromDays(1),
            "2 días" => TimeSpan.FromDays(2),
            "3 días" => TimeSpan.FromDays(3),
            "tiempo real" => TimeSpan.FromMinutes(15),
            _ => TimeSpan.FromMinutes(15)
        };
}
