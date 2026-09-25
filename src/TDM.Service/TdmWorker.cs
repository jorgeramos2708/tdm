using System.Diagnostics;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using TDM.Application;
using TDM.Collectors.TSplus;
using TDM.Collectors.Windows;
using TDM.Core;
using TDM.Correlation;
using TDM.Models;
using TDM.Notifications;
using TDM.Persistence;

namespace TDM.Service;

public sealed class TdmWorker : BackgroundService
{
    private static readonly TimeSpan NormalInterval = TimeSpan.FromSeconds(60);
    private static readonly TimeSpan IntensiveInterval = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan IntensiveWindow = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan HeavyRefresh = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan SnapshotRefresh = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan SnapshotTimeout = TimeSpan.FromSeconds(8);
    private static readonly TimeSpan ForensicStateInterval = TimeSpan.FromMinutes(2);
    private static readonly TimeSpan IntegrityStateInterval = TimeSpan.FromMinutes(10);

    private readonly ILogger<TdmWorker> _logger;
    private readonly string _root = TdmDataPaths.MachineRootPath;
    private readonly IncrementalWindowsEventCollector _windowsIncremental = new();
    private readonly IncrementalTsplusLogCollector _tsplusIncremental = new();
    private readonly List<AlertSignal> _lastHeavyPreventiveSignals = [];
    private DateTimeOffset? _lastHeavySampleAt;
    private TimeSpan _lastSleepInterval = NormalInterval;
    private readonly object _snapshotSync = new();
    private Task<SystemSnapshot>? _snapshotTask;
    private SystemSnapshot? _snapshot;
    private DateTimeOffset _snapshotCapturedAt;
    private DateTimeOffset _nextHeavyAt = DateTimeOffset.MinValue;
    private DateTimeOffset _nextForensicStateAt = DateTimeOffset.MinValue;
    private DateTimeOffset _nextIntegrityStateAt = DateTimeOffset.MinValue;
    private DateTimeOffset? _intensiveUntil;
    private long _completedSamples;
    private int _deferredSamples;
    private int _consecutiveDefers;
    private readonly CollectorCircuitBreaker _circuitBreaker = new();
    private readonly TdmHealthCheck _healthCheck;
    private DateTimeOffset _lastHealthCheckAt = DateTimeOffset.MinValue;
    private readonly HealthCheckServer _healthServer;

    // Q7: fallo rápido en construcción manual con logger nulo (la ruta de descarte heavy lo usa).
    public TdmWorker(ILogger<TdmWorker> logger)
        : this(logger, new CollectorCircuitBreaker(), new TdmHealthCheck(TdmDataPaths.MachineRootPath, new CollectorCircuitBreaker()), new HealthCheckServer(new TdmHealthCheck(TdmDataPaths.MachineRootPath, new CollectorCircuitBreaker())))
    {
    }

    internal TdmWorker(ILogger<TdmWorker> logger, CollectorCircuitBreaker circuitBreaker, TdmHealthCheck healthCheck, HealthCheckServer healthServer)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _circuitBreaker = circuitBreaker;
        _healthCheck = healthCheck;
        _healthServer = healthServer;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Fail-fast config validation (service mode)
        ConfigValidator.ValidateOrThrow(rootPath: _root, portable: false);

        // Startup dependency check (fail-fast si dependencias críticas faltan)
        var depResult = StartupDependencyChecker.RunAll(throwOnCritical: true);
foreach (var check in depResult.Checks)
        {
            var level = check.Passed ? Microsoft.Extensions.Logging.LogLevel.Information : (check.IsCritical ? Microsoft.Extensions.Logging.LogLevel.Critical : Microsoft.Extensions.Logging.LogLevel.Warning);
            _logger.Log(level, 0, $"Startup check {check.Name}: {check.Detail}", null, (s, _) => s);
        }

        // Portable executable integrity verification (fail-fast si hash no coincide)
        if (PortableRuntime.IsEnabled)
        {
            try { PortableIntegrityVerifier.VerifyOrThrow(); }
            catch (InvalidOperationException ex)
            {
                _logger.LogCritical(ex, "INTEGRIDAD DEL EJECUTABLE COMPROMETIDA");
                throw;
            }
        }

        // Global exception handlers for service crash diagnosis
        SetupGlobalExceptionHandlers();
        CollectorAssemblyResolver.Initialize(_root);

        Directory.CreateDirectory(_root);
        var heartbeatStore = new ServiceHeartbeatStore(_root);
        var observabilityStore = new ObservabilityStore(_root);
        var settingsStore = new SupportMonitoringSettingsStore(_root);
        var ledger = new IncidentLedger(_root);
        var desktopSink = new DesktopJournalNotificationSink(_root);
        var emailSink = new SmtpEmailNotificationSink(_root);
        var dispatcher = new NotificationDispatcher([desktopSink, emailSink], _root);

_logger.LogInformation("TDM.Service {Version} iniciado. Root={Root}", TdmProductInfo.Version, _root);
        await WriteHeartbeatSafeAsync(heartbeatStore, "STARTING", NormalInterval, null, stoppingToken).ConfigureAwait(false);

        // Start health check server (/health, /ready, /live)
        _healthServer.Start();
        _logger.LogInformation("Health check server iniciado en http://localhost:51821/health");

        try
            {
                while (!stoppingToken.IsCancellationRequested)
                {
                    var cycleStarted = DateTimeOffset.Now;
                    var interval = NormalInterval;
                    string? lastError = null;
                    var status = "RUNNING";

                    _healthCheck.RecordCycleStart();

                    try
                    {
                    await ProcessNotificationSelfTestAsync(dispatcher, stoppingToken).ConfigureAwait(false);
                    var guard = ResourceLoadGuard.Capture();
                    if (guard.ShouldDefer)
                    {
                        _deferredSamples++;
                        _consecutiveDefers++;
                        status = "PROTECTED";
                        _logger.LogWarning("Muestra aplazada por ResourceLoadGuard: {Summary}", guard.Summary);
                        // P0-emergencia: ante aplazamientos consecutivos el servicio se quedaba
                        // ciego justo bajo carga (cuando más probables son los incidentes). Cada
                        // 3er ciclo aplazado se toma una muestra mínima (solo incrementales,
                        // timeout 5 s, tope 300 eventos) para no perder paros ni crashes.
                        // Nunca tumba el ciclo: cualquier fallo se registra y se sigue en PROTECTED.
                        if (EmergencyPolicy.IsEmergencyDue(_consecutiveDefers))
                        {
                            try
                            {
                                await RunEmergencySampleAsync(observabilityStore, settingsStore, ledger, dispatcher, stoppingToken).ConfigureAwait(false);
                            }
                            catch (Exception ex) when (!stoppingToken.IsCancellationRequested)
                            {
                                _logger.LogWarning(ex, "Muestra de emergencia descartada; se conserva el estado PROTECTED");
                            }
                        }
                    }
                    else
                    {
                        _consecutiveDefers = 0;
                        var includeHeavy = DateTimeOffset.Now >= _nextHeavyAt;
                        if (includeHeavy) _nextHeavyAt = DateTimeOffset.Now + HeavyRefresh;

                        var snapshot = await GetSystemSnapshotAsync(stoppingToken).ConfigureAwait(false);
                        var tsplusProfile = TsplusReleaseCatalog.Resolve(snapshot);

                        // Load diagnostic options from configuration
                        DiagnosticOptions? options = null;
                        try
                        {
                            var configStore = new SupportMonitoringSettingsStore(_root);
                            var monitoringSettings = await configStore.LoadAsync(stoppingToken).ConfigureAwait(false);
                            var thresholds = monitoringSettings.Thresholds;
                            options = new DiagnosticOptions
                            {
                                MaxFilesPerDirectory = thresholds.MaxFilesPerDirectory,
                                MaxBytesPerFile = thresholds.MaxBytesPerFile,
                                MaxTotalBytes = thresholds.MaxTotalBytes,
                                MaxEvents = thresholds.MaxEvents,
                                EnableRdpEtw = false,
                                CauseStabilityFlappingThreshold = thresholds.CauseStabilityFlappingThreshold,
                                MaxFilesPerDirectoryIncremental = thresholds.MaxFilesPerDirectoryIncremental,
                                MaxBytesPerFileIncremental = thresholds.MaxBytesPerFileIncremental,
                                MaxTotalBytesIncremental = thresholds.MaxTotalBytesIncremental,
                                MaxEventsIncremental = thresholds.MaxEventsIncremental
                            };
                        }
                        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                        {
                            _logger.LogDebug(ex, "No se pudo cargar configuración de umbrales; usando valores por defecto");
                        }

                        var context = new DiagnosticContext(snapshot, NormalInterval, TsplusProfile: tsplusProfile, Options: options);
                        var collectors = CollectorCatalog.CreateServiceMonitor(guard, includeHeavy);
                        collectors.Add(_windowsIncremental);
                        collectors.Add(_tsplusIncremental);
                        // P03: timeouts por categoría (25 s normal / 40 s profundo / 3 min global) en vez
                        // del uniforme de 3 s, que truncaba el grafo SCM y las dependencias TSplus y
                        // encadenaba aplazamientos StillRunning. El presupuesto global sigue acotando.
                        var engine = new DiagnosticEngine(collectors, DiagnosticExecutionPolicy.ProductionDefault with { MaxRawEvents = 1_500 }, _circuitBreaker);

                        var report = await engine.RunAsync(context, stoppingToken).ConfigureAwait(false);

                        // Baseline adaptativo por máquina: evalúa CPU/memoria contra lo habitual en
                        // ESTE equipo (no solo umbrales globales) y acumula la muestra. Solo emite
                        // hallazgos Advertencia con historial suficiente; nunca genera incidentes.
                        try
                        {
                            var baselineStore = new AdaptiveBaselineStore(_root);
                            foreach (var adaptive in await baselineStore.EvaluateAndUpdateAsync(guard.CpuPercent, guard.MemoryFreePercent, stoppingToken).ConfigureAwait(false))
                                report = report with { Hallazgos = [.. report.Hallazgos, adaptive] };
                        }
                        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                        {
                            _logger.LogWarning(ex, "Línea base adaptativa no disponible en este ciclo");
                        }

                        // T2: si el snapshot vino de caché por timeout y supera 2×SnapshotRefresh, se
                        // declara rancio (Advertencia: no contamina baseline, solo telemetría) y bloquea
                        // la renovación heavy vía el gate Q2/T1. Sin esto el ciclo parecía fresco.
                        var snapshotAge = DateTimeOffset.Now - _snapshotCapturedAt;
                        if (_snapshot is not null && snapshotAge > SnapshotRefresh * 2)
                        {
                            _logger.LogWarning("Snapshot del sistema rancio ({Age}); el ciclo se marca parcial.", snapshotAge);
                            report = report with
                            {
                                Hallazgos =
                                [
                                    .. report.Hallazgos,
                                    new DiagnosticFinding(
                                        "TDM-SNAPSHOT-STALE",
                                        "Snapshot del sistema",
                                        DiagnosticSeverity.Advertencia,
                                        "El contexto del sistema proviene de caché por timeout de captura.",
                                        "La detección TSplus/rutas puede estar desactualizada; los hallazgos de este ciclo se conservan como parciales y no renuevan la referencia heavy.",
                                        [new EvidenceItem("Antigüedad del snapshot", snapshotAge.ToString()),
                                         new EvidenceItem("Cobertura", "Parcial")],
                                        ConfidenceLevel.Alta,
                                        Capa: DiagnosticLayer.Desconocida)
                                ]
                            };
                        }

                        // P0: registrar el estado actual antes de la correlación permite que la transición
                        // que acaba de ocurrir (por ejemplo Running → Stopped) participe en el RCA del mismo ciclo.
                        var stateStore = new LocalStateStore(_root);
                        var preRecordedSnapshot = StateSnapshotBuilder.Build(report, TdmProductInfo.Version);
                        var preRecordedResult = await stateStore.RecordAsync(preRecordedSnapshot, "service-monitor", stoppingToken).ConfigureAwait(false);
                        report = StateReportIntegrator.AddTransitionsFromRecordResult(report, preRecordedResult, "service-monitor");

                        // P0-aprendizaje: historial verificado por el técnico (últimos 90 días; misma
                        // ventana que VerifiedHistoryCalibrator.DefaultLookback). El store nunca lanza
                        // por archivo ausente; ante E/S denegada se conserva null y el ranking usa
                        // solo evidencia actual, igual que antes de este cambio.
                        IReadOnlyDictionary<string, (int Confirmadas, int Descartadas, double Tasa)>? verifiedHitRates = null;
                        try
                        {
                            var feedback = await new DiagnosticFeedbackStore(_root)
                                .ReadAsync(from: DateTimeOffset.Now - TimeSpan.FromDays(90), ct: stoppingToken)
                                .ConfigureAwait(false);
                            if (feedback.Count > 0)
                                verifiedHitRates = DiagnosticFeedbackStore.HitRateByCandidate(feedback);
                        }
                        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                        {
                            _logger.LogWarning(ex, "Historial verificado no disponible en este ciclo; el ranking usa solo evidencia actual");
                        }

                        report = DiagnosticWorkflow.Analyze(report, includeGuidedResolution: false, verifiedHitRates: verifiedHitRates);

                        // P2-estabilidad: si la causa principal rota entre muestras, el top se
                        // lee como hipótesis competitivas. Historial acotado (12) en cursor
                        // propio; best-effort para no acoplar el ciclo a esta telemetría.
                        // Solo en el servicio: el diagnóstico manual es esporádico y una ventana
                        // de 6 muestras podría abarcar meses.
                        try
                        {
                            CollectorCursorStore.TryLoad<List<string>>("primary-cause-history", out var causeHistory, out _);
                            causeHistory ??= [];
                            causeHistory.Add(report.CausaRaizPrincipal?.Id ?? "");
                            while (causeHistory.Count > 12) causeHistory.RemoveAt(0);
                            CollectorCursorStore.TrySave("primary-cause-history", causeHistory, out _);
                            var policy = DiagnosticExecutionPolicy.ForLookback(NormalInterval);
                            var unstable = CauseStabilityAnalyzer.Analyze(causeHistory, maxDistinct: policy.CauseStabilityFlappingThreshold);
                            if (unstable is not null)
                                report = report with { Hallazgos = [.. report.Hallazgos, unstable] };
                        }
                        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                        {
                            _logger.LogWarning(ex, "Historial de causa principal no disponible; se omite el chequeo de estabilidad");
                        }

                        // P0-root-divergence: con servicio vivo y otra raíz, los historiales
                        // (transiciones, feedback, cursores) se bifurcan en silencio.
                        // Best-effort y Advertencia a propósito: no interfiere con el pase de tensiones.
                        try
                        {
                            var heartbeat = await new ServiceHeartbeatStore(_root).ReadAsync(stoppingToken).ConfigureAwait(false);
                            var divergence = StateRootDivergence.Evaluate(
                                ServiceHeartbeatStore.IsFresh(heartbeat), _root, TdmDataPaths.MachineRootPath);
                            if (divergence is not null)
                                report = report with { Hallazgos = [.. report.Hallazgos, divergence] };
                        }
                        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                        {
                            _logger.LogWarning(ex, "Comprobación de divergencia de raíz no disponible");
                        }

                        report = await StateReportIntegrator.RecordAndEnrichAsync(
                            report, TdmProductInfo.Version, stoppingToken, channel: "service-monitor", rootPath: _root,
                            preRecordedResult: preRecordedResult).ConfigureAwait(false);

                        var processMetrics = CaptureSelfMetrics();
                        var runtime = new ObservabilityRuntimeState
                        {
                            // P04: registra la cadencia real que produjo esta muestra (decidida al
                            // final del ciclo anterior), no el valor inicial del ciclo actual.
                            MonitorIntervalSeconds = (int)_lastSleepInterval.TotalSeconds,
                            MonitorMode = includeHeavy ? "servicio / muestreo ampliado" : "servicio / normal",
                            DeferredSamples = _deferredSamples,
                            TdmWorkingSetMb = processMetrics.WorkingSetMb,
                            TdmCpuPercent = null,
                            TdmHandleCount = processMetrics.Handles,
                            TdmThreadCount = processMetrics.Threads,
                            ObservabilityBytes = observabilityStore.WindowSizeBytes
                        };
                        var sample = await observabilityStore.RecordAsync(report, "service-monitor", runtime, stoppingToken).ConfigureAwait(false);
                        var settings = await settingsStore.LoadAsync(stoppingToken).ConfigureAwait(false);
                        var managed = await ledger.ReconcileAsync(sample.Incidents ?? [], sample.Timestamp, settings, "LOCAL", stoppingToken).ConfigureAwait(false);
                        var signals = BuildSignals(report, managed, includeHeavy, settings.Thresholds);
                        var emitted = await dispatcher.DispatchAsync(signals, sample.Timestamp, stoppingToken).ConfigureAwait(false);
                        _completedSamples++;

                        var historyStatus = report.Eventos.LastOrDefault(e => e.Tipo == "TDM_LOCAL_HISTORY_STATUS");
                        var transitions = historyStatus is null ? 0 : EvidenceReader.Int32(historyStatus, "Transiciones detectadas") ?? 0;
                        if (transitions > 0 || emitted.Count > 0)
                            _intensiveUntil = DateTimeOffset.Now + IntensiveWindow;

                        if (_intensiveUntil.HasValue && _intensiveUntil.Value > DateTimeOffset.Now && guard.AllowsIntensiveSampling)
                            interval = IntensiveInterval;

                        // T4: latido intermedio antes de la fase longitudinal (forensic 8 s + integrity
                        // 15 s + engine de hasta 3 min): con un solo latido a fin de ciclo, un engine
                        // lento dejaba el heartbeat rancio >150 s y la GUI flappeaba a local.
                        // W5: va DESPUÉS de decidir intensive e incrementar el contador, así informa
                        // el intervalo que realmente se dormirá y el conteo ya actualizado.
                        await WriteHeartbeatSafeAsync(heartbeatStore, status, interval, lastError, stoppingToken).ConfigureAwait(false);
                        // FIX42: el estado longitudinal vive en canales independientes. Así una
                        // muestra ligera posterior no borra la referencia contra la que se detectan
                        // cambios de configuración, servicios o integridad física.
                        await CaptureLongitudinalStateIfDueAsync(snapshot, cycleStarted, stoppingToken).ConfigureAwait(false);
                    }
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
                catch (Exception ex)
                {
                    status = "DEGRADED";
                    lastError = ex.Message;
                    _logger.LogError(ex, "Error controlado en ciclo de TDM.Service");
                }
                finally
                {
                    _healthCheck.RecordCycleEnd(status == "RUNNING" || status == "DEGRADED", lastError);
                }

                await WriteHeartbeatSafeAsync(heartbeatStore, status, interval, lastError, stoppingToken).ConfigureAwait(false);
                var elapsed = DateTimeOffset.Now - cycleStarted;
                var delay = interval - elapsed;
                if (delay < TimeSpan.FromSeconds(1)) delay = TimeSpan.FromSeconds(1);
                _lastSleepInterval = interval;
                await Task.Delay(delay, stoppingToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
        finally
        {
            await WriteHeartbeatSafeAsync(heartbeatStore, "STOPPED", _lastSleepInterval, null, CancellationToken.None).ConfigureAwait(false);
            _logger.LogInformation("TDM.Service detenido.");
            try { await _healthServer.StopAsync().ConfigureAwait(false); }
            catch (Exception ex) { _logger.LogWarning(ex, "Error deteniendo health check server"); }
        }
    }

    /// <summary>
    /// Muestra mínima bajo presión: solo los readers incrementales (Windows + TSplus),
    /// con timeout corto y sin fase pesada ni longitudinal. Reutiliza el mismo pipeline
    /// de persistencia/ledger/dispatch para que paros y crashes sigan generando incidentes
    /// y alertas aunque el ciclo normal esté aplazado. Usa el último snapshot conocido;
    /// sin snapshot aún, no hay contexto válido y se omite.
    /// </summary>
    private async Task RunEmergencySampleAsync(
        ObservabilityStore observabilityStore,
        SupportMonitoringSettingsStore settingsStore,
        IncidentLedger ledger,
        NotificationDispatcher dispatcher,
        CancellationToken ct)
    {
        var snapshot = _snapshot;
        if (snapshot is null)
        {
            _logger.LogDebug("Muestra de emergencia omitida: aún no hay snapshot del sistema.");
            return;
        }
        var tsplusProfile = TsplusReleaseCatalog.Resolve(snapshot);

        // Load diagnostic options from configuration
        DiagnosticOptions? options = null;
        try
        {
            var configStore = new SupportMonitoringSettingsStore(_root);
            var monitoringSettings = await configStore.LoadAsync(ct).ConfigureAwait(false);
            var thresholds = monitoringSettings.Thresholds;
            options = new DiagnosticOptions
            {
                MaxFilesPerDirectory = thresholds.MaxFilesPerDirectory,
                MaxBytesPerFile = thresholds.MaxBytesPerFile,
                MaxTotalBytes = thresholds.MaxTotalBytes,
                MaxEvents = thresholds.MaxEvents,
                EnableRdpEtw = false,
                CauseStabilityFlappingThreshold = thresholds.CauseStabilityFlappingThreshold,
                MaxFilesPerDirectoryIncremental = thresholds.MaxFilesPerDirectoryIncremental,
                MaxBytesPerFileIncremental = thresholds.MaxBytesPerFileIncremental,
                MaxTotalBytesIncremental = thresholds.MaxTotalBytesIncremental,
                MaxEventsIncremental = thresholds.MaxEventsIncremental
            };
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _logger.LogDebug(ex, "No se pudo cargar configuración de umbrales (emergencia); usando valores por defecto");
        }

        var context = new DiagnosticContext(snapshot, EmergencyPolicy.Lookback, TsplusProfile: tsplusProfile, Options: options);
        var policy = DiagnosticExecutionPolicy.Uniform(EmergencyPolicy.CollectorTimeout, EmergencyPolicy.MaxRawEvents);
        var engine = new DiagnosticEngine(
            new IReadOnlyCollector[] { _windowsIncremental, _tsplusIncremental },
            policy,
            _circuitBreaker);
        var report = await engine.RunAsync(context, ct).ConfigureAwait(false);
        report = DiagnosticWorkflow.Analyze(report, includeGuidedResolution: false);
        var processMetrics = CaptureSelfMetrics();
        var runtime = new ObservabilityRuntimeState
        {
            MonitorIntervalSeconds = (int)_lastSleepInterval.TotalSeconds,
            MonitorMode = "servicio / emergencia",
            DeferredSamples = _deferredSamples,
            TdmWorkingSetMb = processMetrics.WorkingSetMb,
            TdmCpuPercent = null,
            TdmHandleCount = processMetrics.Handles,
            TdmThreadCount = processMetrics.Threads,
            ObservabilityBytes = observabilityStore.WindowSizeBytes
        };
        var sample = await observabilityStore.RecordAsync(report, "service-monitor", runtime, ct).ConfigureAwait(false);
        var settings = await settingsStore.LoadAsync(ct).ConfigureAwait(false);
        var managed = await ledger.ReconcileAsync(sample.Incidents ?? [], sample.Timestamp, settings, "LOCAL", ct).ConfigureAwait(false);
        var signals = BuildSignals(report, managed, includeHeavy: false, settings.Thresholds);
        var emitted = await dispatcher.DispatchAsync(signals, sample.Timestamp, ct).ConfigureAwait(false);
        _completedSamples++;
        _logger.LogWarning("Muestra de emergencia completada tras {Deferred} aplazamientos consecutivos: {Managed} gestionados, {Emitted} señales.",
            _consecutiveDefers, managed.Count, emitted.Count);
    }

    private IReadOnlyList<AlertSignal> BuildSignals(DiagnosticReport report, IReadOnlyList<ManagedIncident> managed, bool includeHeavy, SupportThresholds? thresholds = null)
    {
        var output = new List<AlertSignal>();
        foreach (var incident in managed.Where(x => x.State is ManagedIncidentState.Active or ManagedIncidentState.Persistent))
        {
            output.Add(new AlertSignal(
                $"incident|{incident.Node}|{incident.Component}|{incident.Kind}",
                incident.LastSeenAt,
                incident.Severity,
                AlertTitleFormatter.ForIncident(incident),
                incident.Summary,
                "IncidentLedger",
                incident.Id));
        }

        var preventive = report.Hallazgos
            .Where(IsPreventiveFinding)
            .Select(f => new AlertSignal(
                $"finding|{f.Id}",
                report.PeriodoAnalizadoFin != default ? report.PeriodoAnalizadoFin : DateTimeOffset.Now,
                f.Severidad.ToString(),
                AlertTitleFormatter.ForFinding(f),
                f.Resumen,
                "PreventiveFinding",
                f.Id))
            .ToList();

        if (includeHeavy)
        {
            // Q2/T1: la referencia heavy solo se renueva si el ciclo ampliado no reportó
            // timeouts/aplazamientos; si fue parcial se conserva la referencia válida previa
            // en vez de marcar como fresco un muestreo incompleto durante 20 min. Se detectan
            // también el error genérico COLLECTOR-*, el agotamiento de presupuesto global y el
            // snapshot rancio por timeout (T2), que antes renovaban heavy igual.
            // W1: también bloquea el recorte por volumen (MaxRawEvents): un heavy truncado por
            // TDM-EVENT-VOLUME-LIMIT no debe marcarse fresco 20 minutos.
            var heavyIncomplete = report.Hallazgos.Any(f =>
                f.Id.StartsWith("COLLECTOR-", StringComparison.OrdinalIgnoreCase) ||
                f.Id.Equals("DIAGNOSTIC-BUDGET-EXHAUSTED", StringComparison.OrdinalIgnoreCase) ||
                f.Id.Equals("TDM-EVENT-VOLUME-LIMIT", StringComparison.OrdinalIgnoreCase) ||
                f.Id.Equals("TDM-SNAPSHOT-STALE", StringComparison.OrdinalIgnoreCase));
            if (!heavyIncomplete)
            {
                _lastHeavyPreventiveSignals.Clear();
                _lastHeavyPreventiveSignals.AddRange(preventive.Where(IsHeavySignal));
                _lastHeavySampleAt = DateTimeOffset.Now;
            }
            else
            {
                _logger.LogWarning("Muestreo ampliado parcial (timeout/aplazamiento): se conserva la referencia heavy previa válida.");
            }
        }

        output.AddRange(preventive.Where(x => !IsHeavySignal(x)));
        // P02: las señales heavy (disco/memoria/CPU/TCP/cert) solo se reinyectan si el último
        // muestreo ampliado es reciente (<= 2xHeavyRefresh). Sin frescura se descartan en vez
        // de alertar con valores de hace 20-30 min tras timeouts/aplazamientos del heavy.
        var heavyStale = !_lastHeavySampleAt.HasValue
            || DateTimeOffset.Now - _lastHeavySampleAt.Value > HeavyRefresh * 2;
        if (!heavyStale)
        {
            output.AddRange(_lastHeavyPreventiveSignals);
        }
        else if (_lastHeavyPreventiveSignals.Count > 0)
        {
            _logger.LogWarning(
                "Señales preventivas heavy descartadas por antigüedad (> {StaleAfter}); último muestreo ampliado: {LastHeavyAt}",
                HeavyRefresh * 2, _lastHeavySampleAt);
            _lastHeavyPreventiveSignals.Clear();
        }
        return output.GroupBy(x => x.Key, StringComparer.OrdinalIgnoreCase)
            .Select(g => g.OrderByDescending(x => SeverityRank(x.Severity)).First())
            .ToList();
    }

    private static bool IsPreventiveFinding(DiagnosticFinding finding)
        => finding.Severidad is DiagnosticSeverity.Advertencia or DiagnosticSeverity.Error or DiagnosticSeverity.Critico
           && (finding.Id.StartsWith("RESOURCE-", StringComparison.OrdinalIgnoreCase)
               || finding.Id.StartsWith("RDP-CERTIFICATE-", StringComparison.OrdinalIgnoreCase));

    private static bool IsHeavySignal(AlertSignal signal)
        => signal.SourceId is not null &&
           (signal.SourceId.StartsWith("RESOURCE-DISK-", StringComparison.OrdinalIgnoreCase)
            || signal.SourceId.StartsWith("RESOURCE-MEMORY-", StringComparison.OrdinalIgnoreCase)
            || signal.SourceId.StartsWith("RESOURCE-CPU-", StringComparison.OrdinalIgnoreCase)
            || signal.SourceId.StartsWith("RESOURCE-TCP-", StringComparison.OrdinalIgnoreCase)
            || signal.SourceId.StartsWith("RDP-CERTIFICATE-", StringComparison.OrdinalIgnoreCase));

    private static int SeverityRank(string value)
        => value.ToLowerInvariant() switch
        {
            "critico" or "crítico" => 4,
            "error" => 3,
            "advertencia" => 2,
            _ => 1
        };

    private async Task<SystemSnapshot> GetSystemSnapshotAsync(CancellationToken ct)
    {
        var now = DateTimeOffset.Now;
        Task<SystemSnapshot> task;
        lock (_snapshotSync)
        {
            if (_snapshotTask is { IsCompletedSuccessfully: true })
            {
                _snapshot = _snapshotTask.Result;
                _snapshotCapturedAt = now;
                _snapshotTask = null;
            }
            if (_snapshotTask is { IsCompleted: true })
            {
                // Q1: una captura fallida/cancelada nunca se reutiliza; se descarta aquí para
                // reintentar en este mismo ciclo en vez de degradar crónicamente hasta reiniciar.
                _snapshotTask = null;
            }
            if (_snapshot is not null && now - _snapshotCapturedAt < SnapshotRefresh) return _snapshot;
            _snapshotTask ??= Task.Run(SystemSnapshotReader.Capture, CancellationToken.None);
            task = _snapshotTask;
        }

        try
        {
            var result = await task.WaitAsync(SnapshotTimeout, ct).ConfigureAwait(false);
            lock (_snapshotSync)
            {
                _snapshot = result;
                _snapshotCapturedAt = DateTimeOffset.Now;
                if (ReferenceEquals(_snapshotTask, task)) _snapshotTask = null;
            }
            return result;
        }
        catch (TimeoutException)
        {
            lock (_snapshotSync)
            {
                if (_snapshot is not null) return _snapshot;
            }
            throw new TimeoutException($"SystemSnapshotReader no terminó dentro de {SnapshotTimeout.TotalSeconds:0} s. La captura queda aislada y no se duplica.");
        }
    }

    private async Task CaptureLongitudinalStateIfDueAsync(SystemSnapshot snapshot, DateTimeOffset cycleStarted, CancellationToken ct)
    {
        var now = DateTimeOffset.Now;
        // Q5: la auditoría longitudinal (forensic 8 s + integrity 15 s secuenciales) no debe
        // estirar el ciclo más allá de la cadencia: si el monitor ya consumió el presupuesto,
        // se omite este ciclo (los temporizadores conservan su cadencia y reintentan).
        if (now - cycleStarted > TimeSpan.FromSeconds(45))
        {
            _logger.LogWarning("Se omite la auditoría longitudinal de este ciclo para preservar la cadencia de monitoreo.");
            return;
        }
        if (now >= _nextForensicStateAt)
        {
            _nextForensicStateAt = now + ForensicStateInterval;
            await CaptureStateChannelSafeAsync(snapshot, CollectorCatalog.CreateForensicStateMonitor(), "forensic-monitor", TimeSpan.FromSeconds(8), ct).ConfigureAwait(false);
        }

        if (now >= _nextIntegrityStateAt)
        {
            _nextIntegrityStateAt = now + IntegrityStateInterval;
            await CaptureStateChannelSafeAsync(snapshot, CollectorCatalog.CreateIntegrityStateMonitor(), "integrity-monitor", TimeSpan.FromSeconds(15), ct).ConfigureAwait(false);
        }
    }

    private async Task CaptureStateChannelSafeAsync(
        SystemSnapshot snapshot,
        IReadOnlyList<IReadOnlyCollector> collectors,
        string channel,
        TimeSpan collectorTimeout,
        CancellationToken ct)
    {
        try
        {
            var tsplusProfile = TsplusReleaseCatalog.Resolve(snapshot);

            // Load diagnostic options from configuration
            DiagnosticOptions? options = null;
            try
            {
                var configStore = new SupportMonitoringSettingsStore(_root);
                var monitoringSettings = await configStore.LoadAsync(ct).ConfigureAwait(false);
                var thresholds = monitoringSettings.Thresholds;
                options = new DiagnosticOptions
                {
                    MaxFilesPerDirectory = thresholds.MaxFilesPerDirectory,
                    MaxBytesPerFile = thresholds.MaxBytesPerFile,
                    MaxTotalBytes = thresholds.MaxTotalBytes,
                    MaxEvents = thresholds.MaxEvents,
                    EnableRdpEtw = false,
                    CauseStabilityFlappingThreshold = thresholds.CauseStabilityFlappingThreshold,
                    MaxFilesPerDirectoryIncremental = thresholds.MaxFilesPerDirectoryIncremental,
                    MaxBytesPerFileIncremental = thresholds.MaxBytesPerFileIncremental,
                    MaxTotalBytesIncremental = thresholds.MaxTotalBytesIncremental,
                    MaxEventsIncremental = thresholds.MaxEventsIncremental
                };
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                _logger.LogDebug(ex, "No se pudo cargar configuración de umbrales (longitudinal); usando valores por defecto");
            }

            var context = new DiagnosticContext(snapshot with { FechaCaptura = DateTimeOffset.Now }, TimeSpan.FromMinutes(15), TsplusProfile: tsplusProfile, Options: options);
            var policy = DiagnosticExecutionPolicy.Uniform(collectorTimeout, 8_000);
            var engine = new DiagnosticEngine(collectors, policy, _circuitBreaker);
            var report = await engine.RunAsync(context, ct).ConfigureAwait(false);
            report = DiagnosticWorkflow.EnrichOperationalState(report);
            var state = StateSnapshotBuilder.Build(report, TdmProductInfo.Version);
            await new LocalStateStore(_root).RecordAsync(state, channel, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Auditoría longitudinal {Channel} no disponible en este ciclo", channel);
        }
    }

    private async Task ProcessNotificationSelfTestAsync(NotificationDispatcher dispatcher, CancellationToken ct)
    {
        var path = Path.Combine(_root, "runtime", "notification-selftest.request");
        if (!File.Exists(path)) return;
        string token;
        try { token = (await File.ReadAllTextAsync(path, ct).ConfigureAwait(false)).Trim(); }
        catch (IOException) { return; }
        if (string.IsNullOrWhiteSpace(token)) token = Guid.NewGuid().ToString("N");

        await dispatcher.SendOneShotAsync(new AlertSignal(
            $"selftest|{token}",
            DateTimeOffset.Now,
            "Informativo",
            "TDM · Prueba de notificación",
            "Canal Service → Dispatcher → Notifier operativo.",
            "SelfTest",
            token), ct).ConfigureAwait(false);
        try { File.Delete(path); } catch { }
    }

    private async Task WriteHeartbeatSafeAsync(ServiceHeartbeatStore store, string status, TimeSpan interval, string? error, CancellationToken ct)
    {
        try
        {
            await store.WriteAsync(new TdmServiceHeartbeat(
                DateTimeOffset.Now,
                TdmProductInfo.Version,
                status,
                Environment.ProcessId,
                (int)Math.Round(interval.TotalSeconds),
                Interlocked.Read(ref _completedSamples),
                _deferredSamples,
                error), ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _logger.LogError(ex, "No fue posible escribir heartbeat de TDM.Service");
        }
    }

private static (double WorkingSetMb, int Handles, int Threads) CaptureSelfMetrics()
    {
        using var process = Process.GetCurrentProcess();
        return (process.WorkingSet64 / 1024d / 1024d, process.HandleCount, process.Threads.Count);
    }

    private void SetupGlobalExceptionHandlers()
    {
        // 1. TaskScheduler unobserved exceptions (background tasks)
        TaskScheduler.UnobservedTaskException += (s, e) =>
        {
            try { _logger.LogCritical(e.Exception, "TASK_SCHEDULER_UNOBSERVED: Unobserved task exception"); }
            catch { }
            e.SetObserved(); // Prevent process crash
        };

        // 2. AppDomain unhandled exceptions (non-TPL threads)
        AppDomain.CurrentDomain.UnhandledException += (s, e) =>
        {
            var ex = e.ExceptionObject as Exception;
            try { _logger.LogCritical(ex, "APPDOMAIN_UNHANDLED: Unhandled exception on non-TPL thread"); }
            catch { }
            // Cannot prevent process exit, but logged for diagnosis
        };

        // 3. Process exit - distinguish crash vs clean shutdown
        var proc = Process.GetCurrentProcess();
        proc.EnableRaisingEvents = true;
        proc.Exited += (s, e) =>
        {
            var exitCode = proc.ExitCode;
            var isCrash = exitCode != 0 && exitCode != -1; // -1 = clean shutdown
            var msg = isCrash
                ? $"PROCESS_CRASH: ExitCode={exitCode} (TDM.Service crashed)"
                : $"PROCESS_EXIT: ExitCode={exitCode} (clean shutdown)";
            try { _logger.LogCritical(msg); }
            catch { /* Best-effort */ }
        };
    }
}
