using System.Diagnostics;
using System.Net.NetworkInformation;
using TDM.Application;
using TDM.Collectors.Windows;
using TDM.Core;
using TDM.Models;
using TDM.Notifications;
using TDM.Persistence;

namespace TDM.Gui.Avalonia.Services;

/// <summary>
/// Monitor ligero integrado para Avalonia.
/// La GUI genera una muestra local cada 5 segundos desde el arranque,
/// incluso cuando TDM.Service está activo. Esa muestra actúa como capa
/// de tiempo real para CPU, memoria, red y salud de TDM; la telemetría
/// del servicio sigue aportando el historial operativo de máquina.
/// </summary>
public sealed class IntegratedMonitoringService : IDisposable
{
    public const int RealtimeIntervalSeconds = 5;
    private static readonly TimeSpan MonitorInterval = TimeSpan.FromSeconds(RealtimeIntervalSeconds);
    private static readonly TimeSpan RealtimeOverallBudget = TimeSpan.FromSeconds(3);
    private static readonly TimeSpan RealtimeCollectorTimeout = TimeSpan.FromSeconds(1);
    private static readonly TimeSpan SnapshotAcquisitionBudget = TimeSpan.FromMilliseconds(750);
    private static readonly TimeSpan SnapshotRefresh = TimeSpan.FromMinutes(30);
    private static readonly TimeSpan ForensicProbeInterval = TimeSpan.FromMinutes(1);
    private static readonly TimeSpan ForensicStateInterval = TimeSpan.FromMinutes(2);
    private static readonly TimeSpan IntegrityStateInterval = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan PortableNotificationInterval = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan AnomalyAlertCooldown = TimeSpan.FromMinutes(5);

    private readonly string _writeRoot = LocalStateStore.DefaultRootPath;
    private readonly ObservabilityStore _store;
    private readonly IncidentLedger? _portableIncidentLedger;
    private readonly NotificationDispatcher? _portableNotificationDispatcher;
    private readonly SupportMonitoringSettingsStore? _portableSettingsStore;
    private readonly EwmaAnomalyDetector _systemDetector = EwmaDetectorFactory.CreateForSystemMetrics();
    private readonly Dictionary<string, DateTimeOffset> _anomalyCooldown = new();
    private readonly CancellationTokenSource _cts = new();
    private readonly SemaphoreSlim _captureGate = new(1, 1);
    private readonly SemaphoreSlim _forensicGate = new(1, 1);
    private readonly object _processSync = new();
    private readonly object _networkSync = new();

    private Task? _loopTask;
    private Task? _forensicLoopTask;
    private bool _usesExternalService;
    private bool _started;
    private bool _disposed;
    private DateTimeOffset _nextForensicStateAt = DateTimeOffset.MinValue;
    private DateTimeOffset _nextIntegrityStateAt = DateTimeOffset.MinValue;
    private DateTimeOffset _nextPortableNotificationAt = DateTimeOffset.MinValue;

    private SystemSnapshot? _cachedSnapshot;
    private DateTimeOffset? _cachedSnapshotAt;
    private Task<SystemSnapshot>? _snapshotTask;

    private DateTimeOffset? _tdmProcessMetricAt;
    private TimeSpan _tdmProcessCpuTotal;
    private double? _latestTdmCpuPercent;
    private int _latestTdmHandleCount;
    private int _latestTdmThreadCount;

    private DateTimeOffset? _networkMetricAt;
    private long _networkBytesReceived;
    private long _networkBytesSent;

    public event Action<IReadOnlyList<IncidentNotification>>? PortableNotificationsProduced;

    public IntegratedMonitoringService()
    {
        _store = new ObservabilityStore(_writeRoot);
        if (PortableRuntime.IsEnabled)
        {
            _portableIncidentLedger = new IncidentLedger(_writeRoot);
            _portableNotificationDispatcher = new NotificationDispatcher(
                [new SmtpEmailNotificationSink(_writeRoot)], _writeRoot);
            _portableSettingsStore = new SupportMonitoringSettingsStore(_writeRoot);
        }
    }

    public Task InitializeAsync(CancellationToken ct = default)
    {
        ThrowIfDisposed();
        if (_started) return Task.CompletedTask;
        _started = true;

        // La primera captura se ejecuta dentro del loop en segundo plano. La ventana
        // puede mostrarse inmediatamente sin esperar inventario, WMI o Event Log.
        _loopTask = Task.Run(() => RunLoopAsync(_cts.Token));
        // El inventario forense usa un loop independiente: nunca bloquea el PeriodicTimer
        // de 5 s que alimenta CPU/memoria/red en tiempo real.
        _forensicLoopTask = Task.Run(() => RunForensicLoopAsync(_cts.Token));
        return Task.CompletedTask;
    }

    private async Task RunLoopAsync(CancellationToken ct)
    {
        try
        {
            _usesExternalService = await IsServiceMonitoringAvailableAsync(ct).ConfigureAwait(false);
            using (var firstSampleCts = CancellationTokenSource.CreateLinkedTokenSource(ct))
            {
                firstSampleCts.CancelAfter(TimeSpan.FromSeconds(8));
                await CaptureAndRecordSafeAsync(firstSampleCts.Token).ConfigureAwait(false);
            }

            using var timer = new PeriodicTimer(MonitorInterval);
            while (await timer.WaitForNextTickAsync(ct).ConfigureAwait(false))
                await CaptureAndRecordSafeAsync(ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
        }
    }

    private async Task RunForensicLoopAsync(CancellationToken ct)
    {
        try
        {
            await CaptureForensicStateSafeAsync(ct).ConfigureAwait(false);
            using var timer = new PeriodicTimer(ForensicProbeInterval);
            while (await timer.WaitForNextTickAsync(ct).ConfigureAwait(false))
                await CaptureForensicStateSafeAsync(ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
        }
    }

    private async Task CaptureForensicStateSafeAsync(CancellationToken ct)
    {
        if (!await _forensicGate.WaitAsync(0, ct).ConfigureAwait(false)) return;
        try
        {
            _usesExternalService = await IsServiceMonitoringAvailableAsync(ct).ConfigureAwait(false);
            if (_usesExternalService) return;

            var load = ResourceLoadGuard.Capture();
            if (load.ShouldDefer) return;

            var now = DateTimeOffset.Now;
            var runForensic = now >= _nextForensicStateAt;
            var runIntegrity = now >= _nextIntegrityStateAt;
            if (!runForensic && !runIntegrity) return;

            SystemSnapshot snapshot;
            try
            {
                snapshot = await Task.Run(SystemSnapshotReader.Capture, CancellationToken.None)
                    .WaitAsync(TimeSpan.FromSeconds(8), ct).ConfigureAwait(false);
            }
            catch (TimeoutException)
            {
                return;
            }

            if (runForensic)
            {
                _nextForensicStateAt = now + ForensicStateInterval;
                await RecordStateChannelAsync(snapshot, CollectorCatalog.CreateForensicStateMonitor(), "forensic-monitor", TimeSpan.FromSeconds(8), ct).ConfigureAwait(false);
            }

            if (runIntegrity)
            {
                _nextIntegrityStateAt = now + IntegrityStateInterval;
                await RecordStateChannelAsync(snapshot, CollectorCatalog.CreateIntegrityStateMonitor(), "integrity-monitor", TimeSpan.FromSeconds(15), ct).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
        }
        catch
        {
            // La auditoría longitudinal es complementaria y aislada del monitor visual de 5 s.
        }
        finally
        {
            _forensicGate.Release();
        }
    }

    private async Task RecordStateChannelAsync(
        SystemSnapshot snapshot,
        IReadOnlyList<IReadOnlyCollector> collectors,
        string channel,
        TimeSpan collectorTimeout,
        CancellationToken ct)
    {
        var context = new DiagnosticContext(snapshot with { FechaCaptura = DateTimeOffset.Now }, TimeSpan.FromMinutes(15));
        var engine = new DiagnosticEngine(collectors, collectorTimeout: collectorTimeout, maxRawEvents: 8_000);
        var report = await engine.RunAsync(context, ct).ConfigureAwait(false);
        report = DiagnosticWorkflow.EnrichOperationalState(report);
        var state = StateSnapshotBuilder.Build(report, TdmProductInfo.Version);
        await new LocalStateStore(_writeRoot).RecordAsync(state, channel, ct).ConfigureAwait(false);
    }

    private async Task CaptureAndRecordSafeAsync(CancellationToken ct)
    {
        if (!await _captureGate.WaitAsync(0, ct).ConfigureAwait(false))
            return;

        try
        {
            var load = ResourceLoadGuard.Capture();
            var snapshot = await GetSystemSnapshotAsync(ct).ConfigureAwait(false);
            var context = new DiagnosticContext(snapshot, TimeSpan.FromMinutes(5));
            var collectors = CollectorCatalog.CreateLightweight(load);
            // El presupuesto total es menor al intervalo de 5 s: una API lenta no puede
            // convertir el monitor visual en un ciclo de 10/15 s ni acumular ejecuciones.
            var realtimePolicy = DiagnosticExecutionPolicy.Uniform(
                RealtimeCollectorTimeout, maxRawEvents: 1_500, overallTimeout: RealtimeOverallBudget);
            var engine = new DiagnosticEngine(collectors, realtimePolicy);

            var report = await engine.RunAsync(context, ct).ConfigureAwait(false);
            report = DiagnosticWorkflow.EnrichOperationalState(report);

            var now = DateTimeOffset.Now;
            var processMetrics = CaptureTdmProcessMetrics(now);
            var networkMetrics = CaptureServerNetworkMetrics(now);
            var runtime = new ObservabilityRuntimeState
            {
                MonitorIntervalSeconds = (int)MonitorInterval.TotalSeconds,
                MonitorMode = _usesExternalService ? "Interfaz TDM 5 s + TDM.Service" : "Interfaz TDM 5 s",
                DeferredSamples = load.ShouldDefer ? 1 : 0,
                TdmWorkingSetMb = processMetrics.WorkingSetMb,
                TdmCpuPercent = processMetrics.CpuPercent,
                TdmHandleCount = processMetrics.HandleCount,
                TdmThreadCount = processMetrics.ThreadCount,
                ObservabilityBytes = _store.WindowSizeBytes,
                NetworkReceiveMbps = networkMetrics.ReceiveMbps,
                NetworkSendMbps = networkMetrics.SendMbps
            };

            // Run anomaly detection on the report's metrics
            var resources = report.Eventos.LastOrDefault(e => e.Tipo.Equals("SYSTEM_RESOURCE_STATE", StringComparison.OrdinalIgnoreCase));
            var cpu = resources?.Evidencia?.FirstOrDefault(e => e.Clave.Equals("CpuPercent"))?.Valor;
            var memory = resources?.Evidencia?.FirstOrDefault(e => e.Clave.Equals("MemoryFreePercent"))?.Valor;

            var anomalyFindings = new List<DiagnosticFinding>();
            if (double.TryParse(cpu, out var cpuVal))
                AddAnomalyFinding(anomalyFindings, "system.cpu", cpuVal, "CPU del sistema", DateTimeOffset.Now);
            if (double.TryParse(memory, out var memVal))
                AddAnomalyFinding(anomalyFindings, "system.memory", memVal, "Memoria libre %", DateTimeOffset.Now);
            if (anomalyFindings.Count > 0)
                report = report with { Hallazgos = [.. report.Hallazgos, .. anomalyFindings] };

            var sample = await _store.RecordAsync(report, "avalonia-monitor", runtime, ct).ConfigureAwait(false);
            await EmitPortableNotificationsIfDueAsync(report, sample, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
        }
        catch
        {
            // La telemetría integrada es complementaria. Un fallo puntual no debe cerrar la GUI.
        }
        finally
        {
            _captureGate.Release();
        }
    }

    private async Task EmitPortableNotificationsIfDueAsync(
        DiagnosticReport report,
        ObservabilitySample sample,
        CancellationToken ct)
    {
        if (!PortableRuntime.IsEnabled
            || _portableIncidentLedger is null
            || _portableNotificationDispatcher is null
            || _portableSettingsStore is null
            || sample.Timestamp < _nextPortableNotificationAt)
            return;

        _nextPortableNotificationAt = sample.Timestamp + PortableNotificationInterval;
        var settings = await _portableSettingsStore.LoadAsync(ct).ConfigureAwait(false);
        var managed = await _portableIncidentLedger.ReconcileAsync(
            sample.Incidents ?? [], sample.Timestamp, settings, "LOCAL", ct).ConfigureAwait(false);
        var signals = BuildPortableSignals(report, managed);
        var emitted = await _portableNotificationDispatcher.DispatchAsync(signals, sample.Timestamp, ct).ConfigureAwait(false);
        if (emitted.Count == 0) return;

        try
        {
            PortableNotificationsProduced?.Invoke(emitted);
        }
        catch
        {
            // Una ventana de aviso nunca debe interrumpir el ciclo de monitoreo.
        }
    }

    private static IReadOnlyList<AlertSignal> BuildPortableSignals(
        DiagnosticReport report,
        IReadOnlyList<ManagedIncident> managed)
    {
        var signals = managed
            .Where(x => x.State is ManagedIncidentState.Active or ManagedIncidentState.Persistent)
            .Select(x => new AlertSignal(
                $"incident|{x.Node}|{x.Component}|{x.Kind}",
                x.LastSeenAt,
                x.Severity,
                AlertTitleFormatter.ForIncident(x),
                x.Summary,
                "IncidentLedger",
                x.Id))
            .ToList();

        signals.AddRange(report.Hallazgos
            .Where(x => x.Severidad is DiagnosticSeverity.Advertencia or DiagnosticSeverity.Error or DiagnosticSeverity.Critico)
            .Select(x => new AlertSignal(
                $"finding|{x.Id}",
                report.PeriodoAnalizadoFin != default ? report.PeriodoAnalizadoFin : DateTimeOffset.Now,
                x.Severidad.ToString(),
                AlertTitleFormatter.ForFinding(x),
                x.Resumen,
                "PortableFinding",
                x.Id)));

        return signals;
    }

    private async Task<SystemSnapshot> GetSystemSnapshotAsync(CancellationToken ct)
    {
        var now = DateTimeOffset.Now;

        if (_snapshotTask is { IsCompletedSuccessfully: true } completed)
        {
            _cachedSnapshot = completed.Result;
            _cachedSnapshotAt = now;
            _snapshotTask = null;
        }
        else if (_snapshotTask is { IsFaulted: true } faulted)
        {
            _ = faulted.Exception;
            _snapshotTask = null;
        }

        var stale = _cachedSnapshot is null
                    || !_cachedSnapshotAt.HasValue
                    || now - _cachedSnapshotAt.Value >= SnapshotRefresh;

        if (stale)
        {
            _snapshotTask ??= Task.Run(SystemSnapshotReader.Capture, CancellationToken.None);
            try
            {
                _cachedSnapshot = await _snapshotTask.WaitAsync(SnapshotAcquisitionBudget, ct).ConfigureAwait(false);
                _cachedSnapshotAt = now;
                _snapshotTask = null;
            }
            catch (TimeoutException)
            {
                _cachedSnapshot ??= BuildFallbackSnapshot(now);
                _cachedSnapshotAt ??= now;
            }
            catch (Exception) when (!ct.IsCancellationRequested)
            {
                if (_snapshotTask?.IsFaulted == true)
                    _ = _snapshotTask.Exception;
                _snapshotTask = null;
                _cachedSnapshot ??= BuildFallbackSnapshot(now);
                _cachedSnapshotAt ??= now;
            }
        }

        var snapshot = _cachedSnapshot ?? BuildFallbackSnapshot(now);
        var age = now - (_cachedSnapshotAt ?? now);
        return snapshot with
        {
            FechaCaptura = now,
            Uptime = snapshot.Uptime + (age > TimeSpan.Zero ? age : TimeSpan.Zero)
        };
    }

    private static SystemSnapshot BuildFallbackSnapshot(DateTimeOffset now)
    {
        var tsplus = TDM.Collectors.Windows.TsplusInstallDiscovery.Discover();
        return new SystemSnapshot(
            Environment.MachineName,
            System.Runtime.InteropServices.RuntimeInformation.OSDescription,
            Environment.OSVersion.Version.ToString(),
            Environment.OSVersion.Version.Build.ToString(),
            System.Runtime.InteropServices.RuntimeInformation.OSArchitecture.ToString(),
            TimeSpan.FromMilliseconds(Environment.TickCount64),
            now,
            tsplus.Detectado,
            tsplus.RutaInstalacion,
            tsplus.Version) with { TsplusEstadoDeteccion = tsplus.Estado };
    }

    private (double WorkingSetMb, double? CpuPercent, int HandleCount, int ThreadCount) CaptureTdmProcessMetrics(DateTimeOffset now)
    {
        lock (_processSync)
        {
            using var process = Process.GetCurrentProcess();
            process.Refresh();
            var workingSet = process.WorkingSet64 / 1024d / 1024d;
            var total = process.TotalProcessorTime;
            double? cpu = _latestTdmCpuPercent;
            if (_tdmProcessMetricAt.HasValue)
            {
                var elapsed = now - _tdmProcessMetricAt.Value;
                if (elapsed.TotalMilliseconds >= 500)
                {
                    var cpuMs = (total - _tdmProcessCpuTotal).TotalMilliseconds;
                    cpu = Math.Clamp(cpuMs / Math.Max(1d, elapsed.TotalMilliseconds * Environment.ProcessorCount) * 100d, 0d, 100d);
                }
            }

            _tdmProcessMetricAt = now;
            _tdmProcessCpuTotal = total;
            _latestTdmCpuPercent = cpu;
            _latestTdmHandleCount = process.HandleCount;
            _latestTdmThreadCount = process.Threads.Count;
            return (workingSet, cpu, _latestTdmHandleCount, _latestTdmThreadCount);
        }
    }

    private (double? ReceiveMbps, double? SendMbps) CaptureServerNetworkMetrics(DateTimeOffset now)
    {
        lock (_networkSync)
        {
            long received = 0;
            long sent = 0;
            try
            {
                foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (nic.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel
                        || nic.OperationalStatus != OperationalStatus.Up)
                        continue;

                    try
                    {
                        var stats = nic.GetIPv4Statistics();
                        received += Math.Max(0, stats.BytesReceived);
                        sent += Math.Max(0, stats.BytesSent);
                    }
                    catch
                    {
                        // Un adaptador aislado no debe afectar la telemetría completa.
                    }
                }
            }
            catch
            {
                return (null, null);
            }

            double? receiveMbps = null;
            double? sendMbps = null;
            if (_networkMetricAt.HasValue)
            {
                var elapsed = (now - _networkMetricAt.Value).TotalSeconds;
                if (elapsed >= 0.5 && received >= _networkBytesReceived && sent >= _networkBytesSent)
                {
                    receiveMbps = Math.Max(0d, (received - _networkBytesReceived) * 8d / elapsed / 1_000_000d);
                    sendMbps = Math.Max(0d, (sent - _networkBytesSent) * 8d / elapsed / 1_000_000d);
                }
            }

            _networkMetricAt = now;
            _networkBytesReceived = received;
            _networkBytesSent = sent;
            return (receiveMbps, sendMbps);
        }
    }

    private static async Task<bool> IsServiceMonitoringAvailableAsync(CancellationToken ct)
    {
        if (PortableRuntime.IsEnabled) return false;
        try
        {
            var machineRoot = TdmDataPaths.MachineRootPath;
            var heartbeat = await new ServiceHeartbeatStore(machineRoot).ReadAsync(ct).ConfigureAwait(false);
            return ServiceHeartbeatStore.IsFresh(heartbeat)
                   && !string.Equals(heartbeat?.Status, "STOPPED", StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    private void AddAnomalyFinding(List<DiagnosticFinding> findings, string metricKey, double value, string metricName, DateTimeOffset timestamp)
    {
        var result = _systemDetector.Process(metricKey, value, timestamp);
        if (result is null) return;

        var lastAlert = _anomalyCooldown.GetValueOrDefault(metricKey, DateTimeOffset.MinValue);
        if (timestamp - lastAlert < AnomalyAlertCooldown) return;
        _anomalyCooldown[metricKey] = timestamp;

        var directionText = result.Direction == AnomalyDirection.High ? "ALTO" : "BAJO";
        var severity = result.Severity == AnomalySeverity.Critical ? DiagnosticSeverity.Critico : DiagnosticSeverity.Advertencia;
        findings.Add(new DiagnosticFinding(
            $"EWMA-{metricKey}-{timestamp:yyyyMMddHHmmss}",
            "Detección de anomalías (EWMA)",
            severity,
            $"Anomalía estadística en {metricName}",
            $"Valor {result.ObservedValue:F2} vs esperado {result.ExpectedValue:F2} (Z={result.ZScore:F1}, {directionText})",
            [
                new EvidenceItem("Métrica", metricName),
                new EvidenceItem("Clave", metricKey),
                new EvidenceItem("Valor observado", result.ObservedValue.ToString("F2")),
                new EvidenceItem("Valor esperado (EWMA)", result.ExpectedValue.ToString("F2")),
                new EvidenceItem("Z-Score", result.ZScore.ToString("F2")),
                new EvidenceItem("Dirección", directionText),
                new EvidenceItem("Muestras", result.SampleCount.ToString())
            ],
            ConfidenceLevel.Media,
            Capa: DiagnosticLayer.Windows));
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _cts.Cancel();
        try { _loopTask?.Wait(TimeSpan.FromSeconds(2)); } catch { }
        try { _forensicLoopTask?.Wait(TimeSpan.FromSeconds(2)); } catch { }
        _captureGate.Dispose();
        _forensicGate.Dispose();
        _cts.Dispose();
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(IntegratedMonitoringService));
    }
}
