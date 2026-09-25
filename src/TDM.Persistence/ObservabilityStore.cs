using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;
using TDM.Models;

namespace TDM.Persistence;

/// <summary>
/// Snapshot agregado para los dashboards nativos de TDM.
/// No contiene contraseñas, direcciones IP, rutas de perfiles ni mensajes crudos.
/// Sí conserva el asunto operativo (cuenta, servicio o proceso) en <see cref="Subject"/>
/// para que el operador identifique qué revisar en los detalles del dashboard.
/// Se construye exclusivamente a partir de evidencia que TDM ya recopiló.
/// </summary>
public sealed record ObservabilityIncident(
    DateTimeOffset Timestamp,
    string Kind,
    string Component,
    string Severity,
    string Summary,
    string? EvidenceSource = null,
    string? EvidenceId = null,
    string? EvidenceFile = null,
    string CapturedBy = "TDM",
    string? Product = null,
    string? Classification = null,
    string? Subject = null);

public sealed record ObservabilitySample
{
    public DateTimeOffset Timestamp { get; init; }
    public string SampleKind { get; init; } = "monitor";
    public double? CpuPercent { get; init; }
    public double? MemoryFreePercent { get; init; }
    public double? MemoryTotalBytes { get; init; }
    public IReadOnlyDictionary<string, double> ProcessRamMb { get; init; } = new Dictionary<string, double>();
    public IReadOnlyDictionary<string, double> ProcessHandles { get; init; } = new Dictionary<string, double>();
    public IReadOnlyDictionary<string, double> ProcessThreads { get; init; } = new Dictionary<string, double>();
    public IReadOnlyDictionary<string, double> DiskFreePercent { get; init; } = new Dictionary<string, double>();
    public IReadOnlyDictionary<string, double> DiskFreeBytes { get; init; } = new Dictionary<string, double>();
    public double? TcpEphemeralUsagePercent { get; init; }
    public int TcpTimeWait { get; init; }
    public int TcpEstablished { get; init; }
    public int ActiveSessions { get; init; }
    public int DisconnectedSessions { get; init; }
    public string SessionCoverage { get; init; } = "No evaluado";
    public int LogonFailures { get; init; }
    public int NlaFailures { get; init; }
    public IReadOnlyDictionary<string, string> ModuleHealth { get; init; } = new Dictionary<string, string>();
    public int CriticalFindings { get; init; }
    public int ErrorFindings { get; init; }
    public int WarningFindings { get; init; }
    public int CrashLoops { get; init; }
    public int Transitions { get; init; }
    public int BaselineDifferences { get; init; }
    public int? CoverageScore { get; init; }
    public string? CausalOrigin { get; init; }
    public string? Originator { get; init; }
    public double DiagnosticDurationMs { get; init; }
    public int CollectorTimeouts { get; init; }
    public string SlowestCollector { get; init; } = "N/D";
    public double SlowestCollectorMs { get; init; }
    public int MonitorIntervalSeconds { get; init; }
    public string MonitorMode { get; init; } = "N/D";
    public int DeferredSamples { get; init; }
    public double TdmWorkingSetMb { get; init; }
    public IReadOnlyDictionary<string, string>? ServiceStates { get; init; }
    public IReadOnlyDictionary<string, string>? DependencyStates { get; init; }
    public IReadOnlyList<ObservabilityIncident>? Incidents { get; init; }
    public double? TdmCpuPercent { get; init; }
    public int TdmHandleCount { get; init; }
    public int TdmThreadCount { get; init; }
    public long ObservabilityBytes { get; init; }
    public double? NetworkReceiveMbps { get; init; }
    public double? NetworkSendMbps { get; init; }
}


public sealed record ObservabilityRuntimeState
{
    public int MonitorIntervalSeconds { get; init; }
    public string MonitorMode { get; init; } = "N/D";
    public int DeferredSamples { get; init; }
    public double TdmWorkingSetMb { get; init; }
    public IReadOnlyDictionary<string, string>? ServiceStates { get; init; }
    public IReadOnlyDictionary<string, string>? DependencyStates { get; init; }
    public IReadOnlyList<ObservabilityIncident>? Incidents { get; init; }
    public double? TdmCpuPercent { get; init; }
    public int TdmHandleCount { get; init; }
    public int TdmThreadCount { get; init; }
    public long ObservabilityBytes { get; init; }
    public double? NetworkReceiveMbps { get; init; }
    public double? NetworkSendMbps { get; init; }

    public ObservabilityRuntimeState() { }

    public ObservabilityRuntimeState(int monitorIntervalSeconds, string monitorMode, int deferredSamples, double tdmWorkingSetMb)
    {
        MonitorIntervalSeconds = monitorIntervalSeconds;
        MonitorMode = monitorMode;
        DeferredSamples = deferredSamples;
        TdmWorkingSetMb = tdmWorkingSetMb;
    }
}


public sealed class ObservabilityStore
{
    private static readonly TimeSpan MaxWindow = TimeSpan.FromDays(3);
    private static readonly TimeSpan FullResolutionWindow = TimeSpan.FromHours(1);
    private const int MaxSamples = 6_500;
    private const long CompactAfterBytes = 12L * 1024 * 1024;

    /// <summary>Ventana histórica máxima disponible para los dashboards.</summary>
    public static TimeSpan MaximumRetention => MaxWindow;
    private int _appendsSinceCompactCheck;
    private DateTimeOffset _lastCompact = DateTimeOffset.MinValue;
    private int _lastReadDiscardedLines;
    public int LastReadDiscardedLines => Volatile.Read(ref _lastReadDiscardedLines);
    private readonly JsonSerializerOptions _json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false
    };

    private readonly string _rootPath;
    public string WindowPath => Path.Combine(_rootPath, "state", "observability-window.jsonl");
    public long WindowSizeBytes
    {
        get
        {
            try { return File.Exists(WindowPath) ? new FileInfo(WindowPath).Length : 0L; }
            catch { return 0L; }
        }
    }

    public ObservabilityStore(string? rootPath = null)
    {
        _rootPath = string.IsNullOrWhiteSpace(rootPath) ? LocalStateStore.DefaultRootPath : rootPath;
        Directory.CreateDirectory(Path.Combine(_rootPath, "state"));
    }

    public async Task<ObservabilitySample> RecordAsync(
        DiagnosticReport report,
        string sampleKind,
        ObservabilityRuntimeState runtime,
        CancellationToken ct = default)
    {
        var sample = BuildSample(report, sampleKind, runtime);
        var lockPath = Path.Combine(_rootPath, ".observability.lock");
        await using var gate = await AcquireLockAsync(lockPath, ct);

        // Ruta caliente de producción: una muestra agrega sólo una línea JSONL.
        // No reescribe toda la ventana cada 30/60 s. La compactación ocurre
        // únicamente cuando el archivo alcanza un tamaño conservador.
        await AppendAsync(sample, ct);
        _appendsSinceCompactCheck++;
        if (_appendsSinceCompactCheck >= 30)
        {
            _appendsSinceCompactCheck = 0;
            if ((_lastCompact == DateTimeOffset.MinValue || sample.Timestamp - _lastCompact >= TimeSpan.FromMinutes(30))
                && File.Exists(WindowPath)
                && new FileInfo(WindowPath).Length >= CompactAfterBytes)
            {
                await CompactUnsafeAsync(sample.Timestamp, ct);
                _lastCompact = sample.Timestamp;
            }
        }

        return sample;
    }

    public async Task<IReadOnlyList<ObservabilitySample>> ReadWindowAsync(TimeSpan window, CancellationToken ct = default)
    {
        var bounded = window <= TimeSpan.Zero ? TimeSpan.FromHours(2) : window > MaxWindow ? MaxWindow : window;
        var samples = await ReadAllUnsafeAsync(ct);
        if (samples.Count == 0) return [];
        var end = samples.Max(x => x.Timestamp);
        var start = end - bounded;
        var selected = samples
            .Where(x => x.Timestamp >= start && x.Timestamp <= end)
            .OrderBy(x => x.Timestamp)
            .GroupBy(x => new { x.Timestamp, x.SampleKind })
            .Select(g => g.Last())
            .ToList();

        return selected.Count <= MaxSamples
            ? selected
            : ReduceForRetention(selected, end);
    }

    private ObservabilitySample BuildSample(DiagnosticReport report, string sampleKind, ObservabilityRuntimeState runtime)
    {
        var resources = report.Eventos.LastOrDefault(e => e.Tipo.Equals("SYSTEM_RESOURCE_STATE", StringComparison.OrdinalIgnoreCase));
        var cpu = ParseCpu(resources);
        var memory = ParseMemory(resources);
        var memoryTotalBytes = MetricDouble(resources, ResourceMetricKeys.MemoryTotalBytes);
        var processRam = ParseProcessMetric(resources, "RamMb");
        var processHandles = ParseProcessMetric(resources, "Handles");
        var processThreads = ParseProcessMetric(resources, "Threads");
        var diskFreePercent = ParseDiskMetric(resources, "FreePercent");
        var diskFreeBytes = ParseDiskMetric(resources, "FreeBytes");
        var tcpEphemeralUsage = MetricDouble(resources, ResourceMetricKeys.TcpEphemeralUsagePercent);
        var tcpTimeWait = MetricInt(resources, ResourceMetricKeys.TcpTimeWait);
        var tcpEstablished = MetricInt(resources, ResourceMetricKeys.TcpEstablished);

        var sessions = report.Eventos.LastOrDefault(e => e.Tipo.Equals("USER_SESSION_INVENTORY", StringComparison.OrdinalIgnoreCase));
        var activeSessionsValue = EvidenceNullableInt(sessions, "Sesiones activas");
        var disconnectedSessionsValue = EvidenceNullableInt(sessions, "Sesiones desconectadas");
        var sessionCoverageRaw = EvidenceValue(sessions, "Cobertura sesiones");
        var sessionCoverage = sessions is null || !activeSessionsValue.HasValue || !disconnectedSessionsValue.HasValue
            ? "No evaluado"
            : !string.Equals(sessionCoverageRaw?.Trim(), "Disponible", StringComparison.OrdinalIgnoreCase)
                ? "Parcial"
                : "Disponible";
        var activeSessions = activeSessionsValue ?? 0;
        var disconnectedSessions = disconnectedSessionsValue ?? 0;
        var logonFailures = report.Eventos.Count(e => e.Tipo.Equals("USER_LOGON_FAILURE", StringComparison.OrdinalIgnoreCase)
                                                     && DiagnosticEventCatalog.IsFunctionalIncident(e));
        var nlaFailures = report.Eventos.Count(e => (e.Tipo.Equals("USER_NLA_PASSWORD_FAILURE", StringComparison.OrdinalIgnoreCase)
                                                   || e.Tipo.Equals("WINDOWS_NLA_PASSWORD_CHANGE_CONFLICT", StringComparison.OrdinalIgnoreCase))
                                                   && DiagnosticEventCatalog.IsFunctionalIncident(e));

        var moduleHealth = report.Eventos
            .Where(e => e.Tipo.Equals("TSPLUS_MODULE_HEALTH_STATE", StringComparison.OrdinalIgnoreCase))
            .GroupBy(e => e.Componente, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(
                g => g.Key,
                g => EvidenceValue(g.Last(), "Estado funcional") ?? g.Last().Severidad.ToString(),
                StringComparer.OrdinalIgnoreCase);

        var transitionStatus = report.Eventos.LastOrDefault(e => e.Tipo.Equals("TDM_LOCAL_HISTORY_STATUS", StringComparison.OrdinalIgnoreCase));
        var transitions = EvidenceInt(transitionStatus, "Transiciones detectadas");
        var baselineDifferences = EvidenceInt(transitionStatus, "Diferencias contra baseline");

        var topCause = report.CausaRaizPrincipal;
        var performance = report.RendimientoDiagnostico;
        var serviceStates = BuildServiceStates(report);
        var dependencyStates = BuildDependencyStates(report);
        var incidents = BuildIncidents(report);
        var timestamp = report.PeriodoAnalizadoFin != default ? report.PeriodoAnalizadoFin : report.Fin;
        if (timestamp == default) timestamp = DateTimeOffset.Now;

        return new ObservabilitySample
        {
            Timestamp = timestamp,
            SampleKind = string.IsNullOrWhiteSpace(sampleKind) ? "monitor" : sampleKind.Trim().ToLowerInvariant(),
            CpuPercent = cpu,
            MemoryFreePercent = memory,
            MemoryTotalBytes = memoryTotalBytes,
            ProcessRamMb = processRam,
            ProcessHandles = processHandles,
            ProcessThreads = processThreads,
            DiskFreePercent = diskFreePercent,
            DiskFreeBytes = diskFreeBytes,
            TcpEphemeralUsagePercent = tcpEphemeralUsage,
            TcpTimeWait = tcpTimeWait,
            TcpEstablished = tcpEstablished,
            ActiveSessions = activeSessions,
            DisconnectedSessions = disconnectedSessions,
            SessionCoverage = sessionCoverage,
            LogonFailures = logonFailures,
            NlaFailures = nlaFailures,
            ModuleHealth = moduleHealth,
            CriticalFindings = report.Hallazgos.Count(f => f.Severidad == DiagnosticSeverity.Critico),
            ErrorFindings = report.Hallazgos.Count(f => f.Severidad == DiagnosticSeverity.Error),
            WarningFindings = report.Hallazgos.Count(f => f.Severidad == DiagnosticSeverity.Advertencia),
            CrashLoops = report.Eventos.Count(e => e.Tipo.Equals("TSPLUS_CRASH_LOOP_PATTERN", StringComparison.OrdinalIgnoreCase)),
            Transitions = transitions,
            BaselineDifferences = baselineDifferences,
            CoverageScore = report.CoberturaDiagnostica?.Score,
            CausalOrigin = topCause?.OrigenClasificado,
            Originator = SanitizeAggregateLabel(topCause?.Componente),
            DiagnosticDurationMs = performance?.DuracionTotalMs ?? 0,
            CollectorTimeouts = performance?.CollectorsConTimeout ?? 0,
            SlowestCollector = performance?.CollectorMasLento ?? "N/D",
            SlowestCollectorMs = performance?.CollectorMasLentoMs ?? 0,
            MonitorIntervalSeconds = Math.Max(0, runtime.MonitorIntervalSeconds),
            MonitorMode = runtime.MonitorMode ?? "N/D",
            DeferredSamples = Math.Max(0, runtime.DeferredSamples),
            TdmWorkingSetMb = Math.Max(0, runtime.TdmWorkingSetMb),
            ServiceStates = serviceStates,
            DependencyStates = dependencyStates,
            Incidents = incidents,
            TdmCpuPercent = runtime.TdmCpuPercent,
            TdmHandleCount = Math.Max(0, runtime.TdmHandleCount),
            TdmThreadCount = Math.Max(0, runtime.TdmThreadCount),
            ObservabilityBytes = Math.Max(0, runtime.ObservabilityBytes),
            NetworkReceiveMbps = runtime.NetworkReceiveMbps.HasValue ? Math.Max(0d, runtime.NetworkReceiveMbps.Value) : null,
            NetworkSendMbps = runtime.NetworkSendMbps.HasValue ? Math.Max(0d, runtime.NetworkSendMbps.Value) : null
        };
    }

    private static IReadOnlyDictionary<string, string> BuildServiceStates(DiagnosticReport report)
    {
        return report.Eventos
            .Where(e => e.Tipo.Equals("SERVICE_STATE", StringComparison.OrdinalIgnoreCase))
            .Select(e => new
            {
                Name = EvidenceValue(e, "Servicio") ?? e.Componente,
                State = EvidenceValue(e, "Estado presentación") ?? EvidenceValue(e, "Estado") ?? e.Mensaje,
                Complementary = e.Producto is TsplusProduct.AdvancedSecurity or TsplusProduct.ServerMonitoring or TsplusProduct.RemoteSupport or TsplusProduct.TwoFactorAuthentication
            })
            .Where(x => !string.IsNullOrWhiteSpace(x.Name))
            .GroupBy(x => x.Name, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g =>
            {
                var last = g.Last();
                var state = SanitizeAggregateLabel(last.State) ?? "N/D";
                return last.Complementary ? $"Complementario · {state}" : state;
            }, StringComparer.OrdinalIgnoreCase);
    }

    private static IReadOnlyDictionary<string, string> BuildDependencyStates(DiagnosticReport report)
    {
        var output = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var e in report.Eventos.Where(e => e.Tipo is "RDP_STATE" or "NETWORK_STATE" or "TSPLUS_PRODUCT_STATE" or "SERVICE_DEPENDENCY_STATE" or "TSPLUS_WINDOWS_FUNCTIONAL_DEPENDENCY_STATE"))
        {
            var serviceName = EvidenceValue(e, "Servicio") ?? EvidenceValue(e, "Servicio origen") ?? e.Componente;
            var dependencyName = EvidenceValue(e, "Dependencia") ?? "N/D";
            var name = e.Tipo switch
            {
                "RDP_STATE" => "RDP/Listener",
                "NETWORK_STATE" => "Red/Gateway",
                "TSPLUS_PRODUCT_STATE" => EvidenceValue(e, "Producto") ?? e.Componente,
                "SERVICE_DEPENDENCY_STATE" => $"{serviceName} → {dependencyName}",
                "TSPLUS_WINDOWS_FUNCTIONAL_DEPENDENCY_STATE" => $"{EvidenceValue(e, "Componente TSplus") ?? e.Componente} → {dependencyName}",
                _ => e.Componente
            };
            var state = e.Tipo switch
            {
                "RDP_STATE" => $"TermService={EvidenceValue(e, "TermService") ?? "N/D"}; Listening={EvidenceValue(e, "Puerto escuchando") ?? "N/D"}",
                "NETWORK_STATE" => $"Activos={EvidenceValue(e, "Adaptadores activos") ?? "N/D"}; Gateway={EvidenceValue(e, "Gateway disponible") ?? "N/D"}",
                "TSPLUS_PRODUCT_STATE" => EvidenceValue(e, "Operación observada") ?? e.Mensaje,
                "SERVICE_DEPENDENCY_STATE" => PresentDependencyState(e),
                "TSPLUS_WINDOWS_FUNCTIONAL_DEPENDENCY_STATE" => EvidenceValue(e, "Estado presentación") ?? PresentDependencyState(e),
                _ => e.Mensaje
            };
            output[name] = SanitizeAggregateLabel(state) ?? "N/D";
        }
        return output;
    }

    private static string PresentDependencyState(DiagnosticEvent e)
    {
        var dependencyState = EvidenceValue(e, "Estado dependencia") ?? EvidenceValue(e, "Estado") ?? "No evaluado";
        var serviceState = EvidenceValue(e, "Estado servicio");

        if (!dependencyState.Equals("Running", StringComparison.OrdinalIgnoreCase) &&
            !string.IsNullOrWhiteSpace(serviceState) &&
            !serviceState.Equals("Running", StringComparison.OrdinalIgnoreCase))
            return $"No activa · servicio origen {serviceState}";

        return dependencyState;
    }

    private static IReadOnlyList<ObservabilityIncident> BuildIncidents(DiagnosticReport report)
    {
        var incidents = report.Eventos
            .Where(DiagnosticEventCatalog.IsFunctionalIncident)
            .Select(e =>
            {
                var evidenceId = EvidenceValue(e, "RecordId") ?? EvidenceValue(e, "ReportId") ?? e.Codigo;
                var timestamp = e.Timestamp!.Value;
                return new ObservabilityIncident(
                    timestamp,
                    e.Tipo,
                    SanitizeAggregateLabel(e.Componente) ?? "Componente",
                    e.Severidad.ToString(),
                    SanitizeAggregateLabel(e.Mensaje) ?? e.Tipo,
                    SanitizeAggregateLabel(e.Fuente),
                    SanitizeAggregateLabel(evidenceId),
                    SanitizeAggregateLabel(e.Archivo),
                    "TDM incremental",
                    e.Producto.ToString(),
                    EvidenceValue(e, "Correlación funcional")?.Equals("Confirmada", StringComparison.OrdinalIgnoreCase) == true
                        ? "IdentityCorrelated"
                        : "Funcional",
                    IncidentSubject(e));
            })
            .ToList();
        return CollapseBursts(ObservabilityIncidentPolicy.Normalize(incidents)
            .OrderBy(x => x.Timestamp)
            .ToList())
            .TakeLast(120)
            .ToList();
    }

    private static IReadOnlyList<ObservabilityIncident> CollapseBursts(IReadOnlyList<ObservabilityIncident> ordered)
    {
        // P09: colapsa ráfagas del mismo (Kind, Componente) con hueco ≤60 s en un solo incidente:
        // conserva el más reciente, la severidad máxima y el conteo en el resumen. Sin esto, una
        // ráfaga (p. ej. RDP CoreTS con N eventos/segundo) genera N incidentes y TakeLast(120)
        // descarta historial útil. La clave del Ledger (nodo|componente|kind) no usa el resumen.
        var output = new List<ObservabilityIncident>();
        foreach (var item in ordered)
        {
            var last = output.Count == 0 ? null : output[^1];
            if (last is not null
                && last.Kind.Equals(item.Kind, StringComparison.OrdinalIgnoreCase)
                && last.Component.Equals(item.Component, StringComparison.OrdinalIgnoreCase)
                && (item.Timestamp - last.Timestamp) <= TimeSpan.FromSeconds(60))
            {
                // W3: conservar EvidenceId del ÚLTIMO (no del primero ni null) para key estable
                // en IdentityKey/agregados/dashboard. El último lleva el RecordId/Source más fresco.
                var count = BurstCount(last.Summary) + 1;
                output[^1] = last with
                {
                    Timestamp = item.Timestamp,
                    Severity = MaxBurstSeverity(last.Severity, item.Severity),
                    Summary = $"{StripBurstSuffix(item.Summary)} (ráfaga ×{count}/60s)",
                    EvidenceId = item.EvidenceId,
                    Subject = item.Subject ?? last.Subject
                };
            }
            else output.Add(item);
        }
        return output;
    }

    private static int BurstCount(string? summary)
    {
        if (string.IsNullOrWhiteSpace(summary)) return 1;
        var match = Regex.Match(summary, @"\(ráfaga ×(\d+)/60s\)\s*$", RegexOptions.CultureInvariant);
        return match.Success && int.TryParse(match.Groups[1].Value, out var n) && n >= 1 ? n : 1;
    }

    private static string StripBurstSuffix(string? summary)
        => string.IsNullOrWhiteSpace(summary)
            ? string.Empty
            : Regex.Replace(summary, @"\s*\(ráfaga ×\d+/60s\)\s*$", string.Empty, RegexOptions.CultureInvariant).Trim();

    private static int BurstSeverityRank(string? value) => value?.Trim().ToLowerInvariant() switch
    {
        "critico" or "crítico" => 3,
        "error" => 2,
        "advertencia" => 1,
        _ => 0
    };

    private static string MaxBurstSeverity(string a, string b)
        => BurstSeverityRank(b) > BurstSeverityRank(a) ? b : a;

    private static double? ParseCpu(DiagnosticEvent? resources)
    {
        var typed = MetricDouble(resources, ResourceMetricKeys.CpuPercent);
        if (typed.HasValue) return typed;

        // Compatibilidad con ventanas creadas antes de RC18.21.
        var raw = EvidenceValue(resources, "CPU");
        if (string.IsNullOrWhiteSpace(raw)) return null;
        var match = Regex.Match(raw, @"(?<v>\d+(?:[\.,]\d+)?)\s*%", RegexOptions.CultureInvariant);
        return match.Success ? ParseDouble(match.Groups["v"].Value) : null;
    }

    private static double? ParseMemory(DiagnosticEvent? resources)
    {
        var typed = MetricDouble(resources, ResourceMetricKeys.MemoryFreePercent);
        if (typed.HasValue) return typed;

        // Compatibilidad con ventanas creadas antes de RC18.21.
        var raw = EvidenceValue(resources, "Memoria física");
        if (string.IsNullOrWhiteSpace(raw)) return null;
        var match = Regex.Match(raw, @"\((?<v>\d+(?:[\.,]\d+)?)%\s+libre\)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        return match.Success ? ParseDouble(match.Groups["v"].Value) : null;
    }

    private static IReadOnlyDictionary<string, double> ParseProcessMetric(DiagnosticEvent? resources, string suffix)
    {
        var output = new Dictionary<string, double>(StringComparer.OrdinalIgnoreCase);
        if (resources?.Evidencia is not null)
        {
            const string prefix = "Metric.Process.";
            foreach (var item in resources.Evidencia.Where(x => x.Clave.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)
                                                                && x.Clave.EndsWith("." + suffix, StringComparison.OrdinalIgnoreCase)))
            {
                var middle = item.Clave[prefix.Length..^(suffix.Length + 1)];
                var lastDot = middle.LastIndexOf('.');
                if (lastDot <= 0) continue;
                var name = middle[..lastDot].Replace('_', ' ');
                var pid = middle[(lastDot + 1)..];
                var value = ParseDouble(item.Valor);
                if (value.HasValue) output[$"{name}[PID {pid}]"] = value.Value;
            }
        }

        if (output.Count > 0 || !suffix.Equals("RamMb", StringComparison.OrdinalIgnoreCase))
            return output;

        // Compatibilidad con RC anteriores: sólo RAM estaba disponible en texto.
        var raw = EvidenceValue(resources, "Procesos TSplus/complementos observados");
        if (string.IsNullOrWhiteSpace(raw)) return output;
        foreach (Match match in Regex.Matches(raw, @"(?<name>[A-Za-z0-9_.-]+)\[PID\s+(?<pid>\d+)\]\s+RAM=(?<ram>\d+(?:[\.,]\d+)?)\s+MB", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
        {
            var value = ParseDouble(match.Groups["ram"].Value);
            if (value.HasValue)
                output[$"{match.Groups["name"].Value}[PID {match.Groups["pid"].Value}]"] = value.Value;
        }
        return output;
    }

    private static IReadOnlyDictionary<string, double> ParseDiskMetric(DiagnosticEvent? resources, string suffix)
    {
        var output = new Dictionary<string, double>(StringComparer.OrdinalIgnoreCase);
        if (resources?.Evidencia is null) return output;
        const string prefix = "Metric.Disk.";
        foreach (var item in resources.Evidencia.Where(x => x.Clave.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)
                                                            && x.Clave.EndsWith("." + suffix, StringComparison.OrdinalIgnoreCase)))
        {
            var drive = item.Clave[prefix.Length..^(suffix.Length + 1)].Trim('.');
            var value = ParseDouble(item.Valor);
            if (value.HasValue && !string.IsNullOrWhiteSpace(drive)) output[drive] = value.Value;
        }
        return output;
    }

    private static double? MetricDouble(DiagnosticEvent? resources, string key)
        => ParseDouble(EvidenceValue(resources, key) ?? string.Empty);

    private static int MetricInt(DiagnosticEvent? resources, string key)
        => int.TryParse(EvidenceValue(resources, key), NumberStyles.Integer, CultureInfo.InvariantCulture, out var value) ? value : 0;


    private static string? SanitizeAggregateLabel(string? value) => SanitizeLabel(value, maskIdentity: true);

    /// <summary>
    /// El asunto del incidente (cuenta, servicio o proceso) se conserva para que el operador
    /// sepa qué revisar; siguen enmascarados IP, correo y rutas de perfil.
    /// </summary>
    private static string? SanitizeSubjectLabel(string? value) => SanitizeLabel(value, maskIdentity: false);

    private static string? SanitizeLabel(string? value, bool maskIdentity)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        var sanitized = TdmVisibleText.Sanitize(value);
        sanitized = Regex.Replace(sanitized, @"\b(?:\d{1,3}\.){3}\d{1,3}\b", "[IP]", RegexOptions.CultureInvariant);
        sanitized = Regex.Replace(sanitized, @"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z]{2,}\b", "[IDENTIDAD]", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        sanitized = Regex.Replace(sanitized, @"(?i)([A-Z]:\\Users\\)[^\\/\s]+", "$1[IDENTIDAD]", RegexOptions.CultureInvariant);
        if (maskIdentity)
            sanitized = Regex.Replace(sanitized, @"\b[A-Za-z0-9._-]{1,}\\[A-Za-z0-9._ -]{2,}\b", "[IDENTIDAD]", RegexOptions.CultureInvariant);
        return sanitized.Length <= 160 ? sanitized : sanitized[..160];
    }

    private static string? IncidentSubject(DiagnosticEvent e)
    {
        var user = FirstEvidence(e, "Usuario", "Account", "Cuenta", "UserName");
        if (!string.IsNullOrWhiteSpace(user))
        {
            var domain = FirstEvidence(e, "Dominio", "Domain");
            var identity = string.IsNullOrWhiteSpace(domain) || user.Contains('\\')
                ? user
                : $"{domain}\\{user}";
            return SanitizeSubjectLabel(identity);
        }

        var service = FirstEvidence(e, "Servicio", "Service", "ServiceName");
        if (!string.IsNullOrWhiteSpace(service)) return SanitizeSubjectLabel(service);

        var process = FirstEvidence(e, "Proceso", "Process", "ProcessName", "Aplicación", "Application");
        if (!string.IsNullOrWhiteSpace(process)) return SanitizeSubjectLabel(process);

        return null;
    }

    private static string? FirstEvidence(DiagnosticEvent e, params string[] keys)
        => keys.Select(k => EvidenceValue(e, k))
            .FirstOrDefault(v => !string.IsNullOrWhiteSpace(v) && !v.Equals("N/D", StringComparison.OrdinalIgnoreCase));

    private static string? EvidenceValue(DiagnosticEvent? e, string key)
        => e?.Evidencia?.FirstOrDefault(x => x.Clave.Equals(key, StringComparison.OrdinalIgnoreCase))?.Valor;

    private static int EvidenceInt(DiagnosticEvent? e, string key)
        => EvidenceNullableInt(e, key) ?? 0;

    private static int? EvidenceNullableInt(DiagnosticEvent? e, string key)
        => int.TryParse(EvidenceValue(e, key), NumberStyles.Integer, CultureInfo.InvariantCulture, out var value) ? value : null;

    private static double? ParseDouble(string value)
        => double.TryParse(value.Replace(',', '.'), NumberStyles.Float, CultureInfo.InvariantCulture, out var parsed) ? parsed : null;

    private async Task<List<ObservabilitySample>> ReadAllUnsafeAsync(CancellationToken ct)
    {
        Interlocked.Exchange(ref _lastReadDiscardedLines, 0);
        if (!File.Exists(WindowPath)) return [];
        var output = new List<ObservabilitySample>();
        await using var stream = new FileStream(WindowPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete,
                32 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
        using var reader = new StreamReader(stream, System.Text.Encoding.UTF8, detectEncodingFromByteOrderMarks: true,
            bufferSize: 32 * 1024, leaveOpen: false);
        while (true)
        {
            ct.ThrowIfCancellationRequested();
            var line = await reader.ReadLineAsync(ct);
            if (line is null) break;
            if (string.IsNullOrWhiteSpace(line)) continue;
            try
            {
                var sample = JsonSerializer.Deserialize<ObservabilitySample>(line, _json);
                if (sample is not null) output.Add(NormalizeSample(sample));
            }
            catch (JsonException)
            {
                // Una línea incompleta por apagado abrupto no invalida el resto del historial.
                Interlocked.Increment(ref _lastReadDiscardedLines);
            }
        }
        return output;
    }


    private static ObservabilitySample NormalizeSample(ObservabilitySample sample)
        => sample with { Incidents = ObservabilityIncidentPolicy.Normalize(sample.Incidents) };

    private async Task AppendAsync(ObservabilitySample sample, CancellationToken ct)
    {
        var payload = JsonSerializer.SerializeToUtf8Bytes(sample, _json);
        await using var stream = new FileStream(WindowPath, FileMode.Append, FileAccess.Write, FileShare.Read,
            16 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
        await stream.WriteAsync(payload, ct);
        await stream.WriteAsync("\n"u8.ToArray(), ct);
        await stream.FlushAsync(ct);
    }

    private async Task CompactUnsafeAsync(DateTimeOffset now, CancellationToken ct)
    {
        var cutoff = now - MaxWindow;
        var retained = (await ReadAllUnsafeAsync(ct))
            .Where(x => x.Timestamp >= cutoff && x.Timestamp <= now.AddMinutes(5))
            .OrderBy(x => x.Timestamp)
            .GroupBy(x => new { x.Timestamp, x.SampleKind })
            .Select(g => g.Last())
            .ToList();

        var samples = ReduceForRetention(retained, now);
        await WriteAtomicJsonLinesAsync(samples, ct);
    }

    private static List<ObservabilitySample> ReduceForRetention(IReadOnlyList<ObservabilitySample> retained, DateTimeOffset end)
    {
        var fullResolutionCutoff = end - FullResolutionWindow;

        // La última hora conserva resolución completa (5 s cuando la GUI está abierta).
        // Para el resto de los tres días se crea un resumen por minuto que conserva
        // picos de recursos e incidentes, evitando que el JSONL crezca sin límite.
        var fullResolution = retained
            .Where(x => x.Timestamp >= fullResolutionCutoff || !IsMonitorSample(x))
            .ToList();

        var historical = retained
            .Where(x => x.Timestamp < fullResolutionCutoff && IsMonitorSample(x))
            .GroupBy(x => x.Timestamp.ToUnixTimeSeconds() / 60)
            .Select(BuildHistoricalAggregate)
            .ToList();

        return historical
            .Concat(fullResolution)
            .OrderBy(x => x.Timestamp)
            .TakeLast(MaxSamples)
            .ToList();
    }

    private static bool IsMonitorSample(ObservabilitySample sample)
        => sample.SampleKind.Contains("monitor", StringComparison.OrdinalIgnoreCase);

    private static ObservabilitySample BuildHistoricalAggregate(IGrouping<long, ObservabilitySample> group)
    {
        var ordered = group.OrderBy(x => x.Timestamp).ToList();
        var last = ordered[^1];
        var incidents = ordered
            .SelectMany(x => x.Incidents ?? [])
            .Where(ObservabilityIncidentPolicy.IsOperationalIncident)
            .GroupBy(ObservabilityIncidentPolicy.IdentityKey, StringComparer.OrdinalIgnoreCase)
            .Select(g => g.OrderByDescending(x => x.Timestamp).First())
            .ToList();

        return last with
        {
            SampleKind = "monitor-summary",
            CpuPercent = MaxNullable(ordered.Select(x => x.CpuPercent)),
            MemoryFreePercent = MinNullable(ordered.Select(x => x.MemoryFreePercent)),
            MemoryTotalBytes = MaxNullable(ordered.Select(x => x.MemoryTotalBytes)),
            NetworkReceiveMbps = MaxNullable(ordered.Select(x => x.NetworkReceiveMbps)),
            NetworkSendMbps = MaxNullable(ordered.Select(x => x.NetworkSendMbps)),
            TdmCpuPercent = MaxNullable(ordered.Select(x => x.TdmCpuPercent)),
            TdmWorkingSetMb = ordered.Max(x => x.TdmWorkingSetMb),
            TdmHandleCount = ordered.Max(x => x.TdmHandleCount),
            TdmThreadCount = ordered.Max(x => x.TdmThreadCount),
            DiagnosticDurationMs = ordered.Max(x => x.DiagnosticDurationMs),
            CollectorTimeouts = ordered.Max(x => x.CollectorTimeouts),
            DeferredSamples = ordered.Max(x => x.DeferredSamples),
            CriticalFindings = ordered.Max(x => x.CriticalFindings),
            ErrorFindings = ordered.Max(x => x.ErrorFindings),
            WarningFindings = ordered.Max(x => x.WarningFindings),
            CrashLoops = ordered.Max(x => x.CrashLoops),
            Incidents = incidents
        };
    }

    private static double? MaxNullable(IEnumerable<double?> values)
    {
        var materialized = values.Where(x => x.HasValue).Select(x => x!.Value).ToList();
        return materialized.Count == 0 ? null : materialized.Max();
    }

    private static double? MinNullable(IEnumerable<double?> values)
    {
        var materialized = values.Where(x => x.HasValue).Select(x => x!.Value).ToList();
        return materialized.Count == 0 ? null : materialized.Min();
    }

    private async Task WriteAtomicJsonLinesAsync(IReadOnlyList<ObservabilitySample> samples, CancellationToken ct)
    {
        var tmp = WindowPath + ".tmp-" + Guid.NewGuid().ToString("N");
        try
        {
            await using (var stream = new FileStream(tmp, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                32 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan))
            {
                foreach (var sample in samples)
                {
                    var payload = JsonSerializer.SerializeToUtf8Bytes(sample, _json);
                    await stream.WriteAsync(payload, ct);
                    await stream.WriteAsync("\n"u8.ToArray(), ct);
                }
                await stream.FlushAsync(ct);
            }
            File.Move(tmp, WindowPath, true);
        }
        finally
        {
            try { if (File.Exists(tmp)) File.Delete(tmp); } catch { }
        }
    }

    private static async Task<FileStream> AcquireLockAsync(string path, CancellationToken ct)
    {
        Exception? last = null;
        for (var i = 0; i < 30; i++)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                return new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None, 1, FileOptions.DeleteOnClose);
            }
            catch (IOException ex)
            {
                last = ex;
                await Task.Delay(100, ct);
            }
        }
        throw new IOException("No fue posible bloquear el historial agregado de observabilidad TDM.", last);
    }
}
