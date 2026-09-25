using CommunityToolkit.Mvvm.ComponentModel;
using TDM.Persistence;

namespace TDM.Gui.Avalonia.ViewModels;

public partial class PreventiveDashboardViewModel : ObservableObject
{
    [ObservableProperty] private string _transitions = "0";
    [ObservableProperty] private string _baselineDrift = "0";
    [ObservableProperty] private string _crashLoops = "0";
    [ObservableProperty] private string _moduleHealth = "NO EVALUADO";
    [ObservableProperty] private string _moduleDetail = "sin salud modular";
    [ObservableProperty] private global::Avalonia.Media.IBrush _moduleAccent = DashboardPalette.Muted;

    [ObservableProperty] private string _preventiveRisk = "NO EVALUADO";
    [ObservableProperty] private string _preventiveScore = "0/100";
    [ObservableProperty] private string _preventiveDetail = "sin historial suficiente";
    [ObservableProperty] private global::Avalonia.Media.IBrush _preventiveRiskAccent = DashboardPalette.Muted;

    [ObservableProperty] private string _dependencyRisk = "NO EVALUADO";
    [ObservableProperty] private string _dependencyDetail = "sin estados de dependencias";
    [ObservableProperty] private global::Avalonia.Media.IBrush _dependencyAccent = DashboardPalette.Muted;

    [ObservableProperty] private string _saturationForecast = "NO EVALUADO";
    [ObservableProperty] private string _saturationDetail = "sin tendencia suficiente";
    [ObservableProperty] private global::Avalonia.Media.IBrush _saturationAccent = DashboardPalette.Muted;

    [ObservableProperty] private string _instabilityCount = "0";
    [ObservableProperty] private string _instabilityDetail = "sin oscilaciones detectadas";
    [ObservableProperty] private global::Avalonia.Media.IBrush _instabilityAccent = DashboardPalette.Good;

    [ObservableProperty] private IReadOnlyList<SignalRow> _signals = Array.Empty<SignalRow>();
    [ObservableProperty] private IReadOnlyList<SignalRow> _stabilityRows = Array.Empty<SignalRow>();
    [ObservableProperty] private IReadOnlyList<SignalRow> _actions = Array.Empty<SignalRow>();
    [ObservableProperty] private IReadOnlyList<double> _cpuSeries = Array.Empty<double>();
    [ObservableProperty] private IReadOnlyList<double> _memoryUsedSeries = Array.Empty<double>();
    [ObservableProperty] private string _cpuValue = "N/D";
    [ObservableProperty] private string _memoryValue = "N/D";

    public void Apply(IReadOnlyList<ObservabilitySample> samples)
        => Apply(samples, SupportMonitoringSettings.Default.Thresholds);

    public void Apply(IReadOnlyList<ObservabilitySample> samples, SupportThresholds? thresholds)
    {
        thresholds ??= SupportMonitoringSettings.Default.Thresholds;
        if (samples.Count == 0) { Reset(); return; }
        var latest = samples[^1];
        var diagnosticLatest = samples.LastOrDefault(x => x.SampleKind.Equals("diagnostic", StringComparison.OrdinalIgnoreCase)) ?? latest;
        var moduleLatest = samples.LastOrDefault(x => x.ModuleHealth.Count > 0) ?? diagnosticLatest;
        var cpuLatest = samples.LastOrDefault(x => x.CpuPercent.HasValue) ?? latest;
        var memoryLatest = samples.LastOrDefault(x => x.MemoryFreePercent.HasValue) ?? latest;
        var resourceLatest = samples.LastOrDefault(x => x.DiskFreePercent.Count > 0 || x.TcpEphemeralUsagePercent.HasValue) ?? latest;
        var lastServiceStates = DashboardRules.TargetServiceStates(samples.LastOrDefault(x => x.ServiceStates is { Count: > 0 })?.ServiceStates);
        var lastDependencyStates = samples.LastOrDefault(x => x.DependencyStates is { Count: > 0 })?.DependencyStates;
        var scoringLatest = diagnosticLatest with
        {
            CpuPercent = cpuLatest.CpuPercent,
            MemoryFreePercent = memoryLatest.MemoryFreePercent,
            ModuleHealth = moduleLatest.ModuleHealth,
            ServiceStates = lastServiceStates,
            DependencyStates = lastDependencyStates,
            DiskFreePercent = resourceLatest.DiskFreePercent,
            DiskFreeBytes = resourceLatest.DiskFreeBytes,
            TcpEphemeralUsagePercent = resourceLatest.TcpEphemeralUsagePercent,
            TcpTimeWait = resourceLatest.TcpTimeWait,
            TcpEstablished = resourceLatest.TcpEstablished
        };

        var transitions = samples.Sum(x => x.Transitions);
        var module = DashboardRules.OverallModuleHealth(scoringLatest.ModuleHealth);
        Transitions = transitions.ToString();
        BaselineDrift = scoringLatest.BaselineDifferences.ToString();
        CrashLoops = scoringLatest.CrashLoops.ToString();
        ModuleHealth = module.Label;
        ModuleDetail = module.Detail;
        ModuleAccent = module.Brush;

        var chartSamples = DashboardRules.ChartSamples(samples);
        CpuSeries = chartSamples.Select(x => x.CpuPercent ?? double.NaN).ToArray();
        MemoryUsedSeries = chartSamples.Select(x => x.MemoryFreePercent.HasValue ? 100d - x.MemoryFreePercent.Value : double.NaN).ToArray();
        CpuValue = cpuLatest.CpuPercent.HasValue ? $"{cpuLatest.CpuPercent.Value:0.0}%" : "N/D";
        MemoryValue = memoryLatest.MemoryFreePercent.HasValue ? $"{100d - memoryLatest.MemoryFreePercent.Value:0.0}% usada" : "N/D";

        var serviceInstability = AnalyzeOperationalStability(samples, dependency: false);
        var dependencyInstability = AnalyzeOperationalStability(samples, dependency: true);
        var currentServiceIssues = CurrentOperationalIssues(scoringLatest.ServiceStates, "Servicio");
        var currentDependencyIssues = CurrentOperationalIssues(scoringLatest.DependencyStates, "Dependencia");
        var forecasts = BuildResourceForecasts(samples, scoringLatest, thresholds);

        ApplyDependencyCard(scoringLatest, currentServiceIssues, currentDependencyIssues, serviceInstability, dependencyInstability);
        ApplyInstabilityCard(samples, serviceInstability, dependencyInstability);
        ApplySaturationCard(samples, forecasts);

        var score = CalculatePreventiveScore(
            scoringLatest,
            transitions,
            currentServiceIssues,
            currentDependencyIssues,
            serviceInstability,
            dependencyInstability,
            forecasts,
            thresholds);
        var hasPreventiveEvidence = scoringLatest.CpuPercent.HasValue || scoringLatest.MemoryFreePercent.HasValue || scoringLatest.DiskFreePercent.Count > 0 ||
            scoringLatest.TcpEphemeralUsagePercent.HasValue || (scoringLatest.ServiceStates?.Count ?? 0) > 0 ||
            (scoringLatest.DependencyStates?.Count ?? 0) > 0 || scoringLatest.ModuleHealth.Count > 0;
        ApplyRiskCard(score, currentServiceIssues.Count, currentDependencyIssues.Count, forecasts.Count, hasPreventiveEvidence);

        StabilityRows = serviceInstability
            .Concat(dependencyInstability)
            .Concat(currentServiceIssues)
            .Concat(currentDependencyIssues)
            .GroupBy(x => x.Name, StringComparer.OrdinalIgnoreCase)
            .Select(g => g.First())
            .Take(10)
            .ToList();

        Signals = BuildSignals(samples, scoringLatest, transitions, forecasts, currentServiceIssues, currentDependencyIssues, serviceInstability, dependencyInstability, thresholds);
        Actions = BuildActions(scoringLatest, forecasts, currentServiceIssues, currentDependencyIssues, serviceInstability, dependencyInstability);
    }

    private void ApplyRiskCard(int score, int serviceIssues, int dependencyIssues, int forecastCount, bool hasEvidence)
    {
        if (!hasEvidence)
        {
            PreventiveRisk = "NO EVALUADO";
            PreventiveScore = "—";
            PreventiveDetail = "sin telemetría preventiva suficiente";
            PreventiveRiskAccent = DashboardPalette.Muted;
            return;
        }

        PreventiveScore = $"{score}/100";
        if (score >= 75)
        {
            PreventiveRisk = "CRÍTICO";
            PreventiveRiskAccent = DashboardPalette.Danger;
        }
        else if (score >= 50)
        {
            PreventiveRisk = "ALTO";
            PreventiveRiskAccent = DashboardPalette.Error;
        }
        else if (score >= 25)
        {
            PreventiveRisk = "MEDIO";
            PreventiveRiskAccent = DashboardPalette.Warn;
        }
        else
        {
            PreventiveRisk = "BAJO";
            PreventiveRiskAccent = DashboardPalette.Good;
        }

        PreventiveDetail = score == 0
            ? "sin señales preventivas relevantes"
            : $"{serviceIssues} servicio(s) · {dependencyIssues} dependencia(s) · {forecastCount} tendencia(s) de recurso";
    }

    private void ApplyDependencyCard(
        ObservabilitySample latest,
        IReadOnlyList<SignalRow> serviceIssues,
        IReadOnlyList<SignalRow> dependencyIssues,
        IReadOnlyList<SignalRow> serviceInstability,
        IReadOnlyList<SignalRow> dependencyInstability)
    {
        var observedStates = (latest.ServiceStates?.Count ?? 0) + (latest.DependencyStates?.Count ?? 0);
        if (observedStates == 0)
        {
            DependencyRisk = "NO EVALUADO";
            DependencyDetail = "sin estados de servicios/dependencias";
            DependencyAccent = DashboardPalette.Muted;
            return;
        }

        var totalIssues = serviceIssues.Count + dependencyIssues.Count;
        var totalInstability = serviceInstability.Count + dependencyInstability.Count;
        var total = totalIssues + totalInstability;
        var hasError = serviceIssues.Concat(dependencyIssues)
            .Any(x => ReferenceEquals(x.Accent, DashboardPalette.Error) || ReferenceEquals(x.Accent, DashboardPalette.Danger));
        if (total == 0)
        {
            DependencyRisk = "SALUDABLE";
            DependencyDetail = "sin degradación observable";
            DependencyAccent = DashboardPalette.Good;
            return;
        }

        DependencyRisk = hasError ? "RIESGO ALTO" : "ATENCIÓN";
        DependencyDetail = $"{serviceIssues.Count} servicio(s) · {dependencyIssues.Count} dependencia(s) · {totalInstability} inestable(s)";
        DependencyAccent = hasError ? DashboardPalette.Error : DashboardPalette.Warn;
    }

    private void ApplyInstabilityCard(IReadOnlyList<ObservabilitySample> samples, IReadOnlyList<SignalRow> services, IReadOnlyList<SignalRow> dependencies)
    {
        var statefulSamples = samples.Count(x => (x.ServiceStates?.Count ?? 0) > 0 || (x.DependencyStates?.Count ?? 0) > 0);
        if (statefulSamples < 3)
        {
            InstabilityCount = "—";
            InstabilityDetail = "se requieren al menos 3 muestras con estados operativos";
            InstabilityAccent = DashboardPalette.Muted;
            return;
        }

        var total = services.Count + dependencies.Count;
        InstabilityCount = total.ToString();
        InstabilityDetail = total == 0
            ? "sin oscilaciones detectadas"
            : $"{services.Count} servicio(s) · {dependencies.Count} dependencia(s)";
        InstabilityAccent = total >= 3 ? DashboardPalette.Error : total > 0 ? DashboardPalette.Warn : DashboardPalette.Good;
    }

    private void ApplySaturationCard(IReadOnlyList<ObservabilitySample> samples, IReadOnlyList<ResourceForecast> forecasts)
    {
        if (forecasts.Count > 0)
        {
            var worst = forecasts.OrderByDescending(x => x.Level).ThenBy(x => x.Minutes ?? double.MaxValue).First();
            SaturationForecast = worst.Level switch
            {
                >= 3 => "RIESGO CRÍTICO",
                2 => "RIESGO ALTO",
                _ => "ATENCIÓN"
            };
            SaturationDetail = worst.Detail;
            SaturationAccent = worst.Level >= 3 ? DashboardPalette.Danger : worst.Level == 2 ? DashboardPalette.Error : DashboardPalette.Warn;
            return;
        }

        var cpuCount = samples.Count(x => x.CpuPercent.HasValue);
        var memoryCount = samples.Count(x => x.MemoryFreePercent.HasValue);
        if (cpuCount >= 6 || memoryCount >= 6)
        {
            SaturationForecast = "ESTABLE";
            SaturationDetail = "sin trayectoria de saturación en la ventana reciente";
            SaturationAccent = DashboardPalette.Good;
        }
        else
        {
            SaturationForecast = "SIN TENDENCIA";
            SaturationDetail = "se requieren más muestras para proyectar";
            SaturationAccent = DashboardPalette.Muted;
        }
    }

    private static IReadOnlyList<SignalRow> BuildSignals(
        IReadOnlyList<ObservabilitySample> samples,
        ObservabilitySample latest,
        int transitions,
        IReadOnlyList<ResourceForecast> forecasts,
        IReadOnlyList<SignalRow> currentServiceIssues,
        IReadOnlyList<SignalRow> currentDependencyIssues,
        IReadOnlyList<SignalRow> serviceInstability,
        IReadOnlyList<SignalRow> dependencyInstability,
        SupportThresholds thresholds)
    {
        var signals = new List<SignalRow>();
        var cpu = samples.TakeLast(Math.Min(12, samples.Count)).Where(x => x.CpuPercent.HasValue).Select(x => x.CpuPercent!.Value).ToList();
        var memoryFree = samples.TakeLast(Math.Min(12, samples.Count)).Where(x => x.MemoryFreePercent.HasValue).Select(x => x.MemoryFreePercent!.Value).ToList();

        if (cpu.Count >= 3 && cpu.TakeLast(3).All(x => x >= thresholds.CpuCritical))
            signals.Add(new SignalRow("CPU sostenida", $"Últimas muestras: {string.Join(" · ", cpu.TakeLast(5).Select(x => $"{x:0}%"))}", DashboardPalette.Warn));
        if (memoryFree.Count >= 3 && memoryFree.First() - memoryFree.Last() >= 8)
            signals.Add(new SignalRow("Memoria libre descendente", $"{memoryFree.First():0}% → {memoryFree.Last():0}%", DashboardPalette.Warn));
        if (latest.CrashLoops > 0)
            signals.Add(new SignalRow("Recurrencia", $"{latest.CrashLoops} ciclo(s) repetitivo(s) de falla", DashboardPalette.Error));
        if (transitions > 0)
            signals.Add(new SignalRow("Cambios de estado", $"{transitions} transición(es) en el periodo", DashboardPalette.Warn));

        signals.AddRange(forecasts.Select(x => new SignalRow(x.Name, x.Detail, x.Level >= 3 ? DashboardPalette.Danger : x.Level == 2 ? DashboardPalette.Error : DashboardPalette.Warn)));
        signals.AddRange(serviceInstability.Take(3));
        signals.AddRange(dependencyInstability.Take(3));
        signals.AddRange(currentServiceIssues.Take(3));
        signals.AddRange(currentDependencyIssues.Take(3));

        foreach (var item in latest.ModuleHealth.Where(x => DashboardRules.HealthRank(x.Value) >= 2).Take(4))
        {
            var state = DashboardRules.HealthState(item.Value);
            signals.Add(new SignalRow(DashboardRules.LocalizedPreventiveModuleName(item.Key), DashboardRules.LocalizeOperationalText(item.Value), state.Brush));
        }

        if (latest.TcpEphemeralUsagePercent >= 70)
            signals.Add(new SignalRow("Presión de puertos efímeros", $"Uso {latest.TcpEphemeralUsagePercent:0.0}% · TIME_WAIT {latest.TcpTimeWait}", latest.TcpEphemeralUsagePercent >= 85 ? DashboardPalette.Error : DashboardPalette.Warn));

        foreach (var disk in latest.DiskFreePercent.Where(x => x.Value <= 15).OrderBy(x => x.Value).Take(3))
            signals.Add(new SignalRow($"Disco {disk.Key}", $"{disk.Value:0.0}% libre", disk.Value <= 5 ? DashboardPalette.Danger : disk.Value <= 10 ? DashboardPalette.Error : DashboardPalette.Warn));

        if (signals.Count == 0)
            signals.Add(new SignalRow("Sin señales preventivas relevantes", "Recursos, servicios, dependencias y salud modular no muestran una tendencia que requiera atención en la ventana disponible.", DashboardPalette.Good));

        return signals
            .GroupBy(x => $"{x.Name}|{x.Detail}", StringComparer.OrdinalIgnoreCase)
            .Select(g => g.First())
            .Take(16)
            .ToList();
    }

    private static IReadOnlyList<SignalRow> BuildActions(
        ObservabilitySample latest,
        IReadOnlyList<ResourceForecast> forecasts,
        IReadOnlyList<SignalRow> currentServiceIssues,
        IReadOnlyList<SignalRow> currentDependencyIssues,
        IReadOnlyList<SignalRow> serviceInstability,
        IReadOnlyList<SignalRow> dependencyInstability)
    {
        var actions = new List<SignalRow>();

        if (currentServiceIssues.Count > 0)
            actions.Add(new SignalRow("Atender servicios degradados", "Revisar estado, eventos recientes y dependencias del servicio antes de que la degradación termine en indisponibilidad.", DashboardPalette.Error));
        if (currentDependencyIssues.Count > 0)
            actions.Add(new SignalRow("Atender dependencias degradadas", "Revisar primero la dependencia afectada antes de intervenir el servicio final que depende de ella.", DashboardPalette.Error));
        if (serviceInstability.Count + dependencyInstability.Count > 0)
            actions.Add(new SignalRow("Investigar inestabilidad", "Correlacionar reinicios/cambios repetidos con el Visor de eventos, dependencias y cambios recientes de configuración.", DashboardPalette.Warn));
        if (forecasts.Any(x => x.Name.Contains("CPU", StringComparison.OrdinalIgnoreCase)))
            actions.Add(new SignalRow("Reducir presión de CPU", "Identificar procesos dominantes y validar si la carga sostenida corresponde a sesiones, TSplus o procesos externos.", DashboardPalette.Warn));
        if (forecasts.Any(x => x.Name.Contains("Memoria", StringComparison.OrdinalIgnoreCase)))
            actions.Add(new SignalRow("Contener presión de memoria", "Revisar procesos con crecimiento de RAM y disponibilidad antes de que el servidor entre en paginación severa.", DashboardPalette.Warn));
        if (forecasts.Any(x => x.Name.Contains("Disco", StringComparison.OrdinalIgnoreCase)) || latest.DiskFreePercent.Any(x => x.Value <= 15))
            actions.Add(new SignalRow("Liberar o ampliar almacenamiento", "Priorizar discos de Windows/TSplus con poco espacio y revisar crecimiento de logs, perfiles y temporales.", DashboardPalette.Warn));
        if (latest.TcpEphemeralUsagePercent >= 70)
            actions.Add(new SignalRow("Reducir presión de conexiones", "Revisar TIME_WAIT, aplicaciones con conexiones cortas y servicios que agotan puertos efímeros.", DashboardPalette.Warn));
        if (latest.BaselineDifferences > 0)
            actions.Add(new SignalRow("Revisar cambios frente a la referencia", $"Hay {latest.BaselineDifferences} diferencia(s); confirmar si fueron cambios planeados antes de que se conviertan en una falla.", DashboardPalette.Warn));
        if (latest.CrashLoops > 0)
            actions.Add(new SignalRow("Detener recurrencias", "Investigar el componente que entra en un ciclo repetitivo de fallos antes de que provoque pérdida de sesiones o indisponibilidad.", DashboardPalette.Error));
        var degradedModule = latest.ModuleHealth
            .Where(x => DashboardRules.HealthRank(x.Value) >= 2)
            .OrderByDescending(x => DashboardRules.HealthRank(x.Value))
            .FirstOrDefault();
        if (!string.IsNullOrWhiteSpace(degradedModule.Key))
            actions.Add(new SignalRow("Revisar módulo TSplus degradado", $"{DashboardRules.LocalizedPreventiveModuleName(degradedModule.Key)}: {DashboardRules.LocalizeOperationalText(degradedModule.Value)}", DashboardRules.HealthState(degradedModule.Value).Brush));

        if (actions.Count == 0)
            actions.Add(new SignalRow("Sin acción preventiva inmediata", "Mantener monitoreo; no se detecta una degradación sostenida que requiera intervención en este momento.", DashboardPalette.Good));

        return actions.Take(8).ToList();
    }

    private static IReadOnlyList<SignalRow> CurrentOperationalIssues(IReadOnlyDictionary<string, string>? states, string prefix)
    {
        if (states is null || states.Count == 0) return Array.Empty<SignalRow>();
        return states
            .Select(x => new { x.Key, x.Value, Level = DashboardRules.OperationalStateLevel(x.Value) })
            .Where(x => x.Level >= 2)
            .OrderByDescending(x => x.Level)
            .ThenBy(x => x.Key, StringComparer.OrdinalIgnoreCase)
            .Select(x => new SignalRow(
                $"{prefix}: {DashboardRules.CompactModuleName(x.Key)}",
                DashboardRules.LocalizeOperationalText(x.Value),
                x.Level >= 3 ? DashboardPalette.Error : DashboardPalette.Warn))
            .Take(10)
            .ToList();
    }

    private static IReadOnlyList<SignalRow> AnalyzeOperationalStability(IReadOnlyList<ObservabilitySample> samples, bool dependency)
    {
        if (samples.Count == 0) return Array.Empty<SignalRow>();
        var end = samples[^1].Timestamp;
        var recent = samples.Where(x => x.Timestamp >= end - TimeSpan.FromHours(2)).ToList();
        if (recent.Count < 3) recent = samples.TakeLast(Math.Min(30, samples.Count)).ToList();

        var dictionaries = recent
            .Select(x => dependency ? x.DependencyStates : x.ServiceStates)
            .Where(x => x is not null && x.Count > 0)
            .Cast<IReadOnlyDictionary<string, string>>()
            .ToList();
        if (dictionaries.Count == 0) return Array.Empty<SignalRow>();

        var names = dictionaries.SelectMany(x => x.Keys)
            .Where(name => dependency || !DashboardRules.IsInternalTdmService(name))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        var result = new List<SignalRow>();

        foreach (var name in names)
        {
            var levels = new List<int>();
            string? latestState = null;
            foreach (var sample in recent)
            {
                var dict = dependency ? sample.DependencyStates : sample.ServiceStates;
                if (dict is null || !dict.TryGetValue(name, out var state) || string.IsNullOrWhiteSpace(state)) continue;
                latestState = state;
                var level = DashboardRules.OperationalStateLevel(state);
                if (levels.Count == 0 || levels[^1] != level) levels.Add(level);
            }

            var changes = Math.Max(0, levels.Count - 1);
            if (changes < 2) continue;

            var peak = levels.Count == 0 ? 0 : levels.Max();
            var accent = peak >= 3 || changes >= 4 ? DashboardPalette.Error : DashboardPalette.Warn;
            var kind = dependency ? "Dependencia inestable" : "Servicio inestable";
            result.Add(new SignalRow(
                $"{kind}: {DashboardRules.CompactModuleName(name)}",
                $"{changes} cambio(s) de estado · actual: {DashboardRules.LocalizeOperationalText(latestState ?? "N/D")}",
                accent));
        }

        return result.OrderByDescending(x => ReferenceEquals(x.Accent, DashboardPalette.Error)).ThenBy(x => x.Name).Take(10).ToList();
    }

    private static IReadOnlyList<ResourceForecast> BuildResourceForecasts(IReadOnlyList<ObservabilitySample> samples, ObservabilitySample latest, SupportThresholds thresholds)
    {
        var result = new List<ResourceForecast>();

        var cpuPoints = MetricPoints(samples, x => x.CpuPercent);
        double? cpuCurrent = cpuPoints.Count == 0 ? null : cpuPoints[^1].Value;
        AddIncreasingForecast(result, "CPU", cpuPoints, cpuCurrent, warning: thresholds.CpuWarning, critical: thresholds.CpuCritical);

        var memoryPoints = MetricPoints(samples, x => x.MemoryFreePercent.HasValue ? 100d - x.MemoryFreePercent.Value : null);
        double? memoryCurrent = memoryPoints.Count == 0 ? null : memoryPoints[^1].Value;
        AddIncreasingForecast(result, "Memoria", memoryPoints, memoryCurrent, warning: thresholds.MemoryUsedWarning, critical: thresholds.MemoryUsedCritical);

        foreach (var drive in latest.DiskFreePercent.Keys.Take(8))
        {
            var points = MetricPoints(samples, x => x.DiskFreePercent.TryGetValue(drive, out var value) ? value : null);
            var current = latest.DiskFreePercent.TryGetValue(drive, out var currentDisk)
                ? currentDisk
                : RecentAverage(points, 2);
            if (!current.HasValue) continue;
            if (current.Value <= 5)
            {
                result.Add(new ResourceForecast($"Disco {drive}", $"espacio libre crítico: {current.Value:0.0}%", 3, 0));
                continue;
            }
            if (current.Value <= 10)
            {
                result.Add(new ResourceForecast($"Disco {drive}", $"espacio libre bajo: {current.Value:0.0}%", 2, 0));
                continue;
            }
            if (current.Value <= 25 && TryEstimateMinutes(points, threshold: 10, increasing: false, out var minutes) && minutes <= 360)
                result.Add(new ResourceForecast($"Disco {drive}", $"podría bajar a 10% libre en ~{FormatMinutes(minutes)}", minutes <= 60 ? 2 : 1, minutes));
        }

        if (latest.TcpEphemeralUsagePercent.HasValue)
        {
            var value = latest.TcpEphemeralUsagePercent.Value;
            if (value >= 85)
                result.Add(new ResourceForecast("Puertos efímeros", $"presión crítica: {value:0.0}% en uso", 3, 0));
            else if (value >= 70)
                result.Add(new ResourceForecast("Puertos efímeros", $"presión elevada: {value:0.0}% en uso", 1, 0));
        }

        return result.OrderByDescending(x => x.Level).ThenBy(x => x.Minutes ?? double.MaxValue).Take(8).ToList();
    }

    private static void AddIncreasingForecast(List<ResourceForecast> output, string name, IReadOnlyList<MetricPoint> points, double? current, double warning, double critical)
    {
        if (!current.HasValue) return;
        if (current.Value >= critical)
        {
            output.Add(new ResourceForecast(name, $"uso crítico sostenido: {current.Value:0.0}%", 3, 0));
            return;
        }
        if (current.Value >= warning)
        {
            output.Add(new ResourceForecast(name, $"uso alto actual: {current.Value:0.0}%", 2, 0));
            return;
        }
        if (current.Value < 50) return;
        if (TryEstimateMinutes(points, warning, increasing: true, out var minutes) && minutes <= 360)
            output.Add(new ResourceForecast(name, $"podría alcanzar {warning:0}% en ~{FormatMinutes(minutes)}", minutes <= 60 ? 2 : 1, minutes));
    }

    private static IReadOnlyList<MetricPoint> MetricPoints(IReadOnlyList<ObservabilitySample> samples, Func<ObservabilitySample, double?> selector)
        => samples
            .Select(x => new { x.Timestamp, Value = selector(x) })
            .Where(x => x.Value.HasValue && !double.IsNaN(x.Value.Value) && !double.IsInfinity(x.Value.Value))
            .GroupBy(x => x.Timestamp)
            .Select(g => new MetricPoint(g.Key, g.Last().Value!.Value))
            .OrderBy(x => x.Time)
            .TakeLast(60)
            .ToList();

    private static double? RecentAverage(IReadOnlyList<MetricPoint> points, int count)
        => points.Count == 0 ? null : points.TakeLast(Math.Min(count, points.Count)).Average(x => x.Value);

    private static bool TryEstimateMinutes(IReadOnlyList<MetricPoint> points, double threshold, bool increasing, out double minutes)
    {
        minutes = double.PositiveInfinity;
        if (points.Count < 6) return false;
        var first = points[0].Time;
        var span = (points[^1].Time - first).TotalMinutes;
        if (span < 0.5) return false;

        var xs = points.Select(x => (x.Time - first).TotalMinutes).ToArray();
        var ys = points.Select(x => x.Value).ToArray();
        var xAvg = xs.Average();
        var yAvg = ys.Average();
        var denominator = xs.Sum(x => Math.Pow(x - xAvg, 2));
        if (denominator <= 0.000001) return false;
        var slope = xs.Zip(ys, (x, y) => (x - xAvg) * (y - yAvg)).Sum() / denominator;

        if (increasing && slope < 0.05) return false;
        if (!increasing && slope > -0.02) return false;

        var current = RecentAverage(points, 3) ?? ys[^1];
        var delta = threshold - current;
        var projected = delta / slope;
        if (projected <= 0 || double.IsNaN(projected) || double.IsInfinity(projected)) return false;

        minutes = projected;
        return true;
    }

    private static int CalculatePreventiveScore(
        ObservabilitySample latest,
        int transitions,
        IReadOnlyList<SignalRow> serviceIssues,
        IReadOnlyList<SignalRow> dependencyIssues,
        IReadOnlyList<SignalRow> serviceInstability,
        IReadOnlyList<SignalRow> dependencyInstability,
        IReadOnlyList<ResourceForecast> forecasts,
        SupportThresholds thresholds)
    {
        var score = 0;
        var serviceCritical = latest.ServiceStates?.Count(x => DashboardRules.OperationalStateLevel(x.Value) >= 3) ?? 0;
        var dependencyCritical = latest.DependencyStates?.Count(x => DashboardRules.OperationalStateLevel(x.Value) >= 3) ?? 0;

        score += Math.Min(25, serviceCritical * 15 + Math.Max(0, serviceIssues.Count - serviceCritical) * 6);
        score += Math.Min(25, dependencyCritical * 15 + Math.Max(0, dependencyIssues.Count - dependencyCritical) * 6);
        score += Math.Min(20, (serviceInstability.Count + dependencyInstability.Count) * 5);
        score += forecasts.Sum(x => x.Level switch { 3 => 18, 2 => 12, _ => 6 });
        score += latest.CrashLoops > 0 ? Math.Min(20, latest.CrashLoops * 10) : 0;
        score += Math.Min(8, latest.BaselineDifferences * 2);
        if (transitions >= thresholds.ServiceChangesCritical) score += 10;
        else if (transitions >= thresholds.ServiceChangesWarning) score += 6;
        else score += Math.Min(4, transitions);

        var worstModule = latest.ModuleHealth.Count == 0 ? 0 : latest.ModuleHealth.Max(x => DashboardRules.HealthRank(x.Value));
        score += worstModule switch { >= 4 => 18, 3 => 12, 2 => 6, _ => 0 };

        return Math.Clamp(score, 0, 100);
    }

    private static string FormatMinutes(double minutes)
    {
        if (minutes < 1) return "<1 min";
        if (minutes < 60) return $"{Math.Ceiling(minutes):0} min";
        return $"{minutes / 60d:0.0} h";
    }

    private void Reset()
    {
        Transitions = BaselineDrift = CrashLoops = "0";
        ModuleHealth = "NO EVALUADO";
        ModuleDetail = "sin datos";
        ModuleAccent = DashboardPalette.Muted;
        PreventiveRisk = DependencyRisk = SaturationForecast = "NO EVALUADO";
        PreventiveScore = "0/100";
        PreventiveDetail = "sin historial suficiente";
        DependencyDetail = "sin estados de dependencias";
        SaturationDetail = "sin tendencia suficiente";
        PreventiveRiskAccent = DependencyAccent = SaturationAccent = DashboardPalette.Muted;
        InstabilityCount = "0";
        InstabilityDetail = "sin oscilaciones detectadas";
        InstabilityAccent = DashboardPalette.Good;
        Signals = StabilityRows = Actions = Array.Empty<SignalRow>();
        CpuSeries = MemoryUsedSeries = Array.Empty<double>();
        CpuValue = MemoryValue = "N/D";
    }

    private sealed record MetricPoint(DateTimeOffset Time, double Value);
    private sealed record ResourceForecast(string Name, string Detail, int Level, double? Minutes);
}
