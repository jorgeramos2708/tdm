using System.Diagnostics;
using System.Globalization;
using System.Net.NetworkInformation;
using TDM.Core;
using TDM.Models;

namespace TDM.Collectors.Windows;

/// <summary>
/// Snapshot preventivo de presión de recursos del servidor.
/// Sólo lectura: no cambia prioridades, pagefile, cuotas, servicios, puertos ni archivos.
/// RC18.21 emite además claves Metric.* estables para que tendencias/observabilidad no
/// dependan de volver a interpretar texto humano.
/// </summary>
public sealed class SystemResourceCollector : IReadOnlyCollector
{
    private const int DefaultEphemeralStart = 49152;
    private const int DefaultEphemeralEnd = 65535;
    private const int DefaultEphemeralCapacity = DefaultEphemeralEnd - DefaultEphemeralStart + 1;

    public string Nombre => "Recursos del sistema";

    public Task<CollectorResult> CollectAsync(DiagnosticContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var findings = new List<DiagnosticFinding>();
        var events = new List<DiagnosticEvent>();
        var evidence = new List<EvidenceItem>();

        // Fase 29 (C1): la detección honra los umbrales configurados (SupportMonitoringSettings
        // llegan vía DiagnosticContext.ResourceThresholds); sin configuración se usan los
        // valores por defecto, idénticos a los literales históricos.
        var thresholds = context.ResourceThresholds ?? ResourceDetectionThresholds.Default;
        var memoryEvaluated = CollectMemory(evidence, findings, thresholds);
        var cpuEvaluated = CollectCpu(evidence, findings, thresholds);
        var disksEvaluated = CollectDisks(context, evidence, findings, thresholds);
        var processCoverage = CollectTopProcesses(evidence);
        var tcpCoverage = CollectTcpPressure(evidence, findings);
        var coverageComplete = memoryEvaluated && cpuEvaluated;
        evidence.Add(new EvidenceItem("Cobertura", coverageComplete ? "Completa" : "Parcial"));
        evidence.Add(new EvidenceItem("Fuentes evaluadas", $"Memoria={(memoryEvaluated ? "Sí" : "No")}; CPU={(cpuEvaluated ? "Sí" : "No")}; discos={(disksEvaluated ? "Sí" : "Parcial")}; procesos={(processCoverage ? "Sí" : "Parcial")}; TCP={(tcpCoverage ? "Sí" : "Parcial")}"));

        events.Add(new DiagnosticEvent(
            DateTimeOffset.Now,
            "TDM",
            "Recursos del sistema",
            DiagnosticLayer.Windows,
            coverageComplete ? DiagnosticSeverity.Informativo : DiagnosticSeverity.Advertencia,
            DiagnosticEventTypes.SystemResourceState,
            coverageComplete
                ? "Snapshot de recursos actuales capturado en modo de solo lectura."
                : "El snapshot de recursos quedó parcialmente no evaluado; TDM no interpreta las métricas faltantes como estado sano.",
            Evidencia: evidence));

        return Task.FromResult(new CollectorResult(findings, events));
    }

    /// <summary>
    /// Clasifica la memoria libre (% free) contra los umbrales configurados de uso.
    /// Fase 29 (C1): evaluador puro para que la detección honre la configuración
    /// sin depender de lecturas WMI en tiempo de prueba.
    /// </summary>
    public static DiagnosticSeverity? EvaluateMemorySeverity(double freePercent, ResourceDetectionThresholds thresholds)
    {
        var usedPercent = 100d - freePercent;
        if (usedPercent >= thresholds.MemoryUsedCriticalPercent) return DiagnosticSeverity.Critico;
        if (usedPercent >= thresholds.MemoryUsedWarningPercent) return DiagnosticSeverity.Advertencia;
        return null;
    }

    /// <summary> Clasifica la carga instantánea de CPU contra los umbrales configurados (Fase 29, C1). </summary>
    public static DiagnosticSeverity? EvaluateCpuSeverity(double averagePercent, ResourceDetectionThresholds thresholds)
    {
        if (averagePercent >= thresholds.CpuCriticalPercent) return DiagnosticSeverity.Critico;
        if (averagePercent >= thresholds.CpuWarningPercent) return DiagnosticSeverity.Advertencia;
        return null;
    }

    /// <summary> Clasifica el espacio libre de disco contra los umbrales configurados (Fase 29, C1). </summary>
    public static DiagnosticSeverity? EvaluateDiskSeverity(double freePercent, ResourceDetectionThresholds thresholds)
    {
        if (freePercent <= thresholds.DiskFreeCriticalPercent) return DiagnosticSeverity.Critico;
        if (freePercent <= thresholds.DiskFreeWarningPercent) return DiagnosticSeverity.Advertencia;
        return null;
    }

    private static bool CollectMemory(List<EvidenceItem> evidence, List<DiagnosticFinding> findings, ResourceDetectionThresholds thresholds)
    {
        var os = SafeWmi.Query(
            "SELECT TotalVisibleMemorySize,FreePhysicalMemory,TotalVirtualMemorySize,FreeVirtualMemory FROM Win32_OperatingSystem",
            o => new
            {
                TotalKb = SafeWmi.ToUlong(o["TotalVisibleMemorySize"]),
                FreeKb = SafeWmi.ToUlong(o["FreePhysicalMemory"]),
                TotalVirtualKb = SafeWmi.ToUlong(o["TotalVirtualMemorySize"]),
                FreeVirtualKb = SafeWmi.ToUlong(o["FreeVirtualMemory"])
            });

        if (os.Count == 0)
        {
            evidence.Add(new("Memoria física", "No determinada"));
            return false;
        }

        var data = os[0];
        var totalKb = data.TotalKb;
        var freeKb = data.FreeKb;
        var totalVirtualKb = data.TotalVirtualKb;
        var freeVirtualKb = data.FreeVirtualKb;
        var freePct = totalKb > 0 ? freeKb * 100d / totalKb : 0d;

        evidence.Add(new("Memoria física", $"{KbToGb(freeKb):F2} GB libres de {KbToGb(totalKb):F2} GB ({freePct:F1}% libre)"));
        evidence.Add(Metric(ResourceMetricKeys.MemoryFreePercent, freePct));
        evidence.Add(Metric(ResourceMetricKeys.MemoryFreeBytes, checked((double)freeKb * 1024d)));
        evidence.Add(Metric(ResourceMetricKeys.MemoryTotalBytes, checked((double)totalKb * 1024d)));
        if (totalVirtualKb > 0)
            evidence.Add(new("Memoria virtual", $"{KbToGb(freeVirtualKb):F2} GB libres de {KbToGb(totalVirtualKb):F2} GB"));

        var memorySeverity = totalKb > 0 ? EvaluateMemorySeverity(freePct, thresholds) : null;
        if (memorySeverity == DiagnosticSeverity.Critico)
        {
            findings.Add(new DiagnosticFinding(
                "RESOURCE-MEMORY-CRITICAL",
                "Memoria física",
                DiagnosticSeverity.Critico,
                "El servidor presenta presión crítica de memoria en el snapshot actual.",
                $"La memoria usada alcanza {100d - freePct:F1}% (umbral crítico configurado {thresholds.MemoryUsedCriticalPercent:0.##}%). Este estado puede degradar servicios, provocar timeouts o agravar fallos, pero por sí solo no demuestra que haya causado un incidente histórico.",
                [new("Memoria libre", $"{freePct:F1}%"), new("Disponible", $"{KbToGb(freeKb):F2} GB"), new("Total", $"{KbToGb(totalKb):F2} GB")],
                ConfidenceLevel.Confirmada,
                Capa: DiagnosticLayer.Windows));
        }
        else if (memorySeverity == DiagnosticSeverity.Advertencia)
        {
            findings.Add(new DiagnosticFinding(
                "RESOURCE-MEMORY-WARNING",
                "Memoria física",
                DiagnosticSeverity.Advertencia,
                "El servidor presenta presión elevada de memoria en el snapshot actual.",
                $"La memoria usada alcanza {100d - freePct:F1}% (umbral de aviso configurado {thresholds.MemoryUsedWarningPercent:0.##}%). TDM la conserva como condición preventiva y exige evidencia temporal adicional antes de atribuirle un crash.",
                [new("Memoria libre", $"{freePct:F1}%"), new("Disponible", $"{KbToGb(freeKb):F2} GB"), new("Total", $"{KbToGb(totalKb):F2} GB")],
                ConfidenceLevel.Alta,
                Capa: DiagnosticLayer.Windows));
        }
        return totalKb > 0;
    }

    private static bool CollectCpu(List<EvidenceItem> evidence, List<DiagnosticFinding> findings, ResourceDetectionThresholds thresholds)
    {
        var loads = SafeWmi.Query(
            "SELECT LoadPercentage FROM Win32_Processor",
            o => SafeWmi.ToDouble(o["LoadPercentage"]))
            .Where(x => x >= 0)
            .ToList();

        if (loads.Count == 0)
        {
            evidence.Add(new("CPU", "No determinada"));
            return false;
        }

        var average = loads.Average();
        evidence.Add(new("CPU", $"Carga instantánea aproximada {average:F0}%"));
        evidence.Add(Metric(ResourceMetricKeys.CpuPercent, average));
        var cpuSeverity = EvaluateCpuSeverity(average, thresholds);
        if (cpuSeverity == DiagnosticSeverity.Critico)
        {
            findings.Add(new DiagnosticFinding(
                "RESOURCE-CPU-CRITICAL",
                "CPU",
                DiagnosticSeverity.Critico,
                "La CPU presenta una carga instantánea crítica.",
                $"La carga instantánea {average:F0}% alcanza o supera el umbral crítico configurado {thresholds.CpuCriticalPercent:0.##}%. El valor es una fotografía del momento del análisis. TDM no lo considera causa raíz sin eventos o evidencia histórica que lo vinculen temporalmente con el incidente.",
                [new("Carga CPU", $"{average:F0}%")],
                ConfidenceLevel.Alta,
                Capa: DiagnosticLayer.Windows));
        }
        else if (cpuSeverity == DiagnosticSeverity.Advertencia)
        {
            findings.Add(new DiagnosticFinding(
                "RESOURCE-CPU-HIGH",
                "CPU",
                DiagnosticSeverity.Advertencia,
                "La CPU presenta una carga instantánea alta.",
                $"La carga instantánea {average:F0}% supera el umbral de aviso configurado {thresholds.CpuWarningPercent:0.##}%. El valor es una fotografía del momento del análisis. TDM no la considera causa raíz sin eventos o evidencia histórica que la vinculen temporalmente con el incidente.",
                [new("Carga CPU", $"{average:F0}%")],
                ConfidenceLevel.Media,
                Capa: DiagnosticLayer.Windows));
        }
        return true;
    }

    private static bool CollectDisks(DiagnosticContext context, List<EvidenceItem> evidence, List<DiagnosticFinding> findings, ResourceDetectionThresholds thresholds)
    {
        var importantRoots = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var systemRoot = Path.GetPathRoot(Environment.SystemDirectory);
        if (!string.IsNullOrWhiteSpace(systemRoot)) importantRoots.Add(systemRoot);
        if (!string.IsNullOrWhiteSpace(context.Sistema.TsplusRuta))
        {
            var tsplusRoot = Path.GetPathRoot(context.Sistema.TsplusRuta);
            if (!string.IsNullOrWhiteSpace(tsplusRoot)) importantRoots.Add(tsplusRoot);
        }

        var observed = false;
        foreach (var drive in DriveInfo.GetDrives().Where(d => d.DriveType == DriveType.Fixed))
        {
            try
            {
                observed = true;
                if (!drive.IsReady) continue;
                var total = drive.TotalSize;
                var free = drive.AvailableFreeSpace;
                var freePct = total > 0 ? free * 100d / total : 0d;
                evidence.Add(new($"Disco {drive.Name}", $"{BytesToGb(free):F2} GB libres de {BytesToGb(total):F2} GB ({freePct:F1}% libre)"));
                evidence.Add(Metric(ResourceMetricKeys.DiskFreePercent(drive.Name), freePct));
                evidence.Add(Metric(ResourceMetricKeys.DiskFreeBytes(drive.Name), free));
                evidence.Add(Metric(ResourceMetricKeys.DiskTotalBytes(drive.Name), total));

                if (!importantRoots.Contains(drive.Name)) continue;
                var diskSeverity = total > 0 ? EvaluateDiskSeverity(freePct, thresholds) : null;
                if (diskSeverity == DiagnosticSeverity.Critico)
                {
                    findings.Add(new DiagnosticFinding(
                        $"RESOURCE-DISK-CRITICAL-{drive.Name[0]}",
                        $"Disco {drive.Name}",
                        DiagnosticSeverity.Critico,
                        "Una unidad crítica para Windows/TSplus tiene muy poco espacio libre.",
                        $"{thresholds.DiskFreeCriticalPercent:0.##}% o menos de espacio libre (umbral crítico configurado) puede afectar logs, temporales, actualizaciones y aplicaciones. TDM no limpia archivos ni modifica cuotas.",
                        [new("Unidad", drive.Name), new("Espacio libre", $"{freePct:F1}%"), new("Disponible", $"{BytesToGb(free):F2} GB")],
                        ConfidenceLevel.Confirmada,
                        Capa: DiagnosticLayer.Windows));
                }
                else if (diskSeverity == DiagnosticSeverity.Advertencia)
                {
                    findings.Add(new DiagnosticFinding(
                        $"RESOURCE-DISK-WARNING-{drive.Name[0]}",
                        $"Disco {drive.Name}",
                        DiagnosticSeverity.Advertencia,
                        "Una unidad crítica para Windows/TSplus tiene espacio libre reducido.",
                        $"{thresholds.DiskFreeWarningPercent:0.##}% o menos de espacio libre (umbral de aviso configurado) se conserva como alerta preventiva; debe correlacionarse con errores de disco, I/O o escritura antes de considerarse causal.",
                        [new("Unidad", drive.Name), new("Espacio libre", $"{freePct:F1}%"), new("Disponible", $"{BytesToGb(free):F2} GB")],
                        ConfidenceLevel.Alta,
                        Capa: DiagnosticLayer.Windows));
                }
            }
            catch (Exception ex)
            {
                evidence.Add(new($"Disco {drive.Name}", $"No determinado: {Short(ex.Message)}"));
            }
        }
        return observed;
    }

    private static bool CollectTopProcesses(List<EvidenceItem> evidence)
    {
        // Esta captura sólo se ejecuta en diagnóstico completo / muestreo ampliado.
        // Se consultan procesos con System.Diagnostics (solo lectura) y se persisten
        // únicamente los principales por RAM para alimentar el dashboard sin WMI adicional.
        var observed = new List<(string Name, int Pid, double RamMb, int Handles, int Threads)>();
        var accessFailures = 0;

        foreach (var process in Process.GetProcesses())
        {
            using (process)
            {
                try
                {
                    var name = process.ProcessName;
                    var ramMb = Math.Max(0d, process.WorkingSet64 / 1024d / 1024d);
                    var handles = Math.Max(0, process.HandleCount);
                    var threads = Math.Max(0, process.Threads.Count);
                    observed.Add((name, process.Id, ramMb, handles, threads));
                }
                catch
                {
                    accessFailures++;
                }
            }
        }

        var top = observed
            .OrderByDescending(x => x.RamMb)
            .ThenBy(x => x.Name, StringComparer.OrdinalIgnoreCase)
            .Take(8)
            .ToList();

        foreach (var row in top)
        {
            evidence.Add(Metric(ResourceMetricKeys.ProcessRamMb(row.Name, row.Pid), row.RamMb));
            evidence.Add(Metric(ResourceMetricKeys.ProcessHandles(row.Name, row.Pid), row.Handles));
            evidence.Add(Metric(ResourceMetricKeys.ProcessThreads(row.Name, row.Pid), row.Threads));
        }

        evidence.Add(new("Procesos principales observados",
            top.Count > 0
                ? string.Join(" | ", top.Select(row => $"{row.Name}[PID {row.Pid}] RAM={row.RamMb:F0} MB; Handles={row.Handles}; Threads={row.Threads}"))
                : accessFailures > 0
                    ? "No concluyente: los procesos visibles no pudieron consultarse"
                    : "Ningún proceso visible"));

        return top.Count > 0 || accessFailures == 0;
    }

    private static bool CollectTcpPressure(List<EvidenceItem> evidence, List<DiagnosticFinding> findings)
    {
        try
        {
            var connections = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpConnections();
            var usedEphemeral = connections
                .Where(x => x.LocalEndPoint.Port >= DefaultEphemeralStart && x.LocalEndPoint.Port <= DefaultEphemeralEnd)
                .Select(x => x.LocalEndPoint.Port)
                .Distinct()
                .Count();
            var timeWait = connections.Count(x => x.State == TcpState.TimeWait);
            var established = connections.Count(x => x.State == TcpState.Established);
            var usagePct = usedEphemeral * 100d / DefaultEphemeralCapacity;

            evidence.Add(new("TCP / puertos efímeros", $"{usedEphemeral}/{DefaultEphemeralCapacity} del rango dinámico predeterminado {DefaultEphemeralStart}-{DefaultEphemeralEnd} ({usagePct:F1}%); TIME_WAIT={timeWait}; ESTABLISHED={established}"));
            evidence.Add(Metric(ResourceMetricKeys.TcpEphemeralUsed, usedEphemeral));
            evidence.Add(Metric(ResourceMetricKeys.TcpEphemeralCapacity, DefaultEphemeralCapacity));
            evidence.Add(Metric(ResourceMetricKeys.TcpEphemeralUsagePercent, usagePct));
            evidence.Add(Metric(ResourceMetricKeys.TcpTimeWait, timeWait));
            evidence.Add(Metric(ResourceMetricKeys.TcpEstablished, established));

            if (usagePct >= 85)
            {
                findings.Add(new DiagnosticFinding(
                    "RESOURCE-TCP-EPHEMERAL-CRITICAL",
                    "TCP / puertos efímeros",
                    DiagnosticSeverity.Critico,
                    "TDM observa una utilización muy alta de puertos TCP efímeros.",
                    "La estimación usa el rango dinámico predeterminado de Windows. Debe confirmarse la configuración efectiva del servidor antes de atribuir causalidad.",
                    [new("Uso estimado", $"{usagePct:F1}%"), new("Puertos locales distintos", usedEphemeral.ToString(CultureInfo.InvariantCulture)), new("TIME_WAIT", timeWait.ToString(CultureInfo.InvariantCulture))],
                    ConfidenceLevel.Media,
                    Capa: DiagnosticLayer.Red));
            }
            else if (usagePct >= 70)
            {
                findings.Add(new DiagnosticFinding(
                    "RESOURCE-TCP-EPHEMERAL-WARNING",
                    "TCP / puertos efímeros",
                    DiagnosticSeverity.Advertencia,
                    "TDM observa presión elevada en el rango TCP efímero predeterminado.",
                    "La señal es preventiva; debe correlacionarse con timeouts, TIME_WAIT y la configuración efectiva del rango dinámico.",
                    [new("Uso estimado", $"{usagePct:F1}%"), new("Puertos locales distintos", usedEphemeral.ToString(CultureInfo.InvariantCulture)), new("TIME_WAIT", timeWait.ToString(CultureInfo.InvariantCulture))],
                    ConfidenceLevel.Media,
                    Capa: DiagnosticLayer.Red));
            }
            return true;
        }
        catch (Exception ex)
        {
            evidence.Add(new("TCP / puertos efímeros", $"No determinado: {Short(ex.Message)}"));
            return false;
        }
    }

    private static EvidenceItem Metric(string key, double value)
        => new(key, value.ToString("0.###", CultureInfo.InvariantCulture));

    private static EvidenceItem Metric(string key, long value)
        => new(key, value.ToString(CultureInfo.InvariantCulture));

    private static EvidenceItem Metric(string key, int value)
        => new(key, value.ToString(CultureInfo.InvariantCulture));

    private static ulong ToUlong(object? value)
    {
        if (value is null) return 0;
        return ulong.TryParse(value.ToString(), out var result) ? result : 0;
    }

    private static double ToDouble(object? value)
    {
        if (value is null) return -1;
        return double.TryParse(value.ToString(), NumberStyles.Float, CultureInfo.InvariantCulture, out var result) ? result : -1;
    }

    private static double KbToGb(ulong kb) => kb / 1024d / 1024d;
    private static double BytesToGb(long bytes) => bytes / 1024d / 1024d / 1024d;
    private static string Short(string value) => value;
}
