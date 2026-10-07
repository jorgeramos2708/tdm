using System.Globalization;
using TDM.Core;
using TDM.Models;

namespace TDM.Collectors.Windows;

/// <summary>
/// Muestra continua de recursos sin WMI. Utiliza las mismas APIs nativas del gobernador.
/// RC18.21 conserva texto legible y publica además claves Metric.* tipadas.
/// </summary>
public sealed class LightweightSystemResourceCollector : IReadOnlyCollector
{
    private const double CpuWindowHysteresisPercent = 5d;

    // F33 (H8): estado de la ventana de CPU con histéresis, fuera de la muestra para que el
    // refresco no parpadee entre estados. El conteo de hallazgos RESOURCE-CPU-* sigue siendo
    // exclusivo del SystemResourceCollector pesado (sin doble conteo de WarningFindings).
    private static readonly object WindowSync = new();
    private static bool _cpuWindowElevated;

    private readonly ResourceLoadGuard.Snapshot? _snapshot;

    public LightweightSystemResourceCollector(ResourceLoadGuard.Snapshot? snapshot = null) => _snapshot = snapshot;

    public string Nombre => "Recursos ligeros Windows";

    public Task<CollectorResult> CollectAsync(DiagnosticContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var snap = _snapshot ?? ResourceLoadGuard.Capture(context.ResourceThresholds);
        // Q10: la CPU por GetSystemTimes es un delta entre dos capturas; la primera muestra es
        // N/D por naturaleza (las claves Metric.* de memoria sí se publican desde el ciclo 1).
        var cpu = snap.CpuPercent.HasValue ? $"Carga instantánea aproximada {snap.CpuPercent.Value:0.0}%" : "N/D (primera muestra; requiere dos capturas consecutivas)";
        var memory = snap.MemoryFreePercent.HasValue ? $"Memoria disponible ({snap.MemoryFreePercent.Value:0.0}% libre)" : "N/D";
        var evidence = new List<EvidenceItem>
        {
            new("CPU", cpu),
            new("Memoria física", memory),
            new("Método", "GetSystemTimes + GlobalMemoryStatusEx; sin WMI")
        };
        if (snap.CpuPercent.HasValue)
            evidence.Add(new(ResourceMetricKeys.CpuPercent, snap.CpuPercent.Value.ToString("0.###", CultureInfo.InvariantCulture)));
        if (snap.MemoryFreePercent.HasValue)
            evidence.Add(new(ResourceMetricKeys.MemoryFreePercent, snap.MemoryFreePercent.Value.ToString("0.###", CultureInfo.InvariantCulture)));
        if (snap.MemoryTotalBytes.HasValue)
            evidence.Add(new(ResourceMetricKeys.MemoryTotalBytes, snap.MemoryTotalBytes.Value.ToString(CultureInfo.InvariantCulture)));

        // F33 (H8): contadores de la guía oficial 9 (MEMORYSTATUSEX) publicados en el ciclo
        // ligero: Available MBytes (ullAvailPhys) y % Committed Bytes In Use
        // ((TotalPageFile - AvailPageFile) / TotalPageFile).
        if (snap.MemoryAvailableBytes.HasValue)
        {
            evidence.Add(new("Available MBytes", $"{snap.MemoryAvailableBytes.Value / 1024d / 1024d:0} MB"));
            evidence.Add(new(ResourceMetricKeys.MemoryAvailableBytes, snap.MemoryAvailableBytes.Value.ToString(CultureInfo.InvariantCulture)));
        }
        if (snap.MemoryCommittedPercent.HasValue)
        {
            evidence.Add(new("% Committed Bytes In Use", $"{snap.MemoryCommittedPercent.Value:0.0}%"));
            evidence.Add(new(ResourceMetricKeys.MemoryPercentCommittedBytesInUse, snap.MemoryCommittedPercent.Value.ToString("0.###", CultureInfo.InvariantCulture)));
        }

        // F33 (H8): ventana de CPU con histéresis de 5 puntos sobre el delta de GetSystemTimes;
        // se publica sólo como evidencia (sin findings nuevos).
        var thresholds = context.ResourceThresholds ?? ResourceDetectionThresholds.Default;
        bool windowElevated;
        lock (WindowSync)
        {
            windowElevated = NextCpuWindow(_cpuWindowElevated, snap.CpuPercent, thresholds.CpuWarningPercent);
            _cpuWindowElevated = windowElevated;
        }
        evidence.Add(new("Ventana de carga CPU", snap.CpuPercent.HasValue
            ? windowElevated
                ? $"Elevada (entrada ≥{thresholds.CpuWarningPercent:0}%, salida <{thresholds.CpuWarningPercent - CpuWindowHysteresisPercent:0}%)"
                : $"Normal (sin cruce del umbral de aviso {thresholds.CpuWarningPercent:0}%)"
            : "N/D (primera muestra; requiere dos capturas consecutivas)"));

        var evt = new DiagnosticEvent(
            snap.Timestamp,
            "TDM / API nativa Windows",
            "Recursos del sistema",
            DiagnosticLayer.Windows,
            DiagnosticSeverity.Informativo,
            DiagnosticEventTypes.SystemResourceState,
            $"CPU={cpu}; memoria={memory}",
            Evidencia: evidence);

        return Task.FromResult(new CollectorResult([], [evt]));
    }

    /// <summary>
    /// F33 (H8): evaluador puro de la ventana de CPU con histéresis de 5 puntos.
    /// Sin muestra (null) conserva el estado anterior; la entrada se produce en
    /// >= enterPercent y la salida sólo por debajo de enterPercent - 5.
    /// </summary>
    public static bool NextCpuWindow(bool previousElevated, double? cpuPercent, double enterPercent)
    {
        if (!cpuPercent.HasValue) return previousElevated;
        return previousElevated
            ? cpuPercent.Value >= enterPercent - CpuWindowHysteresisPercent
            : cpuPercent.Value >= enterPercent;
    }
}
