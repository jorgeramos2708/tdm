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
    private readonly ResourceLoadGuard.Snapshot? _snapshot;

    public LightweightSystemResourceCollector(ResourceLoadGuard.Snapshot? snapshot = null) => _snapshot = snapshot;

    public string Nombre => "Recursos ligeros Windows";

    public Task<CollectorResult> CollectAsync(DiagnosticContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var snap = _snapshot ?? ResourceLoadGuard.Capture();
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
}
