using System;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Linq;
using TDM.Models;
using TDM.Persistence;

namespace TDM.Core;

/// <summary>
/// Servicio de detección de anomalías en streaming para métricas de observabilidad.
/// Integra EWMA detectors y genera eventos/anomalías para el pipeline de diagnóstico.
/// </summary>
public sealed class AnomalyDetectionService : IDisposable
{
    private readonly EwmaAnomalyDetector _systemDetector;
    private readonly EwmaAnomalyDetector _networkDetector;
    private readonly EwmaAnomalyDetector _processDetector;
    private readonly EwmaAnomalyDetector _tcpDetector;
    private readonly EwmaAnomalyDetector _diskDetector;
    private readonly EwmaAnomalyDetector _tsplusDetector;

    private readonly ConcurrentDictionary<string, DateTimeOffset> _lastAlert = new();
    private readonly TimeSpan _alertCooldown = TimeSpan.FromMinutes(5);

    public AnomalyDetectionService()
    {
        _systemDetector = EwmaDetectorFactory.CreateForSystemMetrics();
        _networkDetector = EwmaDetectorFactory.CreateForNetworkMetrics();
        _processDetector = EwmaDetectorFactory.CreateForProcessMetrics();
        _tcpDetector = EwmaDetectorFactory.CreateForTcpMetrics();
        _diskDetector = EwmaDetectorFactory.CreateForDiskMetrics();
        _tsplusDetector = EwmaDetectorFactory.CreateForTsplusMetrics();
    }

    /// <summary>
    /// Analiza una muestra de observabilidad y retorna anomalías detectadas.
    /// </summary>
    public IReadOnlyList<AnomalyEvent> Analyze(ObservabilitySample sample)
    {
        var anomalies = new List<AnomalyEvent>();

        // Sistema: CPU, Memoria
        if (sample.CpuPercent.HasValue)
            CheckAndAdd(anomalies, _systemDetector.Process($"system.cpu", sample.CpuPercent.Value, sample.Timestamp), "system.cpu", "CPU del sistema", sample.Timestamp);

        if (sample.MemoryFreePercent.HasValue)
            CheckAndAdd(anomalies, _systemDetector.Process($"system.memory", sample.MemoryFreePercent.Value, sample.Timestamp), "system.memory", "Memoria libre %", sample.Timestamp);

        // Red
        if (sample.NetworkReceiveMbps.HasValue)
            CheckAndAdd(anomalies, _networkDetector.Process($"network.rx", sample.NetworkReceiveMbps.Value, sample.Timestamp), "network.rx", "Red entrada Mbps", sample.Timestamp);

        if (sample.NetworkSendMbps.HasValue)
            CheckAndAdd(anomalies, _networkDetector.Process($"network.tx", sample.NetworkSendMbps.Value, sample.Timestamp), "network.tx", "Red salida Mbps", sample.Timestamp);

        // TCP
        if (sample.TcpEphemeralUsagePercent.HasValue)
            CheckAndAdd(anomalies, _tcpDetector.Process($"tcp.ephemeral", sample.TcpEphemeralUsagePercent.Value, sample.Timestamp), "tcp.ephemeral", "Puertos efímeros %", sample.Timestamp);

        // Discos
        foreach (var kvp in sample.DiskFreePercent)
        {
            CheckAndAdd(anomalies, _diskDetector.Process($"disk.{kvp.Key}", kvp.Value, sample.Timestamp), $"disk.{kvp.Key}", $"Disco {kvp.Key} libre %", sample.Timestamp);
        }

        // Procesos (top consumidores)
        foreach (var kvp in sample.ProcessRamMb)
        {
            CheckAndAdd(anomalies, _processDetector.Process($"process.ram.{kvp.Key}", kvp.Value, sample.Timestamp), $"process.ram.{kvp.Key}", $"Proceso {kvp.Key} RAM MB", sample.Timestamp);
        }

        // TSplus métricas (si disponibles)
        if (sample.ActiveSessions > 0)
            CheckAndAdd(anomalies, _tsplusDetector.Process($"tsplus.sessions", sample.ActiveSessions, sample.Timestamp), "tsplus.sessions", "Sesiones TSplus activas", sample.Timestamp);

        return anomalies;
    }

    private void CheckAndAdd(List<AnomalyEvent> anomalies, AnomalyResult? result, string metricKey, string metricName, DateTimeOffset timestamp)
    {
        if (result == null) return;

        // Cooldown para evitar spam de alertas
        var lastAlert = _lastAlert.GetValueOrDefault(metricKey, DateTimeOffset.MinValue);
        if (DateTimeOffset.UtcNow - lastAlert < TimeSpan.FromMinutes(5))
            return;

        _lastAlert[metricKey] = DateTimeOffset.UtcNow;

        anomalies.Add(new AnomalyEvent(
            MetricKey: metricKey,
            MetricName: metricName,
            Timestamp: timestamp,
            ObservedValue: result.ObservedValue,
            ExpectedValue: result.ExpectedValue,
            ZScore: result.ZScore,
            Direction: result.Direction,
            Severity: result.Severity,
            SampleCount: result.SampleCount));
    }

    public void Dispose()
    {
        // No resources to dispose
    }
}

/// <summary>
/// Evento de anomalía detectada listo para persistir como evento/incidente.
/// </summary>
public sealed record AnomalyEvent(
    string MetricKey,
    string MetricName,
    DateTimeOffset Timestamp,
    double ObservedValue,
    double ExpectedValue,
    double ZScore,
    AnomalyDirection Direction,
    AnomalySeverity Severity,
    int SampleCount)
{
    public string SeverityText => Severity == AnomalySeverity.Critical ? "CRÍTICO" : "ADVERTENCIA";
    public string DirectionText => Direction == AnomalyDirection.High ? "ALTO" : "BAJO";

    public DiagnosticEvent ToDiagnosticEvent()
    {
        var severity = Severity == AnomalySeverity.Critical ? DiagnosticSeverity.Critico : DiagnosticSeverity.Advertencia;
        var directionText = Direction == AnomalyDirection.High ? "ALTO" : "BAJO";

        return new DiagnosticEvent(
            Timestamp,
            "TDM.AnomalyDetector",
            "Detección de anomalías (EWMA)",
            DiagnosticLayer.Windows,
            severity,
            "ANOMALY_DETECTED",
            $"Anomalía detectada en {MetricName}: valor {ObservedValue:F2} vs esperado {ExpectedValue:F2} (Z={ZScore:F1}, {DirectionText})",
            Evidencia:
            [
                new EvidenceItem("Métrica", MetricName),
                new EvidenceItem("Clave", MetricKey),
                new EvidenceItem("Valor observado", ObservedValue.ToString("F2")),
                new EvidenceItem("Valor esperado (EWMA)", ExpectedValue.ToString("F2")),
                new EvidenceItem("Z-Score", ZScore.ToString("F2")),
                new EvidenceItem("Dirección", DirectionText),
                new EvidenceItem("Severidad", SeverityText),
                new EvidenceItem("Muestras", SampleCount.ToString()),
                new EvidenceItem("Umbral Z", "3.0 (Warning) / 6.0 (Critical)")
            ],
            Producto: TsplusProduct.Ninguno);
    }
}