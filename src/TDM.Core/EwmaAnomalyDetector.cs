using System;
using System.Collections.Generic;
using System.Linq;
using TDM.Models;

namespace TDM.Core;

/// <summary>
/// Exponential Weighted Moving Average (EWMA) detector for streaming anomaly detection.
/// Lightweight, single-pass, O(1) memory per metric.
/// </summary>
public sealed class EwmaAnomalyDetector
{
    private readonly double _alpha;           // Smoothing factor (0 < alpha <= 1)
    private readonly double _thresholdSigma;  // Alert threshold in standard deviations
    private readonly int _warmupSamples;      // Samples before alerting

    private readonly Dictionary<string, EwmaState> _states = new();

    public EwmaAnomalyDetector(double alpha = 0.3, double thresholdSigma = 3.0, int warmupSamples = 10)
    {
        if (alpha <= 0 || alpha > 1) throw new ArgumentOutOfRangeException(nameof(alpha), "Alpha must be in (0, 1]");
        if (thresholdSigma <= 0) throw new ArgumentOutOfRangeException(nameof(thresholdSigma), "Threshold must be positive");
        if (warmupSamples < 1) throw new ArgumentOutOfRangeException(nameof(warmupSamples), "Warmup must be >= 1");

        _alpha = alpha;
        _thresholdSigma = thresholdSigma;
        _warmupSamples = warmupSamples;
    }

    /// <summary>
    /// Processes a new metric value and returns anomaly result if anomalous.
    /// Returns null if not anomalous or still in warmup.
    /// </summary>
    public AnomalyResult? Process(string metricKey, double value, DateTimeOffset timestamp)
    {
        if (!_states.TryGetValue(metricKey, out var state))
        {
            state = new EwmaState { Count = 0 };
            _states[metricKey] = state;
        }

        state.Count++;

        if (state.Count == 1)
        {
            state.Mean = value;
            state.Variance = 0;
            return null; // First sample, no baseline yet
        }

        // Update EWMA mean and variance (Welford's online algorithm adapted for EWMA)
        var diff = value - state.Mean;
        state.Mean += _alpha * diff;
        state.Variance = (1 - _alpha) * (state.Variance + _alpha * diff * diff);

        state.SamplesSeen++;

        // Don't alert during warmup
        if (state.SamplesSeen < _warmupSamples)
            return null;

        var stdDev = Math.Sqrt(Math.Max(state.Variance, 1e-12));
        var zScore = Math.Abs(value - state.Mean) / stdDev;

        if (zScore >= _thresholdSigma)
        {
            var direction = value > state.Mean ? AnomalyDirection.High : AnomalyDirection.Low;
            var severity = zScore >= _thresholdSigma * 2 ? AnomalySeverity.Critical : AnomalySeverity.Warning;

            return new AnomalyResult(
                MetricKey: metricKey,
                Timestamp: timestamp,
                ObservedValue: value,
                ExpectedValue: state.Mean,
                ZScore: zScore,
                Direction: direction,
                Severity: severity,
                SampleCount: state.SamplesSeen);
        }

        return null;
    }

    /// <summary>
    /// Resets state for a metric (useful on config change).
    /// </summary>
    public void Reset(string metricKey) => _states.Remove(metricKey);

    /// <summary>
    /// Resets all states.
    /// </summary>
    public void ResetAll() => _states.Clear();

    /// <summary>
    /// Gets current EWMA statistics for a metric.
    /// </summary>
    public EwmaStats? GetStats(string metricKey)
    {
        if (!_states.TryGetValue(metricKey, out var state)) return null;
        return new EwmaStats(
            MetricKey: metricKey,
            Mean: state.Mean,
            StdDev: Math.Sqrt(Math.Max(state.Variance, 0)),
            SampleCount: state.SamplesSeen,
            IsWarmedUp: state.SamplesSeen >= _warmupSamples);
    }

    private sealed class EwmaState
    {
        public int Count = 0;
        public int SamplesSeen = 0;
        public double Mean = 0;
        public double Variance = 0;
    }
}

/// <summary>
/// Result of anomaly detection.
/// </summary>
public sealed record AnomalyResult(
    string MetricKey,
    DateTimeOffset Timestamp,
    double ObservedValue,
    double ExpectedValue,
    double ZScore,
    AnomalyDirection Direction,
    AnomalySeverity Severity,
    int SampleCount);

public enum AnomalyDirection { High, Low }
public enum AnomalySeverity { Warning, Critical }

/// <summary>
/// Current EWMA statistics for a metric.
/// </summary>
public sealed record EwmaStats(
    string MetricKey,
    double Mean,
    double StdDev,
    int SampleCount,
    bool IsWarmedUp);

/// <summary>
/// Pre-configured EWMA detectors for known metric keys.
/// </summary>
public static class EwmaDetectorFactory
{
    public static EwmaAnomalyDetector CreateForSystemMetrics()
        => new(alpha: 0.3, thresholdSigma: 3.0, warmupSamples: 10);

    public static EwmaAnomalyDetector CreateForNetworkMetrics()
        => new(alpha: 0.2, thresholdSigma: 3.0, warmupSamples: 15);

    public static EwmaAnomalyDetector CreateForProcessMetrics()
        => new(alpha: 0.4, thresholdSigma: 3.0, warmupSamples: 5);

    public static EwmaAnomalyDetector CreateForTcpMetrics()
        => new(alpha: 0.3, thresholdSigma: 3.0, warmupSamples: 10);

    public static EwmaAnomalyDetector CreateForDiskMetrics()
        => new(alpha: 0.1, thresholdSigma: 3.0, warmupSamples: 20);

    public static EwmaAnomalyDetector CreateForTsplusMetrics()
        => new(alpha: 0.3, thresholdSigma: 3.0, warmupSamples: 10);
}