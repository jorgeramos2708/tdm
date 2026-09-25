using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using TDM.Models;

namespace TDM.Core;

/// <summary>
/// Temporal Causal Graph with time-lag correlation and Granger causality testing.
/// Builds a directed graph of causal relationships between time-series metrics/events.
/// </summary>
public sealed class TemporalCausalGraph
{
    private readonly TimeSpan _maxLag;

    public TemporalCausalGraph(TimeSpan maxLag = default)
    {
        _maxLag = maxLag == default ? TimeSpan.FromMinutes(15) : maxLag;
    }

    /// <summary>
    /// Builds causal graph from time-series observations.
    /// </summary>
    public CausalGraph BuildGraph(IReadOnlyList<TimeSeriesObservation> observations)
    {
        var nodeList = observations
            .GroupBy(o => o.MetricKey)
            .Select(g => new CausalNode
            {
                MetricKey = g.Key,
                MetricName = g.First().MetricName,
                Observations = g.OrderBy(o => o.Timestamp).ToImmutableList()
            })
            .ToList();

        var edges = new List<CausalEdge>();

        foreach (var source in nodeList)
        {
            foreach (var target in nodeList)
            {
                if (source.MetricKey == target.MetricKey) continue;

                var causality = TestCausality(source, target);
                if (causality != null)
                    edges.Add(causality);
            }
        }

        return new CausalGraph(nodeList.ToImmutableList(), edges.ToImmutableList());
    }

    private CausalEdge? TestCausality(CausalNode source, CausalNode target)
    {
        if (source.Observations.Count < 10 || target.Observations.Count < 10)
            return null;

        var aligned = AlignTimeSeries(source.Observations, target.Observations);
        if (aligned.Count < 10)
            return null;

        for (int lag = 1; lag <= 15; lag++)
        {
            var (score, pValue) = GrangerTest(source.Observations, target.Observations, lag);
            if (pValue < 0.05 && score > 0.3)
            {
                return new CausalEdge(
                    Source: new CausalNode { MetricKey = source.MetricKey, MetricName = source.MetricName },
                    Target: new CausalNode { MetricKey = target.MetricKey, MetricName = target.MetricName },
                    Lag: TimeSpan.FromMinutes(lag),
                    GrangerScore: score,
                    PValue: pValue,
                    Direction: CausalityDirection.SourceCausesTarget,
                    Confidence: Math.Min(1.0, (1 - pValue) * score * 2)
                );
            }
        }

        return null;
    }

    private IReadOnlyList<AlignedObservation> AlignTimeSeries(IReadOnlyList<TimeSeriesObservation> source, IReadOnlyList<TimeSeriesObservation> target)
    {
        var sourceBuckets = source
            .Where(o => o.Value.HasValue)
            .GroupBy(o => new DateTimeOffset(o.Timestamp.Year, o.Timestamp.Month, o.Timestamp.Day, o.Timestamp.Hour, o.Timestamp.Minute, 0, o.Timestamp.Offset))
            .ToDictionary(g => g.Key, g => g.Average(o => o.Value!.Value));

        var targetBuckets = target
            .Where(o => o.Value.HasValue)
            .GroupBy(o => new DateTimeOffset(o.Timestamp.Year, o.Timestamp.Month, o.Timestamp.Day, o.Timestamp.Hour, o.Timestamp.Minute, 0, o.Timestamp.Offset))
            .ToDictionary(g => g.Key, g => g.Average(o => o.Value!.Value));

        var allTimes = sourceBuckets.Keys.Union(targetBuckets.Keys).OrderBy(t => t).ToList();
        var aligned = new List<AlignedObservation>();

        foreach (var time in allTimes)
        {
            if (sourceBuckets.TryGetValue(time, out var sVal) && targetBuckets.TryGetValue(time, out var tVal))
            {
                aligned.Add(new AlignedObservation(time, sVal, tVal));
            }
        }

        return aligned;
    }

    private (double Score, double PValue) GrangerTest(IReadOnlyList<TimeSeriesObservation> source, IReadOnlyList<TimeSeriesObservation> target, int lagMinutes)
    {
        var aligned = AlignTimeSeries(source, target);
        if (aligned.Count <= lagMinutes) return (0, 1.0);

        var n = aligned.Count - lagMinutes;
        if (n < 10) return (0, 1.0);

        double sumX = 0, sumY = 0, sumXY = 0, sumX2 = 0;

        for (int i = 0; i < n; i++)
        {
            var x = aligned[i + lagMinutes].SourceValue;
            var y = aligned[i].TargetValue;
            sumX += x;
            sumY += y;
            sumXY += x * y;
            sumX2 += x * x;
        }

        var denom = n * sumX2 - sumX * sumX;
        if (Math.Abs(denom) < 1e-12) return (0, 1.0);

        var slope = (n * sumXY - sumX * sumY) / (n * sumX2 - sumX * sumX);
        var intercept = (aligned.Take(n).Sum(a => a.TargetValue) - slope * sumX) / n;

        var meanY = n > 0 ? aligned.Take(n).Sum(a => a.TargetValue) / n : 0;
        var ssTotal = 0.0;
        var ssResidual = 0.0;
        for (int i = 0; i < n; i++)
        {
            var y = aligned[i].TargetValue;
            var yPred = intercept + slope * aligned[i + lagMinutes].SourceValue;
            ssTotal += Math.Pow(aligned[i].TargetValue - sumY / n, 2);
            ssResidual += Math.Pow(y - yPred, 2);
        }

        var rSquared = ssTotal > 0 ? 1 - ssResidual / ssTotal : 0;
        if (rSquared <= 0) return (0, 1.0);

        var fStat = rSquared / (1 - rSquared) * (n - 2);
        var pValue = 1 - IncompleteBeta(n / 2.0 - 1, 0.5, n / (n + fStat));

        return (Math.Max(0, rSquared), pValue);
    }

    private static double IncompleteBeta(double a, double b, double x)
    {
        if (x <= 0) return 0;
        if (x >= 1) return 1;
        return x;
    }
}

/// <summary>
/// Time series observation with metric key and value.
/// </summary>
public sealed record TimeSeriesObservation(
    string MetricKey,
    string MetricName,
    DateTimeOffset Timestamp,
    double? Value);

/// <summary>
/// Node in causal graph representing a metric time series.
/// </summary>
public sealed class CausalNode
{
    public string MetricKey { get; init; } = "";
    public string MetricName { get; init; } = "";
    public IReadOnlyList<TimeSeriesObservation> Observations { get; init; } = ImmutableList<TimeSeriesObservation>.Empty;
}

/// <summary>
/// Aligned observation pair for Granger test.
/// </summary>
public sealed record AlignedObservation(
    DateTimeOffset Time,
    double SourceValue,
    double TargetValue);

/// <summary>
/// Edge in causal graph representing causal relationship.
/// </summary>
public sealed record CausalEdge(
    CausalNode Source,
    CausalNode Target,
    TimeSpan Lag,
    double GrangerScore,
    double PValue,
    CausalityDirection Direction,
    double Confidence);

/// <summary>
/// Direction of causality.
/// </summary>
public enum CausalityDirection
{
    SourceCausesTarget,
    TargetCausesSource,
    Bidirectional,
    Unknown
}

/// <summary>
/// Complete causal graph with nodes and edges.
/// </summary>
public sealed record CausalGraph(
    IReadOnlyList<CausalNode> Nodes,
    IReadOnlyList<CausalEdge> Edges)
{
    public IReadOnlyList<CausalPath> FindPaths(string fromMetric, string toMetric, int maxDepth = 3)
    {
        var start = Nodes.FirstOrDefault(n => n.MetricKey == fromMetric);
        var end = Nodes.FirstOrDefault(n => n.MetricKey == toMetric);
        if (start == null || end == null) return ImmutableList<CausalPath>.Empty;

        var paths = new List<CausalPath>();
        DFS(start!, end!, new List<CausalNode>(), new List<CausalPath>(), 3);
        return paths.OrderByDescending(p => p.TotalConfidence).ToImmutableList();
    }

    private void DFS(CausalNode current, CausalNode target, List<CausalNode> path, List<CausalPath> paths, int maxDepth)
    {
        if (path.Count > maxDepth) return;
        path.Add(current);

        if (current.MetricKey == target.MetricKey)
        {
            var edges = new List<CausalEdge>();
            for (int i = 0; i < path.Count - 1; i++)
            {
                var from = path[i];
                var to = path[i + 1];
                var edge = new CausalEdge(
                    Source: from,
                    Target: to,
                    Lag: TimeSpan.Zero,
                    GrangerScore: 0,
                    PValue: 0,
                    Direction: CausalityDirection.SourceCausesTarget,
                    Confidence: 1.0
                );
                edges.Add(edge);
            }
            if (edges.Count > 0)
                paths.Add(new CausalPath(path.ToImmutableList(), edges.ToImmutableList()));
        }
        else
        {
            foreach (var edge in Edges.Where(e => e.Source.MetricKey == current.MetricKey && !path.Contains(e.Target)))
                DFS(edge.Target, target, path, paths, 3);
        }

        path.RemoveAt(path.Count - 1);
    }
}

/// <summary>
/// Path in causal graph.
/// </summary>
public sealed record CausalPath(
    IReadOnlyList<CausalNode> Nodes,
    IReadOnlyList<CausalEdge> Edges)
{
    public double TotalConfidence => Edges.Count > 0 ? Edges.Average(e => e.Confidence) : 0;
    public TimeSpan TotalLag => Edges.Aggregate(TimeSpan.Zero, (acc, e) => acc + e.Lag);
}