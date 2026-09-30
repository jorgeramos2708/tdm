using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using TDM.Core;

namespace TDM.Collectors.TSplus;

/// <summary>
/// P1-05: History store for multi-generation configuration diff.
/// Stores multiple generations of config baselines (last 30 days by default)
/// and allows diffing against any previous generation.
/// </summary>
public sealed class ConfigurationHistoryStore
{
    private const string HistoryKeyPrefix = "tsplus-config-history-";
    private const int DefaultRetentionDays = 30;
    private const int MaxHistoryEntries = 100;

    private readonly JsonSerializerOptions _json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase, WriteIndented = false };

    public static readonly ConfigurationHistoryStore Instance = new();

    private ConfigurationHistoryStore() { }

    /// <summary>
    /// Saves a config baseline to history with timestamp-based key.
    /// Also updates the latest baseline for quick access.
    /// </summary>
    public void SaveAsync(ConfigBaselineState baseline, CancellationToken ct = default)
    {
        var historyKey = HistoryKeyPrefix + baseline.SavedAt.ToUniversalTime().ToString("yyyyMMddTHHmmssZ");

        // Save historical entry
        CollectorCursorStore.TrySave(historyKey, baseline, out _);
        CollectorCursorStore.TrySave("tsplus-config-baseline", baseline, out _);

        PruneOldEntries();
    }

    /// <summary>
    /// Gets the most recent baseline (for current diff).
    /// </summary>
    public ConfigBaselineState? GetLatestAsync(CancellationToken ct = default)
    {
        if (!CollectorCursorStore.TryLoad<ConfigBaselineState>("tsplus-config-baseline", out var baseline, out _))
            return null;
        return baseline;
    }

    /// <summary>
    /// Gets all historical baselines within the retention period, newest first.
    /// </summary>
    public IReadOnlyList<ConfigBaselineState> GetHistoryAsync(int retentionDays = DefaultRetentionDays, CancellationToken ct = default)
    {
        var cutoff = DateTimeOffset.UtcNow.AddDays(-retentionDays);
        var results = new List<ConfigBaselineState>();
        foreach (var key in CollectorCursorStore.ListKeys(HistoryKeyPrefix))
        {
            ct.ThrowIfCancellationRequested();
            if (CollectorCursorStore.TryLoad<ConfigBaselineState>(key, out var entry, out _) && entry is not null && entry.SavedAt >= cutoff)
                results.Add(entry);
        }

        return results
            .OrderByDescending(x => x.SavedAt)
            .Take(MaxHistoryEntries)
            .ToList();
    }

    /// <summary>
    /// Gets a baseline from a specific generation ago (1 = previous, 2 = two gens ago, etc.)
    /// relative to the latest saved baseline.
    /// </summary>
    public ConfigBaselineState? GetGenerationAsync(int generationsAgo, CancellationToken ct = default)
    {
        if (generationsAgo <= 0) return GetLatestAsync(ct);

        var latest = GetLatestAsync(ct);
        var previous = GetHistoryAsync(DefaultRetentionDays, ct)
            .Where(x => latest is null || x.SavedAt != latest.SavedAt)
            .ToList();
        if (previous.Count == 0) return latest;
        return generationsAgo <= previous.Count ? previous[generationsAgo - 1] : null;
    }

    /// <summary>
    /// Computes diff against a specific historical baseline (by index or timestamp).
    /// </summary>
    public List<TsplusConfigSemanticDiff.KeyChange> DiffAgainstGenerationAsync(
        ConfigBaselineState currentBaseline, int generationsAgo, CancellationToken ct = default)
    {
        var historical = GetGenerationAsync(generationsAgo, ct);
        if (historical is null || historical.IniStructure is null)
            return new List<TsplusConfigSemanticDiff.KeyChange>();

        return TsplusConfigSemanticDiff.DiffIni(historical.IniStructure, currentBaseline.IniStructure ?? new()).ToList();
    }

    /// <summary>
    /// Computes multi-generation diff summary showing changes across generations.
    /// </summary>
    public string GetMultiGenDiffSummaryAsync(ConfigBaselineState currentBaseline, int maxGenerations = 5, CancellationToken ct = default)
    {
        var summaries = new List<string>();
        var baseline = GetLatestAsync(ct);
        
        if (baseline is null || baseline.IniStructure is null)
            return "Sin línea base histórica para comparar.";

        for (int i = 1; i <= maxGenerations; i++)
        {
            var gen = GetGenerationAsync(i, ct);
            if (gen is null || gen.IniStructure is null) break;

            var changes = TsplusConfigSemanticDiff.DiffIni(gen.IniStructure, currentBaseline.IniStructure ?? new()).ToList();
            if (changes.Count > 0)
            {
                var summary = TsplusConfigSemanticDiff.Summarize(changes, cap: 4);
                summaries.Add($"Gen -{i} ({gen.SavedAt:yyyy-MM-dd HH:mm}): {summary}");
            }
        }

        return summaries.Count == 0 
            ? "Sin cambios en las últimas generaciones." 
            : string.Join(" | ", summaries);
    }

    private void PruneOldEntries()
    {
        var cutoff = DateTimeOffset.UtcNow.AddDays(-DefaultRetentionDays);
        var entries = new List<(string Key, DateTimeOffset SavedAt)>();
        foreach (var key in CollectorCursorStore.ListKeys(HistoryKeyPrefix))
        {
            if (CollectorCursorStore.TryLoad<ConfigBaselineState>(key, out var entry, out _) && entry is not null)
                entries.Add((key, entry.SavedAt));
        }

        var ordered = entries.OrderByDescending(x => x.SavedAt).ToList();
        for (var i = 0; i < ordered.Count; i++)
        {
            if (ordered[i].SavedAt < cutoff || i >= MaxHistoryEntries)
                CollectorCursorStore.TryDelete(ordered[i].Key);
        }
    }
}