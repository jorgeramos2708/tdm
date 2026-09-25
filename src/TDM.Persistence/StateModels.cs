namespace TDM.Persistence;

public sealed record PersistentObservation(
    string Key,
    string Type,
    string Component,
    string Layer,
    string Product,
    string Severity,
    string Value,
    bool TrackTransition,
    bool BaselineEligible);

public sealed record PersistentStateSnapshot(
    int SchemaVersion,
    string ToolVersion,
    DateTimeOffset CapturedAt,
    string Machine,
    string OperatingSystem,
    string Version,
    string Build,
    string Architecture,
    bool TsplusDetected,
    string? TsplusVersion,
    IReadOnlyList<PersistentObservation> Observations);

public sealed record StateTransition(
    DateTimeOffset Timestamp,
    string Key,
    string Type,
    string Component,
    string Layer,
    string Product,
    string PreviousValue,
    string CurrentValue,
    string PreviousSeverity,
    string CurrentSeverity);

public sealed record BaselineDifference(
    string Key,
    string Type,
    string Component,
    string PreviousValue,
    string CurrentValue,
    string CurrentSeverity);

public sealed record LocalStoreStatus(
    string RootPath,
    string LatestSnapshotPath,
    string BaselinePath,
    bool BaselineExists,
    DateTimeOffset? BaselineCapturedAt,
    int RetentionDays,
    int HistoryFileCount,
    int TransitionFileCount);

public sealed record RecordResult(
    PersistentStateSnapshot Snapshot,
    IReadOnlyList<StateTransition> Transitions,
    IReadOnlyList<BaselineDifference> BaselineDifferences,
    string RootPath,
    string HistoryPath,
    string TransitionsPath,
    string LatestSnapshotPath,
    string? BaselinePath);
