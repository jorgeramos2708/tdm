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
    string CurrentSeverity,
    // §2/CapturedAt: el cambio real ocurrió en (ChangedAfter, Timestamp]; Timestamp
    // es la cota superior (la foto) y ChangedAfter la anterior (primer instante
    // posible). Null en journals previos a la Fase 14 (JSON backward-compatible).
    DateTimeOffset? ChangedAfter = null);

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
    int TransitionFileCount,
    long CorruptSnapshotReads = 0);

public sealed record RecordResult(
    PersistentStateSnapshot Snapshot,
    IReadOnlyList<StateTransition> Transitions,
    IReadOnlyList<BaselineDifference> BaselineDifferences,
    string RootPath,
    string HistoryPath,
    string TransitionsPath,
    string LatestSnapshotPath,
    string? BaselinePath,
    // F24: true si el latest.json anterior estaba corrupto al registrar este ciclo; en
    // ese caso las transiciones del ciclo no se pudieron calcular contra él y debe
    // declararse en el informe en lugar de perderlas en silencio.
    bool PreviousSnapshotCorrupt = false);
