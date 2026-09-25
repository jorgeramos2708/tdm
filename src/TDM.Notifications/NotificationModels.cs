namespace TDM.Notifications;

public enum NotificationTransition { Opened, Escalated, Recovered }

public sealed record AlertSignal(
    string Key,
    DateTimeOffset Timestamp,
    string Severity,
    string Title,
    string Summary,
    string SourceKind,
    string? SourceId = null);

public sealed record IncidentNotification(
    string Id,
    DateTimeOffset Timestamp,
    NotificationTransition Transition,
    string Severity,
    string Title,
    string Summary,
    string SourceKind,
    string? SourceId = null,
    string? ConditionSeverity = null);

public interface INotificationSink
{
    Task SendAsync(IncidentNotification notification, CancellationToken ct = default);
}

public sealed record NotificationActiveState(string Key, string Severity, string Title, string Summary, string SourceKind, string? SourceId);

public sealed record NotificationDispatcherState(IReadOnlyDictionary<string, NotificationActiveState> Active);
