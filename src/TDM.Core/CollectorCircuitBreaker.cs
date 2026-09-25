using System.Collections.Concurrent;

namespace TDM.Core;

/// <summary>
/// Circuit breaker para collectors que fallan repetidamente.
/// Después de N fallos consecutivos, el collector se deshabilita temporalmente.
/// </summary>
public sealed class CollectorCircuitBreaker
{
    private readonly ConcurrentDictionary<string, CollectorState> _states = new();
    private readonly int _failureThreshold;
    private readonly TimeSpan _resetTimeout;

    public CollectorCircuitBreaker(int failureThreshold = 3, TimeSpan? resetTimeout = null)
    {
        _failureThreshold = Math.Max(1, failureThreshold);
        _resetTimeout = resetTimeout ?? TimeSpan.FromMinutes(5);
    }

    public bool IsOpen(string collectorName)
    {
        if (!_states.TryGetValue(collectorName, out var state)) return false;
        if (state.ConsecutiveFailures < _failureThreshold) return false;
        if (DateTimeOffset.UtcNow - state.LastFailure < _resetTimeout) return true;
        // Timeout expirado → half-open (permitir un intento)
        state.ConsecutiveFailures = _failureThreshold - 1;
        return false;
    }

    public void RecordSuccess(string collectorName)
    {
        if (_states.TryGetValue(collectorName, out var state))
        {
            state.ConsecutiveFailures = 0;
            state.LastSuccess = DateTimeOffset.UtcNow;
        }
    }

    public void RecordFailure(string collectorName, Exception ex)
    {
        var state = _states.GetOrAdd(collectorName, _ => new CollectorState());
        state.ConsecutiveFailures++;
        state.LastFailure = DateTimeOffset.UtcNow;
        state.LastException = ex;
    }

    public CollectorStatus GetStatus(string collectorName)
    {
        if (!_states.TryGetValue(collectorName, out var state))
            return new CollectorStatus(collectorName, 0, null, false, DateTimeOffset.MinValue);

        var isOpen = state.ConsecutiveFailures >= _failureThreshold &&
                     DateTimeOffset.UtcNow - state.LastFailure < _resetTimeout;
        return new CollectorStatus(
            collectorName,
            state.ConsecutiveFailures,
            state.LastException?.GetType().Name,
            isOpen,
            state.LastFailure);
    }

    public IReadOnlyList<CollectorStatus> GetAllStatuses()
        => _states.Select(kv => GetStatus(kv.Key)).ToList();

    public void Reset(string collectorName)
    {
        if (_states.TryGetValue(collectorName, out var state))
        {
            state.ConsecutiveFailures = 0;
            state.LastException = null;
        }
    }

    public void ResetAll() => _states.Clear();

    private sealed class CollectorState
    {
        public int ConsecutiveFailures;
        public DateTimeOffset LastFailure;
        public DateTimeOffset LastSuccess;
        public Exception? LastException;
    }
}

public sealed record CollectorStatus(
    string CollectorName,
    int ConsecutiveFailures,
    string? LastExceptionType,
    bool IsOpen,
    DateTimeOffset LastFailureAt);