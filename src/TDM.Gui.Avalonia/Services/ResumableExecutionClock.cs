using System.Diagnostics;

namespace TDM.Gui.Avalonia.Services;

/// <summary>
/// Cronómetro acumulativo: cada Start reanuda, Pause conserva lo medido y Reset
/// es la única operación que vuelve explícitamente a cero.
/// </summary>
public sealed class ResumableExecutionClock
{
    private readonly object _sync = new();
    private readonly Stopwatch _activeSegment = new();
    private TimeSpan _accumulated;

    public TimeSpan Elapsed
    {
        get
        {
            lock (_sync)
                return _accumulated + _activeSegment.Elapsed;
        }
    }

    public bool IsRunning
    {
        get
        {
            lock (_sync)
                return _activeSegment.IsRunning;
        }
    }

    public void Start()
    {
        lock (_sync)
        {
            if (!_activeSegment.IsRunning)
                _activeSegment.Start();
        }
    }

    public void Pause()
    {
        lock (_sync)
        {
            if (!_activeSegment.IsRunning) return;
            _activeSegment.Stop();
            _accumulated += _activeSegment.Elapsed;
            _activeSegment.Reset();
        }
    }

    public void Reset(bool continueRunning)
    {
        lock (_sync)
        {
            _accumulated = TimeSpan.Zero;
            _activeSegment.Reset();
            if (continueRunning)
                _activeSegment.Start();
        }
    }
}
