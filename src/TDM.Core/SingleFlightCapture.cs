namespace TDM.Core;

/// <summary>
/// Single-flight con abandono observado para capturas costosas (auditoría crítica
/// FIX93, C2/C3/H5): como máximo existe una tarea en vuelo por instancia, los vuelos
/// terminados se cosechan explícitamente y un vuelo que no termina sólo se reemplaza
/// (observando su excepción para evitar UnobservedTaskException) tras superar su edad
/// de abandono. Así ningún llamante puede acumular capturas concurrentes mientras la
/// previa siga viva, ni quedarse esperando para siempre una tarea muerta.
/// </summary>
public sealed class SingleFlightCapture<T>
{
    private readonly object _sync = new();
    private Task<T>? _flight;
    private DateTimeOffset _startedAt;

    /// <summary>Vuelo en curso, si lo hay (expuesto para diagnósticos y tests).</summary>
    public Task<T>? InFlight
    {
        get { lock (_sync) return _flight; }
    }

    /// <summary>
    /// Devuelve el vuelo en curso, o inicia uno nuevo con <paramref name="factory"/>.
    /// Mientras el vuelo activo no complete y su edad sea menor que
    /// <paramref name="abandonAge"/> se reutiliza (nunca se duplica); si lo supera se
    /// descarta observando su excepción y se emite uno nuevo. Un vuelo ya terminado que
    /// no se hubiera cosechado se descarta observado: el llamante debe cosecharlo antes
    /// con <see cref="TryTakeCompleted"/>.
    /// </summary>
    public Task<T> Start(Func<T> factory, TimeSpan abandonAge, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(factory);
        if (abandonAge <= TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(abandonAge), "La edad de abandono debe ser positiva.");

        lock (_sync)
        {
            if (_flight is { IsCompleted: false } pending)
            {
                if (now - _startedAt < abandonAge)
                    return pending;
                // C2/C3: abandonar un vuelo colgado exceso de tiempo, observándolo.
                ObserveFaulted(pending);
            }
            else if (_flight is not null)
            {
                ObserveFaulted(_flight);
            }

            _flight = Task.Run(factory);
            _startedAt = now;
            return _flight;
        }
    }

    /// <summary>
    /// Cosecha y retira el vuelo si ya terminó (éxito o fallo; un fallo se retira ya
    /// observado). Devuelve null si el vuelo sigue en curso o no existe.
    /// </summary>
    public Task<T>? TryTakeCompleted()
    {
        lock (_sync)
        {
            if (_flight is not { IsCompleted: true } completed)
                return null;
            _flight = null;
            ObserveFaulted(completed);
            return completed;
        }
    }

    /// <summary>
    /// Descarta el vuelo indicado si sigue siendo el activo, observando su excepción.
    /// Se usa al agotar el presupuesto de espera: la tarea se suelta para que el
    /// siguiente ciclo emita una captura fresca en lugar de re-awaitear la muerta.
    /// </summary>
    public void Abandon(Task<T> task)
    {
        lock (_sync)
        {
            if (!ReferenceEquals(_flight, task))
                return;
            ObserveFaulted(task);
            _flight = null;
        }
    }

    private static void ObserveFaulted(Task task)
    {
        if (task.IsFaulted)
        {
            _ = task.Exception;
            return;
        }

        if (!task.IsCompleted)
        {
            _ = task.ContinueWith(
                static t => _ = t.Exception,
                CancellationToken.None,
                TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously,
                TaskScheduler.Default);
        }
    }
}
