using System.Collections.Concurrent;
using TDM.Models;

namespace TDM.Core;

/// <summary>
/// Aísla collectors potencialmente síncronos del hilo llamador y aplica un límite real
/// al tiempo que el motor espera por cada fuente. Si una API nativa no coopera con
/// CancellationToken, la tarea queda registrada hasta terminar y no se vuelve a lanzar
/// el mismo tipo de collector en paralelo.
/// </summary>
public static class CollectorExecutionBoundary
{
    private static readonly ConcurrentDictionary<string, Task<CollectorResult>> InFlight = new(StringComparer.Ordinal);
    private static readonly object AdmissionSync = new();
    private const int MaxInFlightCollectors = 8;

    public static int InFlightCount => InFlight.Count;

    public static async Task<CollectorResult> RunAsync(
        IReadOnlyCollector collector,
        DiagnosticContext context,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(collector);
        if (timeout <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(timeout));

        var key = collector.GetType().FullName ?? collector.Nombre;
        using var collectorCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        Task<CollectorResult> work;

        // La admisión es atómica: comprobar, reservar y arrancar se realiza bajo el mismo
        // bloqueo corto. Así dos diagnósticos concurrentes no pueden iniciar dos veces el
        // mismo tipo de collector entre TryGetValue y TryAdd.
        lock (AdmissionSync)
        {
            if (InFlight.TryGetValue(key, out var previous))
            {
                if (!previous.IsCompleted)
                    throw new CollectorStillRunningException(collector.Nombre);

                // La continuación puede no haber retirado todavía una tarea ya terminada.
                InFlight.TryRemove(key, out _);
            }

            if (InFlight.Count >= MaxInFlightCollectors)
                throw new CollectorExecutionCapacityException(collector.Nombre, InFlight.Count);

            work = Task.Run(
                async () => await collector.CollectAsync(context, collectorCts.Token).ConfigureAwait(false),
                CancellationToken.None);
            InFlight[key] = work;
        }

        _ = work.ContinueWith(
            static (completed, state) =>
            {
                var tuple = ((ConcurrentDictionary<string, Task<CollectorResult>> map, string key))state!;
                if (tuple.map.TryGetValue(tuple.key, out var current) && ReferenceEquals(current, completed))
                    tuple.map.TryRemove(tuple.key, out _);
                // Observar la excepción evita UnobservedTaskException si el motor dejó de esperar por timeout.
                _ = completed.Exception;
            },
            (InFlight, key),
            CancellationToken.None,
            TaskContinuationOptions.ExecuteSynchronously,
            TaskScheduler.Default);

        try
        {
            return await work.WaitAsync(timeout, cancellationToken).ConfigureAwait(false);
        }
        catch (TimeoutException)
        {
            collectorCts.Cancel();
            throw;
        }
    }
}

public sealed class CollectorStillRunningException : Exception
{
    public CollectorStillRunningException(string collectorName)
        : base($"El collector '{collectorName}' todavía está finalizando una ejecución anterior que excedió su límite de tiempo.")
    {
        CollectorName = collectorName;
    }

    public string CollectorName { get; }
}

public sealed class CollectorExecutionCapacityException : Exception
{
    public CollectorExecutionCapacityException(string collectorName, int inFlight)
        : base($"TDM aplazó '{collectorName}' porque {inFlight} collector(es) siguen finalizando operaciones nativas anteriores.")
    {
        CollectorName = collectorName;
        InFlight = inFlight;
    }

    public string CollectorName { get; }
    public int InFlight { get; }
}
