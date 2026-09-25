namespace TDM.Persistence;

/// <summary>
/// Límite de concurrencia sin cola interna. Si no hay capacidad, el llamador recibe false
/// inmediatamente y decide si aplaza/reintenta. Útil para APIs nativas/UNC que pueden quedar
/// bloqueadas y no deben acumular trabajo pendiente dentro del proceso.
/// </summary>
internal sealed class NonQueuingOperationLimiter
{
    private readonly int _maxConcurrency;
    private int _active;

    public NonQueuingOperationLimiter(int maxConcurrency)
    {
        if (maxConcurrency <= 0) throw new ArgumentOutOfRangeException(nameof(maxConcurrency));
        _maxConcurrency = maxConcurrency;
    }

    public int Active => Volatile.Read(ref _active);
    public int Capacity => _maxConcurrency;

    public bool TryAcquire(out IDisposable? lease)
    {
        while (true)
        {
            var current = Volatile.Read(ref _active);
            if (current >= _maxConcurrency)
            {
                lease = null;
                return false;
            }

            if (Interlocked.CompareExchange(ref _active, current + 1, current) == current)
            {
                lease = new Lease(this);
                return true;
            }
        }
    }

    private void Release()
        => Interlocked.Decrement(ref _active);

    private sealed class Lease : IDisposable
    {
        private NonQueuingOperationLimiter? _owner;

        public Lease(NonQueuingOperationLimiter owner) => _owner = owner;

        public void Dispose()
        {
            var owner = Interlocked.Exchange(ref _owner, null);
            owner?.Release();
        }
    }
}
