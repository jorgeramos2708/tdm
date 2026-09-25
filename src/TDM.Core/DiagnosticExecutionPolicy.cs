namespace TDM.Core;

/// <summary>
/// Presupuesto de ejecución del diagnóstico. Evita que múltiples APIs nativas lentas
/// conviertan un diagnóstico en una espera de varios minutos sin límite global.
/// </summary>
public sealed record DiagnosticExecutionPolicy(
    TimeSpan OverallTimeout,
    TimeSpan DefaultCollectorTimeout,
    TimeSpan DeepCollectorTimeout,
    int MaxRawEvents,
    bool UseCategoryTimeouts = true,
    int CauseStabilityFlappingThreshold = 2)
{
    public static DiagnosticExecutionPolicy ProductionDefault { get; } = new(
        OverallTimeout: TimeSpan.FromMinutes(3),
        DefaultCollectorTimeout: TimeSpan.FromSeconds(25),
        DeepCollectorTimeout: TimeSpan.FromSeconds(40),
        MaxRawEvents: 50_000,
        UseCategoryTimeouts: true,
        CauseStabilityFlappingThreshold: 2);

    public static DiagnosticExecutionPolicy Uniform(TimeSpan collectorTimeout, int maxRawEvents = 50_000, TimeSpan? overallTimeout = null)
        => new(
            overallTimeout ?? TimeSpan.FromMinutes(3),
            collectorTimeout,
            collectorTimeout,
            Math.Max(1_000, maxRawEvents),
            UseCategoryTimeouts: false);

    /// <summary>
    /// Ajusta el presupuesto al horizonte solicitado. Las ventanas largas implican más
    /// Event Log, WER y logs TSplus; mantener el presupuesto de 15 minutos podía dejar
    /// collectors críticos sin ejecutar y generar una cobertura falsamente optimista.
    /// </summary>
    public static DiagnosticExecutionPolicy ForLookback(TimeSpan lookback)
    {
        if (lookback <= TimeSpan.FromHours(4)) return ProductionDefault;
        if (lookback <= TimeSpan.FromHours(12))
            return new(TimeSpan.FromMinutes(4), TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(50), 65_000, true);
        if (lookback <= TimeSpan.FromHours(24))
            return new(TimeSpan.FromMinutes(5), TimeSpan.FromSeconds(35), TimeSpan.FromSeconds(60), 80_000, true);
        return new(TimeSpan.FromMinutes(7), TimeSpan.FromSeconds(40), TimeSpan.FromSeconds(75), 100_000, true);
    }

    public TimeSpan TimeoutFor(IReadOnlyCollector collector)
    {
        if (!UseCategoryTimeouts) return Positive(DefaultCollectorTimeout, TimeSpan.FromSeconds(45));
        var name = collector.GetType().Name;
        var deep = name.Contains("Forensic", StringComparison.OrdinalIgnoreCase)
                   || name.Contains("Event", StringComparison.OrdinalIgnoreCase)
                   || name.Contains("Log", StringComparison.OrdinalIgnoreCase)
                   || name.Contains("Inventory", StringComparison.OrdinalIgnoreCase)
                   || name.Contains("InternalConfiguration", StringComparison.OrdinalIgnoreCase)
                   || name.Contains("UserSessionProfile", StringComparison.OrdinalIgnoreCase);
        return Positive(deep ? DeepCollectorTimeout : DefaultCollectorTimeout, TimeSpan.FromSeconds(25));
    }

    public DiagnosticExecutionPolicy Normalize()
        => this with
        {
            OverallTimeout = Positive(OverallTimeout, TimeSpan.FromMinutes(3)),
            DefaultCollectorTimeout = Positive(DefaultCollectorTimeout, TimeSpan.FromSeconds(25)),
            DeepCollectorTimeout = Positive(DeepCollectorTimeout, TimeSpan.FromSeconds(40)),
            MaxRawEvents = Math.Max(1_000, MaxRawEvents)
        };

    private static TimeSpan Positive(TimeSpan value, TimeSpan fallback)
        => value > TimeSpan.Zero ? value : fallback;
}
