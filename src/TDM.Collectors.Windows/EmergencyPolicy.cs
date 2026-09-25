namespace TDM.Collectors.Windows;

/// <summary>
/// Presupuesto y cadencia de la muestra de emergencia (ver TdmWorker): ante
/// aplazamientos consecutivos por carga, cada N ciclos se toma una muestra mínima
/// con solo readers incrementales. Constantes centralizadas para que los tests
/// pineen la decisión y el presupuesto. Puro.
/// </summary>
public static class EmergencyPolicy
{
    public const int EveryConsecutiveDefers = 3;
    public static readonly TimeSpan CollectorTimeout = TimeSpan.FromSeconds(5);
    public const int MaxRawEvents = 300;
    public static readonly TimeSpan Lookback = TimeSpan.FromMinutes(2);

    public static bool IsEmergencyDue(int consecutiveDefers, int every = EveryConsecutiveDefers)
        => every > 0 && consecutiveDefers > 0 && consecutiveDefers % every == 0;
}
