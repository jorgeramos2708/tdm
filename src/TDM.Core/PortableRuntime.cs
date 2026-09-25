namespace TDM.Core;

/// <summary>
/// Indica si la ejecución es en modo portable (TDM_PORTABLE definido en build).
/// </summary>
public static class PortableRuntime
{
#if TDM_PORTABLE
    public static bool IsEnabled { get; } = true;
#else
    public static bool IsEnabled { get; } = false;
#endif
}