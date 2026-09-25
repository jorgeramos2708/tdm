namespace TDM.Models;

/// <summary>
/// Fuente única para la versión visible/persistida del producto.
/// </summary>
public static class TdmProductInfo
{
    public const string Version = "1.0 RC18.21.0";
    public const string ReleaseChannel = "RC";
    public const string ProductName = "TSplus Diagnostic Monitor (TDM)";
    public static string DisplayName => $"{ProductName} v{Version}";
}
