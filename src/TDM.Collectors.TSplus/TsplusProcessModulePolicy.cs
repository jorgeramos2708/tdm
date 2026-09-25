namespace TDM.Collectors.TSplus;

/// <summary>
/// Reglas puras para el inventario de módulos por proceso TSplus: qué cuenta como
/// propio (bajo la raíz de instalación) y qué ruta de carga es sospechosa
/// (directorios de escritura temporal/descargas). Pineado por tests.
/// </summary>
public static class TsplusProcessModulePolicy
{
    private static readonly string[] SuspiciousMarkers =
    [
        "\\Temp\\", "\\TMP\\", "\\Downloads\\", "\\INetCache\\", "\\INetCookies\\",
        "$Recycle", "\\AppData\\Local\\Temp\\"
    ];

    public static bool IsUnderRoot(string? path, string? root)
    {
        if (string.IsNullOrWhiteSpace(path) || string.IsNullOrWhiteSpace(root)) return false;
        var baseDir = root.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
            + Path.DirectorySeparatorChar;
        return path.StartsWith(baseDir, StringComparison.OrdinalIgnoreCase);
    }

    public static bool IsSuspiciousLocation(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        var normalized = path.Replace('/', '\\');
        return SuspiciousMarkers.Any(m => normalized.Contains(m, StringComparison.OrdinalIgnoreCase));
    }
}
