namespace TDM.Models;

/// <summary>
/// Única regla de presentación para ocultar nombres técnicos del framework en
/// notificaciones, incidentes, reportes y cualquier texto visible de TDM.
/// Los nombres internos de proyectos y namespaces no se modifican.
/// </summary>
public static class TdmVisibleText
{
    public static string Sanitize(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return text ?? string.Empty;

        var value = text
            .Replace("TDM.Notifier.Avalonia.exe", "TDM.Notifier.exe", StringComparison.OrdinalIgnoreCase)
            .Replace("TDM.Gui.Avalonia.exe", "TDM.Application.exe", StringComparison.OrdinalIgnoreCase)
            .Replace("TDM.Notifier.Avalonia", "TDM.Notifier", StringComparison.OrdinalIgnoreCase)
            .Replace("TDM.Gui.Avalonia", "TDM.Application", StringComparison.OrdinalIgnoreCase)
            .Replace("NotifierAvalonia", "Notifier", StringComparison.OrdinalIgnoreCase)
            .Replace("Avalonia", string.Empty, StringComparison.OrdinalIgnoreCase)
            .Replace("TDM..", "TDM.", StringComparison.OrdinalIgnoreCase)
            .Replace("..exe", ".exe", StringComparison.OrdinalIgnoreCase)
            .Replace("· ·", "·", StringComparison.Ordinal);

        while (value.Contains("  ", StringComparison.Ordinal))
            value = value.Replace("  ", " ", StringComparison.Ordinal);

        return value.Trim();
    }
}
