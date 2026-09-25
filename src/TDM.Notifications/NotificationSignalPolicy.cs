namespace TDM.Notifications;

/// <summary>
/// Normaliza condiciones que Windows registra como eventos distintos aunque pertenezcan
/// al mismo incidente visible. Un crash .NET puede producir 1026, 1000 y 1001; para el
/// operador representan una sola falla de proceso y deben ocupar una sola tarjeta.
/// </summary>
public static class NotificationSignalPolicy
{
    private static readonly HashSet<string> ProcessCrashKinds = new(StringComparer.OrdinalIgnoreCase)
    {
        "APPLICATION_CRASH",
        "DOTNET_UNHANDLED_EXCEPTION",
        "WER_REPORT"
    };

    public static string CanonicalKey(string key)
    {
        if (string.IsNullOrWhiteSpace(key)) return key;

        var parts = key.Split('|');
        if (parts.Length < 4 ||
            !parts[0].Equals("incident", StringComparison.OrdinalIgnoreCase) ||
            !ProcessCrashKinds.Contains(parts[^1]))
            return key;

        parts[2] = NormalizeProcessName(parts[2]);
        parts[^1] = "PROCESS_CRASH";
        return string.Join('|', parts);
    }

    public static int EvidencePreference(string key)
    {
        var kind = key.Split('|').LastOrDefault() ?? string.Empty;
        return kind.ToUpperInvariant() switch
        {
            "APPLICATION_CRASH" => 3,
            "DOTNET_UNHANDLED_EXCEPTION" => 2,
            "WER_REPORT" => 1,
            _ => 0
        };
    }

    private static string NormalizeProcessName(string value)
    {
        var normalized = value.Trim();
        foreach (var prefix in new[] { "Application:", "Aplicación:", "Application", "Aplicación" })
        {
            if (!normalized.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) continue;
            normalized = normalized[prefix.Length..].TrimStart(' ', ':');
            break;
        }

        // Algunos EventRecord entregan el encabezado 1026 sin saltos de línea y el
        // componente termina incluyendo CoreCLR/.NET/Description. La identidad visual
        // debe conservar únicamente el ejecutable para correlacionarlo con el 1000.
        var executableEnd = normalized.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
        if (executableEnd >= 0)
            normalized = normalized[..(executableEnd + 4)].Trim();

        return normalized;
    }
}
