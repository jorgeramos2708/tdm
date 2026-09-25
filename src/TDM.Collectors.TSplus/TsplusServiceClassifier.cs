using Microsoft.Win32;
using TDM.Models;

namespace TDM.Collectors.TSplus;

/// <summary>Clasificación conservadora, de solo lectura, de servicios relacionados con TSplus.</summary>
internal static class TsplusServiceClassifier
{
    private static readonly string[] Tokens =
    [
        "TSplus", "Application Publishing Service", "APSC",
        "ServerMonitoring", "TSplus-ServerMonitoring", "TSplus-Security",
        "RemoteSupport", "TSplus-RemoteSupport", "TSplus-TwoFactor",
        "UniversalPrinter", "Web Portal", "WebPortal", "HTML5Service", "HTML5", "Web Server"
    ];

    public static bool IsRelated(string name, string displayName)
        => ContainsTsplusMarker($"{name} {displayName}");

    public static bool IsRelatedIncludingImagePath(string name, string displayName, out string? imagePath)
    {
        imagePath = null;
        if (IsRelated(name, displayName)) return true;
        imagePath = ReadImagePath(name);
        return !string.IsNullOrWhiteSpace(imagePath) && ContainsTsplusMarker(imagePath);
    }

    public static TsplusProduct Classify(string name, string displayName, string? imagePath = null)
    {
        var value = $"{name} {displayName} {imagePath}";
        if (ContainsAny(value, "Advanced Security", "TSplus-Security")) return TsplusProduct.AdvancedSecurity;
        if (ContainsAny(value, "ServerMonitoring", "Server Monitoring", "TSplus-ServerMonitoring")) return TsplusProduct.ServerMonitoring;
        if (ContainsAny(value, "RemoteSupport", "Remote Support", "TSplus-RemoteSupport")) return TsplusProduct.RemoteSupport;
        if (ContainsAny(value, "TwoFactor", "Two Factor", "2FA")) return TsplusProduct.TwoFactorAuthentication;
        return TsplusProduct.RemoteAccess;
    }

    private static string? ReadImagePath(string serviceName)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{serviceName}", writable: false);
            return key?.GetValue("ImagePath")?.ToString();
        }
        catch
        {
            return null;
        }
    }

    private static bool ContainsTsplusMarker(string value)
    {
        if (Tokens.Any(token => value.Contains(token, StringComparison.OrdinalIgnoreCase))) return true;
        var normalized = value.Replace('/', '\\');
        return normalized.Contains(@"\TSplus\", StringComparison.OrdinalIgnoreCase)
               || normalized.Contains(@"\TSplus-", StringComparison.OrdinalIgnoreCase)
               || normalized.Contains(@"\Connection Client\", StringComparison.OrdinalIgnoreCase);
    }

    private static bool ContainsAny(string value, params string[] terms)
        => terms.Any(term => value.Contains(term, StringComparison.OrdinalIgnoreCase));
}
