using TDM.Models;

namespace TDM.Collectors.TSplus;

/// <summary>
/// Catálogo conservador de artefactos de configuración TSplus que TDM conoce por nombre.
/// No implica que el archivo sea obligatorio en todas las versiones/roles; sólo define
/// cómo clasificarlo cuando existe. Los artefactos no catalogados siguen inventariándose
/// por extensión y ruta durante la auditoría profunda.
/// </summary>
public sealed record TsplusConfigurationArtifactDescriptor(
    string FileName,
    TsplusProduct Product,
    string Component,
    string ParserPolicy,
    bool Sensitive = false);

public static class TsplusConfigurationArtifactCatalog
{
    private static readonly IReadOnlyDictionary<string, TsplusConfigurationArtifactDescriptor> Known =
        new Dictionary<string, TsplusConfigurationArtifactDescriptor>(StringComparer.OrdinalIgnoreCase)
        {
            ["AppControl.ini"] = new("AppControl.ini", TsplusProduct.RemoteAccess, "Application Publishing", "INI / estructura y publicación"),
            ["settings.js"] = new("settings.js", TsplusProduct.RemoteAccess, "Web / HTML5", "JavaScript / lectura segura sin ejecución"),
            ["balance.bin"] = new("balance.bin", TsplusProduct.RemoteAccess, "Gateway / Load Balancing", "balance.bin / granja y Reverse Proxy"),
            ["GatewayPortalLoadBalancing.ini"] = new("GatewayPortalLoadBalancing.ini", TsplusProduct.RemoteAccess, "Gateway / Load Balancing", "INI / estructura de granja"),
            ["appsettings.json"] = new("appsettings.json", TsplusProduct.RemoteAccess, "Web / HTML5", "JSON / sintaxis"),
            ["common_applications.js"] = new("common_applications.js", TsplusProduct.RemoteAccess, "Web / HTML5", "JavaScript / lectura segura sin ejecución"),
            ["startup.config"] = new("startup.config", TsplusProduct.RemoteAccess, "Sesiones / RemoteApp", "XML/configuración / sintaxis conservadora"),
            ["settings.bin"] = new("settings.bin", TsplusProduct.RemoteAccess, "Web / HTML5", "BIN / metadatos"),
            ["webcredentials.ini"] = new("webcredentials.ini", TsplusProduct.RemoteAccess, "Web / HTML5", "INI / estructura; contenido sensible no exportado", true),
            ["webcredentials1.ini"] = new("webcredentials1.ini", TsplusProduct.RemoteAccess, "Web / HTML5", "INI / estructura; contenido sensible no exportado", true)
        };

    public static IReadOnlyList<TsplusConfigurationArtifactDescriptor> Descriptors { get; } =
        Known.Values.OrderBy(x => x.FileName, StringComparer.OrdinalIgnoreCase).ToArray();

    public static TsplusConfigurationArtifactDescriptor? Find(string? fileName)
        => !string.IsNullOrWhiteSpace(fileName) && Known.TryGetValue(fileName, out var descriptor) ? descriptor : null;

    public static string ClassifyComponent(string path)
        => Find(Path.GetFileName(path))?.Component ?? ClassifyByPath(path).Component;

    public static TsplusProduct ClassifyProduct(string path)
        => Find(Path.GetFileName(path))?.Product ?? ClassifyByPath(path).Product;

    private static (TsplusProduct Product, string Component) ClassifyByPath(string path)
    {
        var value = path.Replace('\\', '/');
        if (ContainsAny(value, "advancedsecurity", "advanced-security", "/security/", "tsplus-security"))
            return (TsplusProduct.AdvancedSecurity, "Advanced Security");
        if (ContainsAny(value, "twofactor", "two-factor", "/2fa/"))
            return (TsplusProduct.TwoFactorAuthentication, "2FA");
        if (ContainsAny(value, "servermonitoring", "server-monitoring", "/monitoring/"))
            return (TsplusProduct.ServerMonitoring, "Server Monitoring");
        if (ContainsAny(value, "remotesupport", "remote-support"))
            return (TsplusProduct.RemoteSupport, "Remote Support");
        if (ContainsAny(value, "gateway", "loadbalanc", "load-balanc"))
            return (TsplusProduct.RemoteAccess, "Gateway / Load Balancing");
        if (ContainsAny(value, "webserver", "webportal", "html5"))
            return (TsplusProduct.RemoteAccess, "Web / HTML5");
        if (ContainsAny(value, "appcontrol", "application", "remoteapp", "seamless"))
            return (TsplusProduct.RemoteAccess, "Application Publishing");
        if (ContainsAny(value, "session", "logon"))
            return (TsplusProduct.RemoteAccess, "Sesiones / logon TSplus");
        return (TsplusProduct.RemoteAccess, "Configuración TSplus");
    }

    private static bool ContainsAny(string value, params string[] terms)
        => terms.Any(term => value.Contains(term, StringComparison.OrdinalIgnoreCase));
}
