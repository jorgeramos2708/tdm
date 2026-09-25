using TDM.Models;

namespace TDM.Collectors.TSplus;

/// <summary>
/// Perfil de compatibilidad deliberadamente acotado para el diagnóstico normal de TDM.
/// No intenta adivinar layouts de versiones fuera del alcance acordado.
/// </summary>
public static class TsplusReleaseCatalog
{
    public static TsplusReleaseProfile Resolve(SystemSnapshot snapshot)
    {
        var raw = snapshot.TsplusVersion ?? string.Empty;
        var parsed = TryParse(raw);

        if (parsed.Major == 19 && parsed.Minor == 30)
            return Current19("19.30", "TSplus Remote Access 19.30");
        if (parsed.Major == 19 && parsed.Minor == 40)
            return Current19("19.40", "TSplus Remote Access 19.40");
        if (parsed.Major == 18)
            return Lts("LTS18", "TSplus Remote Access LTS 18");
        if (parsed.Major == 17)
            return Lts("LTS17", "TSplus Remote Access LTS 17");

        return new TsplusReleaseProfile(
            "UNSUPPORTED",
            string.IsNullOrWhiteSpace(raw) ? "Versión no determinada" : $"TSplus {raw}",
            false,
            "TDM limita el diagnóstico funcional normal a 19.30, 19.40, LTS 18 y LTS 17. No se infieren archivos obligatorios para otras ramas.",
            CommonFiles());
    }

    private static TsplusReleaseProfile Current19(string id, string name)
        => new(id, name, true,
            "Rama actual soportada por el perfil normal de TDM.",
            CommonFiles());

    private static TsplusReleaseProfile Lts(string id, string name)
        => new(id, name, true,
            "Rama LTS soportada por el perfil normal de TDM.",
            CommonFiles());

    private static Dictionary<string, string> CommonFiles() => new(StringComparer.OrdinalIgnoreCase)
    {
        ["Web.SettingsJs"] = Path.Combine("Clients", "www", "software", "html5", "settings.js"),
        ["Web.PortalAppSettings"] = Path.Combine("Clients", "webportal", "appsettings.json"),
        ["Web.RunWebServer"] = Path.Combine("Clients", "webserver", "runwebserver.bat"),
        ["Web.HttpWebsJar"] = Path.Combine("Clients", "webserver", "httpwebs.jar"),
        ["Web.HbLog"] = Path.Combine("Clients", "www", "cgi-bin", "hb.log"),
        ["Applications.AppControl"] = Path.Combine("UserDesktop", "files", "AppControl.ini"),
        ["Sessions.ApscLog"] = Path.Combine("UserDesktop", "files", "APSC.log"),
        ["Farm.LegacyLoadBalancing"] = Path.Combine("UserDesktop", "files", "GatewayPortalLoadBalancing.ini"),
        ["Farm.Balance"] = Path.Combine("Clients", "webserver", "balance.bin"),
        ["Farm.Log"] = Path.Combine("UserDesktop", "files", "svcenterprise.log"),
        ["AdminTool.Log"] = Path.Combine("UserDesktop", "files", "AdminTool.log")
    };

    private static (int Major, int Minor) TryParse(string raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return (0, 0);
        var token = raw.Trim().Split(' ', '-', '+')[0];
        var parts = token.Split('.', StringSplitOptions.RemoveEmptyEntries);
        var major = parts.Length > 0 && int.TryParse(parts[0], out var ma) ? ma : 0;
        var minor = parts.Length > 1 && int.TryParse(parts[1], out var mi) ? mi : 0;
        return (major, minor);
    }
}
