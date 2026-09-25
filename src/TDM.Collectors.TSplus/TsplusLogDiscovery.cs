using TDM.Models;
using TDM.Core;

namespace TDM.Collectors.TSplus;

public sealed record TsplusLogDiscoveryResult(
    IReadOnlyList<TsplusLogSource> Sources,
    int DynamicDirectoriesVisited,
    int DynamicDirectoriesAdded,
    int DiscoveryErrors,
    bool DiscoveryTruncated,
    bool UserProfilesTruncated);

public static class TsplusLogDiscovery
{
    public static IReadOnlyList<TsplusLogSource> Discover(string? installPath)
        => DiscoverDetailed(installPath).Sources;

    public static TsplusLogDiscoveryResult DiscoverDetailed(string? installPath)
    {
        var result = new List<TsplusLogSource>();
        var discoveryErrors = 0;
        var dynamicVisited = 0;
        var dynamicAdded = 0;
        var dynamicTruncated = false;
        var profilesTruncated = false;

        if (!string.IsNullOrWhiteSpace(installPath))
        {
            AddFile(result, "Portal web", Path.Combine(installPath, "Clients", "www", "cgi-bin", "hb.log"));
            AddFile(result, "Control de sesión", Path.Combine(installPath, "UserDesktop", "files", "APSC.log"));
            AddFile(result, "Load Balancing", Path.Combine(installPath, "UserDesktop", "files", "svcenterprise.log"));
            AddFile(result, "AdminTool", Path.Combine(installPath, "UserDesktop", "files", "AdminTool.log"));
            AddFile(result, "2FA", Path.Combine(installPath, "UserDesktop", "files", "TwoFactor.Admin.log"), DiagnosticLayer.Tsplus, TsplusProduct.TwoFactorAuthentication);

            // Diagnóstico normal: se usan logs principales conocidos. No se recorre UserDesktop\files
            // de forma genérica porque contiene configuración/binarios ajenos al objetivo de logging.

            // El gateway HTML5 escribe weblog.txt y puede producir hs_err_pid*.log cuando la JVM cae.
            // Se audita el directorio completo, pero el lector sólo toma .log/.txt/.trace y limita tamaño/cantidad.
            AddDirectory(result, "HTML5 / Web Server", Path.Combine(installPath, "Clients", "webserver"));

            // Universal Printer: TSplus documenta logs del lado servidor en C:\wsession\UniversalPrinter\logs
            // y archivos de diagnóstico/gestión bajo UserDesktop\files\UniversalPrinter.
            AddDirectory(result, "Universal Printer / instalación", Path.Combine(installPath, "UserDesktop", "files", "UniversalPrinter"));

            // Mission Assurance: además de ubicaciones documentadas/conocidas, TDM descubre
            // directorios que realmente contienen logs dentro del árbol de instalación. La búsqueda
            // es sólo de metadatos, acotada y omite reparse points; el lector mantiene límites por archivo.
            var dynamic = DiscoverDynamicLogDirectories(result, installPath);
            dynamicVisited = dynamic.Visited;
            dynamicAdded = dynamic.Added;
            dynamicTruncated = dynamic.Truncated;
            discoveryErrors += dynamic.Errors;
        }

        var systemDrive = Path.GetPathRoot(Environment.SystemDirectory) ?? @"C:\";
        AddDirectory(result, "Apertura de sesión", Path.Combine(systemDrive, "wsession", "trace"));
        AddDirectory(result, "Universal Printer / servidor", Path.Combine(systemDrive, "wsession", "UniversalPrinter", "logs"));

        var pf86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        if (!string.IsNullOrWhiteSpace(pf86))
        {
            AddDirectory(result, "TSplus Advanced Security", Path.Combine(pf86, "TSplus-Security", "logs"), DiagnosticLayer.Seguridad, TsplusProduct.AdvancedSecurity);
            AddDirectory(result, "Server Monitoring", Path.Combine(pf86, "TSplus-ServerMonitoring", "logs"), DiagnosticLayer.Tsplus, TsplusProduct.ServerMonitoring);
            AddDirectory(result, "Remote Support", Path.Combine(pf86, "TSplus-RemoteSupport", "logs"), DiagnosticLayer.Tsplus, TsplusProduct.RemoteSupport);
            AddDirectory(result, "Connection Client", Path.Combine(pf86, "Connection Client", "RDP6", "logs"));
        }

        // TSplus documenta una ubicación RDP6 por usuario. En vez de asumir un único perfil,
        // TDM inspecciona únicamente los directorios que realmente existen bajo C:\Users.
        var usersRoot = Path.Combine(systemDrive, "Users");
        try
        {
            if (FileSystemProbe.Directory(usersRoot).IsAvailable)
            {
                var profileCount = 0;
                foreach (var profile in Directory.EnumerateDirectories(usersRoot))
                {
                    profileCount++;
                    if (profileCount > 200)
                    {
                        profilesTruncated = true;
                        break;
                    }
                    var logs = Path.Combine(profile, "RDP6", "logs");
                    if (FileSystemProbe.Directory(logs).IsAvailable)
                        AddDirectory(result, $"Connection Client ({Path.GetFileName(profile)})", logs);
                    var universalLogs = Path.Combine(profile, "AppData", "Roaming", "UniversalPrinter", "logs");
                    if (FileSystemProbe.Directory(universalLogs).IsAvailable)
                        AddDirectory(result, $"Universal Printer ({Path.GetFileName(profile)})", universalLogs);
                }
            }
        }
        catch
        {
            discoveryErrors++;
        }

        var sources = result
            .GroupBy(s => s.Ruta, StringComparer.OrdinalIgnoreCase)
            .Select(g => g.First())
            .ToList();
        return new TsplusLogDiscoveryResult(sources, dynamicVisited, dynamicAdded, discoveryErrors, dynamicTruncated, profilesTruncated);
    }

    private sealed record DynamicDiscoveryStats(int Visited, int Added, int Errors, bool Truncated);

    private static DynamicDiscoveryStats DiscoverDynamicLogDirectories(List<TsplusLogSource> result, string root)
    {
        const int maxDirectories = 600;
        const int maxDepth = 6;
        const int maxLogDirectories = 80;
        var pending = new Queue<(string Path, int Depth)>();
        pending.Enqueue((root, 0));
        var visited = 0;
        var added = 0;
        var errors = 0;
        while (pending.Count > 0 && visited < maxDirectories && added < maxLogDirectories)
        {
            var (current, depth) = pending.Dequeue();
            visited++;
            try
            {
                var hasLogs = Directory.EnumerateFiles(current, "*", SearchOption.TopDirectoryOnly)
                    .Take(300)
                    .Any(IsLogCandidate);
                if (hasLogs)
                {
                    AddDirectory(result, $"Logs descubiertos · {ComponentFromPath(current)}", current);
                    added++;
                }

                if (depth >= maxDepth) continue;
                foreach (var child in Directory.EnumerateDirectories(current, "*", SearchOption.TopDirectoryOnly).Take(150))
                {
                    try
                    {
                        if ((File.GetAttributes(child) & FileAttributes.ReparsePoint) != 0) continue;
                    }
                    catch { errors++; continue; }
                    pending.Enqueue((child, depth + 1));
                    if (pending.Count + visited >= maxDirectories) break;
                }
            }
            catch { errors++; }
        }

        var truncated = pending.Count > 0 || visited >= maxDirectories || added >= maxLogDirectories;
        return new DynamicDiscoveryStats(visited, added, errors, truncated);
    }

    private static bool IsLogCandidate(string path)
    {
        var ext = Path.GetExtension(path);
        if (ext.Equals(".log", StringComparison.OrdinalIgnoreCase) || ext.Equals(".trace", StringComparison.OrdinalIgnoreCase)) return true;
        if (!ext.Equals(".txt", StringComparison.OrdinalIgnoreCase)) return false;
        var name = Path.GetFileName(path);
        return name.Contains("log", StringComparison.OrdinalIgnoreCase) || name.Contains("trace", StringComparison.OrdinalIgnoreCase)
               || path.Contains("logs", StringComparison.OrdinalIgnoreCase) || path.Contains("trace", StringComparison.OrdinalIgnoreCase);
    }

    private static string ComponentFromPath(string path)
    {
        if (path.Contains("webserver", StringComparison.OrdinalIgnoreCase) || path.Contains("www", StringComparison.OrdinalIgnoreCase)) return "Web / HTML5";
        if (path.Contains("security", StringComparison.OrdinalIgnoreCase)) return "Advanced Security";
        if (path.Contains("twofactor", StringComparison.OrdinalIgnoreCase) || path.Contains("2fa", StringComparison.OrdinalIgnoreCase)) return "2FA";
        if (path.Contains("monitor", StringComparison.OrdinalIgnoreCase)) return "Server Monitoring";
        if (path.Contains("remotesupport", StringComparison.OrdinalIgnoreCase)) return "Remote Support";
        if (path.Contains("universalprinter", StringComparison.OrdinalIgnoreCase)) return "Universal Printer";
        return "Remote Access";
    }

    private static void AddFile(
        List<TsplusLogSource> result,
        string component,
        string path,
        DiagnosticLayer layer = DiagnosticLayer.Tsplus,
        TsplusProduct product = TsplusProduct.RemoteAccess,
        bool optional = true)
    {
        try
        {
            var file = new FileInfo(path);
            result.Add(new TsplusLogSource(
                component, path, false, file.Exists,
                file.Exists ? new DateTimeOffset(file.LastWriteTimeUtc) : null,
                file.Exists ? file.Length : null,
                layer, product, optional));
        }
        catch
        {
            result.Add(new TsplusLogSource(component, path, false, false, null, null, layer, product, optional));
        }
    }

    private static void AddDirectory(
        List<TsplusLogSource> result,
        string component,
        string path,
        DiagnosticLayer layer = DiagnosticLayer.Tsplus,
        TsplusProduct product = TsplusProduct.RemoteAccess,
        bool optional = true)
    {
        try
        {
            var dir = new DirectoryInfo(path);
            result.Add(new TsplusLogSource(
                component, path, true, dir.Exists,
                dir.Exists ? new DateTimeOffset(dir.LastWriteTimeUtc) : null,
                null, layer, product, optional));
        }
        catch
        {
            result.Add(new TsplusLogSource(component, path, true, false, null, null, layer, product, optional));
        }
    }
}
