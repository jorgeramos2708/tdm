using System.Text.RegularExpressions;
using TDM.Core;

namespace TDM.Collectors.TSplus;

/// <summary>
/// Descubrimiento local y conservador de topología Farm/Gateway.
/// Sólo inspecciona archivos principales conocidos de la instalación local de TSplus;
/// no abre conexiones remotas ni valida activamente los Application Servers.
/// </summary>
public sealed record TsplusFarmTopology(
    bool TsplusDetected,
    bool FarmDetected,
    string LocalRole,
    string? InstallRoot,
    IReadOnlyList<string> ApplicationServers,
    int ObservedRoutes,
    string EvidenceSource,
    string Detail);

public static partial class TsplusFarmTopologyDiscovery
{
    [GeneratedRegex(@"/~~(?<name>[^=/:\s]+)", RegexOptions.IgnoreCase)]
    private static partial Regex BalanceNameRegex();

    public static TsplusFarmTopology Discover(string? installRoot)
    {
        if (string.IsNullOrWhiteSpace(installRoot) || !FileSystemProbe.Directory(installRoot).IsAvailable)
            return new TsplusFarmTopology(false, false, "Standalone", installRoot, [], 0, "Sin instalación", "TSplus Remote Access no detectado en una ruta local válida.");

        var root = Path.GetFullPath(installRoot);
        var balance = Path.Combine(root, "Clients", "webserver", "balance.bin");
        var legacy = Path.Combine(root, "UserDesktop", "files", "GatewayPortalLoadBalancing.ini");
        var balanceProbe = FileSystemProbe.File(balance);
        var legacyProbe = FileSystemProbe.File(legacy);
        var namesProbe = ReadBalanceNames(balance, balanceProbe);
        var routesProbe = ReadNonCommentLineCount(balance, balanceProbe);

        var names = namesProbe.IsAvailable
            ? (namesProbe.Value ?? []).Where(x => !IsLocalMachineName(x)).ToList()
            : [];
        var routes = routesProbe.IsAvailable ? routesProbe.Value : 0;
        var positiveBalanceEvidence = balanceProbe.IsAvailable && (names.Count > 0 || routes > 0);
        var farmDetected = positiveBalanceEvidence || legacyProbe.IsAvailable;
        var coverageUnavailable = balanceProbe.IsUnavailable || legacyProbe.IsUnavailable
            || (balanceProbe.IsAvailable && (namesProbe.IsUnavailable || routesProbe.IsUnavailable));

        var source = positiveBalanceEvidence ? "balance.bin"
            : legacyProbe.IsAvailable ? "GatewayPortalLoadBalancing.ini"
            : coverageUnavailable ? "Cobertura local incompleta"
            : "Sin evidencia Farm";

        if (farmDetected)
        {
            var detail = names.Count > 0
                ? $"Gateway/Farm detectado por configuración local; {names.Count} Application Server(s) derivado(s)."
                : "Gateway/Farm detectado por configuración local; no se pudieron derivar nombres de Application Servers.";
            return new TsplusFarmTopology(true, true, "Gateway", root, names, routes, source, detail);
        }

        if (coverageUnavailable)
        {
            var detail = $"No fue posible determinar con fiabilidad si existe Farm/Gateway. balance.bin={balanceProbe.StatusText}; INI legado={legacyProbe.StatusText}.";
            return new TsplusFarmTopology(true, false, "No determinado", root, names, routes, source, detail);
        }

        return new TsplusFarmTopology(true, false, "Standalone", root, names, routes, source,
            "No se observó configuración Farm/Gateway en las fuentes locales principales y ambas pudieron evaluarse.");
    }

    private static ProbeResult<List<string>> ReadBalanceNames(string path, ProbeResult<bool> fileProbe)
    {
        if (fileProbe.IsAbsent) return ProbeResult<List<string>>.Absent();
        if (!fileProbe.IsAvailable) return ProbeResult<List<string>>.Unavailable(fileProbe.Detail ?? fileProbe.StatusText);
        try
        {
            var output = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var line in File.ReadLines(path).Take(5000))
            {
                var match = BalanceNameRegex().Match(line);
                if (match.Success && !string.IsNullOrWhiteSpace(match.Groups["name"].Value))
                    output.Add(match.Groups["name"].Value.Trim());
            }
            return ProbeResult<List<string>>.Available(output.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToList());
        }
        catch (UnauthorizedAccessException ex) { return ProbeResult<List<string>>.AccessDenied(ex.Message); }
        catch (IOException ex) { return ProbeResult<List<string>>.Error(ex.Message); }
        catch (Exception ex) { return ProbeResult<List<string>>.Error(ex.Message); }
    }

    private static ProbeResult<int> ReadNonCommentLineCount(string path, ProbeResult<bool> fileProbe)
    {
        if (fileProbe.IsAbsent) return ProbeResult<int>.Absent();
        if (!fileProbe.IsAvailable) return ProbeResult<int>.Unavailable(fileProbe.Detail ?? fileProbe.StatusText);
        try
        {
            var count = File.ReadLines(path).Take(5000).Count(line =>
            {
                var value = line.Trim();
                return !string.IsNullOrWhiteSpace(value) && !value.StartsWith('#') && !value.StartsWith(';');
            });
            return ProbeResult<int>.Available(count);
        }
        catch (UnauthorizedAccessException ex) { return ProbeResult<int>.AccessDenied(ex.Message); }
        catch (IOException ex) { return ProbeResult<int>.Error(ex.Message); }
        catch (Exception ex) { return ProbeResult<int>.Error(ex.Message); }
    }

    private static bool IsLocalMachineName(string candidate)
    {
        var shortName = candidate.Split('.')[0];
        return shortName.Equals(Environment.MachineName, StringComparison.OrdinalIgnoreCase);
    }
}
