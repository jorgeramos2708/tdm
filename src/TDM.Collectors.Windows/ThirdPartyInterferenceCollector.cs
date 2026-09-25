using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.ServiceProcess;
using System.Xml.Linq;
using Microsoft.Win32;
using TDM.Core;
using TDM.Models;

namespace TDM.Collectors.Windows;

/// <summary>
/// Identifica evidencia LOCAL de software de terceros que pueda intervenir en procesos TSplus.
/// La presencia de un EDR/antivirus/driver/DLL es contexto, no culpabilidad. Sólo se eleva una
/// señal causal cuando un evento menciona explícitamente TSplus o un módulo externo aparece como
/// módulo con error de un crash TSplus. No realiza conexiones de red ni modifica servicios.
/// </summary>
public sealed class ThirdPartyInterferenceCollector : IReadOnlyCollector
{
    public string Nombre => "Interferencia de terceros / EDR / DLL / drivers";

    public Task<CollectorResult> CollectAsync(DiagnosticContext context, CancellationToken cancellationToken = default)
    {
        var findings = new List<DiagnosticFinding>();
        var events = new List<DiagnosticEvent>();
        if (!context.Sistema.TsplusDetectado)
            return Task.FromResult(CollectorResult.Empty);

        var runtimes = EnumerateThirdPartySecurityRuntimes(cancellationToken);
        var loadedModules = EnumerateExternalModulesInTsplusProcesses(context.Sistema, cancellationToken);

        events.Add(new DiagnosticEvent(
            DateTimeOffset.Now,
            "TDM",
            "Software de terceros observado",
            DiagnosticLayer.Seguridad,
            DiagnosticSeverity.Informativo,
            "THIRD_PARTY_RUNTIME_INVENTORY",
            "Inventario local y no causal de software de seguridad/red de terceros y módulos externos observados en procesos TSplus.",
            Evidencia:
            [
                new EvidenceItem("Runtimes de seguridad/red observados", runtimes.Count.ToString()),
                new EvidenceItem("Productos observados", runtimes.Count == 0 ? "Ninguno identificado" : string.Join(" | ", runtimes.Select(x => x.Display).Distinct(StringComparer.OrdinalIgnoreCase).Take(20))),
                new EvidenceItem("Módulos externos cargados en procesos TSplus", loadedModules.Count.ToString()),
                new EvidenceItem("Interpretación", "Presencia no implica causalidad; sólo se usa como contexto o para resolver un módulo con error explícito")
            ]));

        ReadThirdPartyCrashModules(context, loadedModules, findings, events, cancellationToken);
        ReadExplicitThirdPartySignals(context, runtimes, events, cancellationToken);

        return Task.FromResult(new CollectorResult(findings, events));
    }

    private static void ReadThirdPartyCrashModules(
        DiagnosticContext context,
        IReadOnlyDictionary<string, ExternalModuleInfo> loadedModules,
        List<DiagnosticFinding> findings,
        List<DiagnosticEvent> events,
        CancellationToken ct)
    {
        var timeClause = DiagnosticWindow.EventLogTimeClause(context);
        var xpath = $"*[System[(EventID=1000) and {timeClause}]]";
        try
        {
            var query = new EventLogQuery("Application", PathType.LogName, xpath) { ReverseDirection = true, TolerateQueryErrors = false };
            using var reader = new EventLogReader(query);
            for (var i = 0; i < 300; i++)
            {
                ct.ThrowIfCancellationRequested();
                using var record = reader.ReadEvent();
                if (record is null) break;
                if (!record.TimeCreated.HasValue) continue;

                var data = ParseEventData(record);
                string V(params string[] names)
                {
                    foreach (var n in names)
                        if (data.TryGetValue(n, out var value) && !string.IsNullOrWhiteSpace(value)) return value.Trim();
                    return string.Empty;
                }

                var appName = V("AppName", "FaultingApplicationName", "param1");
                var appPath = V("AppPath", "FaultingApplicationPath", "param11");
                var moduleName = V("ModuleName", "FaultingModuleName", "param4");
                var modulePath = V("ModulePath", "FaultingModulePath", "param12");
                if (!TouchesTsplus(appName, appPath, context.Sistema)) continue;
                if (string.IsNullOrWhiteSpace(moduleName) && string.IsNullOrWhiteSpace(modulePath)) continue;
                if (IsWindowsModule(moduleName, modulePath) || IsTsplusModule(moduleName, modulePath, context.Sistema)) continue;

                ExternalModuleInfo? info = null;
                if (!string.IsNullOrWhiteSpace(modulePath) && File.Exists(modulePath))
                    info = DescribeModule(modulePath);
                if (info is null && !string.IsNullOrWhiteSpace(moduleName) && loadedModules.TryGetValue(moduleName, out var current))
                    info = current;

                // Si sólo tenemos el nombre del módulo y no existe ruta ni metadata, conservamos la señal
                // únicamente si el nombre no es uno de los módulos comunes del runtime/Windows.
                if (info is null && !LooksLikeExternalModuleName(moduleName)) continue;

                var originator = SpecificOriginator(info, moduleName, modulePath);
                var product = ClassifyTsplusProduct(appName, appPath);
                var ts = new DateTimeOffset(record.TimeCreated.Value);
                var evidence = new List<EvidenceItem>
                {
                    new("Aplicación TSplus", string.IsNullOrWhiteSpace(appName) ? "N/D" : appName),
                    new("Ruta de aplicación", string.IsNullOrWhiteSpace(appPath) ? "N/D" : appPath),
                    new("Módulo con error", string.IsNullOrWhiteSpace(moduleName) ? "N/D" : moduleName),
                    new("Ruta del módulo", string.IsNullOrWhiteSpace(modulePath) ? info?.Path ?? "N/D" : modulePath),
                    new("Empresa", info?.Company ?? "No determinada"),
                    new("Producto", info?.Product ?? "No determinado"),
                    new("Originador específico", originator),
                    new("Clasificación", "Módulo externo al árbol Windows y al árbol TSplus"),
                    new("Nota causal", "Módulo con error externo es evidencia fuerte de intervención técnica, pero no demuestra por sí sola defecto del proveedor")
                };

                events.Add(new DiagnosticEvent(
                    ts,
                    record.ProviderName ?? "Application Error",
                    originator,
                    DiagnosticLayer.Seguridad,
                    DiagnosticSeverity.Error,
                    "THIRD_PARTY_MODULE_TSPLUS_CRASH",
                    $"Un proceso TSplus falló con un módulo externo: {originator}.",
                    record.Id.ToString(),
                    string.IsNullOrWhiteSpace(modulePath) ? info?.Path : modulePath,
                    Evidencia: evidence,
                    Producto: product));

                findings.Add(new DiagnosticFinding(
                    $"THIRD-PARTY-MODULE-TSPLUS-CRASH-{record.RecordId}",
                    originator,
                    DiagnosticSeverity.Error,
                    "Un módulo externo aparece como módulo con error dentro de un crash de proceso TSplus.",
                    "TDM identificó un módulo que no pertenece al árbol de Windows ni al árbol TSplus como módulo con error de Application Error 1000. Debe revisarse ese componente concreto antes de atribuir el incidente a Windows o TSplus. La presencia del módulo como punto de fallo es evidencia técnica fuerte, no una sentencia sobre la calidad del producto de terceros.",
                    evidence,
                    ConfidenceLevel.Alta,
                    SolucionSugerida: "Revise versión, firma/proveedor y compatibilidad del módulo externo; correlacione con el proceso TSplus y con eventos del producto de terceros. No desinstale seguridad, drivers ni agentes sólo por esta señal.",
                    Capa: DiagnosticLayer.Seguridad));
            }
        }
        catch (EventLogNotFoundException) { }
        catch (UnauthorizedAccessException) { }
        catch (EventLogException ex)
        {
            // Y1: una lectura corrupta a mitad de canal no debe perder los módulos ya
            // identificados ni silenciar la cobertura: se declara parcial con rastro.
            findings.Add(new DiagnosticFinding(
                "THIRD-PARTY-EVENTLOG-COVERAGE",
                "Interferencia de terceros",
                DiagnosticSeverity.Advertencia,
                "La lectura de Application para módulos de terceros quedó parcial.",
                "Los módulos ya identificados se conservan; la cobertura del canal queda parcial.",
                [new EvidenceItem("Canal", "Application"), new EvidenceItem("Cobertura", "Parcial"), new EvidenceItem("Detalle", ex.Message)],
                ConfidenceLevel.Media,
                Capa: DiagnosticLayer.Seguridad));
        }
    }

    private static void ReadExplicitThirdPartySignals(
        DiagnosticContext context,
        IReadOnlyList<ThirdPartyRuntimeInfo> runtimes,
        List<DiagnosticEvent> events,
        CancellationToken ct)
    {
        var window = DiagnosticWindow.Resolve(context);
        var start = window.Start;
        var end = window.End;
        var timeClause = DiagnosticWindow.EventLogTimeClause(context);
        foreach (var log in new[] { "Application", "System" })
        {
            try
            {
                var query = new EventLogQuery(log, PathType.LogName, $"*[System[(Level=1 or Level=2 or Level=3) and {timeClause}]]")
                {
                    ReverseDirection = true,
                    TolerateQueryErrors = false
                };
                using var reader = new EventLogReader(query);
                for (var i = 0; i < 900; i++)
                {
                    ct.ThrowIfCancellationRequested();
                    using var record = reader.ReadEvent();
                    if (record is null) break;
                    if (!record.TimeCreated.HasValue) continue;
                    var ts = new DateTimeOffset(record.TimeCreated.Value);
                    if (ts > end) continue;
                    if (ts < start) break;
                    var provider = record.ProviderName ?? string.Empty;
                    var message = SafeDescription(record);
                    var text = $"{provider} {message}";
                    if (!TouchesTsplus(text, null, context.Sistema)) continue;

                    var runtime = runtimes.FirstOrDefault(r =>
                        r.Tokens.Any(token => text.Contains(token, StringComparison.OrdinalIgnoreCase)));
                    if (runtime is null)
                    {
                        var known = KnownProduct(text);
                        if (known is not null)
                            runtime = new ThirdPartyRuntimeInfo(known.Value.Display, null, known.Value.Tokens);
                    }
                    if (runtime is null) continue;

                    events.Add(new DiagnosticEvent(
                        ts,
                        provider,
                        runtime.Display,
                        DiagnosticLayer.Seguridad,
                        DiagnosticSeverity.Error,
                        "THIRD_PARTY_SECURITY_INTERFERENCE_SIGNAL",
                        "Un evento de un producto de terceros menciona explícitamente una ruta o componente TSplus.",
                        record.Id.ToString(),
                        Evidencia:
                        [
                            new EvidenceItem("Originador específico", runtime.Display),
                            new EvidenceItem("Proveedor del evento", provider),
                            new EvidenceItem("Servicio/ruta observada", runtime.Path ?? "N/D"),
                            new EvidenceItem("Relación con TSplus", "Explícita en el texto del evento"),
                            new EvidenceItem("Nota causal", "Se requiere correlación temporal/funcional antes de declarar causa primaria")
                        ]));
                }
            }
            catch (EventLogNotFoundException) { }
            catch (UnauthorizedAccessException) { }
            catch (EventLogException ex)
            {
                // Y1: idem sitio anterior, para Application y System (aquí solo hay eventos,
                // así que el rastro es un evento de cobertura, no un finding).
                events.Add(new DiagnosticEvent(
                    DateTimeOffset.Now, "TDM", "Interferencia de terceros / " + log,
                    DiagnosticLayer.Seguridad, DiagnosticSeverity.Advertencia, "THIRD_PARTY_EVENTLOG_COVERAGE",
                    $"La lectura de {log} para señales de terceros quedó parcial; lo ya leído se conserva.",
                    Evidencia:
                    [
                        new EvidenceItem("Canal", log),
                        new EvidenceItem("Cobertura", "Parcial"),
                        new EvidenceItem("Detalle", ex.Message)
                    ]));
            }
        }
    }

    private static List<ThirdPartyRuntimeInfo> EnumerateThirdPartySecurityRuntimes(CancellationToken ct)
    {
        var result = new List<ThirdPartyRuntimeInfo>();
        try
        {
            foreach (var service in ServiceController.GetServices())
            {
                using (service)
                {
                    ct.ThrowIfCancellationRequested();
                    var serviceName = service.ServiceName ?? string.Empty;
                    var display = service.DisplayName ?? serviceName;
                    var path = ReadServiceImagePath(serviceName);
                    var combined = $"{serviceName} {display} {path}";
                    var known = KnownProduct(combined);
                    if (known is null) continue;
                    result.Add(new ThirdPartyRuntimeInfo(known.Value.Display, path, known.Value.Tokens));
                    if (result.Count >= 40) break;
                }
            }
        }
        catch { }
        return result
            .GroupBy(x => x.Display, StringComparer.OrdinalIgnoreCase)
            .Select(g => g.First())
            .ToList();
    }

    private static Dictionary<string, ExternalModuleInfo> EnumerateExternalModulesInTsplusProcesses(SystemSnapshot system, CancellationToken ct)
    {
        var result = new Dictionary<string, ExternalModuleInfo>(StringComparer.OrdinalIgnoreCase);
        foreach (var process in Process.GetProcesses())
        {
            using (process)
            {
                ct.ThrowIfCancellationRequested();
                string? exePath = null;
                try { exePath = process.MainModule?.FileName; } catch { }
                string name;
                try { name = process.ProcessName; } catch { continue; }
                if (!TouchesTsplus(name, exePath, system)) continue;

                try
                {
                    foreach (ProcessModule module in process.Modules)
                    {
                        var path = module.FileName;
                        var moduleName = module.ModuleName;
                        if (string.IsNullOrWhiteSpace(path) || string.IsNullOrWhiteSpace(moduleName)) continue;
                        if (IsWindowsModule(moduleName, path) || IsTsplusModule(moduleName, path, system)) continue;
                        var info = DescribeModule(path) ?? new ExternalModuleInfo(path, null, null);
                        result.TryAdd(moduleName, info);
                        if (result.Count >= 200) return result;
                    }
                }
                catch { }
            }
        }
        return result;
    }

    private static string? ReadServiceImagePath(string serviceName)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{serviceName}");
            return key?.GetValue("ImagePath")?.ToString();
        }
        catch { return null; }
    }

    private static (string Display, string[] Tokens)? KnownProduct(string text)
    {
        (string Display, string[] Tokens)[] products =
        [
            ("CrowdStrike Falcon", ["crowdstrike", "csfalcon", "falcon sensor"]),
            ("SentinelOne", ["sentinelone", "sentinelagent", "sentinel agent"]),
            ("Sophos", ["sophos"]),
            ("ESET", ["eset", "ekrn"]),
            ("Trend Micro", ["trend micro", "tmlisten", "ntrtscan"]),
            ("Trellix / McAfee", ["trellix", "mcafee", "mfemms", "masvc"]),
            ("Bitdefender", ["bitdefender", "vsserv"]),
            ("VMware Carbon Black", ["carbon black", "cb defense", "cbdefense", "cb.exe"]),
            ("Fortinet", ["fortinet", "forticlient"]),
            ("Palo Alto Cortex", ["cortex xdr", "traps", "cyserver"]),
            ("Zscaler", ["zscaler", "zsatunnel"]),
            ("Broadcom / Symantec Endpoint Protection", ["symantec", "sep", "smc.exe"]),
            ("Cisco Secure Endpoint", ["cisco amp", "secure endpoint", "sfc.exe"]),
            ("Kaspersky", ["kaspersky", "avp.exe"]),
            ("Malwarebytes", ["malwarebytes", "mbamservice"]),
            ("Avast", ["avast", "avastsvc"]),
            ("AVG", ["avg antivirus", "avgsvc"])
        ];
        foreach (var product in products)
            if (product.Tokens.Any(t => text.Contains(t, StringComparison.OrdinalIgnoreCase))) return product;
        return null;
    }

    private static ExternalModuleInfo? DescribeModule(string path)
    {
        try
        {
            if (!File.Exists(path)) return null;
            var info = FileVersionInfo.GetVersionInfo(path);
            return new ExternalModuleInfo(path,
                string.IsNullOrWhiteSpace(info.CompanyName) ? null : info.CompanyName,
                string.IsNullOrWhiteSpace(info.ProductName) ? null : info.ProductName);
        }
        catch { return null; }
    }

    private static string SpecificOriginator(ExternalModuleInfo? info, string moduleName, string modulePath)
    {
        var combined = $"{info?.Company} {info?.Product} {info?.Path} {moduleName} {modulePath}";
        var known = KnownProduct(combined);
        if (known is not null) return known.Value.Display;
        if (!string.IsNullOrWhiteSpace(info?.Product)) return $"{info.Product} / {Path.GetFileName(info.Path)}";
        if (!string.IsNullOrWhiteSpace(info?.Company)) return $"{info.Company} / {Path.GetFileName(info.Path)}";
        var file = Path.GetFileName(string.IsNullOrWhiteSpace(modulePath) ? moduleName : modulePath);
        return string.IsNullOrWhiteSpace(file) ? "Módulo externo no identificado" : $"Módulo externo: {file}";
    }

    private static bool TouchesTsplus(string? nameOrText, string? path, SystemSnapshot system)
    {
        var text = $"{nameOrText} {path}";
        if (!string.IsNullOrWhiteSpace(system.TsplusRuta) && text.Contains(system.TsplusRuta, StringComparison.OrdinalIgnoreCase)) return true;
        string[] markers = ["tsplus", "servermonitoring", "remote support", "remotesupport", "\\wsession", "logonsession.exe", "alternateshell.exe"];
        return markers.Any(m => text.Contains(m, StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsWindowsModule(string? name, string? path)
    {
        if (!string.IsNullOrWhiteSpace(path))
        {
            var win = Environment.GetFolderPath(Environment.SpecialFolder.Windows).TrimEnd('\\') + "\\";
            try { if (Path.GetFullPath(path).StartsWith(win, StringComparison.OrdinalIgnoreCase)) return true; } catch { }
        }
        string[] common = ["kernelbase.dll", "kernel32.dll", "ntdll.dll", "ucrtbase.dll", "msvcrt.dll", "clr.dll", "coreclr.dll"];
        return !string.IsNullOrWhiteSpace(name) && common.Contains(Path.GetFileName(name), StringComparer.OrdinalIgnoreCase);
    }

    private static bool IsTsplusModule(string? name, string? path, SystemSnapshot system)
    {
        var text = $"{name} {path}";
        if (!string.IsNullOrWhiteSpace(system.TsplusRuta) && text.Contains(system.TsplusRuta, StringComparison.OrdinalIgnoreCase)) return true;
        return text.Contains("TSplus", StringComparison.OrdinalIgnoreCase) ||
               text.Contains("ServerMonitoring", StringComparison.OrdinalIgnoreCase) ||
               text.Contains("RemoteSupport", StringComparison.OrdinalIgnoreCase);
    }

    private static bool LooksLikeExternalModuleName(string? module)
    {
        if (string.IsNullOrWhiteSpace(module) || module.Equals("unknown", StringComparison.OrdinalIgnoreCase)) return false;
        var file = Path.GetFileName(module);
        return file.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) || file.EndsWith(".sys", StringComparison.OrdinalIgnoreCase);
    }

    private static TsplusProduct ClassifyTsplusProduct(string appName, string appPath)
    {
        var text = $"{appName} {appPath}";
        if (text.Contains("ServerMonitoring", StringComparison.OrdinalIgnoreCase)) return TsplusProduct.ServerMonitoring;
        if (text.Contains("TSplus-Security", StringComparison.OrdinalIgnoreCase) || text.Contains("Advanced Security", StringComparison.OrdinalIgnoreCase)) return TsplusProduct.AdvancedSecurity;
        if (text.Contains("RemoteSupport", StringComparison.OrdinalIgnoreCase)) return TsplusProduct.RemoteSupport;
        if (text.Contains("TwoFactor", StringComparison.OrdinalIgnoreCase) || text.Contains("2FA", StringComparison.OrdinalIgnoreCase)) return TsplusProduct.TwoFactorAuthentication;
        return TsplusProduct.RemoteAccess;
    }

    private static Dictionary<string, string> ParseEventData(EventRecord record)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            var doc = XDocument.Parse(record.ToXml());
            XNamespace ns = "http://schemas.microsoft.com/win/2004/08/events/event";
            var data = doc.Descendants(ns + "EventData").Elements(ns + "Data").ToList();
            for (var i = 0; i < data.Count; i++)
            {
                var name = data[i].Attribute("Name")?.Value;
                if (!string.IsNullOrWhiteSpace(name)) result[name] = data[i].Value;
                result[$"param{i + 1}"] = data[i].Value;
            }
        }
        catch { }
        return result;
    }

    private static string SafeDescription(EventRecord record)
    {
        try { return record.FormatDescription() ?? "Descripción no disponible."; }
        catch { return "Descripción no disponible."; }
    }

    private sealed record ThirdPartyRuntimeInfo(string Display, string? Path, string[] Tokens);
    private sealed record ExternalModuleInfo(string Path, string? Company, string? Product);
}
