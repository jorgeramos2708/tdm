using Microsoft.Win32;
using System.ServiceProcess;
using TDM.Core;
using TDM.Models;

namespace TDM.Collectors.TSplus;

/// <summary>
/// Inventaría productos del ecosistema TSplus y observa su disponibilidad operativa.
/// No inspecciona, interpreta ni modifica licencias. Todo el collector es de solo lectura.
/// </summary>
public sealed class TsplusProductStateCollector : IReadOnlyCollector
{
    public string Nombre => "Productos TSplus / estado operativo";

    public Task<CollectorResult> CollectAsync(DiagnosticContext context, CancellationToken cancellationToken = default)
    {
        var events = new List<DiagnosticEvent>();
        var findings = new List<DiagnosticFinding>();
        var servicesProbe = TsplusServiceSnapshotReader.Read(cancellationToken);
        var services = servicesProbe.IsAvailable
            ? servicesProbe.Value ?? new Dictionary<string, (string DisplayName, ServiceControllerStatus Status)>(StringComparer.OrdinalIgnoreCase)
            : new Dictionary<string, (string DisplayName, ServiceControllerStatus Status)>(StringComparer.OrdinalIgnoreCase);

        if (servicesProbe.IsUnavailable)
        {
            findings.Add(new DiagnosticFinding(
                "TSPLUS-PRODUCT-SERVICE-COVERAGE", "Productos TSplus / servicios", DiagnosticSeverity.Advertencia,
                "No fue posible evaluar de forma confiable los servicios asociados a los productos TSplus.",
                "TDM mantiene esta fuente como no evaluada; una lista vacía de servicios no se interpreta como ausencia de producto ni como falla confirmada.",
                [new EvidenceItem("Estado de lectura", servicesProbe.StatusText), new EvidenceItem("Detalle", servicesProbe.Detail ?? "Sin detalle adicional")],
                ConfidenceLevel.Confirmada, Capa: DiagnosticLayer.Windows));
        }

        foreach (var item in Discover(context.Sistema, services))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var operational = EvaluateOperation(item, services, context.Sistema, servicesProbe.IsAvailable);
            var evidence = new List<EvidenceItem>
            {
                new("Producto", ProductName(item.Product)),
                new("Instalación", item.Installed ? "Instalado" : "No instalado"),
                new("Rutas detectadas", item.Roots.Count == 0 ? "Ninguna" : string.Join(" | ", item.Roots)),
                new("Servicios relacionados", servicesProbe.IsAvailable ? RelatedServices(item.Product, services) : "No evaluado"),
                new("Cobertura de servicios", servicesProbe.IsAvailable ? "Disponible" : $"Parcial: {servicesProbe.StatusText}"),
                new("Artefactos principales", MainArtifacts(item.Product, item.Roots, context.Sistema)),
                new("Operación observada", operational.State),
                new("Salud", operational.Health),
                new("Relación con Remote Access", Relationship(item.Product)),
                new("Licenciamiento", "Fuera del alcance de TDM; sólo se conserva como contexto si un log lo menciona explícitamente")
            };

            events.Add(new DiagnosticEvent(
                DateTimeOffset.Now,
                "TDM",
                ProductName(item.Product),
                DiagnosticLayer.Tsplus,
                operational.Severity,
                "TSPLUS_PRODUCT_STATE",
                $"{ProductName(item.Product)}: {(item.Installed ? "instalado" : "no instalado")}; estado observado: {operational.State}.",
                Evidencia: evidence,
                Producto: item.Product));

            if (item.Installed && operational.IsFailure)
            {
                findings.Add(new DiagnosticFinding(
                    $"PRODUCT-HEALTH-{item.Product}",
                    ProductName(item.Product),
                    DiagnosticSeverity.Advertencia,
                    $"{ProductName(item.Product)} presenta una anomalía operativa observable.",
                    operational.Detail,
                    evidence,
                    ConfidenceLevel.Media,
                    Capa: DiagnosticLayer.Tsplus));
            }
        }

        return Task.FromResult(new CollectorResult(findings, events));
    }

    private static IReadOnlyList<ProductDiscovery> Discover(SystemSnapshot system,
        IReadOnlyDictionary<string, (string DisplayName, ServiceControllerStatus Status)> services)
    {
        var pf86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        var pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var list = new List<ProductDiscovery>
        {
            new(TsplusProduct.RemoteAccess, system.TsplusDetectado,
                system.TsplusDetectado && !string.IsNullOrWhiteSpace(system.TsplusRuta) ? [system.TsplusRuta!] : [])
        };

        list.Add(DiscoverProduct(TsplusProduct.AdvancedSecurity, pf86, pf,
            ["TSplus-Security", "TSplus Advanced Security", "TSplus AdvancedSecurity"],
            ["TSplus-Security.exe"], ["AdvancedSecurity", "TSplus-Security"], services));

        list.Add(DiscoverProduct(TsplusProduct.ServerMonitoring, pf86, pf,
            ["TSplus-ServerMonitoring", "TSplus Server Monitoring"],
            ["ServerMonitoring.exe", "ServerMonitoring.Service.exe"], ["ServerMonitoring", "TSplus-ServerMonitoring"], services));

        list.Add(DiscoverProduct(TsplusProduct.RemoteSupport, pf86, pf,
            ["TSplus-RemoteSupport", "TSplus Remote Support", "TSplus RemoteSupport", "RemoteSupport"],
            ["RemoteSupport.exe", "RemoteSupportUnattended.exe"], ["RemoteSupport", "Remote Support"], services));

        var twoFaRoots = new List<string>();
        if (system.TsplusDetectado && !string.IsNullOrWhiteSpace(system.TsplusRuta))
        {
            var binary = Path.Combine(system.TsplusRuta!, "UserDesktop", "files", "TwoFactor.Admin.exe");
            if (FileSystemProbe.File(binary).IsAvailable) twoFaRoots.Add(system.TsplusRuta!);
        }
        list.Add(new(TsplusProduct.TwoFactorAuthentication, twoFaRoots.Count > 0, twoFaRoots));
        return list;
    }

    private static ProductDiscovery DiscoverProduct(TsplusProduct product, string pf86, string pf,
        string[] folderNames, string[] expectedBinaries, string[] serviceTokens,
        IReadOnlyDictionary<string, (string DisplayName, ServiceControllerStatus Status)> services)
    {
        var roots = new List<string>();
        foreach (var baseDir in new[] { pf86, pf }.Where(x => !string.IsNullOrWhiteSpace(x)).Distinct(StringComparer.OrdinalIgnoreCase))
        foreach (var name in folderNames)
        {
            var path = Path.Combine(baseDir, name);
            if (FileSystemProbe.Directory(path).IsAvailable && !roots.Contains(path, StringComparer.OrdinalIgnoreCase)) roots.Add(path);
        }

        foreach (var location in FindUninstallLocations(folderNames.Concat(serviceTokens).ToArray()))
            if (FileSystemProbe.Directory(location).IsAvailable && !roots.Contains(location, StringComparer.OrdinalIgnoreCase)) roots.Add(location);

        var binaryEvidence = roots.Any(root => HasExpectedBinary(root, expectedBinaries));
        var serviceEvidence = services.Any(s => serviceTokens.Any(t =>
            s.Key.Contains(t, StringComparison.OrdinalIgnoreCase) || s.Value.DisplayName.Contains(t, StringComparison.OrdinalIgnoreCase)));
        var uninstallEvidence = HasUninstallEntry(folderNames.Concat(serviceTokens).ToArray());
        return new ProductDiscovery(product, binaryEvidence || serviceEvidence || uninstallEvidence, roots);
    }

    private static OperationalObservation EvaluateOperation(ProductDiscovery product,
        IReadOnlyDictionary<string, (string DisplayName, ServiceControllerStatus Status)> services,
        SystemSnapshot system,
        bool servicesAvailable)
    {
        if (!product.Installed) return new("No aplica", "No aplica", DiagnosticSeverity.Informativo, false, "Producto no instalado.");

        if (!servicesAvailable && product.Product != TsplusProduct.TwoFactorAuthentication)
            return new("No evaluado", "Cobertura parcial", DiagnosticSeverity.Advertencia, false,
                "Service Control Manager no estuvo disponible; TDM no infiere el estado operativo de los servicios asociados.");

        if (product.Product == TsplusProduct.RemoteAccess)
        {
            var term = ServiceStatus(services, "TermService");
            var aps = FindService(services, ["APSC", "Application Publishing Session Control", "Application Publishing"]);
            var listenerEvidence = term == ServiceControllerStatus.Running;
            if (term != ServiceControllerStatus.Running)
                return new("Degradado", "Falla", DiagnosticSeverity.Advertencia, true, "Remote Desktop Services no está Running.");
            if (aps is not null && aps.Value.Status != ServiceControllerStatus.Running)
                return new("Degradado", "Falla", DiagnosticSeverity.Advertencia, true, $"El servicio {aps.Value.DisplayName} no está Running.");
            return new(listenerEvidence ? "Operativo según dependencias básicas" : "Por comprobar", "Sin fallas básicas detectadas", DiagnosticSeverity.Informativo, false,
                "TermService y APS/APSC no presentan una falla básica observable.");
        }

        if (product.Product == TsplusProduct.TwoFactorAuthentication)
            return new("Instalado; operación se valida durante autenticación", "No evaluada", DiagnosticSeverity.Informativo, false,
                "2FA no expone un servicio independiente obligatorio en esta comprobación; se correlaciona con eventos de autenticación cuando existan.");

        var tokens = product.Product switch
        {
            TsplusProduct.ServerMonitoring => new[] { "ServerMonitoring", "TSplus-ServerMonitoring" },
            TsplusProduct.AdvancedSecurity => new[] { "AdvancedSecurity", "TSplus-Security" },
            TsplusProduct.RemoteSupport => new[] { "RemoteSupport", "Remote Support" },
            _ => Array.Empty<string>()
        };
        var matches = FindServices(services, tokens).ToList();
        if (matches.Count == 0)
            return new("Instalado; sin servicio identificable", "Por evaluar", DiagnosticSeverity.Informativo, false,
                "El producto está instalado por evidencia de archivos/Registro, pero TDM no identificó un servicio asociado.");
        if (matches.Any(x => x.Status == ServiceControllerStatus.Running))
            return new("Servicios principales en ejecución", "Estado actual disponible", DiagnosticSeverity.Informativo, false,
                "Al menos un servicio relacionado se encuentra Running. Esto no descarta errores históricos del producto.");
        return new("Servicios relacionados detenidos", "Advertencia", DiagnosticSeverity.Advertencia, true,
            "Se detectaron servicios relacionados, pero ninguno está Running.");
    }

    private static IEnumerable<(string Name, string DisplayName, ServiceControllerStatus Status)> FindServices(
        IReadOnlyDictionary<string, (string DisplayName, ServiceControllerStatus Status)> services, string[] tokens) =>
        services.Where(s => tokens.Any(t => s.Key.Contains(t, StringComparison.OrdinalIgnoreCase) || s.Value.DisplayName.Contains(t, StringComparison.OrdinalIgnoreCase)))
            .Select(s => (s.Key, s.Value.DisplayName, s.Value.Status));

    private static (string Name, string DisplayName, ServiceControllerStatus Status)? FindService(
        IReadOnlyDictionary<string, (string DisplayName, ServiceControllerStatus Status)> services, string[] tokens)
    {
        var matches = FindServices(services, tokens).ToList();
        return matches.Count == 0 ? null : matches[0];
    }

    private static ServiceControllerStatus? ServiceStatus(IReadOnlyDictionary<string, (string DisplayName, ServiceControllerStatus Status)> services, string name) =>
        services.TryGetValue(name, out var s) ? s.Status : null;

    private static string RelatedServices(TsplusProduct product,
        IReadOnlyDictionary<string, (string DisplayName, ServiceControllerStatus Status)> services)
    {
        var tokens = product switch
        {
            TsplusProduct.RemoteAccess => new[] { "APSC", "Application Publishing", "TermService" },
            TsplusProduct.ServerMonitoring => new[] { "ServerMonitoring", "TSplus-ServerMonitoring" },
            TsplusProduct.AdvancedSecurity => new[] { "AdvancedSecurity", "TSplus-Security" },
            TsplusProduct.RemoteSupport => new[] { "RemoteSupport", "Remote Support" },
            _ => Array.Empty<string>()
        };
        var matches = FindServices(services, tokens).Take(12).Select(x => $"{x.DisplayName} [{x.Name}]={x.Status}").ToList();
        return matches.Count == 0 ? "Ninguno identificado" : string.Join(" | ", matches);
    }

    private static string MainArtifacts(TsplusProduct product, IReadOnlyList<string> roots, SystemSnapshot system)
    {
        if (!product.Equals(TsplusProduct.RemoteAccess) && roots.Count == 0) return "No determinados";
        var candidates = product switch
        {
            TsplusProduct.RemoteAccess when !string.IsNullOrWhiteSpace(system.TsplusRuta) =>
                new[] { Path.Combine(system.TsplusRuta!, "UserDesktop", "files", "AdminTool.exe"), @"C:\wsession" },
            TsplusProduct.TwoFactorAuthentication when roots.Count > 0 =>
                new[] { Path.Combine(roots[0], "UserDesktop", "files", "TwoFactor.Admin.exe") },
            TsplusProduct.AdvancedSecurity => roots.Select(r => Path.Combine(r, "TSplus-Security.exe")).ToArray(),
            TsplusProduct.ServerMonitoring => roots.SelectMany(r => new[] { Path.Combine(r, "ServerMonitoring.exe"), Path.Combine(r, "ServerMonitoring.Service.exe") }).ToArray(),
            TsplusProduct.RemoteSupport => roots.SelectMany(r => new[] { Path.Combine(r, "RemoteSupport.exe"), Path.Combine(r, "RemoteSupportUnattended.exe") }).ToArray(),
            _ => Array.Empty<string>()
        };
        var statuses = candidates.Select(p => $"{p}={((FileSystemProbe.File(p).IsAvailable || FileSystemProbe.Directory(p).IsAvailable) ? "Presente" : "No presente / no evaluado si hubo error de acceso")}").ToList();
        return statuses.Count == 0 ? "No determinados" : string.Join(" | ", statuses);
    }

    private static string Relationship(TsplusProduct product) => product switch
    {
        TsplusProduct.RemoteAccess => "Producto principal del diagnóstico",
        TsplusProduct.TwoFactorAuthentication => "Complemento nativo de Remote Access; puede afectar autenticación cuando interviene",
        TsplusProduct.AdvancedSecurity => "Producto complementario independiente; no se asume causa de Remote Access sin correlación",
        TsplusProduct.ServerMonitoring => "Producto complementario independiente; no se asume causa de Remote Access sin correlación",
        TsplusProduct.RemoteSupport => "Producto complementario independiente; no se asume causa de Remote Access sin correlación",
        _ => "No determinada"
    };

    private static bool HasUninstallEntry(string[] tokens) => FindUninstallLocations(tokens, includeEmpty: true).Any();

    private static IEnumerable<string> FindUninstallLocations(string[] tokens, bool includeEmpty = false)
    {
        var uninstallRoots = new[] { @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" };
        foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
            foreach (var path in uninstallRoots)
            {
                using var root = baseKey.OpenSubKey(path, writable: false);
                if (root is null) continue;
                foreach (var subName in root.GetSubKeyNames())
                {
                    using var sub = root.OpenSubKey(subName, writable: false);
                    if (sub is null) continue;
                    var display = sub.GetValue("DisplayName")?.ToString() ?? string.Empty;
                    if (!tokens.Any(t => display.Contains(t, StringComparison.OrdinalIgnoreCase))) continue;
                    var loc = sub.GetValue("InstallLocation")?.ToString();
                    if (!string.IsNullOrWhiteSpace(loc)) yield return loc;
                    else if (includeEmpty) yield return $"registry:{display}";
                }
            }
        }
    }

    private static bool HasExpectedBinary(string root, IReadOnlyList<string> binaries)
    {
        // Las raíces de productos complementarios se resuelven por ruta conocida/Registro/servicio.
        // No se hace búsqueda recursiva durante el diagnóstico normal.
        foreach (var binary in binaries)
        {
            try { if (FileSystemProbe.File(Path.Combine(root, binary)).IsAvailable) return true; }
            catch { }
        }
        return false;
    }

    private static string ProductName(TsplusProduct p) => p switch
    {
        TsplusProduct.RemoteAccess => "Remote Access",
        TsplusProduct.TwoFactorAuthentication => "2FA",
        TsplusProduct.AdvancedSecurity => "Advanced Security",
        TsplusProduct.ServerMonitoring => "Server Monitoring",
        TsplusProduct.RemoteSupport => "Remote Support",
        _ => "TSplus"
    };

    private sealed record ProductDiscovery(TsplusProduct Product, bool Installed, IReadOnlyList<string> Roots);
    private sealed record OperationalObservation(string State, string Health, DiagnosticSeverity Severity, bool IsFailure, string Detail);
}
