using System.ServiceProcess;
using TDM.Core;
using TDM.Models;

namespace TDM.Collectors.TSplus;

/// <summary>
/// Captura el estado de dependencias críticas TSplus/Windows sin modificar servicios.
/// No interpreta una dependencia caída como licencia inválida: sólo informa disponibilidad operativa.
/// </summary>
public sealed class TsplusDependencyHealthCollector : IReadOnlyCollector
{
    public string Nombre => "Salud de dependencias TSplus";

    public Task<CollectorResult> CollectAsync(DiagnosticContext context, CancellationToken cancellationToken = default)
    {
        var findings = new List<DiagnosticFinding>();
        var events = new List<DiagnosticEvent>();
        var evidence = new List<EvidenceItem>();

        var servicesProbe = SnapshotServices();
        var services = servicesProbe.IsAvailable
            ? servicesProbe.Value ?? new Dictionary<string, (string display, ServiceControllerStatus status)>(StringComparer.OrdinalIgnoreCase)
            : new Dictionary<string, (string display, ServiceControllerStatus status)>(StringComparer.OrdinalIgnoreCase);
        var scmCoveragePartial = servicesProbe.IsUnavailable;

        if (scmCoveragePartial)
        {
            evidence.Add(new("Cobertura Service Control Manager", $"No evaluada: {servicesProbe.StatusText}"));
            findings.Add(new DiagnosticFinding(
                "TSPLUS-DEPENDENCY-SCM-COVERAGE", "Dependencias TSplus / Windows", DiagnosticSeverity.Advertencia,
                "No fue posible evaluar los servicios de dependencia mediante Service Control Manager.",
                "TDM conserva la cobertura como parcial y no interpreta servicios no leídos como detenidos ni saludables.",
                [new("Estado de lectura", servicesProbe.StatusText), new("Detalle", servicesProbe.Detail ?? "Sin detalle adicional")],
                ConfidenceLevel.Confirmada, Capa: DiagnosticLayer.Windows));
        }
        else
        {
            AddServiceState(evidence, services, "TermService", "Remote Desktop Services", requiredForRemoteAccess: context.Sistema.TsplusDetectado, findings, DiagnosticLayer.Rdp);
            AddServiceState(evidence, services, "RpcSs", "Remote Procedure Call (RPC)", requiredForRemoteAccess: context.Sistema.TsplusDetectado, findings, DiagnosticLayer.Windows);
            AddServiceState(evidence, services, "Spooler", "Print Spooler", requiredForRemoteAccess: false, findings, DiagnosticLayer.Windows);
            AddServiceState(evidence, services, "DcomLaunch", "DCOM Server Process Launcher", requiredForRemoteAccess: false, findings, DiagnosticLayer.Windows);
            AddServiceState(evidence, services, "EventLog", "Windows Event Log", requiredForRemoteAccess: false, findings, DiagnosticLayer.Windows);
            AddServiceState(evidence, services, "Winmgmt", "Windows Management Instrumentation", requiredForRemoteAccess: false, findings, DiagnosticLayer.Windows);
            AddServiceState(evidence, services, "UmRdpService", "Remote Desktop Services UserMode Port Redirector", requiredForRemoteAccess: false, findings, DiagnosticLayer.Rdp);
            AddServiceState(evidence, services, "BFE", "Base Filtering Engine (BFE)", requiredForRemoteAccess: false, findings, DiagnosticLayer.Windows);
            AddServiceState(evidence, services, "MpsSvc", "Windows Defender Firewall (MpsSvc)", requiredForRemoteAccess: false, findings, DiagnosticLayer.Windows);
            AddServiceState(evidence, services, "Nsi", "Network Store Interface (NSI)", requiredForRemoteAccess: false, findings, DiagnosticLayer.Red);

            // FIX64: dependencias Windows adicionales con impacto frecuente en RDP/TSplus.
            // Se agregan sólo si existen en el servidor para evitar falsos faltantes en roles no instalados.
            AddOptionalServiceState(evidence, services, "SessionEnv", "Remote Desktop Configuration");
            AddOptionalServiceState(evidence, services, "RpcEptMapper", "RPC Endpoint Mapper");
            AddOptionalServiceState(evidence, services, "Dnscache", "DNS Client");
            AddOptionalServiceState(evidence, services, "NlaSvc", "Network Location Awareness");
            AddOptionalServiceState(evidence, services, "Dhcp", "DHCP Client");
            AddOptionalServiceState(evidence, services, "Netman", "Network Connections");
            AddOptionalServiceState(evidence, services, "iphlpsvc", "IP Helper");
            AddOptionalServiceState(evidence, services, "WinHttpAutoProxySvc", "WinHTTP Web Proxy Auto-Discovery");
            AddOptionalServiceState(evidence, services, "LanmanWorkstation", "Workstation");
            AddOptionalServiceState(evidence, services, "LanmanServer", "Server");
            AddOptionalServiceState(evidence, services, "ProfSvc", "User Profile Service");
            AddOptionalServiceState(evidence, services, "UserManager", "User Manager");
            AddOptionalServiceState(evidence, services, "gpsvc", "Group Policy Client");
            AddOptionalServiceState(evidence, services, "SamSs", "Security Accounts Manager");
            AddOptionalServiceState(evidence, services, "CryptSvc", "Cryptographic Services");
            AddOptionalServiceState(evidence, services, "KeyIso", "CNG Key Isolation");
            AddOptionalServiceState(evidence, services, "W32Time", "Windows Time");
            AddOptionalServiceState(evidence, services, "Netlogon", "Netlogon");
            AddOptionalServiceState(evidence, services, "Schedule", "Task Scheduler");
            AddOptionalServiceState(evidence, services, "SENS", "System Event Notification Service");
            AddOptionalServiceState(evidence, services, "TermServLicensing", "Remote Desktop Licensing");
            AddOptionalServiceState(evidence, services, "Tssdis", "Remote Desktop Connection Broker");
            AddOptionalServiceState(evidence, services, "RDMS", "Remote Desktop Management");
            AddOptionalServiceState(evidence, services, "TSGateway", "Remote Desktop Gateway");
        }

        var aps = scmCoveragePartial ? null : FindFirst(services,
            "Application Publishing Service",
            "TSplus Application Publishing",
            "ApplicationPublishing",
            "Application Publishing");
        if (aps is null)
        {
            evidence.Add(new("Application Publishing Service (APS)", scmCoveragePartial ? "No evaluado" : context.Sistema.TsplusDetectado ? "No identificado por nombre conocido" : "No aplica"));
        }
        else
        {
            evidence.Add(new("Application Publishing Service (APS)", $"{aps.Value.display} [{aps.Value.name}] = {aps.Value.status}"));
            if (context.Sistema.TsplusDetectado && aps.Value.status != ServiceControllerStatus.Running)
            {
                findings.Add(new DiagnosticFinding(
                    "TSPLUS-APS-NOT-RUNNING", "Application Publishing Service", DiagnosticSeverity.Critico,
                    "El servicio Application Publishing Service de TSplus no está operativo.",
                    "APS/APSC es una dependencia funcional de Remote Access. Su indisponibilidad puede impedir publicación o control de sesiones. TDM investiga esta dependencia antes de atribuir la falla a capas superiores.",
                    [new("Servicio", aps.Value.name), new("Nombre", aps.Value.display), new("Estado", aps.Value.status.ToString())],
                    ConfidenceLevel.Alta, Capa: DiagnosticLayer.Tsplus));
            }
        }

        if (!scmCoveragePartial)
        {
            AddProductServiceSummary(evidence, services, TsplusProduct.ServerMonitoring, ["TSplus-ServerMonitoring", "ServerMonitoring"]);
            AddProductServiceSummary(evidence, services, TsplusProduct.AdvancedSecurity, ["TSplus-Security", "Advanced Security"]);
            AddProductServiceSummary(evidence, services, TsplusProduct.RemoteSupport, ["RemoteSupport", "Remote Support"]);
            AddProductServiceSummary(evidence, services, TsplusProduct.TwoFactorAuthentication, ["TwoFactor", "Two-Factor", "2FA", "TSplus-TwoFactor"]);
        }

        if (context.Sistema.TsplusDetectado && !string.IsNullOrWhiteSpace(context.Sistema.TsplusRuta))
        {
            var files = Path.Combine(context.Sistema.TsplusRuta!, "UserDesktop", "files");
            evidence.Add(new("AdminTool.exe", ProbeFile(Path.Combine(files, "AdminTool.exe"))));
            evidence.Add(new("TwoFactor.Admin.exe", ProbeFile(Path.Combine(files, "TwoFactor.Admin.exe"))));
            evidence.Add(new("C:\\wsession", FileSystemProbe.Display(FileSystemProbe.Directory(@"C:\wsession"))));
        }

        events.Add(new DiagnosticEvent(DateTimeOffset.Now, "TDM", "Mapa de dependencias TSplus", DiagnosticLayer.Tsplus,
            scmCoveragePartial ? DiagnosticSeverity.Advertencia : DiagnosticSeverity.Informativo, "TSPLUS_DEPENDENCY_HEALTH",
            "Snapshot de dependencias críticas TSplus/Windows capturado en modo de solo lectura.",
            Evidencia: evidence, Producto: TsplusProduct.RemoteAccess));

        return Task.FromResult(new CollectorResult(findings, events));
    }

    private static ProbeResult<IReadOnlyDictionary<string, (string display, ServiceControllerStatus status)>> SnapshotServices()
        => TsplusServiceSnapshotReader.Read();

    private static void AddServiceState(List<EvidenceItem> evidence,
        IReadOnlyDictionary<string, (string display, ServiceControllerStatus status)> services,
        string serviceName, string label, bool requiredForRemoteAccess,
        List<DiagnosticFinding> findings, DiagnosticLayer layer)
    {
        if (!services.TryGetValue(serviceName, out var state))
        {
            evidence.Add(new(label, "No identificado"));
            return;
        }
        evidence.Add(new(label, $"{state.status} [{serviceName}]"));
        if (requiredForRemoteAccess && state.status != ServiceControllerStatus.Running)
        {
            findings.Add(new DiagnosticFinding($"DEPENDENCY-{serviceName}-DOWN", label, DiagnosticSeverity.Critico,
                $"La dependencia {label} no está en ejecución.",
                "TDM detectó el estado mediante Service Control Manager en modo de solo lectura. Debe investigarse la causa antes de modificar TSplus.",
                [new("Servicio", serviceName), new("Estado", state.status.ToString())], ConfidenceLevel.Alta, Capa: layer));
        }
    }

    private static void AddOptionalServiceState(
        List<EvidenceItem> evidence,
        IReadOnlyDictionary<string, (string display, ServiceControllerStatus status)> services,
        string serviceName,
        string label)
    {
        if (!services.TryGetValue(serviceName, out var state)) return;
        evidence.Add(new(label, $"{state.status} [{serviceName}]"));
    }

    private static (string name, string display, ServiceControllerStatus status)? FindFirst(
        IReadOnlyDictionary<string, (string display, ServiceControllerStatus status)> services, params string[] tokens)
    {
        foreach (var entry in services)
        {
            if (tokens.Any(t => entry.Key.Contains(t, StringComparison.OrdinalIgnoreCase) || entry.Value.display.Contains(t, StringComparison.OrdinalIgnoreCase)))
                return (entry.Key, entry.Value.display, entry.Value.status);
        }
        return null;
    }

    private static void AddProductServiceSummary(List<EvidenceItem> evidence,
        IReadOnlyDictionary<string, (string display, ServiceControllerStatus status)> services,
        TsplusProduct product, string[] tokens)
    {
        var matches = services
            .Where(s => tokens.Any(t => s.Key.Contains(t, StringComparison.OrdinalIgnoreCase) || s.Value.display.Contains(t, StringComparison.OrdinalIgnoreCase)))
            .Take(10)
            .Select(s => $"{s.Value.display} [{s.Key}]={s.Value.status}")
            .ToList();
        evidence.Add(new($"Servicios {ProductName(product)}", matches.Count == 0 ? "Ninguno identificado" : string.Join(" | ", matches)));
    }

    private static string ProbeFile(string path) => FileSystemProbe.Display(FileSystemProbe.File(path), $"Presente ({path})", $"No presente ({path})");
    private static string ProductName(TsplusProduct p) => p switch
    {
        TsplusProduct.ServerMonitoring => "Server Monitoring",
        TsplusProduct.AdvancedSecurity => "Advanced Security",
        TsplusProduct.RemoteSupport => "Remote Support",
        _ => "TSplus"
    };
}
