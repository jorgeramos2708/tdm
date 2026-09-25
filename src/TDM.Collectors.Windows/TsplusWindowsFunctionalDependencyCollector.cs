using System.ServiceProcess;
using TDM.Core;
using TDM.Models;

namespace TDM.Collectors.Windows;

/// <summary>
/// Expone relaciones funcionales TSplus -> Windows que no necesariamente aparecen como
/// ServicesDependedOn en el SCM. El objetivo es explicar cuándo una función TSplus puede
/// fallar porque una dependencia Windows situada debajo de ella no está disponible.
///
/// Importante: una relación funcional no convierte automáticamente un servicio detenido
/// en causa raíz. Servicios Manual/Trigger y dependencias condicionales se muestran como
/// contexto y requieren evidencia funcional/temporal adicional para elevar causalidad.
/// </summary>
public sealed class TsplusWindowsFunctionalDependencyCollector : IReadOnlyCollector
{
    public string Nombre => "Dependencias funcionales TSplus / Windows";

    public Task<CollectorResult> CollectAsync(DiagnosticContext context, CancellationToken cancellationToken = default)
    {
        var events = new List<DiagnosticEvent>();
        var findings = new List<DiagnosticFinding>();

        if (!context.Sistema.TsplusDetectado)
            return Task.FromResult(new CollectorResult(findings, events));

        cancellationToken.ThrowIfCancellationRequested();

        // Núcleo de sesión remota. TermService y ProfSvc son prerrequisitos funcionales
        // del acceso/sesión; SessionEnv y UmRdpService son componentes bajo demanda y no
        // deben marcarse como fallo sólo porque estén Stopped/Manual.
        AddRelation(events, "Remote Access / RDP", "TermService", "Directa funcional",
            "La sesión TSplus se apoya en la pila RDP de Windows. Si TermService no está operativo, el listener/sesión remota puede fallar antes de TSplus.",
            requiredRunning: true, TsplusProduct.RemoteAccess, DiagnosticLayer.Rdp);

        AddRelation(events, "Remote Access / perfiles", "ProfSvc", "Directa funcional",
            "Windows User Profile Service participa en la carga del perfil del usuario. Una falla de perfil puede impedir o degradar la sesión aunque TSplus esté sano.",
            requiredRunning: true, TsplusProduct.RemoteAccess, DiagnosticLayer.Windows);

        AddRelation(events, "Remote Access / RPC", "RpcSs", "Base Windows",
            "RPC es una dependencia base de múltiples componentes Windows consumidos por Remote Access. Si RPC falla, TDM debe situar el origen en Windows antes de TSplus.",
            requiredRunning: true, TsplusProduct.RemoteAccess, DiagnosticLayer.Windows);

        AddRelation(events, "Remote Access / configuración RDP", "SessionEnv", "Bajo demanda",
            "Remote Desktop Configuration forma parte de la configuración de sesiones RDP. En versiones modernas de Windows puede permanecer Manual/Stopped sin indicar una falla por sí sola.",
            requiredRunning: false, TsplusProduct.RemoteAccess, DiagnosticLayer.Rdp);

        AddRelation(events, "Remote Access / redirección de dispositivos", "UmRdpService", "Bajo demanda",
            "Remote Desktop Services UserMode Port Redirector participa en redirecciones de dispositivos. Puede ser Trigger/Manual; su estado se interpreta junto con el síntoma de redirección.",
            requiredRunning: false, TsplusProduct.RemoteAccess, DiagnosticLayer.Rdp);

        var root = context.Sistema.TsplusRuta;
        if (!string.IsNullOrWhiteSpace(root))
        {
            if (UniversalPrinterDetected(root!))
            {
                AddRelation(events, "Universal Printer", "Spooler", "Directa funcional",
                    "Universal Printer utiliza la pila de impresión de Windows. Si Print Spooler falla, TDM debe investigar Windows/PrintService antes de atribuir la falla a TSplus.",
                    requiredRunning: true, TsplusProduct.RemoteAccess, DiagnosticLayer.Windows);
            }

            if (VirtualPrinterDetected(root!))
            {
                AddRelation(events, "Virtual Printer", "Spooler", "Directa funcional",
                    "Virtual Printer requiere la pila de impresión de Windows para crear/procesar trabajos. Spooler caído puede ser el origen Windows del síntoma TSplus.",
                    requiredRunning: true, TsplusProduct.RemoteAccess, DiagnosticLayer.Windows);
            }

            if (TwoFactorDetected(root!))
            {
                AddRelation(events, "Two-Factor Authentication (2FA)", "W32Time", "Temporal / condicional",
                    "TSplus 2FA requiere reloj sincronizado. W32Time detenido no demuestra por sí solo desfase, pero obliga a validar sincronización antes de culpar al módulo 2FA.",
                    requiredRunning: false, TsplusProduct.TwoFactorAuthentication, DiagnosticLayer.Windows);
            }

            if (FarmDetected(root!))
            {
                AddRelation(events, "Farm/Gateway", "W32Time", "Temporal / condicional",
                    "Los nodos de una granja TSplus deben mantener fecha/hora coherente. El servicio se usa como señal de soporte; la causa requiere confirmar desfase real.",
                    requiredRunning: false, TsplusProduct.RemoteAccess, DiagnosticLayer.Windows);
                AddRelation(events, "Farm/Gateway", "Dnscache", "Red / condicional",
                    "Farm/Gateway puede depender de resolución DNS cuando los Application Servers se configuran por hostname. Un fallo DNS puede aparentar caída de nodo o gateway.",
                    requiredRunning: false, TsplusProduct.RemoteAccess, DiagnosticLayer.Red);
            }
        }

        var domain = ReadDomainJoinState();
        if (domain.Joined == true)
        {
            AddRelation(events, "Remote Access / autenticación de dominio", "Netlogon", "Dominio / condicional",
                "En un servidor unido a dominio, Netlogon y la comunicación con controladores de dominio pueden ser el origen Windows de fallos de autenticación que se manifiestan en TSplus.",
                requiredRunning: false, TsplusProduct.RemoteAccess, DiagnosticLayer.Windows,
                extraEvidence: [new EvidenceItem("Dominio detectado", domain.Domain ?? "Sí")]);
            AddRelation(events, "Remote Access / autenticación de dominio", "Dnscache", "DNS / condicional",
                "Active Directory depende de resolución DNS para localizar controladores de dominio. Un problema DNS puede producir logons fallidos aunque TSplus esté operativo.",
                requiredRunning: false, TsplusProduct.RemoteAccess, DiagnosticLayer.Red,
                extraEvidence: [new EvidenceItem("Dominio detectado", domain.Domain ?? "Sí")]);
            AddRelation(events, "Remote Access / Kerberos", "W32Time", "Tiempo / condicional",
                "Kerberos es sensible al desfase de reloj. El estado de W32Time es contexto; TDM requiere además eventos de autenticación/tiempo para elevarlo a causa.",
                requiredRunning: false, TsplusProduct.RemoteAccess, DiagnosticLayer.Windows,
                extraEvidence: [new EvidenceItem("Dominio detectado", domain.Domain ?? "Sí")]);
        }

        events.Add(new DiagnosticEvent(
            DateTimeOffset.Now,
            "TDM",
            "Mapa funcional TSplus / Windows",
            DiagnosticLayer.Windows,
            DiagnosticSeverity.Informativo,
            "TSPLUS_WINDOWS_FUNCTIONAL_DEPENDENCY_COVERAGE",
            "TDM añadió dependencias funcionales Windows que pueden explicar síntomas TSplus aunque no exista una relación ServicesDependedOn directa en el SCM.",
            Evidencia:
            [
                new EvidenceItem("Regla", "SCM real + dependencias funcionales tipadas"),
                new EvidenceItem("Relaciones emitidas", events.Count(e => e.Tipo == "TSPLUS_WINDOWS_FUNCTIONAL_DEPENDENCY_STATE").ToString()),
                new EvidenceItem("Dominio", domain.Joined.HasValue ? domain.Joined.Value ? $"Unido: {domain.Domain ?? "N/D"}" : "No unido" : "No evaluado"),
                new EvidenceItem("Principio", "Stopped no equivale a causa; Manual/Trigger y relaciones condicionales requieren evidencia adicional")
            ],
            Producto: TsplusProduct.RemoteAccess));

        return Task.FromResult(new CollectorResult(findings, events));
    }

    private static void AddRelation(
        List<DiagnosticEvent> events,
        string component,
        string serviceName,
        string relationType,
        string reason,
        bool requiredRunning,
        TsplusProduct product,
        DiagnosticLayer layer,
        IReadOnlyList<EvidenceItem>? extraEvidence = null)
    {
        var state = ReadService(serviceName);
        var startMode = WindowsServiceCatalog.ReadStartMode(serviceName);
        var presentation = Presentation(state.Status, state.Available, startMode, requiredRunning);
        var severity = !state.Available
            ? DiagnosticSeverity.Advertencia
            : requiredRunning && state.Status != ServiceControllerStatus.Running
                ? DiagnosticSeverity.Error
                : DiagnosticSeverity.Informativo;

        var evidence = new List<EvidenceItem>
        {
            new("Componente TSplus", component),
            new("Dependencia", serviceName),
            new("Estado dependencia", state.Available ? state.Status!.Value.ToString() : "No evaluado"),
            new("Estado presentación", presentation),
            new("Inicio", startMode),
            new("Tipo relación", relationType),
            new("Requerida ahora", requiredRunning ? "Sí" : "Condicional / bajo demanda"),
            new("Motivo", reason),
            new("Fuente", "Relación funcional tipada; estado leído desde Service Control Manager")
        };
        if (extraEvidence is not null) evidence.AddRange(extraEvidence);
        if (!string.IsNullOrWhiteSpace(state.Error)) evidence.Add(new EvidenceItem("Cobertura", state.Error!));

        events.Add(new DiagnosticEvent(
            DateTimeOffset.Now,
            "TDM / Service Control Manager",
            $"{component} → {serviceName}",
            layer,
            severity,
            "TSPLUS_WINDOWS_FUNCTIONAL_DEPENDENCY_STATE",
            state.Available
                ? $"{component} depende funcionalmente de {serviceName}; estado observado: {state.Status}."
                : $"{component} depende funcionalmente de {serviceName}; el estado del servicio quedó NO EVALUADO.",
            Evidencia: evidence,
            Producto: product));
    }

    private static string Presentation(ServiceControllerStatus? status, bool available, string startMode, bool requiredRunning)
    {
        if (!available || !status.HasValue) return "No evaluado";
        if (status == ServiceControllerStatus.Running) return requiredRunning ? "Running · requerido" : "Running · condicional";
        if (requiredRunning) return $"{status} · requerido";
        if (startMode.Equals("Manual", StringComparison.OrdinalIgnoreCase)) return "Condicional · Bajo demanda (Manual)";
        if (startMode.Equals("Deshabilitado", StringComparison.OrdinalIgnoreCase)) return "Condicional · Deshabilitado";
        return $"Condicional · {status}";
    }

    private static ServiceRead ReadService(string name)
    {
        try
        {
            using var sc = new ServiceController(name);
            return new ServiceRead(true, sc.Status, null);
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            return new ServiceRead(false, null, "No evaluado: " + ex.Message);
        }
    }

    private static bool UniversalPrinterDetected(string root)
    {
        if (ServiceExists("NovaPDF11Service")) return true;
        if (FileSystemProbe.Directory(Path.Combine(root, "UserDesktop", "files", "UniversalPrinter")).IsAvailable) return true;
        var systemDrive = Path.GetPathRoot(Environment.SystemDirectory) ?? @"C:\";
        return FileSystemProbe.Directory(Path.Combine(systemDrive, "wsession", "UniversalPrinter")).IsAvailable;
    }

    private static bool VirtualPrinterDetected(string root)
    {
        if (FileSystemProbe.File(Path.Combine(root, "UserDesktop", "files", "VirtualPrinterTool.exe")).IsAvailable) return true;
        // El instalador puede venir incluido aunque Virtual Printer no esté instalado.
        // No lo usamos como señal de activación para evitar mostrar una dependencia falsa.
        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        return !string.IsNullOrWhiteSpace(programFiles)
               && FileSystemProbe.Directory(Path.Combine(programFiles, "Virtual Devices", "Virtual Printer (Server)")).IsAvailable;
    }

    private static bool TwoFactorDetected(string root)
        => FileSystemProbe.File(Path.Combine(root, "UserDesktop", "files", "TwoFactor.Admin.exe")).IsAvailable;

    private static bool FarmDetected(string root)
    {
        var balancePath = Path.Combine(root, "Clients", "webserver", "balance.bin");
        var legacy = FileSystemProbe.File(Path.Combine(root, "UserDesktop", "files", "GatewayPortalLoadBalancing.ini"));
        if (legacy.IsAvailable) return true;

        var balance = FileSystemProbe.File(balancePath);
        if (!balance.IsAvailable) return false;
        try
        {
            return File.ReadLines(balancePath).Take(5000).Any(line =>
            {
                var value = line.Trim();
                return value.Length > 0 && !value.StartsWith('#') && !value.StartsWith(';');
            });
        }
        catch
        {
            return false;
        }
    }

    private static bool ServiceExists(string name)
    {
        try { using var sc = new ServiceController(name); _ = sc.Status; return true; }
        catch { return false; }
    }

    private static DomainJoinState ReadDomainJoinState()
    {
        var results = SafeWmi.Query(
            "SELECT PartOfDomain, Domain FROM Win32_ComputerSystem",
            o => new
            {
                Joined = o["PartOfDomain"] is bool b ? (bool?)b : null,
                Domain = o["Domain"]?.ToString()
            });

        if (results.Count == 0)
            return new DomainJoinState(null, null);

        return new DomainJoinState(results[0].Joined, string.IsNullOrWhiteSpace(results[0].Domain) ? null : results[0].Domain);
    }

    private sealed record ServiceRead(bool Available, ServiceControllerStatus? Status, string? Error);
    private sealed record DomainJoinState(bool? Joined, string? Domain);
}
