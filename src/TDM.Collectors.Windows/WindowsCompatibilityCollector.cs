using TDM.Core;
using TDM.Models;

namespace TDM.Collectors.Windows;

/// <summary>
/// Estado de compatibilidad Windows que puede afectar directamente a TSplus.
/// Sólo lectura: no cambia Registro, roles, servicios ni estado de reinicio.
/// Las lecturas no disponibles se exponen como cobertura parcial y nunca como estado sano.
/// </summary>
public sealed class WindowsCompatibilityCollector : IReadOnlyCollector
{
    private const string LogonSessionPath = @"C:\wsession\logonsession.exe";
    private readonly IWindowsCompatibilityProbeSource _probes;

    public WindowsCompatibilityCollector() : this(new WindowsCompatibilityProbeSource()) { }

    public WindowsCompatibilityCollector(IWindowsCompatibilityProbeSource probes)
        => _probes = probes ?? throw new ArgumentNullException(nameof(probes));

    public string Nombre => "Compatibilidad Windows / TSplus";

    public Task<CollectorResult> CollectAsync(DiagnosticContext context, CancellationToken cancellationToken = default)
    {
        var findings = new List<DiagnosticFinding>();
        var events = new List<DiagnosticEvent>();

        AuditPendingReboot(findings, events);
        if (context.Sistema.TsplusDetectado)
        {
            AuditRdpPolicy(findings, events);
            AuditWinlogonIntegration(findings, events);
            if (context.Sistema.SistemaOperativo.Contains("Server", StringComparison.OrdinalIgnoreCase))
                AuditRdsServerRoles(findings, events, cancellationToken);
        }

        return Task.FromResult(new CollectorResult(findings, events));
    }

    private void AuditPendingReboot(List<DiagnosticFinding> findings, List<DiagnosticEvent> events)
    {
        var reasons = new List<string>();
        var probes = new List<(string Name, ProbeResult<bool> Result)>
        {
            ("Component-Based Servicing", _probes.CbsRebootPending()),
            ("Windows Update", _probes.WindowsUpdateRebootPending()),
            ("PendingFileRenameOperations", _probes.PendingFileRename()),
            ("Cambio de nombre", _probes.PendingComputerRename())
        };

        foreach (var probe in probes)
            if (probe.Result.IsAvailable && probe.Result.Value)
                reasons.Add(probe.Name);

        var unavailable = probes.Where(x => x.Result.IsUnavailable).ToList();
        var partial = unavailable.Count > 0;
        var rebootObserved = reasons.Count > 0;
        var state = rebootObserved ? "Sí" : partial ? "No evaluado" : "No observado";
        var message = rebootObserved
            ? "Windows presenta indicadores de reinicio pendiente."
            : partial
                ? "No fue posible evaluar por completo el estado de reinicio pendiente."
                : "No se observaron indicadores comunes de reinicio pendiente.";

        events.Add(new DiagnosticEvent(
            DateTimeOffset.Now,
            "Windows",
            "Estado de reinicio",
            DiagnosticLayer.Windows,
            rebootObserved || partial ? DiagnosticSeverity.Advertencia : DiagnosticSeverity.Informativo,
            DiagnosticEventTypes.WindowsRebootPendingState,
            message,
            Evidencia:
            [
                new EvidenceItem("Reinicio pendiente", state),
                new EvidenceItem("Motivos", reasons.Count == 0 ? (partial ? "No concluyente" : "Ninguno observado") : string.Join(" | ", reasons)),
                new EvidenceItem("Cobertura", partial ? "Parcial" : "Completa"),
                new EvidenceItem("Fuentes no evaluadas", unavailable.Count == 0 ? "Ninguna" : string.Join(" | ", unavailable.Select(x => $"{x.Name}: {x.Result.StatusText}")))
            ]));

        if (partial)
            AddProbeCoverageFinding(findings, "WINDOWS-PROBE-REBOOT", "Estado de reinicio", unavailable);

        if (rebootObserved)
        {
            findings.Add(new DiagnosticFinding(
                "WINDOWS-PENDING-REBOOT",
                "Windows",
                DiagnosticSeverity.Advertencia,
                "Windows tiene operaciones que requieren reinicio.",
                "Un reinicio pendiente puede dejar actualizaciones, reemplazos de archivos o cambios del sistema a medio aplicar. TDM lo conserva como antecedente de Windows y no lo declara causa de TSplus sin correlación temporal adicional.",
                [new EvidenceItem("Motivos", string.Join(" | ", reasons)), new EvidenceItem("Cobertura", partial ? "Parcial" : "Completa")],
                ConfidenceLevel.Alta,
                "Microsoft Learn — Microsoft.Windows/RebootPending",
                "https://learn.microsoft.com/en-us/powershell/dsc/reference/resources/microsoft/windows/rebootpending/",
                "Complete primero el ciclo de mantenimiento/reinicio si coincide con el inicio del incidente y valide después si persiste la falla. TDM no reinicia el servidor.",
                DiagnosticLayer.Windows));
        }
    }

    private void AuditRdpPolicy(List<DiagnosticFinding> findings, List<DiagnosticEvent> events)
    {
        var policyProbe = _probes.RdpPolicyDenyConnections();
        var localProbe = _probes.RdpLocalDenyConnections();

        var policy = policyProbe.IsAvailable ? policyProbe.Value : null;
        var local = localProbe.IsAvailable ? localProbe.Value : null;
        var canDetermine = policyProbe.IsAvailable && (policy.HasValue || localProbe.IsAvailable);
        var denied = canDetermine && (policy == 1 || (policy is null && local == 1));
        var partial = !canDetermine;

        var blockedValue = denied ? "Sí" : partial ? "No evaluado" : "No observado";
        var message = denied
            ? "La configuración efectiva observada deshabilita conexiones RDP."
            : partial
                ? "No fue posible determinar de forma confiable si fDenyTSConnections bloquea RDP."
                : "No se observó fDenyTSConnections efectivo en estado de bloqueo.";

        events.Add(new DiagnosticEvent(
            DateTimeOffset.Now,
            "Windows Registry / Group Policy",
            "Remote Desktop access policy",
            DiagnosticLayer.Windows,
            denied ? DiagnosticSeverity.Critico : partial ? DiagnosticSeverity.Advertencia : DiagnosticSeverity.Informativo,
            DiagnosticEventTypes.WindowsRdpPolicyState,
            message,
            Evidencia:
            [
                new EvidenceItem("Policy fDenyTSConnections", ProbeValue(policyProbe, "No configurada")),
                new EvidenceItem("Local fDenyTSConnections", ProbeValue(localProbe, "No configurada")),
                new EvidenceItem("RDP bloqueado", blockedValue),
                new EvidenceItem("Cobertura", partial ? "Parcial" : "Completa")
            ],
            Producto: TsplusProduct.RemoteAccess));

        if (partial)
        {
            var unavailable = new List<(string Name, ProbeResult<int?> Result)>();
            if (policyProbe.IsUnavailable) unavailable.Add(("Directiva RDP", policyProbe));
            if (localProbe.IsUnavailable) unavailable.Add(("Configuración local RDP", localProbe));
            AddProbeCoverageFinding(findings, "WINDOWS-PROBE-RDP-POLICY", "Directiva de acceso RDP", unavailable);
        }

        if (denied)
        {
            findings.Add(new DiagnosticFinding(
                "WINDOWS-RDP-DISABLED-POLICY",
                "Windows RDP / Group Policy",
                DiagnosticSeverity.Critico,
                "Windows tiene deshabilitadas las conexiones RDP mediante configuración efectiva.",
                "TSplus Remote Access depende de la capacidad de Windows para aceptar/crear sesiones RDP. Esta configuración pertenece a Windows y debe investigarse antes de reparar TSplus.",
                [
                    new EvidenceItem("Policy fDenyTSConnections", policy?.ToString() ?? "No configurada"),
                    new EvidenceItem("Local fDenyTSConnections", local?.ToString() ?? "No configurada")
                ],
                ConfidenceLevel.Confirmada,
                "Microsoft Learn — General Remote Desktop connection troubleshooting",
                "https://learn.microsoft.com/en-us/troubleshoot/windows-server/remote/rdp-error-general-troubleshooting",
                "Revise la directiva que controla Remote Desktop y su procedencia (local/dominio) antes de cambiarla. TDM no modifica Group Policy ni el Registro.",
                DiagnosticLayer.Windows));
        }
    }

    private void AuditWinlogonIntegration(List<DiagnosticFinding> findings, List<DiagnosticEvent> events)
    {
        var userinitProbe = _probes.WinlogonUserinit();
        var fileProbe = _probes.LogonSessionFileExists();
        var fileExists = fileProbe.IsAvailable && fileProbe.Value;
        var integrated = userinitProbe.IsAvailable && (userinitProbe.Value?.Contains("logonsession.exe", StringComparison.OrdinalIgnoreCase) ?? false);
        var registryUnknown = userinitProbe.IsUnavailable;
        var fileUnknown = fileProbe.IsUnavailable;
        var coveragePartial = registryUnknown || fileUnknown;
        var fileMissing = fileProbe.IsAvailable && !fileProbe.Value;
        var userinitMissingIntegration = userinitProbe.IsAvailable && !integrated;
        var confirmedIssue = fileMissing || userinitMissingIntegration;

        events.Add(new DiagnosticEvent(
            DateTimeOffset.Now,
            "Windows Registry",
            "Winlogon / Userinit",
            DiagnosticLayer.Windows,
            confirmedIssue || coveragePartial ? DiagnosticSeverity.Advertencia : DiagnosticSeverity.Informativo,
            DiagnosticEventTypes.WindowsTsplusWinlogonIntegration,
            coveragePartial
                ? "No fue posible evaluar por completo la integración de Winlogon con el inicializador de sesión TSplus."
                : "Integración de Winlogon con el inicializador de sesión TSplus capturada en modo de solo lectura.",
            Archivo: LogonSessionPath,
            Evidencia:
            [
                new EvidenceItem("Userinit contiene logonsession.exe", registryUnknown ? "No evaluado" : integrated ? "Sí" : "No"),
                new EvidenceItem("Lectura Userinit", userinitProbe.StatusText),
                new EvidenceItem("logonsession.exe presente", fileUnknown ? "No evaluado" : fileExists ? "Sí" : "No"),
                new EvidenceItem("Lectura logonsession.exe", fileProbe.StatusText),
                new EvidenceItem("Cobertura", coveragePartial ? "Parcial" : "Completa"),
                new EvidenceItem("Ruta esperada", LogonSessionPath)
            ],
            Producto: TsplusProduct.RemoteAccess));

        if (registryUnknown)
            AddProbeCoverageFinding(findings, "WINDOWS-PROBE-WINLOGON", "Winlogon / Userinit", new List<(string Name, ProbeResult<string?> Result)> { ("Userinit", userinitProbe) });
        if (fileUnknown)
            AddProbeCoverageFinding(findings, "WINDOWS-PROBE-LOGONSESSION-FILE", "Inicializador de sesión TSplus", new List<(string Name, ProbeResult<bool> Result)> { ("logonsession.exe", fileProbe) });

        if (confirmedIssue)
        {
            findings.Add(new DiagnosticFinding(
                "WINDOWS-TSPLUS-WINLOGON-INTEGRATION",
                "Windows Winlogon / TSplus logonsession",
                DiagnosticSeverity.Critico,
                !fileExists ? "No se encontró C:\\wsession\\logonsession.exe." : "Winlogon Userinit no contiene la llamada a logonsession.exe.",
                "TSplus documenta esta integración como un punto crítico en problemas de pantalla negra/imposibilidad de iniciar sesión. El hallazgo cruza configuración Windows con un componente TSplus; la responsabilidad final debe correlacionarse con antivirus, actualización o integridad de la instalación.",
                [
                    new EvidenceItem("Userinit contiene logonsession.exe", integrated ? "Sí" : "No"),
                    new EvidenceItem("logonsession.exe presente", fileExists ? "Sí" : "No"),
                    new EvidenceItem("Ruta", LogonSessionPath)
                ],
                ConfidenceLevel.Alta,
                "TSplus Support — Black screen and impossible to login - error on logonsession.exe",
                "https://support.tsplus.net/support/solutions/articles/44002222051-black-screen-and-impossible-to-login-error-on-logonsession-exe",
                "Revise la causa del cambio o ausencia antes de editar Winlogon: antivirus/EDR, actualización TSplus y presencia real del ejecutable. TDM no modifica Userinit ni restaura archivos.",
                DiagnosticLayer.Windows));
        }
    }

    private void AuditRdsServerRoles(List<DiagnosticFinding> findings, List<DiagnosticEvent> events, CancellationToken ct)
    {
        var rolesProbe = _probes.RdsConflictingRoles(ct);
        var detected = rolesProbe.IsAvailable ? rolesProbe.Value ?? [] : [];
        var partial = rolesProbe.IsUnavailable;

        events.Add(new DiagnosticEvent(
            DateTimeOffset.Now,
            "Windows Server Features",
            "RDS roles",
            DiagnosticLayer.Windows,
            detected.Count > 0 || partial ? DiagnosticSeverity.Advertencia : DiagnosticSeverity.Informativo,
            DiagnosticEventTypes.WindowsRdsRoleCompatibility,
            partial
                ? "No fue posible evaluar por completo la compatibilidad de roles RDS con TSplus."
                : "Compatibilidad de roles RDS con TSplus evaluada en modo de solo lectura.",
            Evidencia:
            [
                new EvidenceItem("Consulta", partial ? $"No evaluada: {rolesProbe.StatusText}" : "Disponible"),
                new EvidenceItem("Roles RDS conflictivos observados", detected.Count == 0 ? (partial ? "No concluyente" : "Ninguno") : string.Join(" | ", detected)),
                new EvidenceItem("Cobertura", partial ? "Parcial" : "Completa")
            ],
            Producto: TsplusProduct.RemoteAccess));

        if (partial)
            AddProbeCoverageFinding(findings, "WINDOWS-PROBE-RDS-ROLES", "Roles RDS", new List<(string Name, ProbeResult<IReadOnlyList<string>> Result)> { ("Win32_ServerFeature", rolesProbe) });

        if (detected.Count > 0)
        {
            findings.Add(new DiagnosticFinding(
                "WINDOWS-RDS-ROLE-CONFLICT",
                "Windows Server / RDS roles",
                DiagnosticSeverity.Critico,
                "Se observaron roles RDS que TSplus indica que no deben estar instalados junto con Remote Access.",
                "La documentación de prerrequisitos de TSplus indica retirar los roles RDS/Terminal Services y RDS Licensing antes de instalar Remote Access. Este hallazgo pertenece a Windows y puede afectar la creación/licenciamiento de sesiones.",
                [new EvidenceItem("Roles", string.Join(" | ", detected)), new EvidenceItem("Cobertura", partial ? "Parcial" : "Completa")],
                ConfidenceLevel.Alta,
                "TSplus Remote Access Prerequisites",
                "https://docs.tsplus.net/tsplus/pre-requisites/",
                "Confirme los roles instalados y la arquitectura soportada antes de cambiar Windows. TDM no elimina roles ni reinicia el servidor.",
                DiagnosticLayer.Windows));
        }
    }

    private static string ProbeValue<T>(ProbeResult<T> result, string availableFallback)
        => result.IsAvailable ? (result.Value is null ? availableFallback : result.Value.ToString() ?? availableFallback) : $"No evaluado ({result.StatusText})";

    private static void AddProbeCoverageFinding<T>(
        List<DiagnosticFinding> findings,
        string id,
        string component,
        IReadOnlyList<(string Name, ProbeResult<T> Result)> unavailable)
    {
        if (unavailable.Count == 0) return;
        findings.Add(new DiagnosticFinding(
            id,
            component,
            DiagnosticSeverity.Advertencia,
            "Una comprobación de solo lectura quedó parcialmente no evaluada.",
            "TDM no convierte una lectura fallida en un estado sano. La conclusión dependiente de esta fuente queda limitada hasta recuperar acceso.",
            unavailable.Select(x => new EvidenceItem(x.Name, $"{x.Result.StatusText}{(string.IsNullOrWhiteSpace(x.Result.Detail) ? string.Empty : $": {x.Result.Detail}")}" )).ToList(),
            ConfidenceLevel.Confirmada,
            Capa: DiagnosticLayer.Windows));
    }
}
