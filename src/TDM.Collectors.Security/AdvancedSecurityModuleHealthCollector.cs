using System.ServiceProcess;
using TDM.Core;
using TDM.Models;

namespace TDM.Collectors.Security;

/// <summary>
/// Diagnóstico normal dirigido de TSplus Advanced Security. Se limita a la raíz oficial,
/// servicio del producto y carpeta oficial de logs. No recorre recursivamente la instalación,
/// no modifica firewall/listas/políticas y no interpreta la ausencia de un log como falla.
/// </summary>
public sealed class AdvancedSecurityModuleHealthCollector : IReadOnlyCollector
{
    public string Nombre => "Módulos TSplus Advanced Security / diagnóstico normal";

    private sealed record ModuleDefinition(string Name, string[] LogTokens, bool OfficialFeatureLog, string Impact);

    private static readonly ModuleDefinition[] Modules =
    [
        new("Servicio / núcleo", ["service"], true, "Motor de configuración y protección de Advanced Security"),
        new("Firewall", ["firewall"], true, "Filtrado/bloqueo de conexiones según la configuración de Advanced Security"),
        new("Geographic Protection", ["geographic", "geography", "homeland"], true, "Control geográfico de conexiones entrantes"),
        new("Bruteforce Protection", ["bruteforce", "brute", "defender"], true, "Bloqueo de intentos de autenticación repetidos"),
        new("Hacker IP Protection", ["hacker", "blacklist", "blockedip", "blocked-ip"], false, "Bloqueo de direcciones conocidas como maliciosas"),
        new("Restrict Working Hours", ["workinghours", "working-hours", "working_hours", "hours"], true, "Restricción de acceso por horario"),
        new("Secure Sessions", ["securesession", "secure-session", "securedesktop", "secure-desktop"], false, "Restricciones de entorno/sesión segura"),
        new("Trusted Devices", ["trusteddevice", "trusted-device", "endpoint"], false, "Control de dispositivos autorizados"),
        new("Permissions", ["permission", "permissions"], false, "Restricciones de permisos y recursos"),
        new("Ransomware Protection", ["ransomware", "quarantine", "snapshot"], true, "Protección y respuesta frente a ransomware"),
        new("Alerts", ["alert", "alerts"], false, "Notificación de eventos de seguridad"),
        new("Reports", ["report", "reports"], false, "Informes de actividad/protección"),
        new("Events", ["event", "events"], false, "Registro de eventos de Advanced Security"),
        new("Application / interfaz", ["application"], true, "Interfaz administrativa del producto")
    ];

    public Task<CollectorResult> CollectAsync(DiagnosticContext context, CancellationToken cancellationToken = default)
    {
        var rootProbe = FindInstallRoot();
        if (rootProbe.IsAbsent) return Task.FromResult(CollectorResult.Empty);

        var events = new List<DiagnosticEvent>();
        var findings = new List<DiagnosticFinding>();
        if (rootProbe.IsUnavailable || string.IsNullOrWhiteSpace(rootProbe.Value))
        {
            findings.Add(new DiagnosticFinding(
                "TSPLUS-ADVSEC-DETECTION-COVERAGE", "TSplus Advanced Security", DiagnosticSeverity.Advertencia,
                "La presencia de Advanced Security quedó NO EVALUADA.",
                "TDM no interpreta un fallo de acceso/E/S en Program Files como ausencia del producto.",
                [new("Estado", rootProbe.StatusText), new("Detalle", rootProbe.Detail ?? "N/D")],
                ConfidenceLevel.Confirmada, Capa: DiagnosticLayer.Seguridad));
            return Task.FromResult(new CollectorResult(findings, events));
        }

        var root = rootProbe.Value!;
        var logsRoot = Path.Combine(root, "logs");
        var logsProbe = EnumerateOfficialLogs(logsRoot, cancellationToken);
        var logs = logsProbe.IsAvailable ? logsProbe.Value ?? [] : [];
        var servicesProbe = FindRelatedServices();
        var services = servicesProbe.IsAvailable ? servicesProbe.Value ?? [] : [];
        var running = services.Any(s => s.Status == ServiceControllerStatus.Running);
        var serviceCoveragePartial = servicesProbe.IsUnavailable;

        events.Add(new DiagnosticEvent(DateTimeOffset.Now, "TDM", "TSplus Advanced Security", DiagnosticLayer.Seguridad,
            serviceCoveragePartial ? DiagnosticSeverity.Advertencia : running ? DiagnosticSeverity.Informativo : DiagnosticSeverity.Error,
            "TSPLUS_ADVSEC_PRODUCT_RUNTIME_STATE",
            serviceCoveragePartial
                ? "Advanced Security está instalado, pero TDM no pudo evaluar de forma confiable el estado de sus servicios."
                : running
                    ? "Advanced Security está instalado y se observó al menos un servicio relacionado Running."
                    : "Advanced Security está instalado, pero no se observó un servicio relacionado Running.",
            Evidencia:
            [
                new("Raíz", root),
                new("Directorio oficial de logs", logsProbe.IsAvailable ? logsRoot : logsProbe.IsAbsent ? "Ausente confirmado / los logs pueden estar deshabilitados" : $"NO EVALUADO · {logsProbe.StatusText}"),
                new("Servicios relacionados", serviceCoveragePartial ? "No evaluado" : services.Count == 0 ? "Ninguno identificado" : string.Join(" | ", services.Select(s => $"{s.Name}={s.Status}"))),
                new("Servicio operativo", serviceCoveragePartial ? "No evaluado" : running ? "Sí" : "No"),
                new("Cobertura servicios", serviceCoveragePartial ? $"Parcial: {servicesProbe.StatusText}" : "Completa"),
                new("Logs observados", logsProbe.IsAvailable ? logs.Count.ToString() : "NO EVALUADO"),
                new("Cobertura logs", logsProbe.IsAvailable ? "Completa" : logsProbe.IsAbsent ? "Ausencia confirmada" : "Parcial"),
                new("Modo", "Diagnóstico dirigido; sin recorrido recursivo; sólo lectura")
            ], Producto: TsplusProduct.AdvancedSecurity));

        if (serviceCoveragePartial)
        {
            findings.Add(new DiagnosticFinding(
                "TSPLUS-ADVSEC-SERVICE-COVERAGE",
                "TSplus Advanced Security",
                DiagnosticSeverity.Advertencia,
                "No fue posible evaluar el servicio de Advanced Security.",
                "TDM no interpreta una lectura SCM fallida como servicio ausente o detenido. La cobertura queda parcial hasta que Windows permita consultar Service Control Manager.",
                [new("Estado de lectura", servicesProbe.StatusText), new("Detalle", servicesProbe.Detail ?? "Sin detalle adicional")],
                ConfidenceLevel.Confirmada,
                Capa: DiagnosticLayer.Seguridad));
        }
        else if (services.Count == 0)
        {
            findings.Add(new DiagnosticFinding(
                "TSPLUS-ADVSEC-SERVICE-NOT-FOUND",
                "TSplus Advanced Security",
                DiagnosticSeverity.Error,
                "La instalación de Advanced Security está presente, pero TDM no localizó su servicio principal.",
                "La raíz del producto existe y no se identificó un servicio relacionado. Esto puede indicar una instalación incompleta o una versión/layout no reconocido.",
                [new("Raíz", root)],
                ConfidenceLevel.Media,
                "TSplus Advanced Security — Getting Started / Advanced Logs",
                "https://docs.tsplus.net/advanced-security/advanced-logs/",
                "Valide desde la consola de Servicios y desde Advanced Security que el servicio del producto exista antes de reparar o reinstalar.",
                DiagnosticLayer.Seguridad));
        }
        else if (!running)
        {
            findings.Add(new DiagnosticFinding(
                "TSPLUS-ADVSEC-SERVICE-NOT-RUNNING",
                "TSplus Advanced Security",
                DiagnosticSeverity.Error,
                "El servicio de Advanced Security no se observa Running.",
                "La protección puede estar degradada o no operativa mientras el servicio principal no esté ejecutándose.",
                services.Select(s => new EvidenceItem(s.Name, s.Status.ToString())).ToList(),
                ConfidenceLevel.Alta,
                "TSplus Advanced Security — Advanced Logs",
                "https://docs.tsplus.net/advanced-security/advanced-logs/",
                "Investigue primero Service Control Manager, crashes y logs del producto. TDM no reinicia el servicio.",
                DiagnosticLayer.Seguridad));
        }

        foreach (var module in Modules)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var matches = logs
                .Where(f => module.LogTokens.Any(t => f.Name.Contains(t, StringComparison.OrdinalIgnoreCase)))
                .OrderByDescending(f => f.LastWrite)
                .Take(10)
                .ToList();

            var coverage = logsProbe.IsUnavailable
                ? $"NO EVALUADO · {logsProbe.StatusText}"
                : matches.Count > 0
                    ? "Log oficial/funcional observado"
                    : module.OfficialFeatureLog
                        ? "Log no observado; puede estar deshabilitado y no se considera falla"
                        : "Estado específico parcial; no existe una fuente local estable documentada para inferir habilitado/deshabilitado";

            events.Add(new DiagnosticEvent(DateTimeOffset.Now, "TDM", $"Advanced Security / {module.Name}", DiagnosticLayer.Seguridad,
                DiagnosticSeverity.Informativo, "TSPLUS_ADVSEC_MODULE_STATE",
                $"Módulo Advanced Security evaluado con diagnóstico dirigido; cobertura: {coverage}.",
                Evidencia:
                [
                    new("Cobertura TDM", coverage),
                    new("Impacto funcional", module.Impact),
                    new("Logs coincidentes", matches.Count == 0 ? "Ninguno observado" : string.Join(" | ", matches.Select(m => m.Name))),
                    new("Última actividad de log", matches.Count == 0 ? "N/D" : matches.Max(m => m.LastWrite).ToString("O")),
                    new("Ausencia de log", "No se interpreta como falla; Advanced Security permite habilitar/deshabilitar logs por función")
                ], Producto: TsplusProduct.AdvancedSecurity));
        }

        events.Add(new DiagnosticEvent(DateTimeOffset.Now, "TDM", "Advanced Security / cobertura modular", DiagnosticLayer.Seguridad,
            DiagnosticSeverity.Informativo, "TSPLUS_ADVSEC_MODULE_SUMMARY",
            "Diagnóstico normal de Advanced Security completado mediante servicio, carpeta oficial de logs y eventos Windows/TSplus ya recopilados.",
            Evidencia:
            [
                new("Módulos evaluados", Modules.Length.ToString()),
                new("Fuentes", "Servicio principal + C:\\Program Files (x86)\\TSplus-Security\\logs + Event Log/SCM + parser de logs TDM"),
                new("Recorrido recursivo", "No"),
                new("Protecciones no modificadas", "Firewall, IPs, ransomware, horarios, permisos, sesiones seguras y dispositivos confiables"),
                new("Acciones activas", "Ninguna")
            ], Producto: TsplusProduct.AdvancedSecurity));

        return Task.FromResult(new CollectorResult(findings, events));
    }

    private static ProbeResult<string> FindInstallRoot()
    {
        var hadUnavailable = false;
        var details = new List<string>();
        foreach (var baseDir in new[]
                 {
                     Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                     Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles)
                 }.Where(p => !string.IsNullOrWhiteSpace(p)).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            foreach (var name in new[] { "TSplus-Security", "TSplus Advanced Security", "TSplus AdvancedSecurity" })
            {
                var path = Path.Combine(baseDir, name);
                var probe = FileSystemProbe.Directory(path);
                if (probe.IsAvailable) return ProbeResult<string>.Available(path);
                if (probe.IsUnavailable) { hadUnavailable = true; details.Add($"{path}: {probe.StatusText}"); }
            }
        }
        return hadUnavailable
            ? ProbeResult<string>.Unavailable(string.Join(" | ", details.Take(5)))
            : ProbeResult<string>.Absent();
    }

    private static ProbeResult<IReadOnlyList<(string Name, ServiceControllerStatus Status)>> FindRelatedServices()
    {
        var output = new List<(string, ServiceControllerStatus)>();
        try
        {
            foreach (var service in ServiceController.GetServices())
            {
                using (service)
                {
                    try
                    {
                        if (service.ServiceName.Contains("TSplus-Security", StringComparison.OrdinalIgnoreCase)
                            || service.DisplayName.Contains("TSplus", StringComparison.OrdinalIgnoreCase) && service.DisplayName.Contains("Security", StringComparison.OrdinalIgnoreCase)
                            || service.ServiceName.Contains("AdvancedSecurity", StringComparison.OrdinalIgnoreCase))
                            output.Add((service.ServiceName, service.Status));
                    }
                    catch { }
                }
            }
            return ProbeResult<IReadOnlyList<(string Name, ServiceControllerStatus Status)>>.Available(output);
        }
        catch (UnauthorizedAccessException ex) { return ProbeResult<IReadOnlyList<(string Name, ServiceControllerStatus Status)>>.AccessDenied(ex.Message); }
        catch (Exception ex) { return ProbeResult<IReadOnlyList<(string Name, ServiceControllerStatus Status)>>.Error(ex.Message); }
    }

    private static ProbeResult<IReadOnlyList<LogEntry>> EnumerateOfficialLogs(string logsRoot, CancellationToken ct)
    {
        var dirProbe = FileSystemProbe.Directory(logsRoot);
        if (dirProbe.IsAbsent) return ProbeResult<IReadOnlyList<LogEntry>>.Absent();
        if (dirProbe.IsUnavailable) return new ProbeResult<IReadOnlyList<LogEntry>>(dirProbe.State, null, dirProbe.Detail);
        try
        {
            var output = new List<LogEntry>();
            foreach (var file in Directory.EnumerateFiles(logsRoot, "*", SearchOption.TopDirectoryOnly).Take(2001))
            {
                ct.ThrowIfCancellationRequested();
                var ext = Path.GetExtension(file);
                if (!ext.Equals(".log", StringComparison.OrdinalIgnoreCase)
                    && !ext.Equals(".txt", StringComparison.OrdinalIgnoreCase)
                    && !ext.Equals(".trace", StringComparison.OrdinalIgnoreCase)) continue;
                try
                {
                    var fi = new FileInfo(file);
                    output.Add(new LogEntry(fi.Name, fi.FullName, fi.LastWriteTime));
                }
                catch (UnauthorizedAccessException ex) { return ProbeResult<IReadOnlyList<LogEntry>>.AccessDenied(ex.Message); }
                catch (IOException ex) { return ProbeResult<IReadOnlyList<LogEntry>>.Error(ex.Message); }
            }
            return ProbeResult<IReadOnlyList<LogEntry>>.Available(output);
        }
        catch (UnauthorizedAccessException ex) { return ProbeResult<IReadOnlyList<LogEntry>>.AccessDenied(ex.Message); }
        catch (IOException ex) { return ProbeResult<IReadOnlyList<LogEntry>>.Error(ex.Message); }
    }

    private sealed record LogEntry(string Name, string FullPath, DateTime LastWrite);
}
