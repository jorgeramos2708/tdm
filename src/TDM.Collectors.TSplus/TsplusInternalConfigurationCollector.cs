using System.Text.Json;
using System.Net.NetworkInformation;
using System.Security.Principal;
using System.Text.RegularExpressions;
using TDM.Core;
using TDM.Models;

namespace TDM.Collectors.TSplus;

/// <summary>
/// Auditoría conservadora y de solo lectura de configuración interna de TSplus Remote Access.
/// No modifica AppControl.ini, servidor web, credenciales, clientes ni parámetros de TSplus.
/// </summary>
public sealed partial class TsplusInternalConfigurationCollector : IReadOnlyCollector
{
    public string Nombre => "Configuración interna TSplus";

    private const int MaxConfigBytes = 4 * 1024 * 1024;

    public Task<CollectorResult> CollectAsync(DiagnosticContext context, CancellationToken cancellationToken = default)
    {
        var findings = new List<DiagnosticFinding>();
        var events = new List<DiagnosticEvent>();

        if (!context.Sistema.TsplusDetectado || string.IsNullOrWhiteSpace(context.Sistema.TsplusRuta))
            return Task.FromResult(CollectorResult.Empty);

        var install = context.Sistema.TsplusRuta!;
        var releaseProfile = TsplusReleaseCatalog.Resolve(context.Sistema);
        var appControlProbe = ResolveAppControl(install);
        var appControl = appControlProbe.IsAvailable ? appControlProbe.Value : null;
        if (appControl is not null)
            AuditAppControl(appControl, context, findings, events, cancellationToken);
        else if (releaseProfile.Soportado && appControlProbe.IsAbsent)
        {
            findings.Add(new DiagnosticFinding(
                "TSPLUS-APPCONTROL-NOT-FOUND",
                "TSplus Application Control",
                DiagnosticSeverity.Error,
                "No se encontró AppControl.ini en la ruta principal esperada de la instalación detectada.",
                "AppControl.ini contiene configuración de publicación/asignación de aplicaciones. Su ausencia puede indicar una instalación incompleta, ruta no estándar o una detección incorrecta de la raíz TSplus. TDM no crea ni modifica el archivo.",
                [new EvidenceItem("Ruta TSplus", install)],
                ConfidenceLevel.Media,
                "TSplus Support — Published Applications and Assignments / AppControl.ini",
                "https://support.tsplus.net/support/solutions/articles/44002059259-are-users-and-groups-saved-when-i-make-a-backup-with-remote-access-",
                "Confirme la ruta de instalación y la presencia de AppControl.ini antes de modificar asignaciones o reinstalar TSplus.",
                DiagnosticLayer.Tsplus));
        }
        else if (releaseProfile.Soportado && appControlProbe.IsUnavailable)
        {
            findings.Add(new DiagnosticFinding(
                "TSPLUS-APPCONTROL-COVERAGE", "TSplus Application Control", DiagnosticSeverity.Advertencia,
                "AppControl.ini quedó NO EVALUADO.",
                "No se pudo confirmar presencia/ausencia por acceso o E/S; TDM no lo registra como archivo faltante.",
                [new EvidenceItem("Cobertura", appControlProbe.StatusText)], ConfidenceLevel.Alta, Capa: DiagnosticLayer.Tsplus));
        }

        AuditWebConfiguration(install, releaseProfile.Soportado, findings, events, cancellationToken);
        AuditWebRuntime(install, context, findings, events, cancellationToken);
        AuditSensitiveMetadataOnly(install, events);

        var internalEvidence = new List<EvidenceItem>
        {
            new("AppControl.ini", appControl ?? (appControlProbe.IsAbsent ? "No localizado" : "NO EVALUADO")),
            new("Portal web", Path.Combine(install, "Clients", "www")),
            new("Web server", Path.Combine(install, "Clients", "webserver")),
            new("Web portal moderno", Path.Combine(install, "Clients", "webportal")),
            new("Modo", "Solo lectura; no se exponen secretos ni credenciales")
        };

        events.Add(new DiagnosticEvent(
            DateTimeOffset.Now,
            "TDM",
            "TSplus Internal Configuration",
            DiagnosticLayer.Tsplus,
            DiagnosticSeverity.Informativo,
            "TSPLUS_INTERNAL_CONFIG_AUDIT",
            "Auditoría de configuración interna de Remote Access completada en modo de solo lectura.",
            Evidencia: internalEvidence,
            Producto: TsplusProduct.RemoteAccess));

        return Task.FromResult(new CollectorResult(findings, events));
    }

    private static ProbeResult<string> ResolveAppControl(string install)
    {
        var candidates = new[]
        {
            Path.Combine(install, "UserDesktop", "files", "AppControl.ini"),
            Path.Combine(install, "UserDesktop", "AppControl.ini")
        };
        var unavailable = new List<string>();
        foreach (var candidate in candidates)
        {
            var probe = FileSystemProbe.File(candidate);
            if (probe.IsAvailable) return ProbeResult<string>.Available(candidate);
            if (probe.IsUnavailable) unavailable.Add($"{candidate}: {probe.StatusText}");
        }
        return unavailable.Count > 0
            ? ProbeResult<string>.Unavailable(string.Join(" | ", unavailable))
            : ProbeResult<string>.Absent();
    }

    private static string? FindWebArtifact(string install, string expectedPath, string fileName, params string[] pathTokens)
    {
        // La ruta oficial es la primera fuente de verdad, pero File.Exists no puede distinguir
        // ausencia de acceso denegado. Si la ruta no puede evaluarse la conservamos para que
        // el caller la represente como NO EVALUADO, nunca como ausente.
        var expectedProbe = FileSystemProbe.File(expectedPath);
        if (expectedProbe.IsAvailable || expectedProbe.IsUnavailable) return expectedPath;

        // Compatibilidad acotada con layouts personalizados/entre versiones. La búsqueda está
        // limitada en profundidad y número de directorios para no convertir el diagnóstico en
        // un escaneo invasivo del disco.
        var queue = new Queue<(string Path, int Depth)>();
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        queue.Enqueue((install, 0));
        const int maxDepth = 4;
        const int maxDirectories = 160;
        var examined = 0;
        while (queue.Count > 0 && examined < maxDirectories)
        {
            var (dir, depth) = queue.Dequeue();
            string full;
            try { full = Path.GetFullPath(dir); } catch { continue; }
            if (!visited.Add(full)) continue;
            examined++;

            var pathText = full.Replace('/', '\\');
            var tokenCompatible = pathTokens.Length == 0 || pathTokens.Any(t => pathText.Contains(t, StringComparison.OrdinalIgnoreCase));
            if (tokenCompatible)
            {
                var candidate = Path.Combine(full, fileName);
                var probe = FileSystemProbe.File(candidate);
                if (probe.IsAvailable || probe.IsUnavailable) return candidate;
            }

            if (depth >= maxDepth) continue;
            try
            {
                foreach (var child in Directory.EnumerateDirectories(full).Take(64))
                    queue.Enqueue((child, depth + 1));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
            {
                _ = ex;
                // Un subárbol no evaluable no demuestra que el artefacto esté ausente.
                // La ruta esperada ya fue evaluada como ausente; seguimos con el resto del árbol.
            }
        }
        return null;
    }

    private static void AuditAppControl(
        string path,
        DiagnosticContext context,
        List<DiagnosticFinding> findings,
        List<DiagnosticEvent> events,
        CancellationToken ct)
    {
        try
        {
            var file = new FileInfo(path);
            if (!file.Exists) return;
            if (file.Length > MaxConfigBytes)
            {
                findings.Add(ConfigFinding(
                    "TSPLUS-APPCONTROL-OVERSIZE",
                    DiagnosticSeverity.Advertencia,
                    "AppControl.ini tiene un tamaño inusual para una configuración INI.",
                    "TDM limita la lectura para evitar cargar configuraciones anormalmente grandes. El archivo debe revisarse antes de atribuir fallas de publicación o asignación.",
                    path,
                    ConfidenceLevel.Media));
                return;
            }

            var lines = File.ReadAllLines(path);
            var sections = ParseIni(lines, ct);
            var duplicateSections = sections.GroupBy(s => s.Name, StringComparer.OrdinalIgnoreCase).Where(g => g.Count() > 1).ToList();
            var appSections = sections.Where(s => AppSectionRegex().IsMatch(s.Name)).ToList();
            var appEvidence = new List<EvidenceItem>
            {
                new("Archivo", path),
                new("Última modificación", file.LastWriteTime.ToString("O")),
                new("Secciones", sections.Count.ToString()),
                new("Aplicaciones publicadas detectadas", appSections.Count.ToString()),
                new("Secciones duplicadas", duplicateSections.Count.ToString())
            };

            events.Add(new DiagnosticEvent(
                DateTimeOffset.Now,
                "TSplus Config",
                "Application Control / AppControl.ini",
                DiagnosticLayer.Tsplus,
                DiagnosticSeverity.Informativo,
                "TSPLUS_APPCONTROL_STATE",
                $"AppControl.ini leído correctamente; {appSections.Count} secciones de aplicación detectadas.",
                Archivo: path,
                Evidencia: appEvidence,
                Producto: TsplusProduct.RemoteAccess));

            foreach (var dup in duplicateSections)
            {
                var isApplication = AppSectionRegex().IsMatch(dup.Key);
                findings.Add(new DiagnosticFinding(
                    $"TSPLUS-APPCONTROL-DUPLICATE-{Sanitize(dup.Key)}",
                    "TSplus Application Control",
                    isApplication ? DiagnosticSeverity.Error : DiagnosticSeverity.Advertencia,
                    $"AppControl.ini contiene una sección duplicada [{dup.Key}].",
                    isApplication
                        ? "Una sección AppN duplicada hace ambigua la definición de la aplicación y puede producir comportamiento inconsistente al publicar o iniciar aplicaciones."
                        : "La sección está repetida. TDM la conserva como anomalía de configuración, pero no la declara causal sin un síntoma compatible.",
                    [new EvidenceItem("Archivo", path), new EvidenceItem("Sección", dup.Key), new EvidenceItem("Repeticiones", dup.Count().ToString())],
                    isApplication ? ConfidenceLevel.Alta : ConfidenceLevel.Media,
                    "TSplus — Application Publishing / AppControl.ini",
                    "https://docs.tsplus.net/tsplus/application-publishing/",
                    "Revise la configuración desde AdminTool y compare AppControl.ini con una copia conocida como válida. No elimine secciones hasta identificar qué entrada usa la configuración actual.",
                    DiagnosticLayer.Tsplus));
            }

            AuditAppControlSecurity(sections, path, findings, events);

            foreach (var section in appSections)
                AuditPublishedApplication(section, path, context, findings, events);
        }
        catch (UnauthorizedAccessException ex)
        {
            findings.Add(new DiagnosticFinding(
                "TSPLUS-APPCONTROL-ACCESS-DENIED",
                "TSplus Application Control",
                DiagnosticSeverity.Advertencia,
                "TDM no pudo leer AppControl.ini por permisos insuficientes.",
                "La configuración de aplicaciones queda sin auditar; TDM no considera esta fuente como sana ni como fallida.",
                [new EvidenceItem("Archivo", path), new EvidenceItem("Error", ex.Message)],
                ConfidenceLevel.Media,
                Capa: DiagnosticLayer.Tsplus));
        }
        catch (IOException ex)
        {
            findings.Add(new DiagnosticFinding(
                "TSPLUS-APPCONTROL-READ-ERROR",
                "TSplus Application Control",
                DiagnosticSeverity.Advertencia,
                "TDM no pudo completar la lectura de AppControl.ini.",
                ex.Message,
                [new EvidenceItem("Archivo", path)],
                ConfidenceLevel.Media,
                Capa: DiagnosticLayer.Tsplus));
        }
    }

    private static void AuditPublishedApplication(
        IniSection section,
        string path,
        DiagnosticContext context,
        List<DiagnosticFinding> findings,
        List<DiagnosticEvent> events)
    {
        var appName = section.Get("appname")?.Trim() ?? string.Empty;
        var appPathRaw = section.Get("path")?.Trim() ?? string.Empty;
        var startupRaw = section.Get("startup")?.Trim() ?? string.Empty;
        var users = section.Get("users")?.Trim() ?? string.Empty;
        var groups = section.Get("groups")?.Trim() ?? string.Empty;
        var allUsers = section.Get("all_users")?.Trim() ?? string.Empty;
        var cmdLine = section.Get("cmdline")?.Trim() ?? string.Empty;

        var duplicateKeys = section.Values
            .GroupBy(v => v.Key, StringComparer.OrdinalIgnoreCase)
            .Where(g => g.Count() > 1)
            .ToList();
        foreach (var duplicate in duplicateKeys)
        {
            var importantKey = duplicate.Key.Equals("path", StringComparison.OrdinalIgnoreCase) ||
                               duplicate.Key.Equals("startup", StringComparison.OrdinalIgnoreCase) ||
                               duplicate.Key.Equals("users", StringComparison.OrdinalIgnoreCase) ||
                               duplicate.Key.Equals("groups", StringComparison.OrdinalIgnoreCase) ||
                               duplicate.Key.Equals("all_users", StringComparison.OrdinalIgnoreCase);
            findings.Add(new DiagnosticFinding(
                $"TSPLUS-APPCONTROL-DUPKEY-{Sanitize(section.Name)}-{Sanitize(duplicate.Key)}",
                string.IsNullOrWhiteSpace(appName) ? section.Name : appName,
                importantKey ? DiagnosticSeverity.Advertencia : DiagnosticSeverity.Informativo,
                $"La sección [{section.Name}] contiene la clave '{duplicate.Key}' más de una vez.",
                importantKey
                    ? "Una clave de publicación/asignación repetida puede hacer ambigua la configuración efectiva. TDM no decide qué valor prevalece sin evidencia operativa de la versión instalada."
                    : "La clave está repetida; se conserva como evidencia de configuración sin asumir impacto operativo.",
                [new EvidenceItem("Archivo", path), new EvidenceItem("Sección", section.Name), new EvidenceItem("Clave", duplicate.Key), new EvidenceItem("Valores", string.Join(" | ", duplicate.Select(x => x.Value)))],
                importantKey ? ConfidenceLevel.Media : ConfidenceLevel.Baja,
                Capa: DiagnosticLayer.Tsplus));
        }

        if (!string.IsNullOrWhiteSpace(allUsers) && !IsBooleanLike(allUsers))
        {
            findings.Add(new DiagnosticFinding(
                $"TSPLUS-APPCONTROL-ALLUSERS-{Sanitize(section.Name)}",
                string.IsNullOrWhiteSpace(appName) ? section.Name : appName,
                DiagnosticSeverity.Advertencia,
                "La aplicación publicada tiene un valor all_users no reconocible.",
                "La asignación global queda ambigua. TDM conserva la anomalía y requiere correlación con un usuario afectado antes de tratarla como causa del incidente.",
                [new EvidenceItem("Archivo", path), new EvidenceItem("Sección", section.Name), new EvidenceItem("all_users", allUsers)],
                ConfidenceLevel.Media,
                Capa: DiagnosticLayer.Tsplus));
        }

        if (string.IsNullOrWhiteSpace(appName))
        {
            findings.Add(new DiagnosticFinding(
                $"TSPLUS-APPCONTROL-NAME-{Sanitize(section.Name)}",
                "TSplus Application Control",
                DiagnosticSeverity.Advertencia,
                $"La sección [{section.Name}] no contiene un nombre de aplicación reconocible.",
                "La entrada existe pero TDM no puede determinar qué aplicación representa. Esto reduce la certeza al correlacionar errores de publicación/inicio.",
                [new EvidenceItem("Archivo", path), new EvidenceItem("Sección", section.Name)],
                ConfidenceLevel.Media,
                Capa: DiagnosticLayer.Tsplus));
        }

        var appPath = ExpandPath(appPathRaw);
        var appPathProbe = !string.IsNullOrWhiteSpace(appPathRaw) && Path.IsPathRooted(appPath)
            ? FileSystemProbe.File(appPath) : ProbeResult<bool>.Unavailable("Ruta no aplicable/no absoluta");
        if (!string.IsNullOrWhiteSpace(appPathRaw) && Path.IsPathRooted(appPath) && appPathProbe.IsAbsent)
        {
            findings.Add(new DiagnosticFinding(
                $"TSPLUS-PUBLISHED-APP-MISSING-{Sanitize(section.Name)}",
                string.IsNullOrWhiteSpace(appName) ? section.Name : appName,
                DiagnosticSeverity.Error,
                "Una aplicación publicada por TSplus apunta a un ejecutable que no existe actualmente.",
                "Si un usuario tiene esta aplicación asignada, TSplus puede autenticar y crear la sesión pero fallar al lanzar la aplicación, quedarse en una pantalla de espera o aplicar un fallback según la configuración.",
                [
                    new EvidenceItem("Archivo", path),
                    new EvidenceItem("Sección", section.Name),
                    new EvidenceItem("Aplicación", appName),
                    new EvidenceItem("Ruta configurada", appPathRaw),
                    new EvidenceItem("Ruta expandida", appPath),
                    new EvidenceItem("Usuarios asignados", FormatAssignments(users)),
                    new EvidenceItem("Grupos asignados", FormatAssignments(groups)),
                    new EvidenceItem("all_users", allUsers)
                ],
                ConfidenceLevel.Alta,
                "TSplus — Application Publishing",
                "https://docs.tsplus.net/tsplus/application-publishing/",
                "Confirme que el ejecutable publicado sigue existiendo y que la ruta configurada en AdminTool corresponde a la aplicación que debe iniciar. No cambie AppControl.ini directamente hasta verificar la asignación.",
                DiagnosticLayer.Tsplus));
        }

        var startup = ExpandPath(startupRaw);
        var startupProbe = !string.IsNullOrWhiteSpace(startupRaw) && Path.IsPathRooted(startup)
            ? FileSystemProbe.Directory(startup) : ProbeResult<bool>.Unavailable("Ruta no aplicable/no absoluta");
        if (!string.IsNullOrWhiteSpace(startupRaw) && Path.IsPathRooted(startup) && startupProbe.IsAbsent)
        {
            findings.Add(new DiagnosticFinding(
                $"TSPLUS-PUBLISHED-APP-STARTUP-{Sanitize(section.Name)}",
                string.IsNullOrWhiteSpace(appName) ? section.Name : appName,
                DiagnosticSeverity.Advertencia,
                "El directorio de inicio configurado para una aplicación publicada no existe.",
                "Una ruta startup inválida puede provocar errores al iniciar la aplicación aunque el ejecutable sí exista.",
                [new EvidenceItem("Archivo", path), new EvidenceItem("Sección", section.Name), new EvidenceItem("Aplicación", appName), new EvidenceItem("Startup", startupRaw)],
                ConfidenceLevel.Alta,
                "TSplus — Application Publishing",
                "https://docs.tsplus.net/tsplus/application-publishing/",
                "Valide en AdminTool la ruta de inicio de la aplicación y confirme que el directorio existe y es accesible para el usuario afectado.",
                DiagnosticLayer.Tsplus));
        }

        if ((appPathProbe.IsUnavailable && !string.IsNullOrWhiteSpace(appPathRaw) && Path.IsPathRooted(appPath))
            || (startupProbe.IsUnavailable && !string.IsNullOrWhiteSpace(startupRaw) && Path.IsPathRooted(startup)))
        {
            findings.Add(new DiagnosticFinding(
                $"TSPLUS-PUBLISHED-APP-COVERAGE-{Sanitize(section.Name)}",
                string.IsNullOrWhiteSpace(appName) ? section.Name : appName,
                DiagnosticSeverity.Advertencia,
                "Una ruta de aplicación publicada quedó NO EVALUADA.",
                "TDM no transforma un fallo de acceso/E/S en ejecutable o directorio ausente.",
                [new EvidenceItem("Ejecutable", appPathProbe.StatusText), new EvidenceItem("Startup", startupProbe.StatusText)],
                ConfidenceLevel.Media, Capa: DiagnosticLayer.Tsplus));
        }

        foreach (var assignment in ParseAssignments(users))
        {
            if (!LooksLocalAssignment(assignment)) continue;
            if (CanResolveAccount(assignment)) continue;
            findings.Add(new DiagnosticFinding(
                $"TSPLUS-PUBLISHED-APP-USER-{Sanitize(section.Name)}-{Sanitize(assignment)}",
                string.IsNullOrWhiteSpace(appName) ? section.Name : appName,
                DiagnosticSeverity.Advertencia,
                "Una asignación local de aplicación TSplus no corresponde a una cuenta Windows resoluble actualmente.",
                "AppControl.ini conserva una asignación a un usuario local que TDM no puede resolver en este servidor. Esto puede ocurrir después de migraciones/cambios de nombre de equipo y puede impedir que el usuario reciba la aplicación esperada.",
                [new EvidenceItem("Archivo", path), new EvidenceItem("Sección", section.Name), new EvidenceItem("Aplicación", appName), new EvidenceItem("Asignación", assignment), new EvidenceItem("Equipo actual", Environment.MachineName)],
                ConfidenceLevel.Media,
                "TSplus Support — AppControl.ini assignments",
                "https://support.tsplus.net/support/solutions/articles/44002059259-are-users-and-groups-saved-when-i-make-a-backup-with-remote-access-",
                "Compare la asignación de AppControl.ini con el usuario real y con AdminTool. Si el equipo fue renombrado o migrado, confirme el prefijo HOST\\usuario antes de modificar la asignación.",
                DiagnosticLayer.Tsplus));
        }

        foreach (var assignment in ParseAssignments(groups))
        {
            if (!LooksLocalAssignment(assignment)) continue;
            if (CanResolveAccount(assignment)) continue;
            findings.Add(new DiagnosticFinding(
                $"TSPLUS-PUBLISHED-APP-GROUP-{Sanitize(section.Name)}-{Sanitize(assignment)}",
                string.IsNullOrWhiteSpace(appName) ? section.Name : appName,
                DiagnosticSeverity.Advertencia,
                "Una asignación local de grupo TSplus no corresponde a una identidad Windows resoluble actualmente.",
                "La aplicación está asociada a un grupo que TDM no puede resolver en este servidor. Si el grupo fue eliminado/renombrado, los usuarios pueden dejar de recibir la aplicación esperada.",
                [new EvidenceItem("Archivo", path), new EvidenceItem("Sección", section.Name), new EvidenceItem("Aplicación", appName), new EvidenceItem("Grupo", assignment)],
                ConfidenceLevel.Media,
                "TSplus — Application assignment",
                "https://docs.tsplus.net/tsplus/assigning-applications-to-users-or-groups/",
                "Confirme el grupo en Windows/Active Directory y la asignación en AdminTool antes de modificar AppControl.ini.",
                DiagnosticLayer.Tsplus));
        }

        // Sólo inventario. La existencia de una aplicación sin usuarios/grupos no es por sí sola una falla.
        events.Add(new DiagnosticEvent(
            DateTimeOffset.Now,
            "TSplus Config",
            string.IsNullOrWhiteSpace(appName) ? section.Name : appName,
            DiagnosticLayer.Tsplus,
            DiagnosticSeverity.Informativo,
            "TSPLUS_PUBLISHED_APPLICATION",
            "Aplicación publicada observada en AppControl.ini.",
            Archivo: path,
            Evidencia:
            [
                new EvidenceItem("Sección", section.Name),
                new EvidenceItem("Aplicación", string.IsNullOrWhiteSpace(appName) ? "N/D" : appName),
                new EvidenceItem("Ruta", string.IsNullOrWhiteSpace(appPathRaw) ? "N/D / launcher interno" : appPathRaw),
                new EvidenceItem("Startup", string.IsNullOrWhiteSpace(startupRaw) ? "N/D" : startupRaw),
                new EvidenceItem("CmdLine", string.IsNullOrWhiteSpace(cmdLine) ? "N/D" : cmdLine),
                new EvidenceItem("Usuarios asignados", FormatAssignments(users)),
                new EvidenceItem("Grupos asignados", FormatAssignments(groups)),
                new EvidenceItem("all_users", string.IsNullOrWhiteSpace(allUsers) ? "N/D" : allUsers)
            ],
            Producto: TsplusProduct.RemoteAccess));
    }

    private static void AuditWebConfiguration(
        string install,
        bool enforceKnownFiles,
        List<DiagnosticFinding> findings,
        List<DiagnosticEvent> events,
        CancellationToken ct)
    {
        var webRoot = Path.Combine(install, "Clients", "www");
        var webServer = Path.Combine(install, "Clients", "webserver");
        var webPortal = Path.Combine(install, "Clients", "webportal");
        var settingsJs = Path.Combine(webRoot, "software", "html5", "settings.js");
        var webRootProbe = FileSystemProbe.Directory(webRoot);
        var webServerProbe = FileSystemProbe.Directory(webServer);
        var webPortalProbe = FileSystemProbe.Directory(webPortal);
        var settingsJsProbe = FileSystemProbe.File(settingsJs);

        if (webRootProbe.IsAvailable)
        {
            if (settingsJsProbe.IsAvailable)
            {
                try
                {
                    var fi = new FileInfo(settingsJs);
                    if (fi.Length == 0)
                    {
                        findings.Add(new DiagnosticFinding(
                            "TSPLUS-WEB-SETTINGSJS-EMPTY",
                            "TSplus Web / HTML5",
                            DiagnosticSeverity.Error,
                            "settings.js existe pero tiene tamaño 0 bytes.",
                            "El archivo contiene parámetros del cliente HTML5. Un archivo vacío es una inconsistencia física y requiere correlación con el runtime Web/HTML5 antes de declararlo causa raíz.",
                            [new EvidenceItem("Archivo", settingsJs), new EvidenceItem("Tamaño", "0")],
                            ConfidenceLevel.Alta,
                            "TSplus — HTML Pages and Customization / settings.js",
                            "https://docs.tsplus.net/tsplus/html-pages-and-customization/",
                            "Compare el archivo con una instalación sana de la misma rama y utilice herramientas oficiales de actualización/reparación antes de editarlo manualmente.",
                            DiagnosticLayer.Tsplus));
                    }

                    var preview = fi.Length <= MaxConfigBytes
                        ? File.ReadAllText(settingsJs)
                        : string.Join(Environment.NewLine, File.ReadLines(settingsJs).Take(2000));
                    var recognizable = preview.Contains("W.", StringComparison.Ordinal) ||
                                       preview.Contains("clipboard", StringComparison.OrdinalIgnoreCase) ||
                                       preview.Contains("playsound", StringComparison.OrdinalIgnoreCase) ||
                                       preview.Contains("full_screen", StringComparison.OrdinalIgnoreCase);

                    events.Add(new DiagnosticEvent(
                        DateTimeOffset.Now,
                        "TSplus Config",
                        "TSplus HTML5 / settings.js",
                        DiagnosticLayer.Tsplus,
                        DiagnosticSeverity.Informativo,
                        "TSPLUS_WEB_SETTINGS_JS_STATE",
                        recognizable
                            ? "settings.js está presente, legible y contiene parámetros HTML5 reconocibles."
                            : "settings.js está presente y legible; TDM no reconoció parámetros de su lista conservadora y reduce la interpretación semántica sin declararlo falla.",
                        Archivo: settingsJs,
                        Evidencia:
                        [
                            new EvidenceItem("Archivo", settingsJs),
                            new EvidenceItem("Tamaño", fi.Length.ToString()),
                            new EvidenceItem("Última modificación", fi.LastWriteTime.ToString("O")),
                            new EvidenceItem("Parámetros reconocibles", recognizable ? "Sí" : "No determinado")
                        ],
                        Producto: TsplusProduct.RemoteAccess));
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    findings.Add(new DiagnosticFinding(
                        "TSPLUS-WEB-SETTINGSJS-READ",
                        "TSplus Web / HTML5",
                        DiagnosticSeverity.Advertencia,
                        "No fue posible leer settings.js.",
                        ex.Message,
                        [new EvidenceItem("Archivo", settingsJs)],
                        ConfidenceLevel.Media,
                        Capa: DiagnosticLayer.Tsplus));
                }
            }
            else if (settingsJsProbe.IsUnavailable)
            {
                findings.Add(new DiagnosticFinding(
                    "TSPLUS-WEB-SETTINGSJS-NOT-EVALUATED",
                    "TSplus Web / HTML5",
                    DiagnosticSeverity.Advertencia,
                    "No fue posible comprobar settings.js.",
                    "La fuente queda como NO EVALUADA; un error de permisos o E/S no se interpreta como archivo ausente ni como Web saludable.",
                    [new EvidenceItem("Archivo", settingsJs), new EvidenceItem("Cobertura", settingsJsProbe.StatusText), new EvidenceItem("Detalle", settingsJsProbe.Detail ?? "N/D")],
                    ConfidenceLevel.Confirmada,
                    Capa: DiagnosticLayer.Tsplus));
            }
            else if (enforceKnownFiles)
            {
                findings.Add(new DiagnosticFinding(
                    "TSPLUS-WEB-SETTINGSJS-MISSING",
                    "TSplus Web / HTML5",
                    DiagnosticSeverity.Error,
                    "No se encontró settings.js aunque el árbol Web de TSplus está presente.",
                    "settings.js es una fuente principal de configuración del cliente HTML5. TDM conserva esta inconsistencia como Error, pero la causa raíz exige correlación con listener, runtime, logs o impacto Web.",
                    [new EvidenceItem("Ruta esperada", settingsJs)],
                    ConfidenceLevel.Alta,
                    "TSplus — HTML Pages and Customization / settings.js",
                    "https://docs.tsplus.net/tsplus/html-pages-and-customization/",
                    "Compare con una instalación sana de la misma rama y repare/actualice TSplus usando herramientas oficiales antes de crear el archivo manualmente.",
                    DiagnosticLayer.Tsplus));
            }
        }
        else if (webRootProbe.IsUnavailable)
        {
            findings.Add(new DiagnosticFinding(
                "TSPLUS-WEB-ROOT-NOT-EVALUATED",
                "TSplus Web / HTML5",
                DiagnosticSeverity.Advertencia,
                @"No fue posible comprobar el árbol Clients\www de TSplus.",
                "La cobertura Web queda parcial; TDM no convierte un fallo de acceso/E/S en ausencia de módulo.",
                [new EvidenceItem("Ruta", webRoot), new EvidenceItem("Cobertura", webRootProbe.StatusText), new EvidenceItem("Detalle", webRootProbe.Detail ?? "N/D")],
                ConfidenceLevel.Confirmada,
                Capa: DiagnosticLayer.Tsplus));
        }

        var appSettingsCandidates = new List<string>
        {
            Path.Combine(webPortal, "appsettings.json"),
            Path.Combine(webRoot, "appsettings.json")
        };

        foreach (var jsonPath in appSettingsCandidates.Distinct(StringComparer.OrdinalIgnoreCase).Where(path => FileSystemProbe.File(path).IsAvailable))
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var stream = File.Open(jsonPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                using var _ = JsonDocument.Parse(stream, new JsonDocumentOptions { AllowTrailingCommas = true, CommentHandling = JsonCommentHandling.Skip });
                events.Add(new DiagnosticEvent(DateTimeOffset.Now, "TSplus Config", "TSplus Web Portal", DiagnosticLayer.Tsplus,
                    DiagnosticSeverity.Informativo, "TSPLUS_WEB_JSON_VALID", "Configuración JSON del portal web legible y sintácticamente válida.", Archivo: jsonPath,
                    Evidencia: [new EvidenceItem("Archivo", jsonPath)], Producto: TsplusProduct.RemoteAccess));
            }
            catch (JsonException ex)
            {
                findings.Add(new DiagnosticFinding(
                    $"TSPLUS-WEB-CONFIG-INVALID-{Sanitize(Path.GetFileName(jsonPath))}",
                    "TSplus Web Portal",
                    DiagnosticSeverity.Error,
                    "Se detectó una configuración JSON inválida en el portal web de TSplus.",
                    "Una configuración JSON corrupta puede impedir que el portal/HTML5 cargue correctamente o que aplique sus parámetros.",
                    [new EvidenceItem("Archivo", jsonPath), new EvidenceItem("Línea", ex.LineNumber?.ToString() ?? "N/D"), new EvidenceItem("Posición", ex.BytePositionInLine?.ToString() ?? "N/D")],
                    ConfidenceLevel.Alta,
                    "TSplus Documentation — Web Portal",
                    "https://docs.tsplus.net/tsplus/quickstart-guide/",
                    "Compare el archivo con una configuración válida de la misma versión o repare la configuración desde las herramientas oficiales de TSplus; no edite a ciegas el JSON en producción.",
                    DiagnosticLayer.Tsplus));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                findings.Add(new DiagnosticFinding(
                    $"TSPLUS-WEB-CONFIG-READ-{Sanitize(Path.GetFileName(jsonPath))}",
                    "TSplus Web Portal",
                    DiagnosticSeverity.Advertencia,
                    "No fue posible validar una configuración del portal web.",
                    ex.Message,
                    [new EvidenceItem("Archivo", jsonPath)],
                    ConfidenceLevel.Media,
                    Capa: DiagnosticLayer.Tsplus));
            }
        }

        // settings.bin contiene opciones de comportamiento del web server. TDM sólo expone una lista blanca
        // de parámetros conocidos y nunca interpreta claves desconocidas como error por sí solas.
        var settings = FindWebArtifact(install, Path.Combine(webServer, "settings.bin"), "settings.bin", "webserver");
        if (!string.IsNullOrWhiteSpace(settings) && FileSystemProbe.File(settings).IsAvailable)
        {
            try
            {
                var lines = File.ReadLines(settings).Take(5000).ToList();
                var known = ParseKnownWebSettings(lines);
                events.Add(new DiagnosticEvent(DateTimeOffset.Now, "TSplus Config", "TSplus Web Server", DiagnosticLayer.Tsplus,
                    DiagnosticSeverity.Informativo, "TSPLUS_WEB_SETTINGS_STATE",
                    "Parámetros conocidos de settings.bin capturados en modo de solo lectura.", Archivo: settings,
                    Evidencia: known.Count == 0
                        ? [new EvidenceItem("Archivo", settings), new EvidenceItem("Parámetros conocidos", "Ninguno detectado")]
                        : [new EvidenceItem("Archivo", settings), .. known.Select(kv => new EvidenceItem(kv.Key, kv.Value.LastOrDefault() ?? "N/D"))],
                    Producto: TsplusProduct.RemoteAccess));

                foreach (var kv in known.Where(x => x.Value.Distinct(StringComparer.OrdinalIgnoreCase).Count() > 1))
                {
                    findings.Add(new DiagnosticFinding(
                        $"TSPLUS-WEB-CONFIG-CONFLICT-{Sanitize(kv.Key)}",
                        "TSplus Web Server",
                        DiagnosticSeverity.Advertencia,
                        $"settings.bin contiene valores distintos repetidos para '{kv.Key}'.",
                        "TDM no puede determinar cuál valor prevalece sin aplicar la semántica interna de la versión instalada. La ambigüedad debe revisarse si coincide con un síntoma Web/HTML5.",
                        [new EvidenceItem("Archivo", settings), new EvidenceItem("Parámetro", kv.Key), new EvidenceItem("Valores", string.Join(" | ", kv.Value.Distinct(StringComparer.OrdinalIgnoreCase)))],
                        ConfidenceLevel.Media,
                        "TSplus Documentation — Built-in Web Server / settings.bin",
                        "https://docs.tsplus.net/tsplus/enforce-https/",
                        "Valide el parámetro desde AdminTool/documentación de la misma versión antes de cambiar settings.bin.",
                        DiagnosticLayer.Tsplus));
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                findings.Add(new DiagnosticFinding(
                    "TSPLUS-WEB-CONFIG-SETTINGS-READ",
                    "TSplus Web Server",
                    DiagnosticSeverity.Advertencia,
                    "No fue posible leer settings.bin.",
                    ex.Message,
                    [new EvidenceItem("Archivo", settings)],
                    ConfidenceLevel.Media,
                    Capa: DiagnosticLayer.Tsplus));
            }
        }

        var balance = FindWebArtifact(install, Path.Combine(webServer, "balance.bin"), "balance.bin", "webserver", "farm", "balance");
        if (!string.IsNullOrWhiteSpace(balance) && FileSystemProbe.File(balance).IsAvailable)
        {
            try
            {
                var routes = File.ReadLines(balance)
                    .Select(l => l.Trim())
                    .Where(l => !string.IsNullOrWhiteSpace(l) && !l.StartsWith("#") && !l.StartsWith(";"))
                    .Take(1000)
                    .ToList();
                var malformed = routes.Where(l => l.StartsWith("/~~", StringComparison.Ordinal) && (!l.Contains('=') || !l.Contains(':'))).Take(20).ToList();
                events.Add(new DiagnosticEvent(DateTimeOffset.Now, "TSplus Config", "TSplus Reverse Proxy / Load Balancing", DiagnosticLayer.Tsplus,
                    malformed.Count == 0 ? DiagnosticSeverity.Informativo : DiagnosticSeverity.Advertencia,
                    "TSPLUS_WEB_BALANCE_STATE",
                    malformed.Count == 0 ? $"balance.bin legible; {routes.Count} ruta(s) observadas." : $"balance.bin contiene {malformed.Count} ruta(s) con sintaxis básica no reconocida.",
                    Archivo: balance,
                    Evidencia: [new EvidenceItem("Archivo", balance), new EvidenceItem("Rutas", routes.Count.ToString()), new EvidenceItem("Rutas sospechosas", malformed.Count.ToString())],
                    Producto: TsplusProduct.RemoteAccess));

                if (malformed.Count > 0)
                {
                    findings.Add(new DiagnosticFinding(
                        "TSPLUS-WEB-CONFIG-BALANCE-MALFORMED",
                        "TSplus Reverse Proxy / Load Balancing",
                        DiagnosticSeverity.Advertencia,
                        "balance.bin contiene rutas cuya sintaxis básica no pudo validarse.",
                        "Una entrada de gateway/load-balancing mal formada puede dirigir incorrectamente una conexión o aplicación. TDM no la declara causal sin un síntoma Web/Gateway compatible en la misma ventana.",
                        [new EvidenceItem("Archivo", balance), new EvidenceItem("Rutas sospechosas", malformed.Count.ToString()), new EvidenceItem("Ejemplo", malformed[0])],
                        ConfidenceLevel.Media,
                        Capa: DiagnosticLayer.Tsplus));
                }
            }
            catch { }
        }

        events.Add(new DiagnosticEvent(
            DateTimeOffset.Now, "TDM", "TSplus Web Stack", DiagnosticLayer.Tsplus, DiagnosticSeverity.Informativo,
            "TSPLUS_WEB_STACK_STATE", "Estado de rutas principales del servidor/portal web capturado.",
            Evidencia:
            [
                new EvidenceItem("Clients\\www", FileSystemProbe.Display(FileSystemProbe.Directory(webRoot))),
                new EvidenceItem("Clients\\webserver", FileSystemProbe.Display(FileSystemProbe.Directory(webServer))),
                new EvidenceItem("Clients\\webportal", FileSystemProbe.Display(FileSystemProbe.Directory(webPortal)))
            ],
            Producto: TsplusProduct.RemoteAccess));
    }

    private static void AuditAppControlSecurity(
        IReadOnlyList<IniSection> sections,
        string path,
        List<DiagnosticFinding> findings,
        List<DiagnosticEvent> events)
    {
        var security = sections.Where(s => s.Name.Equals("Security", StringComparison.OrdinalIgnoreCase)).ToList();
        if (security.Count == 0) return;

        var values = security.SelectMany(s => s.Values)
            .GroupBy(v => v.Key, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.Select(x => x.Value.Trim()).ToList(), StringComparer.OrdinalIgnoreCase);
        string Last(string key) => values.TryGetValue(key, out var list) && list.Count > 0 ? list[^1] : "N/D";

        var evidence = new List<EvidenceItem>
        {
            new("Archivo", path),
            new("alwaydesktop", Last("alwaydesktop")),
            new("Block_rdp_splitter", Last("Block_rdp_splitter"))
        };
        events.Add(new DiagnosticEvent(DateTimeOffset.Now, "TSplus Config", "Application Control / Security", DiagnosticLayer.Tsplus,
            DiagnosticSeverity.Informativo, "TSPLUS_APPCONTROL_SECURITY_STATE",
            "Opciones conocidas de comportamiento de sesión/publicación capturadas.", Archivo: path, Evidencia: evidence, Producto: TsplusProduct.RemoteAccess));

        foreach (var key in new[] { "alwaydesktop", "Block_rdp_splitter" })
        {
            if (!values.TryGetValue(key, out var configured)) continue;
            var value = configured.LastOrDefault() ?? string.Empty;
            if (IsBooleanLike(value)) continue;
            findings.Add(new DiagnosticFinding(
                $"TSPLUS-APPCONTROL-INVALID-{Sanitize(key)}",
                "TSplus Application Control",
                DiagnosticSeverity.Advertencia,
                $"El parámetro '{key}' tiene un valor no reconocible.",
                "El parámetro influye en el comportamiento de escritorio/publicación. TDM no adivina cómo lo interpretará una versión concreta si el valor no es booleano reconocible.",
                [new EvidenceItem("Archivo", path), new EvidenceItem("Parámetro", key), new EvidenceItem("Valor", value)],
                ConfidenceLevel.Media,
                "TSplus Documentation / Support — AppControl.ini",
                "https://docs.tsplus.net/tsplus/enforce-web-portal/",
                "Confirme el valor esperado en AdminTool o en la documentación correspondiente a la versión instalada.",
                DiagnosticLayer.Tsplus));
        }
    }

    private static void AuditWebRuntime(
        string install,
        DiagnosticContext context,
        List<DiagnosticFinding> findings,
        List<DiagnosticEvent> events,
        CancellationToken ct)
    {
        var expectedWebServer = Path.Combine(install, "Clients", "webserver");
        var runBat = FindWebArtifact(install, Path.Combine(expectedWebServer, "runwebserver.bat"), "runwebserver.bat", "webserver");
        var jar = FindWebArtifact(install, Path.Combine(expectedWebServer, "httpwebs.jar"), "httpwebs.jar", "webserver", "html5");
        var webServer = !string.IsNullOrWhiteSpace(runBat) ? Path.GetDirectoryName(runBat)!
            : !string.IsNullOrWhiteSpace(jar) ? Path.GetDirectoryName(jar)!
            : expectedWebServer;
        var webServerDirectoryProbe = FileSystemProbe.Directory(webServer);
        if (webServerDirectoryProbe.IsAbsent && string.IsNullOrWhiteSpace(runBat) && string.IsNullOrWhiteSpace(jar)) return;
        if (webServerDirectoryProbe.IsUnavailable && string.IsNullOrWhiteSpace(runBat) && string.IsNullOrWhiteSpace(jar))
        {
            findings.Add(new DiagnosticFinding(
                "TSPLUS-WEB-RUNTIME-NOT-EVALUATED",
                "TSplus HTML5 / Web Server",
                DiagnosticSeverity.Advertencia,
                "No fue posible comprobar el directorio del runtime Web/HTML5.",
                "La cobertura queda como NO EVALUADA; no se infiere que el Web Server esté ausente o detenido.",
                [new EvidenceItem("Ruta", webServer), new EvidenceItem("Cobertura", webServerDirectoryProbe.StatusText), new EvidenceItem("Detalle", webServerDirectoryProbe.Detail ?? "N/D")],
                ConfidenceLevel.Confirmada,
                Capa: DiagnosticLayer.Tsplus));
            return;
        }
        string javaExe = string.Empty;
        int? httpPort = null;
        int? httpsPort = null;

        if (!string.IsNullOrWhiteSpace(runBat) && FileSystemProbe.File(runBat).IsAvailable)
        {
            try
            {
                var info = new FileInfo(runBat!);
                var content = info.Length <= 512 * 1024 ? File.ReadAllText(runBat!) : string.Join(Environment.NewLine, File.ReadLines(runBat!).Take(200));
                var javaMatch = WebJavaExecutableRegex().Match(content);
                if (javaMatch.Success) javaExe = Environment.ExpandEnvironmentVariables(javaMatch.Groups["path"].Value);
                var portsMatch = WebServerPortsRegex().Match(content);
                if (portsMatch.Success)
                {
                    if (int.TryParse(portsMatch.Groups["http"].Value, out var hp)) httpPort = hp;
                    if (int.TryParse(portsMatch.Groups["https"].Value, out var sp)) httpsPort = sp;
                }

                var javaProbe = string.IsNullOrWhiteSpace(javaExe) ? ProbeResult<bool>.Unavailable("Ruta Java no determinada") : FileSystemProbe.File(javaExe);
                if (!string.IsNullOrWhiteSpace(javaExe) && javaProbe.IsAbsent)
                {
                    findings.Add(new DiagnosticFinding(
                        "TSPLUS-WEB-RUNTIME-JAVA-MISSING",
                        "TSplus HTML5 / Web Server",
                        DiagnosticSeverity.Error,
                        "runwebserver.bat apunta a un ejecutable Java/HTML5service que no existe.",
                        "El gateway HTML5 no puede iniciar correctamente si el ejecutable configurado en su comando de arranque ya no existe.",
                        [new EvidenceItem("Archivo", runBat!), new EvidenceItem("Ejecutable configurado", javaExe)],
                        ConfidenceLevel.Alta,
                        "TSplus Support — HTML5 gateway startup parameters",
                        "https://support.tsplus.net/support/solutions/articles/44000038439-how-to-change-default-starting-parameters-of-html5-gateway-",
                        "Confirme desde AdminTool la versión/ruta de Java incluida por TSplus y regenere la configuración mediante las herramientas oficiales antes de editar manualmente el batch.",
                        DiagnosticLayer.Tsplus));
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                findings.Add(new DiagnosticFinding(
                    "TSPLUS-WEB-RUNTIME-BAT-READ",
                    "TSplus HTML5 / Web Server",
                    DiagnosticSeverity.Advertencia,
                    "No fue posible auditar runwebserver.bat.",
                    ex.Message,
                    [new EvidenceItem("Archivo", runBat!)],
                    ConfidenceLevel.Media,
                    Capa: DiagnosticLayer.Tsplus));
            }
        }

        // Coherencia interna: HTTP y HTTPS en el mismo puerto es una configuración inválida
        // (un solo listener no puede servir ambos esquemas en el mismo puerto).
        if (httpPort.HasValue && httpsPort.HasValue && httpPort.Value == httpsPort.Value)
        {
            findings.Add(new DiagnosticFinding(
                "TSPLUS-WEB-PORTS-DUPLICATE",
                "TSplus HTML5 / Web Server",
                DiagnosticSeverity.Advertencia,
                $"HTTP y HTTPS están configurados en el mismo puerto ({httpPort}).",
                "Un único puerto no puede servir ambos esquemas a la vez; una de las dos vías quedará inoperativa. TDM no modifica la configuración.",
                [new EvidenceItem("Puerto HTTP", httpPort.Value.ToString()), new EvidenceItem("Puerto HTTPS", httpsPort.Value.ToString())],
                ConfidenceLevel.Media,
                Capa: DiagnosticLayer.Tsplus));
        }

        var runBatProbe = string.IsNullOrWhiteSpace(runBat) ? ProbeResult<bool>.Absent() : FileSystemProbe.File(runBat);
        var jarProbe = string.IsNullOrWhiteSpace(jar) ? FileSystemProbe.File(Path.Combine(expectedWebServer, "httpwebs.jar")) : FileSystemProbe.File(jar);
        if (runBatProbe.IsAvailable && jarProbe.IsAbsent)
        {
            findings.Add(new DiagnosticFinding(
                "TSPLUS-WEB-RUNTIME-JAR-MISSING",
                "TSplus HTML5 / Web Server",
                DiagnosticSeverity.Error,
                "El gateway HTML5 tiene script de arranque pero no se encontró httpwebs.jar.",
                "El archivo forma parte del comando de arranque observado del servidor HTML5. Su ausencia es una inconsistencia interna que puede impedir iniciar el portal/gateway.",
                [new EvidenceItem("runwebserver.bat", runBat ?? Path.Combine(expectedWebServer, "runwebserver.bat")), new EvidenceItem("httpwebs.jar", jar ?? Path.Combine(expectedWebServer, "httpwebs.jar"))],
                ConfidenceLevel.Alta,
                "TSplus Support — HTML5 gateway startup parameters",
                "https://support.tsplus.net/support/solutions/articles/44000038439-how-to-change-default-starting-parameters-of-html5-gateway-",
                "Compare la instalación con el paquete oficial de la misma versión y repare/actualice TSplus si se confirma que el archivo falta.",
                DiagnosticLayer.Tsplus));
        }

        var listenerEvidence = new List<EvidenceItem>();
        var webListenerOk = false;
        foreach (var port in new[] { httpPort, httpsPort }.Where(p => p.HasValue).Select(p => p!.Value).Distinct())
        {
            var owner = TcpListenerOwnershipProbe.Probe(port, install, javaExe);
            listenerEvidence.Add(new EvidenceItem($"Puerto {port} / propietario", owner.EvidenceText));

            if (owner.State == TcpListenerOwnershipState.NoListener)
            {
                findings.Add(new DiagnosticFinding(
                    $"TSPLUS-WEB-PORT-NOT-LISTENING-{port}",
                    "TSplus HTML5 / Web Server",
                    DiagnosticSeverity.Advertencia,
                    $"El puerto web {port} aparece configurado en runwebserver.bat pero no se observó un listener TCP durante la captura.",
                    "Esto puede indicar que el gateway/servidor web no está iniciado, cayó o que la arquitectura usa un servidor web/proxy externo. Se requiere correlación con weblog.txt y eventos del proceso antes de declararlo causa.",
                    [new EvidenceItem("Puerto", port.ToString()), new EvidenceItem("Archivo", runBat ?? "N/D")],
                    ConfidenceLevel.Media,
                    "TSplus Documentation — Built-in Web Server",
                    "https://docs.tsplus.net/tsplus/built-in-web-server/",
                    "Revise el estado del Web Server en AdminTool y los logs del gateway. No abra/cierre puertos ni reinicie servicios automáticamente desde TDM.",
                    DiagnosticLayer.Tsplus));
            }
            else if (owner.State == TcpListenerOwnershipState.OtherProcess)
            {
                findings.Add(new DiagnosticFinding(
                    $"TSPLUS-WEB-PORT-OWNED-BY-OTHER-{port}",
                    "TSplus HTML5 / Web Server",
                    DiagnosticSeverity.Advertencia,
                    $"El puerto web {port} está ocupado por un proceso que no pudo relacionarse con el runtime TSplus esperado.",
                    "Un listener ajeno puede ocultar una caída del Web Server si sólo se valida el número de puerto. TDM conserva el PID/proceso observado y exige correlación antes de declarar saludable el módulo.",
                    [new EvidenceItem("Puerto", port.ToString()), new EvidenceItem("Propietario", owner.Detail)],
                    ConfidenceLevel.Alta,
                    Capa: DiagnosticLayer.Tsplus));
            }
            else if (owner.State is TcpListenerOwnershipState.OwnerUnknown or TcpListenerOwnershipState.NotEvaluated)
            {
                findings.Add(new DiagnosticFinding(
                    $"TSPLUS-WEB-PORT-OWNER-NOT-EVALUATED-{port}",
                    "TSplus HTML5 / Web Server",
                    DiagnosticSeverity.Advertencia,
                    $"El listener del puerto {port} no pudo atribuirse con certeza al runtime TSplus.",
                    "La presencia de un puerto abierto no se interpreta como salud del módulo cuando el proceso propietario no puede comprobarse.",
                    [new EvidenceItem("Puerto", port.ToString()), new EvidenceItem("Estado", owner.EvidenceText)],
                    ConfidenceLevel.Confirmada,
                    Capa: DiagnosticLayer.Tsplus));
            }
            if (owner.State == TcpListenerOwnershipState.ExpectedProcess) webListenerOk = true;
        }

        // Coherencia interna: portal configurado (al menos un puerto) pero completamente sordo.
        // Los avisos por puerto ya existen; este hallazgo declara el estado del módulo Web/HTML5.
        if ((httpPort.HasValue || httpsPort.HasValue) && !webListenerOk)
        {
            findings.Add(new DiagnosticFinding(
                "TSPLUS-WEB-CONFIG-NOLISTEN",
                "TSplus HTML5 / Web Server",
                DiagnosticSeverity.Error,
                "El portal web está configurado pero ningún puerto configurado tiene listener del runtime TSplus.",
                "Sin listener operativo el portal no puede aceptar conexiones aunque la configuración exista. Verifique en AdminTool si el Web Server está iniciado o si se usa un proxy/servidor externo de forma intencional. TDM no inicia servicios ni abre puertos.",
                [
                    new EvidenceItem("Puerto HTTP configurado", httpPort?.ToString() ?? "N/D"),
                    new EvidenceItem("Puerto HTTPS configurado", httpsPort?.ToString() ?? "N/D")
                ],
                ConfidenceLevel.Alta,
                "TSplus Documentation — Built-in Web Server",
                "https://docs.tsplus.net/tsplus/built-in-web-server/",
                "Revise el estado del Web Server en AdminTool y los logs del gateway antes de reinstalar.",
                DiagnosticLayer.Tsplus));
        }

        var runtimeEvidence = new List<EvidenceItem>
        {
            new("runwebserver.bat", FileSystemProbe.Display(runBatProbe, $"Presente: {runBat}", "No presente en el árbol TSplus")),
            new("Ejecutable Java/HTML5service", string.IsNullOrWhiteSpace(javaExe) ? "No determinado" : javaExe),
            new("Ejecutable existe", string.IsNullOrWhiteSpace(javaExe) ? "No determinado" : FileSystemProbe.Display(FileSystemProbe.File(javaExe), "Sí", "No")),
            new("httpwebs.jar", FileSystemProbe.Display(jarProbe, $"Presente: {jar}", "No presente en el árbol TSplus")),
            new("Puerto HTTP configurado", httpPort?.ToString() ?? "No determinado"),
            new("Puerto HTTPS configurado", httpsPort?.ToString() ?? "No determinado")
        };
        runtimeEvidence.AddRange(listenerEvidence);
        events.Add(new DiagnosticEvent(DateTimeOffset.Now, "TDM", "TSplus HTML5 / Web Server", DiagnosticLayer.Tsplus,
            DiagnosticSeverity.Informativo, "TSPLUS_WEB_RUNTIME_STATE", "Estado local del runtime HTML5 capturado.",
            Evidencia: runtimeEvidence, Producto: TsplusProduct.RemoteAccess));

        // Crash reports JVM/HTML5 ya existentes: la fecha del archivo permite correlación temporal sin habilitar dumps.
        try
        {
            var from = (context.HoraIncidente ?? DateTimeOffset.Now) - context.Lookback;
            var to = context.HoraIncidente ?? DateTimeOffset.Now;
            foreach (var crash in Directory.EnumerateFiles(webServer, "hs_err_pid*.log", SearchOption.TopDirectoryOnly).Take(50))
            {
                ct.ThrowIfCancellationRequested();
                var fi = new FileInfo(crash);
                var ts = new DateTimeOffset(fi.LastWriteTime);
                if (ts < from || ts > to) continue;
                events.Add(new DiagnosticEvent(ts, "TSplus HTML5 JVM", "TSplus HTML5 / Web Server", DiagnosticLayer.Tsplus,
                    DiagnosticSeverity.Error, "TSPLUS_HTML5_JVM_CRASH",
                    "Se encontró un reporte de crash de la JVM/HTML5 dentro de la ventana analizada.", Archivo: crash,
                    Evidencia: [new EvidenceItem("Archivo", crash), new EvidenceItem("Última modificación", fi.LastWriteTime.ToString("O")), new EvidenceItem("Tamaño", fi.Length.ToString())],
                    Producto: TsplusProduct.RemoteAccess));
                findings.Add(new DiagnosticFinding(
                    $"TSPLUS-WEB-JVM-CRASH-{Sanitize(fi.Name)}", "TSplus HTML5 / Web Server", DiagnosticSeverity.Error,
                    "Existe evidencia local de un crash del runtime Java/HTML5 dentro del periodo analizado.",
                    "El reporte hs_err_pid es evidencia independiente de que el proceso JVM/HTML5 sufrió una caída. TDM aún debe correlacionar el contenido/logs con el síntoma para determinar por qué cayó.",
                    [new EvidenceItem("Archivo", crash), new EvidenceItem("Hora", ts.ToLocalTime().ToString("dd/MM/yyyy HH:mm:ss"))],
                    ConfidenceLevel.Alta,
                    "TSplus Support — HTML5 gateway crash",
                    "https://support.tsplus.net/support/solutions/articles/44000038557-what-to-do-when-html5-gateway-stops-or-crashes-",
                    "Revise el reporte hs_err_pid y weblog.txt; valide memoria/Java/runtime antes de intervenir RDP o perfiles.",
                    DiagnosticLayer.Tsplus));
            }
        }
        catch { }
    }

    private static Dictionary<string, List<string>> ParseKnownWebSettings(IEnumerable<string> lines)
    {
        var allow = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "disable_http_only", "disable_ssl_on_http", "disable_http_on_https", "disable_rdp",
            "avoid_disable_rule_of_local_rdp_on_rdg", "logon_type_allowance", "disable_internet_servers",
            "allow_http_while_no_ssl",
            // TSplus documenta estas comprobaciones para escenarios con proxies/load balancers personalizados.
            // TDM sólo muestra su estado; un valor false no se considera error por sí solo.
            "ip_equality_check", "websockets_origin_host_match", "x_ip_forward_header_match",
            "approve_by_client_cookie", "approve_by_cookie", "browser_user_agent_check",
            "timing_equality_check", "page_refresh_from_same_ip", "jwng_referer_required",
            "download_folder_any_referer_required", "download_by_iframe_referer_required",
            "check_ticket_referer", "check_cgi_referer"
        };
        var result = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var raw in lines)
        {
            var line = raw.Trim();
            if (string.IsNullOrWhiteSpace(line) || line.StartsWith('#') || line.StartsWith(';')) continue;
            var idx = line.IndexOf('=');
            if (idx <= 0) continue;
            var key = line[..idx].Trim();
            if (!allow.Contains(key)) continue;
            var value = line[(idx + 1)..].Trim();
            if (!result.TryGetValue(key, out var values)) result[key] = values = [];
            values.Add(value);
        }
        return result;
    }

    private static bool IsBooleanLike(string value)
    {
        var v = value.Trim().Trim('"', '\'').ToLowerInvariant();
        return v is "yes" or "no" or "true" or "false" or "1" or "0" or "si" or "sí";
    }

    private static void AuditSensitiveMetadataOnly(string install, List<DiagnosticEvent> events)
    {
        foreach (var path in new[]
        {
            Path.Combine(install, "UserDesktop", "files", "webcredentials.ini"),
            Path.Combine(install, "UserDesktop", "files", "webcredentials1.ini"),
            Path.Combine(install, "Clients", "www", "webcredentials.ini"),
            Path.Combine(install, "Clients", "www", "webcredentials1.ini")
        }.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (!FileSystemProbe.File(path).IsAvailable) continue;
            try
            {
                var f = new FileInfo(path);
                events.Add(new DiagnosticEvent(DateTimeOffset.Now, "TDM", "TSplus Web Credentials", DiagnosticLayer.Tsplus,
                    DiagnosticSeverity.Informativo, "TSPLUS_SENSITIVE_CONFIG_PRESENT",
                    "Archivo sensible TSplus detectado. TDM conserva sólo metadatos y no lee ni exporta credenciales.",
                    Archivo: path,
                    Evidencia: [new EvidenceItem("Archivo", path), new EvidenceItem("Tamaño", f.Length.ToString()), new EvidenceItem("Última modificación", f.LastWriteTime.ToString("O"))],
                    Producto: TsplusProduct.RemoteAccess));
            }
            catch { }
        }
    }

    private static List<IniSection> ParseIni(IReadOnlyList<string> lines, CancellationToken ct)
    {
        var result = new List<IniSection>();
        IniSection? current = null;
        for (var i = 0; i < lines.Count; i++)
        {
            ct.ThrowIfCancellationRequested();
            var raw = lines[i];
            var line = raw.Trim();
            if (string.IsNullOrWhiteSpace(line) || line.StartsWith(';') || line.StartsWith('#')) continue;
            if (line.StartsWith('[') && line.EndsWith(']') && line.Length > 2)
            {
                current = new IniSection(line[1..^1].Trim(), i + 1);
                result.Add(current);
                continue;
            }
            if (current is null) continue;
            var idx = line.IndexOf('=');
            if (idx <= 0) continue;
            var key = line[..idx].Trim();
            var value = line[(idx + 1)..];
            current.Values.Add(new KeyValuePair<string, string>(key, value));
        }
        return result;
    }

    private static DiagnosticFinding ConfigFinding(string id, DiagnosticSeverity severity, string summary, string detail, string path, ConfidenceLevel confidence) =>
        new(id, "TSplus Configuration", severity, summary, detail, [new EvidenceItem("Archivo", path)], confidence, Capa: DiagnosticLayer.Tsplus);

    private static string ExpandPath(string value)
    {
        try { return Environment.ExpandEnvironmentVariables(value.Trim().Trim('"')); }
        catch { return value; }
    }

    private static IReadOnlyList<string> ParseAssignments(string value) =>
        string.IsNullOrWhiteSpace(value)
            ? []
            : value.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Distinct(StringComparer.OrdinalIgnoreCase).Take(100).ToList();

    private static string FormatAssignments(string value)
    {
        var items = ParseAssignments(value);
        if (items.Count == 0) return "Ninguno";
        return string.Join(";", items.Take(20)) + (items.Count > 20 ? $";... (+{items.Count - 20})" : string.Empty);
    }

    private static bool LooksLocalAssignment(string value)
    {
        if (string.IsNullOrWhiteSpace(value)) return false;
        var slash = value.IndexOf('\\');
        if (slash < 0) return true;
        var prefix = value[..slash];
        return prefix.Equals(Environment.MachineName, StringComparison.OrdinalIgnoreCase)
            || prefix.Equals(".", StringComparison.OrdinalIgnoreCase)
            || prefix.Equals("BUILTIN", StringComparison.OrdinalIgnoreCase)
            || prefix.Equals("NT AUTHORITY", StringComparison.OrdinalIgnoreCase);
    }

    private static bool CanResolveAccount(string value)
    {
        try
        {
            var normalized = value.StartsWith(".\\", StringComparison.Ordinal) ? Environment.MachineName + value[1..] : value;
            _ = new NTAccount(normalized).Translate(typeof(SecurityIdentifier));
            return true;
        }
        catch { return false; }
    }

    private static string Sanitize(string value) => new(value.Where(char.IsLetterOrDigit).Select(char.ToUpperInvariant).Take(28).ToArray());

    private sealed class IniSection(string name, int line)
    {
        public string Name { get; } = name;
        public int Line { get; } = line;
        public List<KeyValuePair<string, string>> Values { get; } = [];
        public string? Get(string key) => Values.LastOrDefault(v => v.Key.Equals(key, StringComparison.OrdinalIgnoreCase)).Value;
    }

    [GeneratedRegex(@"@?""(?<path>[A-Za-z]:\\[^""]+\.exe)""", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex WebJavaExecutableRegex();

    [GeneratedRegex(@"NSIOServer\s+(?<http>\d{1,5})\s+(?<https>\d{1,5})", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex WebServerPortsRegex();

    [GeneratedRegex(@"^App\d+$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex AppSectionRegex();
}
