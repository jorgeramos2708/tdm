using System.Security.Cryptography;
using System.ServiceProcess;
using System.Text.RegularExpressions;
using TDM.Core;
using TDM.Models;

namespace TDM.Collectors.TSplus;

/// <summary>
/// Diagnóstico normal por componentes funcionales de TSplus Remote Access.
/// Usa únicamente fuentes principales conocidas por el perfil de versión; no recorre
/// recursivamente toda la instalación ni realiza conexiones activas a otros nodos.
/// </summary>
public sealed class RemoteAccessModuleCoverageCollector : IReadOnlyCollector
{
    private readonly bool _calculateHashes;

    public RemoteAccessModuleCoverageCollector(bool calculateHashes = true)
        => _calculateHashes = calculateHashes;

    public string Nombre => "Módulos TSplus Remote Access / diagnóstico normal";

    private static readonly Regex BalanceNameRegex = new(@"/~~(?<name>[^=/:\s]+)", RegexOptions.Compiled | RegexOptions.IgnoreCase);

    public Task<CollectorResult> CollectAsync(DiagnosticContext context, CancellationToken cancellationToken = default)
    {
        if (!context.Sistema.TsplusDetectado || string.IsNullOrWhiteSpace(context.Sistema.TsplusRuta))
            return Task.FromResult(CollectorResult.Empty);

        var root = Path.GetFullPath(context.Sistema.TsplusRuta!);
        var profile = TsplusReleaseCatalog.Resolve(context.Sistema);
        var events = new List<DiagnosticEvent>();
        var findings = new List<DiagnosticFinding>();
        var servicesProbe = TsplusServiceSnapshotReader.Read(cancellationToken);
        var services = servicesProbe.IsAvailable
            ? servicesProbe.Value ?? new Dictionary<string, (string DisplayName, ServiceControllerStatus Status)>(StringComparer.OrdinalIgnoreCase)
            : new Dictionary<string, (string DisplayName, ServiceControllerStatus Status)>(StringComparer.OrdinalIgnoreCase);
        var servicesAvailable = servicesProbe.IsAvailable;
        var systemDrive = Path.GetPathRoot(Environment.SystemDirectory) ?? @"C:\";

        if (!servicesAvailable)
        {
            findings.Add(new DiagnosticFinding(
                "TSPLUS-REMOTEACCESS-SERVICE-COVERAGE", "Remote Access / servicios", DiagnosticSeverity.Advertencia,
                "No fue posible consultar de forma confiable los servicios usados por el diagnóstico de Remote Access.",
                "Los campos dependientes del Service Control Manager quedan como no evaluados; TDM no interpreta una lectura fallida como servicio ausente o detenido.",
                [new EvidenceItem("Estado de lectura", servicesProbe.StatusText), new EvidenceItem("Detalle", servicesProbe.Detail ?? "Sin detalle adicional")],
                ConfidenceLevel.Confirmada, Capa: DiagnosticLayer.Windows));
        }

        events.Add(new DiagnosticEvent(
            DateTimeOffset.Now,
            "TDM",
            "Perfil de compatibilidad TSplus",
            DiagnosticLayer.Tsplus,
            profile.Soportado ? DiagnosticSeverity.Informativo : DiagnosticSeverity.Advertencia,
            "TSPLUS_VERSION_PROFILE_STATE",
            profile.Soportado
                ? $"Perfil de diagnóstico normal seleccionado: {profile.Nombre}."
                : $"La versión detectada queda fuera del perfil funcional soportado: {profile.Nombre}.",
            Evidencia:
            [
                new EvidenceItem("Versión detectada", context.Sistema.TsplusVersion ?? "N/D"),
                new EvidenceItem("Perfil", profile.Id),
                new EvidenceItem("Soportado por diagnóstico funcional", profile.Soportado ? "Sí" : "No"),
                new EvidenceItem("Alcance", "19.30, 19.40, LTS 18 y LTS 17"),
                new EvidenceItem("Modo", "Diagnóstico dirigido; sin auditoría recursiva completa")
            ],
            Producto: TsplusProduct.RemoteAccess));

        if (!profile.Soportado)
        {
            findings.Add(new DiagnosticFinding(
                "TSPLUS-VERSION-PROFILE-UNSUPPORTED",
                "Compatibilidad TSplus",
                DiagnosticSeverity.Advertencia,
                "La versión de TSplus no pertenece a las ramas funcionales soportadas por este perfil de TDM.",
                profile.Motivo,
                [new EvidenceItem("Versión", context.Sistema.TsplusVersion ?? "N/D"), new EvidenceItem("Perfil", profile.Id)],
                ConfidenceLevel.Alta,
                "TSplus — Updating Remote Access / Long Term Support",
                "https://docs.tsplus.net/tsplus/updating-terminal-service-plus/",
                "Mantenga TSplus actualizado o utilice una rama LTS soportada. TDM continuará recopilando evidencia genérica sin declarar archivos obligatorios de una versión desconocida.",
                DiagnosticLayer.Tsplus));
        }

        AuditCoreRdp(root, services, servicesAvailable, systemDrive, events);
        AuditWeb(root, profile, findings, events, _calculateHashes);
        AuditApplications(root, profile, findings, events, _calculateHashes);
        AuditSessions(root, profile, services, servicesAvailable, systemDrive, findings, events);
        AuditFarm(root, profile, findings, events, _calculateHashes);
        AuditOptionalModules(root, events);

        events.Add(new DiagnosticEvent(
            DateTimeOffset.Now, "TDM", "TSplus Remote Access / cobertura modular", DiagnosticLayer.Tsplus,
            servicesAvailable ? DiagnosticSeverity.Informativo : DiagnosticSeverity.Advertencia, "TSPLUS_REMOTEACCESS_MODULE_SUMMARY",
            servicesAvailable
                ? "Diagnóstico normal Remote Access completado mediante fuentes principales conocidas por versión."
                : "Diagnóstico normal Remote Access completado con cobertura parcial: los servicios Windows no pudieron evaluarse.",
            Evidencia:
            [
                new("Perfil", profile.Id),
                new("Cobertura de servicios", servicesAvailable ? "Disponible" : $"Parcial: {servicesProbe.StatusText}"),
                new("Web/HTML5", "Configuración principal + runtime + logs/puertos por collectors especializados"),
                new("Aplicaciones", "AppControl.ini + rutas publicadas + asignaciones"),
                new("Sesiones/perfiles", "TermService/WTS + C:\\wsession + APSC.log cuando está habilitado"),
                new("Farm/Gateway", "balance.bin + configuración/log local; sin sondeo remoto"),
                new("Impresión", "Universal/Virtual Printer mediante PrintingHealthCollector"),
                new("Auditoría profunda del árbol", "Deshabilitada en diagnóstico normal"),
                new("Acciones activas", "Ninguna; sólo lectura")
            ],
            Producto: TsplusProduct.RemoteAccess));

        return Task.FromResult(new CollectorResult(findings, events));
    }

    private static void AuditCoreRdp(
        string root,
        IReadOnlyDictionary<string, (string DisplayName, ServiceControllerStatus Status)> services,
        bool servicesAvailable,
        string systemDrive,
        List<DiagnosticEvent> events)
    {
        AddModule(events, "Core RDP / acceso remoto", servicesAvailable ? "Directa" : "Parcial",
            [
                new("TermService", ServiceState(services, servicesAvailable, "TermService")),
                new("APSC/APSC-like", FindServiceState(services, servicesAvailable, "APSC", "Application Publishing Session Control", "Application Publishing")),
                new("C:\\wsession", FileSystemProbe.Display(FileSystemProbe.Directory(Path.Combine(systemDrive, "wsession")))),
                new("Raíz Remote Access", root)
            ]);
    }

    private static void AuditWeb(
        string root,
        TsplusReleaseProfile profile,
        List<DiagnosticFinding> findings,
        List<DiagnosticEvent> events,
        bool calculateHashes)
    {
        var settingsJs = Resolve(root, profile, "Web.SettingsJs");
        var appSettings = Resolve(root, profile, "Web.PortalAppSettings");
        var runWeb = Resolve(root, profile, "Web.RunWebServer");
        var jar = Resolve(root, profile, "Web.HttpWebsJar");
        var hbLog = Resolve(root, profile, "Web.HbLog");

        var webDir = Path.Combine(root, "Clients", "www");
        var webDirProbe = FileSystemProbe.Directory(webDir);
        var settingsProbe = FileSystemProbe.File(settingsJs);
        var runWebProbe = FileSystemProbe.File(runWeb);
        var jarProbe = FileSystemProbe.File(jar);
        var webCoverageUnavailable = webDirProbe.IsUnavailable || settingsProbe.IsUnavailable || runWebProbe.IsUnavailable || jarProbe.IsUnavailable;
        var webInstalled = webDirProbe.IsAvailable || runWebProbe.IsAvailable || jarProbe.IsAvailable;
        var configOk = settingsProbe.IsAvailable;
        var runtimeArtifactsOk = runWebProbe.IsAvailable && jarProbe.IsAvailable;
        var health = webCoverageUnavailable && !webInstalled
            ? "No evaluado · acceso/lectura incompleta"
            : !webInstalled ? "No detectado"
            : configOk && runtimeArtifactsOk ? "Configuración/runtime presentes" : "Incompleto; requiere correlación";

        AddKnownFileState(events, "Web / HTML5", "settings.js", settingsJs, profile, requiredWhenModulePresent: webInstalled, calculateHash: calculateHashes);
        AddKnownFileState(events, "Web / Web Portal", "appsettings.json", appSettings, profile, requiredWhenModulePresent: false, calculateHash: calculateHashes);
        AddKnownFileState(events, "Web / HTML5", "runwebserver.bat", runWeb, profile, requiredWhenModulePresent: webInstalled, calculateHash: calculateHashes);
        AddKnownFileState(events, "Web / HTML5", "httpwebs.jar", jar, profile, requiredWhenModulePresent: webInstalled, calculateHash: calculateHashes);

        events.Add(new DiagnosticEvent(
            DateTimeOffset.Now, "TDM", "Web Server / HTML5 / Web Portal", DiagnosticLayer.Tsplus,
            DiagnosticSeverity.Informativo, "TSPLUS_WEB_FILESET_STATE",
            "Conjunto funcional Web evaluado mediante archivos principales del perfil; no se realizó recorrido recursivo de la instalación.",
            Evidencia:
            [
                new("Cobertura", "Dirigida por perfil de versión"),
                new("Estado preliminar", health),
                new("settings.js", FileState(settingsJs)),
                new("appsettings.json", FileState(appSettings)),
                new("runwebserver.bat", FileState(runWeb)),
                new("httpwebs.jar", FileState(jar)),
                new("hb.log", FileState(hbLog)),
                new("Regla causal", "Archivo/configuración + runtime/listener + log/evento + impacto funcional")
            ],
            Producto: TsplusProduct.RemoteAccess));

        AddModule(events, "Web Server / HTML5 / Web Portal", "Directa",
            [
                new("Perfil", profile.Id),
                new("Estado preliminar", health),
                new("Configuración principal settings.js", FileState(settingsJs)),
                new("Portal appsettings.json", FileState(appSettings)),
                new("Runtime runwebserver.bat", FileState(runWeb)),
                new("Runtime httpwebs.jar", FileState(jar)),
                new("Log Web hb.log", FileState(hbLog)),
                new("Cobertura de archivos", "Sólo fuentes principales conocidas; sin inventario recursivo completo")
            ]);
    }

    private static void AuditApplications(
        string root,
        TsplusReleaseProfile profile,
        List<DiagnosticFinding> findings,
        List<DiagnosticEvent> events,
        bool calculateHashes)
    {
        var appControl = Resolve(root, profile, "Applications.AppControl");
        AddKnownFileState(events, "Publicación de aplicaciones", "AppControl.ini", appControl, profile, requiredWhenModulePresent: true, calculateHash: calculateHashes);
        events.Add(new DiagnosticEvent(
            DateTimeOffset.Now, "TDM", "Publicación de aplicaciones", DiagnosticLayer.Tsplus,
            DiagnosticSeverity.Informativo, "TSPLUS_APPLICATION_FILESET_STATE",
            "Configuración principal de publicación evaluada sin recorrer recursivamente la instalación.",
            Evidencia:
            [
                new("Cobertura", "Dirigida por perfil de versión"),
                new("AppControl.ini", FileState(appControl)),
                new("Interpretación", "El collector de configuración interna valida secciones, asignaciones y rutas de ejecutables publicados"),
                new("Regla causal", "Configuración + ejecutable publicado + usuario/grupo + sesión/evento")
            ],
            Producto: TsplusProduct.RemoteAccess));

        AddModule(events, "Publicación y asignación de aplicaciones", "Directa",
            [
                new("Perfil", profile.Id),
                new("AppControl.ini", FileState(appControl)),
                new("Auditoría", "Asignaciones, duplicados, rutas publicadas y ejecutables se validan por configuración interna."),
                new("Cobertura de archivos", "Archivo principal conocido; sin búsqueda recursiva")
            ]);
    }

    private static void AuditSessions(
        string root,
        TsplusReleaseProfile profile,
        IReadOnlyDictionary<string, (string DisplayName, ServiceControllerStatus Status)> services,
        bool servicesAvailable,
        string systemDrive,
        List<DiagnosticFinding> findings,
        List<DiagnosticEvent> events)
    {
        var apscLog = Resolve(root, profile, "Sessions.ApscLog");
        var wsession = Path.Combine(systemDrive, "wsession");
        var trace = Path.Combine(wsession, "trace");
        var termService = ServiceState(services, servicesAvailable, "TermService");
        var sessionState = termService.Equals("Running", StringComparison.OrdinalIgnoreCase)
            ? "Runtime RDP disponible"
            : termService.Equals("No evaluado", StringComparison.OrdinalIgnoreCase) || termService.Equals("No localizado", StringComparison.OrdinalIgnoreCase)
                ? "No determinado"
                : $"TermService={termService}";

        // Los logs de TSplus pueden estar deshabilitados y son dinámicos. APSC.log se usa como
        // evidencia temporal, pero no como archivo de configuración estable ni como baseline/hash.

        events.Add(new DiagnosticEvent(
            DateTimeOffset.Now, "TDM", "Sesiones / logon TSplus", DiagnosticLayer.Tsplus,
            servicesAvailable ? DiagnosticSeverity.Informativo : DiagnosticSeverity.Advertencia, "TSPLUS_SESSION_FILESET_STATE",
            "Fuentes principales de sesiones evaluadas sin recorrer recursivamente la instalación.",
            Evidencia:
            [
                new("Cobertura", "Dirigida por perfil + runtime Windows/RDS"),
                new("TermService", termService),
                new("C:\\wsession", FileSystemProbe.Display(FileSystemProbe.Directory(wsession))),
                new("C:\\wsession\\trace", FileSystemProbe.Display(FileSystemProbe.Directory(trace), "Presente", "No presente / logging puede estar deshabilitado")),
                new("APSC.log", FileState(apscLog, "No presente / logging puede estar deshabilitado")),
                new("Estado preliminar", sessionState),
                new("Regla causal", "WTS/RDP + perfil + wsession/APSC cuando disponible + eventos logon/logoff")
            ],
            Producto: TsplusProduct.RemoteAccess));

        AddModule(events, "Sesiones / perfiles / logon", "Directa",
            [
                new("Perfil", profile.Id),
                new("TermService", termService),
                new("wsession", FileSystemProbe.Display(FileSystemProbe.Directory(wsession), $"Presente: {wsession}", "No presente")),
                new("Traza wsession", FileSystemProbe.Display(FileSystemProbe.Directory(trace), $"Presente: {trace}", "No presente; puede estar deshabilitada")),
                new("APSC.log", FileState(apscLog, "No presente; puede estar deshabilitado")),
                new("Cobertura Windows", "WTS, perfiles, eventos RDP y Service Control Manager"),
                new("Cobertura de archivos", "Fuentes principales conocidas; sin búsqueda recursiva")
            ]);
    }

    private static void AuditFarm(
        string root,
        TsplusReleaseProfile profile,
        List<DiagnosticFinding> findings,
        List<DiagnosticEvent> events,
        bool calculateHashes)
    {
        var legacyIni = Resolve(root, profile, "Farm.LegacyLoadBalancing");
        var balance = Resolve(root, profile, "Farm.Balance");
        var farmLog = Resolve(root, profile, "Farm.Log");
        var balanceProbe = FileSystemProbe.File(balance);
        var legacyProbe = FileSystemProbe.File(legacyIni);
        var names = balanceProbe.IsAvailable ? ReadBalanceNames(balance) : [];
        var routeCount = balanceProbe.IsAvailable ? ReadNonCommentLineCount(balance) : 0;
        var farmEvidence = (balanceProbe.IsAvailable && (names.Count > 0 || routeCount > 0)) || legacyProbe.IsAvailable;
        var farmCoverageIncomplete = balanceProbe.IsUnavailable || legacyProbe.IsUnavailable;
        var inferredRole = farmEvidence
            ? "Farm Controller / Gateway (inferido por configuración local)"
            : farmCoverageIncomplete ? "No determinado · cobertura local incompleta" : "Servidor independiente";

        // Validaciones conservadoras de coherencia local. No se declara una granja ausente por
        // faltar el INI legado y no se sondean nodos remotos. balance.bin sólo se usa como
        // evidencia cuando su contenido observable permite derivar nombres/rutas.
        if (balanceProbe.IsAvailable && routeCount > 0 && names.Count == 0)
        {
            findings.Add(new DiagnosticFinding(
                "TSPLUS-FARM-BALANCE-NAME-MISMATCH",
                "Farm / Reverse Proxy",
                DiagnosticSeverity.Advertencia,
                "balance.bin contiene rutas, pero TDM no pudo derivar nombres internos de Application Servers.",
                "Puede tratarse de un formato de configuración no reconocido o de una configuración incompleta. No se considera causa raíz sin impacto de granja/gateway y evidencia temporal adicional.",
                [new("Archivo", balance), new("Rutas observadas", routeCount.ToString()), new("Nombres derivados", "0")],
                ConfidenceLevel.Media,
                "TSplus — Farm / Reverse Proxy",
                "https://docs.tsplus.net/tsplus/farm-overview/",
                "Compare la topología mostrada por Farm Manager/AdminTool con balance.bin. No edite el archivo directamente desde TDM.",
                DiagnosticLayer.Tsplus));
        }
        if (balanceProbe.IsAvailable && names.Count > 0 && routeCount > 0 && routeCount < names.Count * 2)
        {
            findings.Add(new DiagnosticFinding(
                "TSPLUS-FARM-BALANCE-INCOMPLETE-DIRECTED",
                "Farm / Reverse Proxy",
                DiagnosticSeverity.Advertencia,
                "La cantidad de rutas observadas en balance.bin parece menor a la esperada para los servidores derivados.",
                "TDM conserva la inconsistencia como señal de configuración y requiere correlación con errores de Gateway/Load Balancing antes de atribuir impacto.",
                [new("Archivo", balance), new("Servidores derivados", names.Count.ToString()), new("Rutas observadas", routeCount.ToString())],
                ConfidenceLevel.Media,
                "TSplus — Farm / Reverse Proxy",
                "https://docs.tsplus.net/tsplus/farm-overview/",
                "Valide la configuración desde Farm Manager/AdminTool y los logs de granja; no modifique balance.bin directamente.",
                DiagnosticLayer.Tsplus));
        }

        AddKnownFileState(events, "Farm / Gateway", "balance.bin", balance, profile, requiredWhenModulePresent: false, calculateHash: calculateHashes);
        AddKnownFileState(events, "Farm / Gateway", "GatewayPortalLoadBalancing.ini", legacyIni, profile, requiredWhenModulePresent: false, calculateHash: calculateHashes);

        events.Add(new DiagnosticEvent(
            DateTimeOffset.Now, "TSplus Config", "Farm / Gateway / Load Balancing / Reverse Proxy", DiagnosticLayer.Tsplus,
            farmCoverageIncomplete && !farmEvidence ? DiagnosticSeverity.Advertencia : DiagnosticSeverity.Informativo, "TSPLUS_FARM_CONFIGURATION_STATE",
            farmEvidence
                ? "Se detectó evidencia local de configuración de granja/gateway. TDM no sondea nodos remotos en diagnóstico normal."
                : farmCoverageIncomplete
                    ? "La topología Farm/Gateway no pudo determinarse con fiabilidad porque una fuente local no fue accesible."
                    : "No se detectó evidencia de granja en las fuentes principales locales evaluables.",
            Archivo: balanceProbe.IsAvailable ? balance : legacyProbe.IsAvailable ? legacyIni : null,
            Evidencia:
            [
                new("Perfil", profile.Id),
                new("Evidencia de granja local", farmEvidence ? "Sí" : farmCoverageIncomplete ? "No determinable" : "No"),
                new("Cobertura de topología", farmCoverageIncomplete ? "Parcial" : "Disponible"),
                new("Rol local inferido", inferredRole),
                new("GatewayPortalLoadBalancing.ini", FileState(legacyIni, "No presente; no prueba ausencia de granja en v19")),
                new("balance.bin", FileState(balance)),
                new("Rutas observadas en balance.bin", routeCount.ToString()),
                new("Application Servers derivados", names.Count.ToString()),
                new("Nombres internos Reverse Proxy", names.Count == 0 ? "Ninguno derivado" : string.Join(" | ", names)),
                new("svcenterprise.log", FileState(farmLog, "No presente / logging puede estar deshabilitado")),
                new("Sondeo remoto", "No")
            ],
            Producto: TsplusProduct.RemoteAccess));

        AddModule(events, "Farm / Gateway / Load Balancing / Reverse Proxy", farmEvidence ? "Directa local" : farmCoverageIncomplete ? "Parcial / no determinada" : "No configurada observada",
            [
                new("Evidencia de granja local", farmEvidence ? "Sí" : farmCoverageIncomplete ? "No determinable" : "No"),
                new("Cobertura de topología", farmCoverageIncomplete ? "Parcial" : "Disponible"),
                new("Rol local inferido", inferredRole),
                new("balance.bin", FileState(balance)),
                new("Servidores derivados", names.Count.ToString()),
                new("Nombres internos", names.Count == 0 ? "Ninguno" : string.Join(" | ", names)),
                new("Nota", "Diagnóstico normal usa archivos principales; no abre conexiones activas ni consulta Farm API.")
            ]);
    }

    private static void AuditOptionalModules(string root, List<DiagnosticEvent> events)
    {
        var twoFaExe = Path.Combine(root, "UserDesktop", "files", "TwoFactor.Admin.exe");
        var twoFaLog = Path.Combine(root, "UserDesktop", "files", "TwoFactor.Admin.log");
        var twoFaProbe = FileSystemProbe.File(twoFaExe);
        AddModule(events, "Two-Factor Authentication (2FA)", twoFaProbe.IsAvailable ? "Parcial" : twoFaProbe.IsUnavailable ? "No evaluado" : "No detectado",
            [
                new("TwoFactor.Admin.exe", FileState(twoFaExe)),
                new("TwoFactor.Admin.log", FileState(twoFaLog, "No presente / logging puede estar deshabilitado")),
                new("Cobertura", "Inventario local; la validación del segundo factor requiere una autenticación real y TDM no la fuerza.")
            ], TsplusProduct.TwoFactorAuthentication);
    }

    private static void AddKnownFileState(
        List<DiagnosticEvent> events,
        string module,
        string name,
        string path,
        TsplusReleaseProfile profile,
        bool requiredWhenModulePresent,
        bool calculateHash)
    {
        var probe = FileSystemProbe.File(path);
        var exists = probe.IsAvailable;
        var readUnavailable = probe.IsUnavailable;
        events.Add(new DiagnosticEvent(
            DateTimeOffset.Now,
            "TDM",
            $"{module} / {name}",
            DiagnosticLayer.Tsplus,
            readUnavailable ? DiagnosticSeverity.Advertencia : DiagnosticSeverity.Informativo,
            "TSPLUS_MODULE_CRITICAL_FILE_STATE",
            exists
                ? "Archivo funcional principal localizado."
                : readUnavailable
                    ? "El archivo funcional principal no pudo evaluarse; TDM no lo clasifica como ausente."
                    : "Archivo funcional principal no localizado en la ruta del perfil; por sí solo no se declara causa raíz.",
            Archivo: exists ? path : null,
            Evidencia:
            [
                new("Módulo", module),
                new("Nombre", name),
                new("Perfil", profile.Id),
                new("Estado de lectura", probe.StatusText),
                new("Presente", exists ? "Sí" : readUnavailable ? "No determinable" : "No"),
                new("Esperado cuando el módulo está presente", requiredWhenModulePresent ? "Sí" : "No/condicional"),
                new("Ruta esperada", path),
                new("Tamaño", exists ? SafeLength(path).ToString() : "N/D"),
                new("Última modificación UTC", exists ? SafeLastWriteUtc(path) : "N/D"),
                new("Versión", exists ? TryVersion(path) : "N/D"),
                new("SHA-256", exists ? (calculateHash ? TrySha256(path) : "Omitido en muestreo ligero") : "N/D")
            ],
            Producto: TsplusProduct.RemoteAccess));
    }

    private static string Resolve(string root, TsplusReleaseProfile profile, string key)
        => profile.ArchivosPrincipales.TryGetValue(key, out var relative)
            ? Path.Combine(root, relative)
            : Path.Combine(root, "__tdm_unknown__", key);

    private static void AddModule(List<DiagnosticEvent> events, string component, string coverage,
        IReadOnlyList<EvidenceItem> evidence, TsplusProduct product = TsplusProduct.RemoteAccess)
    {
        var list = evidence.ToList();
        list.Insert(0, new EvidenceItem("Cobertura TDM", coverage));
        events.Add(new DiagnosticEvent(DateTimeOffset.Now, "TDM", component, DiagnosticLayer.Tsplus,
            DiagnosticSeverity.Informativo, "TSPLUS_REMOTEACCESS_MODULE_STATE",
            $"Módulo Remote Access evaluado; cobertura TDM: {coverage}.", Evidencia: list, Producto: product));
    }

    private static string ServiceState(IReadOnlyDictionary<string, (string DisplayName, ServiceControllerStatus Status)> services, bool servicesAvailable, string name)
        => !servicesAvailable ? "No evaluado" : services.TryGetValue(name, out var state) ? state.Status.ToString() : "No localizado";

    private static string FindServiceState(IReadOnlyDictionary<string, (string DisplayName, ServiceControllerStatus Status)> services, bool servicesAvailable, params string[] tokens)
    {
        if (!servicesAvailable) return "No evaluado";
        var match = services.FirstOrDefault(s => tokens.Any(t => s.Key.Contains(t, StringComparison.OrdinalIgnoreCase)
            || s.Value.DisplayName.Contains(t, StringComparison.OrdinalIgnoreCase)));
        return string.IsNullOrWhiteSpace(match.Key) ? "No localizado" : $"{match.Key} ({match.Value.Status})";
    }

    private static List<string> ReadBalanceNames(string path)
    {
        var output = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (!FileSystemProbe.File(path).IsAvailable) return [];
        try
        {
            foreach (var line in File.ReadLines(path).Take(5000))
            {
                var match = BalanceNameRegex.Match(line);
                if (match.Success && !string.IsNullOrWhiteSpace(match.Groups["name"].Value))
                    output.Add(match.Groups["name"].Value.Trim());
            }
        }
        catch { }
        return output.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToList();
    }

    private static int ReadNonCommentLineCount(string path)
    {
        if (!FileSystemProbe.File(path).IsAvailable) return 0;
        try
        {
            return File.ReadLines(path).Take(5000).Count(line =>
            {
                var value = line.Trim();
                return !string.IsNullOrWhiteSpace(value) && !value.StartsWith('#') && !value.StartsWith(';');
            });
        }
        catch { return 0; }
    }

    private static string FileState(string path, string missing = "No presente")
    {
        var probe = FileSystemProbe.File(path);
        if (probe.IsAbsent) return missing;
        if (probe.IsUnavailable) return $"NO EVALUADO · {probe.StatusText}: {path}";
        try
        {
            var fi = new FileInfo(path);
            return $"Presente: {path} | {fi.Length} bytes | modificado {fi.LastWriteTime:O}";
        }
        catch (UnauthorizedAccessException) { return $"NO EVALUADO · acceso denegado: {path}"; }
        catch (IOException) { return $"NO EVALUADO · error de E/S: {path}"; }
        catch { return $"Presente: {path}"; }
    }

    private static string SafeLastWriteUtc(string path)
    {
        try { return File.GetLastWriteTimeUtc(path).ToString("O"); }
        catch { return "N/D"; }
    }

    private static long SafeLength(string path)
    {
        try { return new FileInfo(path).Length; }
        catch { return -1; }
    }

    private static string TryVersion(string path)
    {
        try
        {
            var version = System.Diagnostics.FileVersionInfo.GetVersionInfo(path).FileVersion;
            return string.IsNullOrWhiteSpace(version) ? "N/D" : version;
        }
        catch { return "N/D"; }
    }

    private static string TrySha256(string path)
    {
        try
        {
            var fi = new FileInfo(path);
            if (!fi.Exists || fi.Length > 64L * 1024 * 1024) return "No calculado (límite 64 MB)";
            using var stream = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            return Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
        }
        catch { return "No disponible"; }
    }
}
