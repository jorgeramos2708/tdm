using TDM.Models;

namespace TDM.Correlation;

/// <summary>
/// Construye troubleshooting guiado exclusivamente a partir de evidencia ya recopilada por TDM.
/// No inicia pruebas activas, no cambia configuración y no convierte ausencia de datos en salud.
/// </summary>
public static class TsplusGuidedTroubleshooter
{
    public static readonly IReadOnlyDictionary<TsplusProduct, string[]> Components =
        new Dictionary<TsplusProduct, string[]>
        {
            [TsplusProduct.RemoteAccess] =
            [
                "General", "RDP / Listener", "Autenticación / NLA", "Sesiones", "Web Portal / HTTPS", "HTML5",
                "Aplicaciones publicadas", "Cliente / RemoteApp", "Impresión", "Gateway / Farm", "Load Balancing", "Licencia / actualización"
            ],
            [TsplusProduct.TwoFactorAuthentication] =
            [
                "General", "Tiempo / TOTP", "Cliente compatible", "Portal / HTTPS", "Usuarios / enrollment", "Gateway / Application Server"
            ],
            [TsplusProduct.AdvancedSecurity] =
            [
                "General", "Bruteforce Protection", "Geographic Protection", "Firewall", "Restrict Working Hours", "Secure Sessions",
                "Trusted Devices", "Permissions", "Ransomware Protection", "Logs"
            ]
        };

    public static IReadOnlyList<GuidedResolutionResult> AnalyzeAll(DiagnosticReport report)
    {
        var results = new List<GuidedResolutionResult>();
        foreach (var product in new[] { TsplusProduct.RemoteAccess, TsplusProduct.TwoFactorAuthentication, TsplusProduct.AdvancedSecurity })
        {
            foreach (var component in Components[product])
                results.Add(Analyze(report, product, component));
        }
        return results;
    }

    public static GuidedResolutionResult Analyze(DiagnosticReport report, TsplusProduct product, string component)
    {
        var idx = new EvidenceIndex(report);
        return product switch
        {
            TsplusProduct.RemoteAccess => AnalyzeRemoteAccess(idx, component),
            TsplusProduct.TwoFactorAuthentication => AnalyzeTwoFactor(idx, component),
            TsplusProduct.AdvancedSecurity => AnalyzeAdvancedSecurity(idx, component),
            _ => NoData(product, component, "Producto fuera del alcance del asistente guiado.", "", "")
        };
    }

    private static bool IsNearAnalysisEnd(DiagnosticReport report, DiagnosticEvent e, TimeSpan maxAge)
    {
        if (e.Timestamp is not DateTimeOffset ts) return false;
        var end = report.PeriodoAnalizadoFin != default ? report.PeriodoAnalizadoFin : report.Fin;
        return ts <= end && end - ts <= maxAge;
    }

    private static GuidedResolutionResult AnalyzeRemoteAccess(EvidenceIndex x, string component)
    {
        if (!x.IsProductInstalled(TsplusProduct.RemoteAccess))
            return NotApplicable(TsplusProduct.RemoteAccess, component, "Remote Access no está detectado en este equipo.",
                "TSplus Remote Access — Quickstart Guide", "https://docs.tsplus.net/tsplus/quickstart-guide/");

        if (component.Equals("General", StringComparison.OrdinalIgnoreCase))
        {
            var children = Components[TsplusProduct.RemoteAccess].Skip(1).Select(c => AnalyzeRemoteAccess(x, c)).ToList();
            var worst = children.OrderByDescending(r => SeverityRank(r.Severidad)).ThenByDescending(r => StateRank(r.Estado)).First();
            var failing = children.Where(r => r.Estado is GuidedResolutionState.Error or GuidedResolutionState.Advertencia).Take(5).ToList();
            return Build(TsplusProduct.RemoteAccess, component,
                failing.Count > 0 ? worst.Estado : GuidedResolutionState.Informativo,
                failing.Count > 0 ? worst.Severidad : DiagnosticSeverity.Informativo,
                failing.Count > 0 ? worst.Confianza : ConfidenceLevel.Media,
                failing.Count > 0 ? "Se observaron anomalías en una o más capas de Remote Access." : "No se observaron fallas claras en las capas evaluadas de Remote Access; las capas sin evidencia permanecen no evaluadas.",
                failing.Count > 0 ? $"La capa que requiere atención primero es: {worst.Componente}. {worst.CausaProbable}" : "Las dependencias y módulos evaluados no muestran una falla activa. Mantenga la cobertura como contexto, no como garantía absoluta.",
                failing.Count > 0 ? worst.Impacto : "Sin impacto funcional atribuible a Remote Access en la evidencia actual.",
                children.Select(r => new GuidedResolutionCheck(r.Componente, StateLabel(r.Estado), r.CausaProbable, r.Severidad)).ToList(),
                failing.SelectMany(r => r.Evidencia).Take(14).ToList(),
                failing.Count > 0 ? worst.ComoCorregir : ["Si el usuario aún reporta un problema, seleccione la capa específica que coincide con el síntoma y valide Eventos/Línea de tiempo."],
                failing.Count > 0 ? worst.ComoValidar : ["Confirmar una nueva conexión y verificar que no aparezcan señales nuevas en Diagnóstico continuo."],
                ["No reinstalar Remote Access sin identificar primero la capa afectada.", "No reiniciar todos los servicios como primera acción."],
                "TSplus Remote Access — Quickstart Guide", "https://docs.tsplus.net/tsplus/quickstart-guide/",
                "Resumen construido a partir de collectors de Remote Access, Windows/RDP, red, logs y configuración principal.");
        }

        if (component.Equals("RDP / Listener", StringComparison.OrdinalIgnoreCase))
        {
            var termDown = x.HasFinding("RDP-TERMSERVICE-NOT-RUNNING", "SVC-TermService") || x.EventHas("RDP_STATE", "TermService", "Stopped");
            var listenerDown = x.HasFinding("RDP-LISTENER-NOT-LISTENING") || x.EventHas("RDP_STATE", "Listener", "NO") || x.EventHas("RDP_STATE", "No escuchando");
            if (termDown || listenerDown)
                return Build(TsplusProduct.RemoteAccess, component, GuidedResolutionState.Error, DiagnosticSeverity.Error, ConfidenceLevel.Alta,
                    "Nuevas conexiones Remote Access/RDP pueden fallar.",
                    termDown ? "Remote Desktop Services (TermService) no está operativo." : "El listener RDP no se observa en estado de escucha.",
                    "La capa RDP base de Windows afecta el acceso Remote Access; TSplus puede ser víctima y no originador.",
                    [Check("TermService", termDown ? "FALLA" : "Revisar", termDown ? "No operativo" : "Sin falla confirmada"), Check("RDP Listener", listenerDown ? "FALLA" : "Revisar", listenerDown ? "No escucha" : "Sin falla confirmada")],
                    x.EvidenceFor("RDP_STATE", "TermService", "Listener", "RDP-Tcp"),
                    ["Revisar TermService y el listener RDP-Tcp desde herramientas Windows.", "Confirmar puerto configurado y que no exista conflicto de bind.", "Revisar firewall sólo si el listener sí está disponible localmente."],
                    ["Confirmar listener en Listen.", "Abrir una sesión de prueba y verificar un RDP_SESSION_LOGON_STAGE nuevo."],
                    ["No cambiar el puerto RDP a ciegas.", "No reinstalar TSplus antes de resolver la capa RDP base."],
                    "Microsoft / TSplus — RDP y Remote Access", "https://docs.tsplus.net/tsplus/quickstart-guide/",
                    "TDM usa TermService, estado del listener y eventos RDP; no inicia conexiones sintéticas.");

            var rdpEvidence = x.Contains("RDP_STATE", "TermService", "RDP-Tcp", "Listener");
            if (!rdpEvidence)
                return NoData(TsplusProduct.RemoteAccess, component, "No hay estado RDP/TermService suficiente en esta vista para declarar la capa saludable.",
                    "TSplus Remote Access — Quickstart Guide", "https://docs.tsplus.net/tsplus/quickstart-guide/");

            var rdpErrors = x.Matches("RDP_", "RDP-Tcp", "Remote Desktop").Where(IsError).ToList();
            return Build(TsplusProduct.RemoteAccess, component,
                rdpErrors.Count > 0 ? GuidedResolutionState.Advertencia : GuidedResolutionState.Saludable,
                rdpErrors.Count > 0 ? DiagnosticSeverity.Advertencia : DiagnosticSeverity.Informativo,
                rdpErrors.Count > 0 ? ConfidenceLevel.Media : ConfidenceLevel.Media,
                rdpErrors.Count > 0 ? "Hay señales RDP que requieren correlación." : "No se detectó una falla del listener/servicio RDP en la ventana.",
                rdpErrors.Count > 0 ? "Existe evidencia RDP no informativa, pero no una caída actual confirmada." : "TermService/listener no muestran una falla activa en la evidencia disponible.",
                "Afecta la conectividad base de Remote Access cuando la señal es persistente.",
                [Check("RDP", rdpErrors.Count > 0 ? "ADVERTENCIA" : "OK", $"Señales no informativas: {rdpErrors.Count}")],
                x.EvidenceFrom(rdpErrors, 8),
                rdpErrors.Count > 0 ? ["Revisar Eventos y Línea de tiempo alrededor de la señal RDP."] : ["Sin corrección recomendada en esta capa."],
                ["Validar una conexión RDP/TSplus según el método usado por el cliente."],
                ["No tratar una señal histórica como una falla actual sin correlación temporal."],
                "TSplus Remote Access — Quickstart Guide", "https://docs.tsplus.net/tsplus/quickstart-guide/",
                "Cobertura RDP local y Event Log.");
        }

        if (component.Equals("Autenticación / NLA", StringComparison.OrdinalIgnoreCase))
        {
            var adEvents = x.MatchesType("WINDOWS_AD_AUTH_DEPENDENCY_FAILURE", "WINDOWS_AD_DOMAIN_CONNECTIVITY_FAILURE", "WINDOWS_AD_TERMSRV_SPN_FAILURE").ToList();
            var nlaEvents = x.MatchesType("WINDOWS_NLA_PASSWORD_CHANGE_CONFLICT", "USER_NLA_PASSWORD_FAILURE").ToList();
            var logon = x.MatchesType("USER_LOGON_FAILURE").ToList();
            var ad = adEvents.Count > 0;
            var nla = nlaEvents.Count > 0;
            var latestDependencyFailure = adEvents.Concat(nlaEvents).Where(e => e.Timestamp is not null).Select(e => e.Timestamp!.Value).DefaultIfEmpty(DateTimeOffset.MinValue).Max();
            var latestSuccess = x.MatchesType("USER_LOGON_SUCCESS", "RDP_AUTHENTICATION_STAGE", "RDP_SESSION_LOGON_STAGE")
                .Where(e => e.Timestamp is not null && !EventText(e).Contains("incorrect", StringComparison.OrdinalIgnoreCase) && !EventText(e).Contains("fail", StringComparison.OrdinalIgnoreCase))
                .Select(e => e.Timestamp!.Value).DefaultIfEmpty(DateTimeOffset.MinValue).Max();
            var recoveredAfterDependencyFailure = latestDependencyFailure != DateTimeOffset.MinValue && latestSuccess > latestDependencyFailure;

            if (ad || nla)
            {
                var cause = ad ? "La autenticación depende de AD/Netlogon/SPN y TDM observó una falla compatible."
                    : "TDM observó una señal NLA/CredSSP o cambio de contraseña compatible con el fallo.";
                var state = recoveredAfterDependencyFailure ? GuidedResolutionState.Advertencia : GuidedResolutionState.Error;
                var severity = recoveredAfterDependencyFailure ? DiagnosticSeverity.Advertencia : DiagnosticSeverity.Error;
                var confidence = recoveredAfterDependencyFailure ? ConfidenceLevel.Media : ConfidenceLevel.Alta;
                var symptom = recoveredAfterDependencyFailure
                    ? "Se observó una falla de autenticación/dependencia, seguida por autenticaciones correctas: el comportamiento parece intermitente o recuperado."
                    : "La dependencia de autenticación presenta una falla sin recuperación posterior demostrada en la ventana.";
                return Build(TsplusProduct.RemoteAccess, component, state, severity, confidence, symptom, cause,
                    "Remote Access puede estar operativo y ser el punto de manifestación de un fallo Windows/AD/NLA. Una recuperación posterior limita la conclusión a degradación intermitente.",
                    [Check("AD / Netlogon / SPN", ad ? "FALLA OBSERVADA" : "Sin señal", ad ? $"Eventos: {adEvents.Count}" : "No confirmada"), Check("NLA / CredSSP", nla ? "FALLA OBSERVADA" : "Sin señal", nla ? $"Eventos: {nlaEvents.Count}" : "No confirmada"), Check("Recuperación posterior", recoveredAfterDependencyFailure ? "SÍ" : "NO DEMOSTRADA", recoveredAfterDependencyFailure ? $"Login correcto posterior: {latestSuccess.ToLocalTime():dd/MM HH:mm:ss}" : "Sin login correcto posterior a la última falla")],
                    x.EvidenceFor("USER_LOGON_FAILURE", "USER_NLA_PASSWORD_FAILURE", "WINDOWS_AD_", "NLA"),
                    ["Revisar DNS/Netlogon y conectividad con controladores de dominio alrededor de la hora exacta del incidente.", "Revisar el subestado de 4625 y el estado de cuenta/política sólo para los usuarios afectados.", "Si hubo recuperación posterior, buscar el cambio temporal de red/servicio que explique la intermitencia antes de modificar TSplus."],
                    ["Confirmar varios logons consecutivos y verificar que no reaparezcan eventos AD/Netlogon/NLA.", "Confirmar USER_LOGON_SUCCESS seguido de RDP_SESSION_LOGON_STAGE para nuevas sesiones."],
                    ["No reinstalar Remote Access por una falla AD/NLA.", "No deshabilitar NLA globalmente como primera prueba."],
                    "TSplus Remote Access — Quickstart Guide", "https://docs.tsplus.net/tsplus/quickstart-guide/",
                    "Correlación temporal Security/RDP/AD/NLA; una autenticación exitosa posterior se trata como evidencia de recuperación, no como negación del incidente previo.");
            }

            if (logon.Count > 0)
                return Build(TsplusProduct.RemoteAccess, component, GuidedResolutionState.Advertencia, DiagnosticSeverity.Advertencia, ConfidenceLevel.Media,
                    "Windows registró uno o más fallos de inicio de sesión.",
                    "Un 4625 o fallo de credencial aislado no demuestra una falla de Remote Access; puede corresponder a contraseña incorrecta, cuenta, política o intento externo.",
                    "Puede afectar usuarios/intentos concretos sin degradar el servicio completo.",
                    [Check("Fallos logon", "OBSERVADOS", logon.Count.ToString())], x.EvidenceFrom(logon, 8),
                    ["Revisar subestado, cuenta y origen de los fallos repetidos.", "Correlacionar por usuario/origen/tiempo antes de elevarlo a incidente de plataforma."],
                    ["Confirmar logon correcto con una cuenta válida y ausencia de fallos repetidos para el mismo flujo."],
                    ["No clasificar un 4625 aislado como caída de Remote Access."],
                    "TSplus Remote Access — Quickstart Guide", "https://docs.tsplus.net/tsplus/quickstart-guide/", "Security/RDP disponible; fallos de credencial se mantienen como señal de usuario hasta demostrar patrón/dependencia.");

            if (x.Contains("USER_AUTH_AUDIT_COVERAGE", "USER_LOGON_SUCCESS", "WINDOWS_NLA_PASSWORD_COMPAT_STATE"))
                return Healthy(TsplusProduct.RemoteAccess, component, "No se observaron fallos generales de autenticación en la ventana.",
                    "TSplus Remote Access — Quickstart Guide", "https://docs.tsplus.net/tsplus/quickstart-guide/", "Cobertura de autenticación Windows/RDP disponible.");
            return NoData(TsplusProduct.RemoteAccess, component, "No hay cobertura suficiente de autenticación Windows/RDP en esta vista.",
                "TSplus Remote Access — Quickstart Guide", "https://docs.tsplus.net/tsplus/quickstart-guide/");
        }

        if (component.Equals("Sesiones", StringComparison.OrdinalIgnoreCase))
        {
            var shell = x.HasType("RDP_SHELL_START_DELAY", "RDP_SHELL_START_GAP", "WINDOWS-RDP-SHELL-PIPELINE-DEGRADED");
            var disconnect = x.MatchesType("RDP_SESSION_DISCONNECT_STAGE", "RDP_SESSION_LOGOFF_STAGE").ToList();
            // RC18.18.2: el estado actual de APS/APSC debe evaluarse sólo en su evidencia propia.
            // Un servicio distinto (por ejemplo Server Monitoring) detenido dentro del mismo snapshot
            // no puede convertir APSC en caído. Si el snapshot actual dice Running, prevalece sobre
            // hallazgos históricos/derivados y los warnings de lookup se tratan como degradación funcional.
            var apsRunning = x.EventEvidenceContains("TSPLUS_DEPENDENCY_HEALTH", "Application Publishing Service (APS)", "Running")
                             || x.EventEvidenceContains("TSPLUS_DEPENDENCY_HEALTH", "APS/APSC", "Running");
            var apsStoppedByEvidence = x.EventEvidenceContains("TSPLUS_DEPENDENCY_HEALTH", "Application Publishing Service (APS)", "Stopped")
                                       || x.EventEvidenceContains("TSPLUS_DEPENDENCY_HEALTH", "APS/APSC", "Stopped");
            var aps = !apsRunning && (apsStoppedByEvidence || x.HasFinding("TSPLUS-APS-NOT-RUNNING"));
            var apsLookupWarnings = x.Matches("APSC - Failed to retrieve username for session id")
                .Where(e => e.Severidad is DiagnosticSeverity.Advertencia or DiagnosticSeverity.Error or DiagnosticSeverity.Critico).ToList();
            if (shell || aps)
                return Build(TsplusProduct.RemoteAccess, component, GuidedResolutionState.Error, DiagnosticSeverity.Error, ConfidenceLevel.Alta,
                    "La sesión autentica pero no completa correctamente el inicio/presentación de aplicaciones.",
                    aps ? "Application Publishing Session Control (APS/APSC) no está operativo." : "El pipeline de shell/RemoteApp presenta retraso o degradación.",
                    "Puede producir pantalla de espera, sesión incompleta o aplicación que no inicia.",
                    [Check("APS/APSC", aps ? "FALLA" : "OK/No confirmada", aps ? "Dependencia Remote Access detenida" : "Sin señal"), Check("Shell", shell ? "DEGRADADO" : "OK/No confirmada", shell ? "Retraso/señal observada" : "Sin señal")],
                    x.EvidenceFor("TSPLUS_DEPENDENCY_HEALTH", "RDP_SHELL", "APSC", "SESSION"),
                    ["Revisar APS/APSC, logs de sesión y Application Error alrededor del incidente.", "Confirmar que la aplicación o shell publicado existe y es accesible."],
                    ["Validar una sesión completa desde autenticación hasta shell/aplicación visible."],
                    ["No tratar una desconexión aislada como crash-loop.", "No reiniciar toda la granja por una sola sesión."],
                    "TSplus Remote Access — Application Publishing", "https://docs.tsplus.net/tsplus/quickstart-guide/",
                    "Pipeline de sesión + estado de dependencias + logs TSplus.");
            if (apsLookupWarnings.Count > 0)
                return Build(TsplusProduct.RemoteAccess, component, GuidedResolutionState.Advertencia, DiagnosticSeverity.Advertencia, ConfidenceLevel.Media,
                    apsRunning
                        ? "APSC está operativo, pero registra fallos funcionales al resolver identidad de algunas sesiones."
                        : "APSC registra fallos funcionales al resolver identidad de algunas sesiones; no existe evidencia suficiente para declararlo detenido.",
                    apsRunning
                        ? "APSC está operativo (Running), pero la señal 'Failed to retrieve username for session id' confirma degradación funcional en la resolución de identidad; no debe interpretarse como caída del servicio."
                        : "La señal observada es 'Failed to retrieve username for session id'; sin un estado Stopped específico de APS/APSC, TDM no declara caída del servicio.",
                    "Puede afectar asociación usuario-sesión, lanzamiento o seguimiento de sesiones concretas, sin demostrar una caída global de Remote Access.",
                    [Check("APS/APSC", "RUNNING / DEGRADADO", $"Fallos de resolución de usuario: {apsLookupWarnings.Count}", DiagnosticSeverity.Advertencia)],
                    x.EvidenceFrom(apsLookupWarnings, 8),
                    ["Correlacionar los SessionId afectados con logon/logoff RDP y APSC.log.", "Comprobar si los avisos se concentran en sesiones que terminan o cambian rápidamente de estado.", "Revisar AD/NLA si los mismos SessionId coinciden con fallos de identidad/autenticación."],
                    ["Confirmar que nuevas sesiones completan logon, shell y publicación sin nuevos avisos APSC para esos SessionId."],
                    ["No reiniciar APS/APSC sólo por mensajes aislados de resolución de usuario.", "No clasificar el servicio como detenido mientras el estado observado sea Running."],
                    "TSplus Remote Access — Application Publishing", "https://docs.tsplus.net/tsplus/quickstart-guide/",
                    "Estado de APS/APSC + APSC.log + pipeline RDP; correlación por SessionId cuando está disponible.");

            if (disconnect.Count > 0)
                return Build(TsplusProduct.RemoteAccess, component, GuidedResolutionState.Advertencia, DiagnosticSeverity.Advertencia, ConfidenceLevel.Media,
                    "Se observaron desconexiones/logoff en la ventana.", "La evidencia indica finalización de sesiones, pero no confirma por sí sola si fue normal, política o falla.",
                    "Puede afectar usuarios individuales o múltiples dependiendo de la recurrencia.",
                    [Check("Desconexiones/logoff", "OBSERVADO", disconnect.Count.ToString())], x.EvidenceFrom(disconnect, 8),
                    ["Correlacionar las desconexiones con servicios, red, Working Hours y eventos de aplicación."],
                    ["Comprobar si las desconexiones cesan y si nuevas sesiones permanecen estables."],
                    ["No asumir que toda desconexión es una falla de Remote Access."],
                    "TSplus Remote Access — Quickstart Guide", "https://docs.tsplus.net/tsplus/quickstart-guide/", "Eventos RDP y TSplus disponibles en la ventana.");
            if (x.Contains("USER_SESSION_INVENTORY", "USER_SESSION_STATE", "RDP_SESSION_PIPELINE_STATE"))
                return Healthy(TsplusProduct.RemoteAccess, component, "No se observó degradación clara del pipeline de sesión.", "TSplus Remote Access — Quickstart Guide", "https://docs.tsplus.net/tsplus/quickstart-guide/", "Cobertura WTS/RDP y logs de sesión.");
            return NoData(TsplusProduct.RemoteAccess, component, "No hay inventario/pipeline de sesión suficiente para declarar esta capa saludable.",
                "TSplus Remote Access — Quickstart Guide", "https://docs.tsplus.net/tsplus/quickstart-guide/");
        }

        if (component.Equals("Web Portal / HTTPS", StringComparison.OrdinalIgnoreCase))
        {
            var tls = x.HasErrorType("CERTIFICATE_OR_TLS", "TLS_SCHANNEL_EVENT") || x.AnyErrorContaining("Schannel", "certificate", "certificado", "TLS handshake", "TLS alert");
            var port = x.HasErrorType("PORT_BIND") || x.AnyErrorContaining("port conflict", "puerto ocupado", "address already in use", "bind failed");
            var config = x.HasErrorFinding("TSPLUS-WEB-JSON", "TSPLUS-WEB-SETTINGS") || x.EventError("TSPLUS_WEB_JSON_VALID", "TSPLUS_WEB_SETTINGS_STATE", "TSPLUS_WEB_STACK_STATE");
            // Y4: tlsWarn con umbral ≥2 y recencia ≤15 min para evitar ruido permanente.
            var recentTlsWarnings = x.MatchesType("TLS_SCHANNEL_EVENT")
                .Where(e => e.Severidad == DiagnosticSeverity.Advertencia && IsNearAnalysisEnd(x.Report, e, TimeSpan.FromMinutes(15)))
                .ToList();
            var tlsWarn = !tls && recentTlsWarnings.Count >= 2;
            if (tls || port || config)
            {
                var cause = tls ? "Existe evidencia compatible con certificado/TLS en la ruta Web."
                    : port ? "El servidor web presenta una señal de bind/puerto en conflicto."
                    : "La configuración/runtime principal del Web Portal presenta una anomalía.";
                return Build(TsplusProduct.RemoteAccess, component, GuidedResolutionState.Error, DiagnosticSeverity.Error, ConfidenceLevel.Alta,
                    "El acceso Web/HTTPS puede fallar aunque RDP directo siga operativo.", cause,
                    "Impacto limitado principalmente a Web Portal/HTML5/RemoteApp vía portal cuando la capa RDP base está sana.",
                    [Check("TLS/certificado", tls ? "REVISAR" : "Sin señal", tls ? "Evento/log compatible" : "No confirmado"), Check("Puerto/bind", port ? "FALLA" : "Sin señal", port ? "Conflicto compatible" : "No confirmado"), Check("Configuración Web", config ? "FALLA" : "Sin señal", config ? "Configuración/runtime" : "No confirmada")],
                    x.EvidenceFor("CERTIFICATE_OR_TLS", "PORT_BIND", "TSPLUS_WEB_", "Schannel"),
                    ["Validar los puertos HTTP/HTTPS configurados y el listener local.", "Revisar certificado, vigencia y cadena si la evidencia es TLS.", "Revisar settings.js/appsettings/runtime antes de reinstalar Remote Access."],
                    ["Abrir el portal por HTTPS desde un cliente autorizado.", "Confirmar que no se generen nuevos PORT_BIND/TLS errors."],
                    ["No deshabilitar HTTPS globalmente para ocultar un problema de certificado."],
                    "TSplus Remote Access — Web Portal / ports", "https://docs.tsplus.net/tsplus/quickstart-guide/",
                    "Configuración Web, logs TSplus y Schannel cuando están disponibles.");
            }
            if (tlsWarn)
            {
                return Build(TsplusProduct.RemoteAccess, component, GuidedResolutionState.Advertencia, DiagnosticSeverity.Advertencia, ConfidenceLevel.Media,
                    "Existen advertencias TLS/Schannel recurrentes en la ruta Web/HTTPS.",
                    "Schannel registró múltiples advertencias (p. ej. handshake degradado) sin error confirmado; pueden anticipar fallas de certificado o compatibilidad TLS.",
                    "Sin impacto confirmado; vigilar si escalan a error o coinciden con fallas de portal.",
                    [Check("TLS/certificado", "REVISAR", $"Advertencias Schannel ({recentTlsWarnings.Count}) sin error confirmado")],
                    x.EvidenceFor("TLS_SCHANNEL_EVENT", "Schannel"),
                    ["Revisar el visor de eventos Schannel/System y la vigencia del certificado.", "Confirmar que el portal responde por HTTPS sin nuevos avisos."],
                    ["Correlacionar cualquier falla de portal con la hora de estas advertencias."],
                    ["No deshabilitar HTTPS globalmente para ocultar un problema de certificado."],
                    "TSplus Remote Access — Web Portal / ports", "https://docs.tsplus.net/tsplus/quickstart-guide/",
                    "Eventos Schannel de advertencia recientes en la ventana.");
            }
            if (x.Contains("TSPLUS_WEB_STACK_STATE", "TSPLUS_WEB_RUNTIME_STATE", "TSPLUS_WEB_SETTINGS_STATE"))
                return Healthy(TsplusProduct.RemoteAccess, component, "No se observó una falla clara del Web Portal/HTTPS.", "TSplus Remote Access — Quickstart Guide", "https://docs.tsplus.net/tsplus/quickstart-guide/", "Cobertura de archivos/runtime Web y logs disponibles.");
            return NoData(TsplusProduct.RemoteAccess, component, "No hay estado Web/HTTPS suficiente para declarar la capa saludable.",
                "TSplus Remote Access — Quickstart Guide", "https://docs.tsplus.net/tsplus/quickstart-guide/");
        }

        if (component.Equals("HTML5", StringComparison.OrdinalIgnoreCase))
        {
            var jvm = x.Contains("HTML5 JVM", "httpwebs.jar", "runwebserver.bat", "JAVA") && x.AnyErrorContaining("HTML5", "JAVA", "httpwebs.jar", "runwebserver.bat");
            var missing = x.HasFinding("TSPLUS-BASELINE-JAVA") || x.EventError("TSPLUS_WEB_RUNTIME_STATE") || x.AnyErrorContaining("httpwebs.jar", "runwebserver.bat");
            if (jvm || missing)
                return Build(TsplusProduct.RemoteAccess, component, GuidedResolutionState.Error, DiagnosticSeverity.Error, ConfidenceLevel.Alta,
                    "HTML5 puede fallar mientras otras formas de acceso sigan disponibles.",
                    jvm ? "El runtime/JVM de HTML5 presenta una falla o crash." : "Faltan o fallan artefactos/runtime principales de HTML5.",
                    "Afecta sesiones HTML5/Web; no implica necesariamente una caída de RDP directo.",
                    [Check("Runtime HTML5", "FALLA", jvm ? "Crash/runtime" : "Artefacto/runtime incompleto")],
                    x.EvidenceFor("TSPLUS_WEB_RUNTIME_STATE", "HTML5", "JAVA", "httpwebs.jar", "runwebserver.bat"),
                    ["Revisar runtime Java/OpenJDK y archivos principales de la misma versión TSplus.", "Comparar con una instalación sana o reparar/actualizar mediante herramientas oficiales."],
                    ["Abrir una sesión HTML5 y confirmar que el runtime permanece estable."],
                    ["No copiar JAR/Java de otra versión a ciegas."],
                    "TSplus Remote Access — Web/HTML5", "https://docs.tsplus.net/tsplus/quickstart-guide/",
                    "Archivos principales Web + logs/crash de JVM; no se ejecuta una sesión HTML5 sintética.");
            if (x.Contains("TSPLUS_WEB_RUNTIME_STATE", "TSPLUS_WEB_FILESET_STATE", "HTML5"))
                return Healthy(TsplusProduct.RemoteAccess, component, "No se observó una falla clara del runtime HTML5.", "TSplus Remote Access — Quickstart Guide", "https://docs.tsplus.net/tsplus/quickstart-guide/", "Cobertura de runtime/archivos y logs disponibles.");
            return NoData(TsplusProduct.RemoteAccess, component, "No hay estado de runtime/archivos HTML5 suficiente para declarar esta capa saludable.",
                "TSplus Remote Access — Quickstart Guide", "https://docs.tsplus.net/tsplus/quickstart-guide/");
        }

        if (component.Equals("Aplicaciones publicadas", StringComparison.OrdinalIgnoreCase))
        {
            var missing = x.HasFinding("TSPLUS-PUBLISHED-APP", "TSPLUS-APPCONTROL-NOT-FOUND") || x.AnyErrorContaining("aplicación publicada", "AppControl", "executabl");
            var denied = x.HasFinding("TSPLUS-APPCONTROL-ACCESS-DENIED") || x.AnyErrorContaining("AppControl", "Access denied");
            if (missing || denied)
                return Build(TsplusProduct.RemoteAccess, component, GuidedResolutionState.Error, DiagnosticSeverity.Error, ConfidenceLevel.Alta,
                    "La sesión puede abrir pero una aplicación no aparece o no inicia.",
                    missing ? "La publicación/asignación apunta a un recurso que falta o no puede resolverse." : "TDM no pudo acceder correctamente a la configuración de Application Control.",
                    "Afecta aplicaciones publicadas; el núcleo Remote Access puede seguir saludable.",
                    [Check("AppControl / publicación", "FALLA", missing ? "Ruta/asignación inválida" : "Acceso/configuración")],
                    x.EvidenceFor("TSPLUS_PUBLISHED_APPLICATION", "TSPLUS_APPCONTROL", "APPLICATION_PUBLISHING"),
                    ["Verificar que el ejecutable publicado exista en el servidor objetivo.", "Revisar asignación a usuario/grupo y coherencia en todos los Application Servers de la granja."],
                    ["Iniciar sesión con una cuenta afectada y confirmar que la aplicación publicada aparece y abre."],
                    ["No reiniciar Remote Access si sólo falla una aplicación publicada."],
                    "TSplus Remote Access — Application Publishing", "https://docs.tsplus.net/tsplus/quickstart-guide/",
                    "AppControl.ini, rutas publicadas, asignaciones y logs de Application Publishing.");
            if (x.Contains("TSPLUS_APPCONTROL_STATE", "TSPLUS_PUBLISHED_APPLICATION", "TSPLUS_APPCONTROL_SECURITY_STATE"))
                return Healthy(TsplusProduct.RemoteAccess, component, "No se observó una falla clara de publicación/asignación de aplicaciones.", "TSplus Remote Access — Application Publishing", "https://docs.tsplus.net/tsplus/quickstart-guide/", "Cobertura dirigida de AppControl y rutas publicadas.");
            return NoData(TsplusProduct.RemoteAccess, component, "No hay evidencia de publicación/asignación suficiente para declarar esta capa saludable.",
                "TSplus Remote Access — Application Publishing", "https://docs.tsplus.net/tsplus/quickstart-guide/");
        }

        if (component.Equals("Cliente / RemoteApp", StringComparison.OrdinalIgnoreCase))
        {
            var encoding = x.HasFinding("TSPLUS-REMOTEAPP-ENCODING-RISK", "TSPLUS_STARTUP_CONFIG_ENCODING_RISK") || x.HasType("TSPLUS_REMOTEAPP_NONASCII_CONFIG_CONTEXT", "REMOTEAPP_NONASCII_LOG_CONTEXT");
            var clientError = x.AnyErrorContaining("CONNECTION_CLIENT", "RemoteApp", "client");
            if (encoding || clientError)
                return Build(TsplusProduct.RemoteAccess, component, GuidedResolutionState.Advertencia, DiagnosticSeverity.Advertencia, ConfidenceLevel.Media,
                    "Una modalidad de cliente TSplus/RemoteApp puede fallar mientras otras funcionan.",
                    encoding ? "Existe riesgo de compatibilidad/encoding en configuración RemoteApp o identidad no ASCII." : "Los logs del Connection Client/RemoteApp contienen una señal de error.",
                    "Impacto específico al tipo de cliente o RemoteApp; no equivale a una caída total de Remote Access.",
                    [Check("Cliente / RemoteApp", "REVISAR", encoding ? "Encoding/identidad" : "Error de cliente")],
                    x.EvidenceFor("REMOTEAPP", "CONNECTION_CLIENT", "ENCODING"),
                    ["Comparar el comportamiento con MSTSC/Web/cliente generado para aislar la ruta afectada.", "Regenerar el cliente mediante el generador oficial si la configuración del cliente quedó obsoleta."],
                    ["Validar el mismo usuario mediante otro método y después con el cliente corregido."],
                    ["No declarar Remote Access completo en falla por un único tipo de cliente."],
                    "TSplus Remote Access — Portable Client Generator", "https://docs.tsplus.net/tsplus/portable-client-generator/",
                    "Logs Connection Client y comprobaciones RemoteApp/encoding disponibles.");
            return Build(TsplusProduct.RemoteAccess, component, GuidedResolutionState.NoEvaluado, DiagnosticSeverity.Informativo, ConfidenceLevel.EvidenciaInsuficiente,
                "No se observó una señal clara específica del cliente/RemoteApp.", "TDM no ejecuta un cliente sintético, por lo que ausencia de error no demuestra que el cliente esté saludable.",
                "Impacto no determinado.", [Check("Cliente / RemoteApp", "N/D", "Requiere evidencia del método de conexión utilizado")],
                x.EvidenceFor("TSPLUS_REMOTEAPP_ENCODING_COVERAGE", "CONNECTION_CLIENT", "RemoteApp"),
                ["Reproducir el problema con el mismo cliente y revisar versión/configuración del cliente generado."],
                ["Confirmar conexión completa con el mismo método que usa el usuario."], ["No cambiar el servidor si el fallo sólo aparece en un cliente sin antes comparar otro método."],
                "TSplus Remote Access — Portable Client Generator", "https://docs.tsplus.net/tsplus/portable-client-generator/", "TDM no ejecuta clientes sintéticos.");
        }

        if (component.Equals("Impresión", StringComparison.OrdinalIgnoreCase))
        {
            // V6: coherente con P08 — un Spooler detenido SIN impresión observada (Advertencia)
            // ya no dispara Error; solo el hallazgo o un evento Error/Crítico con la evidencia.
            var spooler = x.HasFinding("PRINT-SPOOLER-DOWN")
                || (x.EventHas("PRINT_SPOOLER_STATE", "Stopped")
                    && x.EventEvidenceContains("PRINT_SPOOLER_STATE", "Impresión TSplus observada", "Sí"));
            var printer = x.AnyErrorContaining("Universal Printer", "Virtual Printer", "PRINTING");
            if (spooler || printer)
                return Build(TsplusProduct.RemoteAccess, component, GuidedResolutionState.Error, DiagnosticSeverity.Error, spooler ? ConfidenceLevel.Alta : ConfidenceLevel.Media,
                    "La sesión puede funcionar pero la impresión remota falla.",
                    spooler ? "Print Spooler no está operativo." : "TDM observó una anomalía en Universal/Virtual Printer o la pila de impresión.",
                    "Impacto aislado principalmente a impresión; no implica que Remote Access esté caído.",
                    [Check("Spooler", spooler ? "FALLA" : "OK/No confirmada", spooler ? "Stopped" : "Sin señal"), Check("TSplus Printing", printer ? "REVISAR" : "Sin señal", printer ? "Evento/hallazgo" : "No confirmado")],
                    x.EvidenceFor("PRINT", "Spooler", "Universal Printer", "Virtual Printer"),
                    ["Revisar Spooler, PrintService y el componente TSplus de impresión usado por el cliente.", "Confirmar que el método de conexión soporte la función de impresión esperada."],
                    ["Imprimir un documento de prueba después de recuperar la pila de impresión."],
                    ["No reinstalar Remote Access completo por una falla de impresión aislada."],
                    "TSplus Remote Access — Printing", "https://docs.tsplus.net/tsplus/quickstart-guide/", "Spooler + estado Universal/Virtual Printer + eventos de impresión.");
            if (x.Contains("PRINT_SPOOLER_STATE", "TSPLUS_UNIVERSAL_PRINTER_STATE", "TSPLUS_VIRTUAL_PRINTER_STATE"))
                return Healthy(TsplusProduct.RemoteAccess, component, "No se observó una falla clara en la pila de impresión.", "TSplus Remote Access — Printing", "https://docs.tsplus.net/tsplus/quickstart-guide/", "Cobertura de Spooler y módulos de impresión.");
            return NoData(TsplusProduct.RemoteAccess, component, "No hay estado de Spooler/impresión suficiente para declarar esta capa saludable.",
                "TSplus Remote Access — Printing", "https://docs.tsplus.net/tsplus/quickstart-guide/");
        }

        if (component.Equals("Gateway / Farm", StringComparison.OrdinalIgnoreCase))
        {
            var farmError = x.HasFinding("TSPLUS-FARM-NO-SERVERS", "TSPLUS-FARM-BALANCE-NAME-MISMATCH") || x.EventError("TSPLUS_FARM_CONFIGURATION_STATE");
            var topology = x.EventsFor("TSPLUS_FARM_CONFIGURATION_STATE").ToList();
            if (farmError)
                return Build(TsplusProduct.RemoteAccess, component, GuidedResolutionState.Error, DiagnosticSeverity.Error, ConfidenceLevel.Alta,
                    "Usuarios pueden entrar por el Gateway pero fallar al alcanzar Application Servers.",
                    "La configuración Farm/Gateway presenta una inconsistencia o no contiene servidores válidos.",
                    "Puede afectar toda la granja o servidores concretos según la topología.",
                    [Check("Farm/Gateway", "FALLA", "Configuración/topología inconsistente")],
                    x.EvidenceFor("TSPLUS_FARM_CONFIGURATION_STATE", "balance.bin", "Gateway", "Application Server"),
                    ["Revisar nombres internos, Application Servers y puertos desde el Farm Controller/Gateway.", "Confirmar que cada Application Server tenga configuración coherente y sea accesible desde el Gateway."],
                    ["Validar un acceso a cada Application Server y revisar el dashboard Multi-servidor."],
                    ["No eliminar/recrear la granja antes de guardar la configuración y aislar el nodo afectado."],
                    "TSplus Remote Access — Farm Overview", "https://docs.tsplus.net/tsplus/farm-overview/",
                    "Configuración local de granja; TDM no sondea remotamente los nodos durante el diagnóstico normal.");
            return Build(TsplusProduct.RemoteAccess, component, topology.Count > 0 ? GuidedResolutionState.Saludable : GuidedResolutionState.NoEvaluado,
                DiagnosticSeverity.Informativo, ConfidenceLevel.Media,
                topology.Count > 0 ? "No se observó una inconsistencia clara de topología Farm/Gateway." : "No hay evidencia de granja suficiente en este nodo.",
                topology.Count > 0 ? "La configuración local de granja no muestra una falla activa." : "El nodo puede ser standalone o la configuración de granja no está disponible.",
                "Sin impacto confirmado.", [Check("Topología", topology.Count > 0 ? "OBSERVADA" : "N/D", $"Muestras: {topology.Count}")],
                x.EvidenceFrom(topology, 8), ["Si existe una granja, use Servidores → Detectar granja y confirme los nodos descubiertos."],
                ["Comprobar que Gateway y Application Servers aparecen con rol correcto."], ["No asumir rol Gateway sin configuración de granja."],
                "TSplus Remote Access — Farm Overview", "https://docs.tsplus.net/tsplus/farm-overview/", "Configuración Farm local y federación TDM.");
        }

        if (component.Equals("Load Balancing", StringComparison.OrdinalIgnoreCase))
        {
            var lb = x.HasFinding("TSPLUS-FARM-BALANCE-INCOMPLETE-DIRECTED", "TSPLUS-FARM-BALANCE-NAME-MISMATCH") || x.AnyErrorContaining("Load Balancing", "balance.bin");
            if (lb)
                return Build(TsplusProduct.RemoteAccess, component, GuidedResolutionState.Advertencia, DiagnosticSeverity.Advertencia, ConfidenceLevel.Media,
                    "Las sesiones pueden distribuirse de forma inesperada entre Application Servers.",
                    "La configuración de Load Balancing presenta una señal incompleta o inconsistente.",
                    "Puede concentrar sesiones en un nodo o impedir que un servidor participe correctamente.",
                    [Check("Load Balancing", "REVISAR", "Configuración inconsistente")], x.EvidenceFor("TSPLUS_WEB_BALANCE_STATE", "TSPLUS_FARM_CONFIGURATION_STATE", "Load Balancing", "balance.bin"),
                    ["Revisar configuración Load Balancing y Server Assignation antes de interpretar un desequilibrio como falla.", "Comparar sesiones/CPU de todos los nodos en Multi-servidor."],
                    ["Confirmar que las nuevas sesiones se distribuyen según la política configurada."],
                    ["No forzar un rebalanceo sin comprobar Server Assignation/sticky sessions."],
                    "TSplus Remote Access — Farm Overview", "https://docs.tsplus.net/tsplus/farm-overview/", "Configuración Farm + observabilidad multi-servidor cuando está disponible.");
            var lbCoverage = x.Contains("TSPLUS_WEB_BALANCE_STATE", "TSPLUS_FARM_CONFIGURATION_STATE", "Load Balancing");
            return Build(TsplusProduct.RemoteAccess, component,
                lbCoverage ? GuidedResolutionState.Informativo : GuidedResolutionState.NoEvaluado,
                DiagnosticSeverity.Informativo,
                lbCoverage ? ConfidenceLevel.Media : ConfidenceLevel.EvidenciaInsuficiente,
                lbCoverage ? "No se observó una señal explícita de Load Balancing inconsistente." : "No hay evidencia suficiente de Load Balancing en este nodo.",
                lbCoverage ? "La configuración disponible no muestra un error explícito, pero la distribución real debe compararse entre nodos." : "Sin configuración o datos multi-servidor TDM no declara el balanceo saludable.",
                "Sin impacto confirmado.", [Check("Load Balancing", lbCoverage ? "OBSERVADO" : "N/D", lbCoverage ? "Requiere comparación de nodos" : "Sin cobertura")],
                x.EvidenceFor("TSPLUS_WEB_BALANCE_STATE", "TSPLUS_FARM_CONFIGURATION_STATE", "Load Balancing"),
                ["Comparar sesiones, CPU y roles de todos los Application Servers en Multi-servidor."],
                ["Validar nuevas sesiones contra la política configurada."], ["No interpretar un reparto desigual como falla sin revisar Server Assignation."],
                "TSplus Remote Access — Farm Overview", "https://docs.tsplus.net/tsplus/farm-overview/", "Configuración local + observabilidad multi-servidor cuando existe.");
        }

        if (component.Equals("Licencia / actualización", StringComparison.OrdinalIgnoreCase))
        {
            var license = x.AnyErrorContaining("LICENSE", "licencia", "license");
            var update = x.HasFinding("TSPLUS-UPDATE-REBOOT-REQUIRED-DAT", "TSPLUS_UPDATE_BLOCKER", "TSPLUS-VERSION-PROFILE-UNSUPPORTED") || x.AnyErrorContaining("reboot_required.dat", "update");
            if (license || update)
                return Build(TsplusProduct.RemoteAccess, component, GuidedResolutionState.Advertencia, DiagnosticSeverity.Advertencia, ConfidenceLevel.Media,
                    "La instalación puede presentar limitación de licencia/edición o mantenimiento pendiente.",
                    license ? "Un log menciona explícitamente un problema de licencia." : "TDM detectó un bloqueo/compatibilidad de actualización que requiere mantenimiento.",
                    "Puede afectar funciones o estabilidad según la evidencia específica.",
                    [Check("Licencia", license ? "REVISAR" : "Sin señal", license ? "Mencionada por log" : "No evaluada directamente"), Check("Actualización", update ? "REVISAR" : "Sin señal", update ? "Bloqueo/compatibilidad" : "No confirmado")],
                    x.EvidenceFor("LICENSE", "UPDATE", "reboot_required", "VERSION_PROFILE"),
                    ["Revisar estado/licencia desde AdminTool y la rama TSplus instalada.", "Seguir el procedimiento oficial de Update Release si existe un bloqueo de actualización."],
                    ["Confirmar que AdminTool muestra estado normal y repetir el diagnóstico después del mantenimiento."],
                    ["No eliminar manualmente archivos de control de update sin seguir el procedimiento oficial."],
                    "TSplus Remote Access — Updating / License", "https://docs.tsplus.net/tsplus/quickstart-guide/", "TDM no activa ni modifica licencias; sólo usa menciones explícitas y artefactos de mantenimiento.");
            return Build(TsplusProduct.RemoteAccess, component, GuidedResolutionState.NoEvaluado, DiagnosticSeverity.Informativo, ConfidenceLevel.EvidenciaInsuficiente,
                "Sin error explícito de licencia/update en la evidencia.", "El licenciamiento completo está fuera del alcance de inferencia automática de TDM.", "Sin impacto confirmado.",
                [Check("Licencia", "N/D", "TDM no interpreta claves/licencias")], [], ["Validar manualmente desde AdminTool si el síntoma sugiere licencia/edición."], ["Confirmar estado y edición desde la herramienta oficial."], ["No inferir licencia sana sólo por ausencia de logs."],
                "TSplus Remote Access — Quickstart Guide", "https://docs.tsplus.net/tsplus/quickstart-guide/", "Cobertura deliberadamente conservadora.");
        }

        return NoData(TsplusProduct.RemoteAccess, component, "Componente Remote Access no reconocido por el asistente.", "TSplus Remote Access", "https://docs.tsplus.net/tsplus/quickstart-guide/");
    }

    private static GuidedResolutionResult AnalyzeTwoFactor(EvidenceIndex x, string component)
    {
        var installed = x.IsProductInstalled(TsplusProduct.TwoFactorAuthentication);
        if (!installed)
            return NotApplicable(TsplusProduct.TwoFactorAuthentication, component, "2FA no está detectado en esta instalación Remote Access.",
                "TSplus — Two-factor Authentication", "https://docs.tsplus.net/tsplus/twofactorauthentication/");

        if (component.Equals("General", StringComparison.OrdinalIgnoreCase))
        {
            var children = Components[TsplusProduct.TwoFactorAuthentication].Skip(1).Select(c => AnalyzeTwoFactor(x, c)).ToList();
            var worst = children.OrderByDescending(r => SeverityRank(r.Severidad)).ThenByDescending(r => StateRank(r.Estado)).First();
            var failures = children.Where(r => r.Estado is GuidedResolutionState.Error or GuidedResolutionState.Advertencia).ToList();
            return Build(TsplusProduct.TwoFactorAuthentication, component,
                failures.Count > 0 ? worst.Estado : GuidedResolutionState.Informativo,
                failures.Count > 0 ? worst.Severidad : DiagnosticSeverity.Informativo,
                failures.Count > 0 ? worst.Confianza : ConfidenceLevel.Media,
                failures.Count > 0 ? "2FA presenta una condición que puede impedir la autenticación." : "2FA está detectado; la operación completa sólo se confirma durante un flujo de autenticación real.",
                failures.Count > 0 ? worst.CausaProbable : "No se observó una causa 2FA clara en la evidencia disponible.",
                failures.Count > 0 ? worst.Impacto : "Sin impacto 2FA confirmado.",
                children.Select(r => new GuidedResolutionCheck(r.Componente, StateLabel(r.Estado), r.CausaProbable, r.Severidad)).ToList(),
                failures.SelectMany(r => r.Evidencia).Take(14).ToList(), failures.Count > 0 ? worst.ComoCorregir : ["Si el código es rechazado, revise Tiempo/TOTP y Cliente compatible primero."],
                failures.Count > 0 ? worst.ComoValidar : ["Completar un inicio de sesión 2FA real desde Web Portal o cliente TSplus compatible."],
                ["No deshabilitar 2FA globalmente como primera prueba.", "No resetear todos los usuarios si el problema afecta sólo a uno."],
                "TSplus — Two-factor Authentication", "https://docs.tsplus.net/tsplus/twofactorauthentication/",
                "TDM usa producto/artefactos, logs 2FA si existen y evidencia de Windows/Web; no solicita ni almacena códigos TOTP.");
        }

        if (component.Equals("Tiempo / TOTP", StringComparison.OrdinalIgnoreCase))
        {
            var timeError = x.HasFinding("TSPLUS-2FA-TIME-SYNC-REVIEW") || x.HasErrorType("WINDOWS_TIME_SYNC_FAILURE", "WINDOWS_TIME_SERVICE_ERROR") || x.AnyErrorContaining("W32Time", "Microsoft-Windows-Time-Service", "clock drift", "desfase de reloj", "time synchronization failed");
            return Build(TsplusProduct.TwoFactorAuthentication, component,
                timeError ? GuidedResolutionState.Error : GuidedResolutionState.NoEvaluado,
                timeError ? DiagnosticSeverity.Error : DiagnosticSeverity.Informativo,
                timeError ? ConfidenceLevel.Alta : ConfidenceLevel.EvidenciaInsuficiente,
                timeError ? "Los códigos TOTP pueden ser rechazados por desfase horario." : "No hay evidencia suficiente para confirmar sincronización entre servidor y dispositivo autenticador.",
                timeError ? "TDM observó una señal compatible con reloj/sincronización fuera de estado normal." : "TSplus requiere que servidor y dispositivo estén sincronizados; TDM sólo puede evaluar el lado servidor cuando existe evidencia.",
                "Afecta códigos de autenticador basados en tiempo; usuario/contraseña pueden ser correctos y el segundo factor fallar.",
                [Check("Reloj servidor", timeError ? "FALLA/REVISAR" : "N/D", timeError ? "Señal de sincronización" : "Sin medición remota del dispositivo")],
                x.EvidenceFor("W32Time", "Time-Service", "clock", "TOTP", "desfase"),
                ["Revisar sincronización Windows/NTP del servidor.", "Confirmar hora automática y zona correcta en el dispositivo del usuario.", "Esperar un nuevo código TOTP antes de reintentar."],
                ["Completar un login 2FA con un código recién generado y confirmar que no aparece rechazo nuevo."],
                ["No resetear el enrollment si el problema es global y coincide con desfase horario."],
                "TSplus — Two-factor Authentication", "https://docs.tsplus.net/tsplus/twofactorauthentication/",
                "No se accede al reloj del dispositivo; la conclusión global requiere validación manual del cliente.");
        }

        if (component.Equals("Cliente compatible", StringComparison.OrdinalIgnoreCase))
        {
            var directRdpFailures = x.MatchesType("USER_LOGON_FAILURE", "RDP_AUTHENTICATION_STAGE").Where(e => ContainsAny(e, "2FA", "two-factor", "second factor")).ToList();
            var generatedClientError = x.AnyErrorContaining("CONNECTION_CLIENT", "2FA") || x.AnyErrorContaining("TwoFactor", "HTTPS");
            var evidence = x.EvidenceFor("2FA", "CONNECTION_CLIENT", "RemoteApp", "mstsc");
            var state = generatedClientError ? GuidedResolutionState.Error : directRdpFailures.Count > 0 ? GuidedResolutionState.Advertencia : GuidedResolutionState.Informativo;
            var cause = generatedClientError
                ? "El cliente generado/portal no puede completar la validación 2FA; revise compatibilidad y HTTPS."
                : "TSplus no soporta 2FA mediante el cliente Microsoft Remote Desktop estándar (mstsc.exe); los clientes TSplus generados requieren soporte 2FA explícito.";
            return Build(TsplusProduct.TwoFactorAuthentication, component, state,
                generatedClientError ? DiagnosticSeverity.Error : DiagnosticSeverity.Informativo,
                generatedClientError ? ConfidenceLevel.Media : ConfidenceLevel.Confirmada,
                "Un usuario 2FA puede ser rechazado si utiliza un método de conexión no compatible.", cause,
                "Puede afectar sólo al método de cliente mientras Web Portal/otro cliente compatible funciona.",
                [Check("Compatibilidad", generatedClientError ? "REVISAR" : "REGLA CONOCIDA", "Web Portal HTML5/RemoteApp o cliente TSplus generado con 2FA")], evidence,
                ["Usar Web Portal HTML5/RemoteApp o un cliente TSplus generado con soporte 2FA.", "Si el puerto HTTPS del portal cambió, regenerar los clientes 2FA anteriores."],
                ["Confirmar la autenticación desde Web Portal y después desde el cliente TSplus regenerado."],
                ["No habilitar mstsc.exe para usuarios 2FA esperando que solicite el segundo factor."],
                "TSplus — Two-factor Authentication / Portable Client Generator", "https://docs.tsplus.net/tsplus/portable-client-generator/",
                "La UI no puede saber siempre qué cliente usó el usuario; TDM sólo eleva una falla cuando existe evidencia compatible.");
        }

        if (component.Equals("Portal / HTTPS", StringComparison.OrdinalIgnoreCase))
        {
            var web = AnalyzeRemoteAccess(x, "Web Portal / HTTPS");
            if (web.Estado == GuidedResolutionState.NoEvaluado)
                return NoData(TsplusProduct.TwoFactorAuthentication, component, "La ruta Web/HTTPS no tiene cobertura suficiente para evaluar su dependencia con 2FA.",
                    "TSplus — Portable Client Generator / 2FA", "https://docs.tsplus.net/tsplus/portable-client-generator/");
            var bad = web.Estado is GuidedResolutionState.Error or GuidedResolutionState.Advertencia;
            return Build(TsplusProduct.TwoFactorAuthentication, component, bad ? GuidedResolutionState.Error : GuidedResolutionState.Saludable,
                bad ? web.Severidad : DiagnosticSeverity.Informativo, bad ? web.Confianza : ConfidenceLevel.Media,
                bad ? "2FA puede fallar porque el Web Portal/HTTPS requerido no está saludable." : "No se observó una falla clara del Web Portal/HTTPS en la evidencia.",
                bad ? web.CausaProbable : "El servidor Web/HTTPS no muestra una falla activa detectable.",
                "Los clientes generados con 2FA validan el código contra el Web Portal por HTTPS.",
                [Check("Web Portal / HTTPS", bad ? "FALLA" : "OK", web.CausaProbable)], web.Evidencia,
                bad ? web.ComoCorregir : ["Mantener disponible el Web Portal/HTTPS para los clientes 2FA."],
                ["Validar el portal HTTPS y completar un login 2FA."],
                ["No diagnosticar el autenticador antes de confirmar que HTTPS funciona."],
                "TSplus — Portable Client Generator / 2FA", "https://docs.tsplus.net/tsplus/portable-client-generator/", "Reutiliza la evidencia Web/HTTPS de Remote Access.");
        }

        if (component.Equals("Usuarios / enrollment", StringComparison.OrdinalIgnoreCase))
        {
            var logError = x.AnyErrorContaining("TwoFactor", "enroll", "activation", "QR", "verification code", "SMS", "email");
            return Build(TsplusProduct.TwoFactorAuthentication, component,
                logError ? GuidedResolutionState.Advertencia : GuidedResolutionState.NoEvaluado,
                logError ? DiagnosticSeverity.Advertencia : DiagnosticSeverity.Informativo,
                logError ? ConfidenceLevel.Media : ConfidenceLevel.EvidenciaInsuficiente,
                logError ? "Hay una señal en logs compatible con enrollment/activación/entrega del código." : "TDM no lee secretos, QR ni la configuración privada del usuario 2FA.",
                logError ? "El usuario puede no haber completado el enrollment o el método SMS/Email/App puede requerir revisión." : "La ausencia de errores no permite afirmar que cada usuario esté correctamente inscrito.",
                "Afecta usuarios concretos y no necesariamente a todo Remote Access.",
                [Check("Enrollment", logError ? "REVISAR" : "N/D", logError ? "Señal en log" : "Configuración sensible no inspeccionada")],
                x.EvidenceFor("TwoFactor", "enroll", "activation", "SMS", "email"),
                ["Revisar Manage Users en Two-Factor Authentication.", "Si el usuario perdió el dispositivo o necesita un nuevo QR, usar Reset para ese usuario desde la herramienta oficial."],
                ["Completar un nuevo enrollment/login para el usuario afectado."],
                ["No exportar secretos/QR en el paquete de soporte.", "No resetear todos los usuarios por un caso individual."],
                "TSplus — Two-factor Authentication", "https://docs.tsplus.net/tsplus/twofactorauthentication/", "TDM conserva privacidad y no inspecciona secretos 2FA.");
        }

        if (component.Equals("Gateway / Application Server", StringComparison.OrdinalIgnoreCase))
        {
            var farm = x.Contains("Gateway", "Application Server", "Farm Controller", "Reverse Proxy");
            var farmErrors = x.AnyErrorContaining("Gateway", "Application Server", "authentication server", "TwoFactor");
            return Build(TsplusProduct.TwoFactorAuthentication, component,
                farmErrors ? GuidedResolutionState.Error : farm ? GuidedResolutionState.Informativo : GuidedResolutionState.NoEvaluado,
                farmErrors ? DiagnosticSeverity.Error : DiagnosticSeverity.Informativo,
                farmErrors ? ConfidenceLevel.Media : ConfidenceLevel.Media,
                farmErrors ? "2FA presenta una señal en un despliegue de granja." : "En despliegues multi-servidor, 2FA se configura en el punto de entrada/Gateway y los Application Servers pueden usar un authentication server URL.",
                farmErrors ? "La relación Gateway/Application Server/autenticación requiere revisión." : "No se observó una falla explícita de topología 2FA.",
                "Una mala configuración puede afectar todos los usuarios que ingresan por el Gateway o sólo un Application Server.",
                [Check("Topología 2FA", farmErrors ? "REVISAR" : farm ? "OBSERVADA" : "N/D", farm ? "Farm/Gateway detectado" : "Sin granja detectada")],
                x.EvidenceFor("Gateway", "Application Server", "TwoFactor", "FARM"),
                ["Configurar/habilitar 2FA en el servidor expuesto como punto de entrada o reverse proxy.", "En Application Servers, validar la URL del servidor de autenticación cuando aplique."],
                ["Probar 2FA por Gateway y comprobar llegada a cada Application Server."],
                ["No configurar cada nodo de forma independiente sin respetar el diseño de la granja."],
                "TSplus — Two-factor Authentication", "https://docs.tsplus.net/tsplus/twofactorauthentication/", "Topología local + federación; no se leen secretos 2FA remotamente.");
        }

        return NoData(TsplusProduct.TwoFactorAuthentication, component, "Componente 2FA no reconocido.", "TSplus — Two-factor Authentication", "https://docs.tsplus.net/tsplus/twofactorauthentication/");
    }

    private static GuidedResolutionResult AnalyzeAdvancedSecurity(EvidenceIndex x, string component)
    {
        var installed = x.IsProductInstalled(TsplusProduct.AdvancedSecurity);
        if (!installed)
            return NotApplicable(TsplusProduct.AdvancedSecurity, component, "Advanced Security no está instalado/detectado en este equipo.",
                "TSplus Advanced Security", "https://docs.tsplus.net/advanced-security/quickstart/");

        if (component.Equals("General", StringComparison.OrdinalIgnoreCase))
        {
            var serviceDown = x.HasFinding("TSPLUS-ADVSEC-SERVICE-NOT-RUNNING", "TSPLUS-ADVSEC-SERVICE-NOT-FOUND") || x.EventError("TSPLUS_ADVSEC_PRODUCT_RUNTIME_STATE");
            var children = Components[TsplusProduct.AdvancedSecurity].Skip(1).Select(c => AnalyzeAdvancedSecurity(x, c)).ToList();
            var failures = children.Where(r => r.Estado is GuidedResolutionState.Error or GuidedResolutionState.Advertencia).ToList();
            if (serviceDown)
                return Build(TsplusProduct.AdvancedSecurity, component, GuidedResolutionState.Error, DiagnosticSeverity.Error, ConfidenceLevel.Alta,
                    "Advanced Security puede no estar aplicando sus protecciones.", "El servicio/núcleo principal no se observa operativo.",
                    "Puede afectar múltiples funciones de seguridad; Remote Access no debe considerarse originador automáticamente.",
                    [Check("Servicio / núcleo", "FALLA", "Servicio no operativo")], x.EvidenceFor("TSPLUS_ADVSEC_PRODUCT_RUNTIME_STATE", "TSplus-Security"),
                    ["Revisar Service Control Manager, crashes y logs Service de Advanced Security."], ["Confirmar servicio Running y repetir el diagnóstico."],
                    ["No deshabilitar protecciones globales para ocultar la falla."], "TSplus Advanced Security — Getting Started / Logs", "https://docs.tsplus.net/advanced-security/quickstart/", "Servicio principal + logs oficiales + eventos Windows.");
            var worst = failures.OrderByDescending(r => SeverityRank(r.Severidad)).FirstOrDefault();
            return Build(TsplusProduct.AdvancedSecurity, component, failures.Count > 0 ? worst!.Estado : GuidedResolutionState.Informativo,
                failures.Count > 0 ? worst!.Severidad : DiagnosticSeverity.Informativo,
                failures.Count > 0 ? worst!.Confianza : ConfidenceLevel.Media,
                failures.Count > 0 ? "Advanced Security presenta una condición de módulo que requiere revisión." : "Advanced Security está instalado; varias funciones sólo pueden evaluarse si sus logs/configuración dejan evidencia.",
                failures.Count > 0 ? worst!.CausaProbable : "No se observó una falla funcional confirmada del núcleo.",
                failures.Count > 0 ? worst!.Impacto : "Sin impacto confirmado.",
                children.Select(r => new GuidedResolutionCheck(r.Componente, StateLabel(r.Estado), r.CausaProbable, r.Severidad)).ToList(),
                failures.SelectMany(r => r.Evidencia).Take(14).ToList(), failures.Count > 0 ? worst!.ComoCorregir : ["Seleccione la función que coincide con el síntoma y revise su cobertura/logs."],
                failures.Count > 0 ? worst!.ComoValidar : ["Repetir el flujo afectado y comprobar Events/Advanced Security."],
                ["No asumir que Advanced Security causó un bloqueo sólo por estar instalado."], "TSplus Advanced Security — Getting Started", "https://docs.tsplus.net/advanced-security/quickstart/", "Cobertura modular conservadora.");
        }

        if (component.Equals("Bruteforce Protection", StringComparison.OrdinalIgnoreCase))
        {
            var logons = x.MatchesType("USER_LOGON_FAILURE").ToList();
            var moduleError = x.AnyErrorContaining("Bruteforce", "brute", "blacklist", "blocked IP");
            var state = moduleError ? GuidedResolutionState.Error : logons.Count >= 10 ? GuidedResolutionState.Advertencia : GuidedResolutionState.Informativo;
            return Build(TsplusProduct.AdvancedSecurity, component, state, moduleError ? DiagnosticSeverity.Error : logons.Count >= 10 ? DiagnosticSeverity.Advertencia : DiagnosticSeverity.Informativo,
                moduleError ? ConfidenceLevel.Media : ConfidenceLevel.Media,
                moduleError ? "Bruteforce Protection presenta una señal de error." : logons.Count >= 10 ? "Se observan numerosos fallos de logon; la protección debería revisarse si provienen de un origen ofensivo." : "No se observó una anomalía clara de Bruteforce Protection.",
                moduleError ? "Logs/evidencia de Advanced Security contienen un fallo relacionado con Bruteforce." : "Los 4625 son la señal de entrada; sin evidencia de bloqueo TDM no afirma que la protección falló.",
                "Puede bloquear IPs ofensivas o, si está mal configurado, dejar intentos sin mitigación.",
                [Check("Fallos Windows", logons.Count.ToString(), "USER_LOGON_FAILURE"), Check("Bruteforce log", moduleError ? "REVISAR" : "Sin error explícito", "Logs pueden estar deshabilitados")],
                x.EvidenceFor("Bruteforce", "USER_LOGON_FAILURE", "blocked", "blacklist"),
                ["Revisar Advanced Security → Bruteforce Protection y Blocked IPs.", "Si hace falta evidencia adicional, habilitar temporalmente el log de Bruteforce con el nivel indicado por soporte."],
                ["Reproducir de forma controlada sólo en laboratorio y confirmar registro/bloqueo esperado."],
                ["No generar ataques de fuerza bruta en producción.", "No desbloquear una IP sin validar que sea legítima."],
                "TSplus Advanced Security — Bruteforce Protection", "https://docs.tsplus.net/advanced-security/bruteforce-protection/", "Fallos Windows + logs Advanced Security cuando están habilitados.");
        }

        if (component.Equals("Geographic Protection", StringComparison.OrdinalIgnoreCase))
        {
            var geoError = x.AnyErrorContaining("Geographic", "geography", "homeland", "GeoIP", "MaxMind");
            return Build(TsplusProduct.AdvancedSecurity, component, geoError ? GuidedResolutionState.Error : GuidedResolutionState.NoEvaluado,
                geoError ? DiagnosticSeverity.Error : DiagnosticSeverity.Informativo, geoError ? ConfidenceLevel.Media : ConfidenceLevel.EvidenciaInsuficiente,
                geoError ? "Geographic Protection presenta una señal de error/bloqueo inesperado." : "Sin log/configuración suficiente para confirmar el comportamiento geográfico.",
                geoError ? "La evaluación GeoIP/firewall contiene una anomalía; VPN/proxy/GeoIP también pueden alterar el país observado." : "La ausencia de log Geographic no se interpreta como salud porque los logs están deshabilitados por defecto.",
                "Puede denegar conexiones desde ubicaciones no permitidas.",
                [Check("Geographic Protection", geoError ? "REVISAR" : "N/D", geoError ? "Señal disponible" : "Cobertura parcial")],
                x.EvidenceFor("Geographic", "GeoIP", "MaxMind", "Firewall"),
                ["Revisar país/IP observado, VPN/proxy y lista permitida.", "Confirmar el motor de firewall usado por Advanced Security."],
                ["Probar desde una IP/ubicación autorizada y confirmar que la conexión se permite."],
                ["No cambiar países permitidos para compensar una geolocalización/IP mal identificada."],
                "TSplus Advanced Security — Geographic Protection", "https://docs.tsplus.net/advanced-security/geographic-protection/", "Logs/configuración disponible; ausencia de log = no evaluado.");
        }

        if (component.Equals("Firewall", StringComparison.OrdinalIgnoreCase))
        {
            var fwError = x.AnyErrorContaining("Advanced Security / Firewall", "firewall") && x.Matches("firewall").Any(IsError);
            return Build(TsplusProduct.AdvancedSecurity, component, fwError ? GuidedResolutionState.Error : GuidedResolutionState.NoEvaluado,
                fwError ? DiagnosticSeverity.Error : DiagnosticSeverity.Informativo, fwError ? ConfidenceLevel.Media : ConfidenceLevel.EvidenciaInsuficiente,
                fwError ? "El motor de firewall presenta una señal de error." : "TDM no confirma la selección Windows Firewall vs firewall integrado sin una fuente estable explícita.",
                fwError ? "Advanced Security no puede aplicar o leer correctamente una regla/bloqueo según la evidencia disponible." : "La selección del motor debe revisarse en Settings → Advanced → Product cuando el síntoma es bloqueo/no bloqueo.",
                "Puede afectar Bruteforce, Geographic y Hacker IP Protection.",
                [Check("Firewall", fwError ? "FALLA/REVISAR" : "N/D", fwError ? "Evento/log" : "Configuración no inferida")],
                x.EvidenceFor("Firewall", "blocked IP", "Windows Firewall"),
                ["Si Windows Firewall está activo, TSplus recomienda usarlo para aplicar reglas.", "Si existe otro firewall que sustituye a Windows Firewall, revisar el firewall integrado de Advanced Security."],
                ["Confirmar que una IP de prueba controlada obtiene el comportamiento esperado sin afectar usuarios."],
                ["No deshabilitar todos los firewalls como prueba en producción."],
                "TSplus Advanced Security — Advanced Firewall", "https://docs.tsplus.net/advanced-security/advanced-firewall/", "No se modifican reglas ni se infiere una configuración ausente.");
        }

        if (component.Equals("Restrict Working Hours", StringComparison.OrdinalIgnoreCase))
        {
            var hours = x.AnyErrorContaining("Working Hours", "workinghours", "outside working", "logoff") || x.Contains("Working Hours") && x.Matches("Working Hours").Any(IsError);
            return Build(TsplusProduct.AdvancedSecurity, component, hours ? GuidedResolutionState.Advertencia : GuidedResolutionState.NoEvaluado,
                hours ? DiagnosticSeverity.Advertencia : DiagnosticSeverity.Informativo, hours ? ConfidenceLevel.Media : ConfidenceLevel.EvidenciaInsuficiente,
                hours ? "Una desconexión/denegación coincide con Working Hours." : "No hay evidencia suficiente para confirmar reglas horarias activas.",
                hours ? "La política de horario puede estar funcionando como fue configurada, no ser una falla de Remote Access." : "Las reglas de usuario/grupo y timezone deben revisarse si la desconexión ocurre a una hora repetible.",
                "Puede impedir login o desconectar automáticamente al finalizar el horario permitido.",
                [Check("Working Hours", hours ? "REVISAR" : "N/D", hours ? "Coincidencia temporal/log" : "Regla no inferida")],
                x.EvidenceFor("Working Hours", "logoff", "timezone"),
                ["Revisar regla directa del usuario antes de reglas de grupo.", "Revisar timezone configurada y horario de desconexión."],
                ["Probar dentro del horario autorizado y confirmar que la sesión permanece activa."],
                ["No reiniciar Remote Access si la desconexión coincide exactamente con una política horaria."],
                "TSplus Advanced Security — Restrict Working Hours", "https://docs.tsplus.net/advanced-security/working-hours-restriction/", "Necesita logs/reglas o correlación horaria; no lee políticas sensibles de usuario de forma agresiva.");
        }

        if (component.Equals("Secure Sessions", StringComparison.OrdinalIgnoreCase))
        {
            var secure = x.AnyErrorContaining("Secure Sessions", "Secure Desktop", "Kiosk") || x.Contains("Secure Sessions", "Kiosk Mode", "Secured Sessions Mode");
            return Build(TsplusProduct.AdvancedSecurity, component, secure ? GuidedResolutionState.Informativo : GuidedResolutionState.NoEvaluado,
                DiagnosticSeverity.Informativo, ConfidenceLevel.Media,
                secure ? "Se detectó contexto compatible con Secure Sessions." : "No hay evidencia suficiente para determinar el nivel de Secure Sessions aplicado.",
                "Restricciones visibles pueden ser comportamiento configurado; además, Secure Sessions puede entrar en conflicto con políticas AD.",
                "Afecta interfaz y recursos visibles dentro de la sesión; no necesariamente la conectividad Remote Access.",
                [Check("Secure Sessions", secure ? "CONTEXTO" : "N/D", secure ? "Política/registro observado" : "Sin fuente suficiente")],
                x.EvidenceFor("Secure Sessions", "Secure Desktop", "Kiosk"),
                ["Revisar nivel Windows/Secured/Kiosk y reglas directas/grupos.", "Si hay GPO de Active Directory, comprobar conflicto antes de cambiar TSplus."],
                ["Validar con el usuario/grupo afectado que la interfaz esperada aparece."],
                ["No usar Secure Sessions como sustituto de Permissions para controlar acceso a unidades."],
                "TSplus Advanced Security — Secure Sessions", "https://docs.tsplus.net/advanced-security/secure-sessions/", "Diagnóstico conservador; la UI no asume configuración no observada.");
        }

        if (component.Equals("Trusted Devices", StringComparison.OrdinalIgnoreCase))
        {
            var trusted = x.AnyErrorContaining("Trusted Devices", "trusteddevice", "endpoint", "invalid device");
            var html5 = x.Contains("HTML5") && x.AnyErrorContaining("Trusted Devices", "endpoint", "device");
            return Build(TsplusProduct.AdvancedSecurity, component, trusted || html5 ? GuidedResolutionState.Advertencia : GuidedResolutionState.NoEvaluado,
                trusted || html5 ? DiagnosticSeverity.Advertencia : DiagnosticSeverity.Informativo,
                trusted || html5 ? ConfidenceLevel.Media : ConfidenceLevel.EvidenciaInsuficiente,
                html5 ? "El acceso usa HTML5 y coincide con Trusted Devices." : trusted ? "Trusted Devices puede estar bloqueando el nombre de dispositivo observado." : "No hay evidencia suficiente para confirmar Trusted Devices.",
                html5 ? "Trusted Devices no es compatible con sesiones HTML5; el Web Portal tampoco puede resolver el nombre real del cliente de forma normal." : trusted ? "El dispositivo no coincide con los dispositivos autorizados o no puede resolverse correctamente." : "La función sólo debe elevarse a causa cuando existe evidencia de bloqueo/dispositivo.",
                "Puede bloquear una conexión intencionalmente mientras Remote Access permanece saludable.",
                [Check("Trusted Devices", trusted ? "REVISAR" : "N/D", html5 ? "HTML5 incompatible" : trusted ? "Dispositivo/bloqueo" : "Sin señal")],
                x.EvidenceFor("Trusted Devices", "trusteddevice", "endpoint", "HTML5", "device"),
                ["Revisar el dispositivo autorizado y el método de conexión.", "Si se permite Web Portal, evaluar conscientemente la reducción de seguridad indicada por TSplus."],
                ["Probar desde un dispositivo explícitamente confiable mediante un método compatible."],
                ["No deshabilitar Trusted Devices globalmente sólo para resolver un único endpoint."],
                "TSplus Advanced Security — Trusted Devices", "https://docs.tsplus.net/advanced-security/trusted-devices/", "TDM mantiene la evidencia de diagnóstico en los reportes HTML/JSON; revise datos identificables antes de compartirlos fuera del entorno autorizado.");
        }

        if (component.Equals("Permissions", StringComparison.OrdinalIgnoreCase))
        {
            var perm = x.AnyErrorContaining("Advanced Security / Permissions", "permissions", "access denied") && x.Contains("Advanced Security");
            return Build(TsplusProduct.AdvancedSecurity, component, perm ? GuidedResolutionState.Advertencia : GuidedResolutionState.NoEvaluado,
                perm ? DiagnosticSeverity.Advertencia : DiagnosticSeverity.Informativo, perm ? ConfidenceLevel.Media : ConfidenceLevel.EvidenciaInsuficiente,
                perm ? "Un acceso denegado puede corresponder a Permissions de Advanced Security." : "Sin evidencia suficiente para atribuir permisos a Advanced Security.",
                perm ? "Una regla de Permissions o ACL subyacente requiere comparación con el recurso afectado." : "Access denied genérico no identifica automáticamente Advanced Security como originador.",
                "Puede afectar carpetas, registro, impresoras u otros recursos sin cortar la sesión.",
                [Check("Permissions", perm ? "REVISAR" : "N/D", perm ? "Access denied con contexto" : "Sin señal")],
                x.EvidenceFor("Permissions", "Access denied", "ACL"),
                ["Usar Inspect/Audit de Permissions para el recurso afectado y revisar también ACL Windows."],
                ["Confirmar acceso con la misma cuenta después del ajuste autorizado."],
                ["No otorgar permisos amplios a Everyone como prueba."],
                "TSplus Advanced Security — Permissions", "https://docs.tsplus.net/advanced-security/permissions/", "TDM no cambia ACL ni habilita auditoría automáticamente.");
        }

        if (component.Equals("Ransomware Protection", StringComparison.OrdinalIgnoreCase))
        {
            var ransomware = x.AnyErrorContaining("Ransomware", "quarantine", "snapshot", "encrypted") || x.Contains("Ransomware") && x.Matches("Ransomware").Any(IsError);
            return Build(TsplusProduct.AdvancedSecurity, component, ransomware ? GuidedResolutionState.Error : GuidedResolutionState.NoEvaluado,
                ransomware ? DiagnosticSeverity.Error : DiagnosticSeverity.Informativo, ransomware ? ConfidenceLevel.Alta : ConfidenceLevel.EvidenciaInsuficiente,
                ransomware ? "Ransomware Protection detectó/bloqueó una actividad o existe una falla en esa función." : "No existe evidencia suficiente para afirmar estado operativo de Ransomware Protection.",
                ransomware ? "La protección puede haber detenido un proceso y movido elementos a cuarentena; el proceso detectado debe revisarse antes de autorizarlo." : "La ausencia de log no equivale a protección sana porque los logs están deshabilitados por defecto.",
                "Puede detener aplicaciones y proteger archivos; un falso positivo puede parecer una falla de aplicación/Remote Access.",
                [Check("Ransomware Protection", ransomware ? "DETECCIÓN/REVISAR" : "N/D", ransomware ? "Log/evento compatible" : "Cobertura parcial")],
                x.EvidenceFor("Ransomware", "quarantine", "snapshot", "encrypted"),
                ["Revisar Report, Quarantine y Snapshots en Advanced Security.", "Confirmar si el proceso detectado es legítimo antes de considerar whitelist.", "En una puesta en marcha nueva, revisar el Learning Period recomendado."],
                ["Confirmar que la aplicación legítima funciona sólo después de una decisión de seguridad autorizada."],
                ["No añadir automáticamente procesos a whitelist.", "No restaurar cuarentena sin validar el archivo/proceso."],
                "TSplus Advanced Security — Ransomware Protection", "https://docs.tsplus.net/advanced-security/ransomware-protection/", "Logs/artefactos disponibles; TDM no ejecuta whitelist ni restore.");
        }

        if (component.Equals("Logs", StringComparison.OrdinalIgnoreCase))
        {
            var logEvents = x.EventsFor("TSPLUS_ADVSEC_MODULE_STATE").ToList();
            var observed = logEvents.SelectMany(e => e.Evidencia ?? []).Count(e => e.Clave.Equals("Logs coincidentes", StringComparison.OrdinalIgnoreCase) && !e.Valor.Contains("Ninguno", StringComparison.OrdinalIgnoreCase));
            return Build(TsplusProduct.AdvancedSecurity, component, observed > 0 ? GuidedResolutionState.Saludable : GuidedResolutionState.NoEvaluado,
                DiagnosticSeverity.Informativo, ConfidenceLevel.Confirmada,
                observed > 0 ? "TDM encontró logs de Advanced Security para una o más funciones." : "No se observaron logs de función Advanced Security.",
                observed > 0 ? "Existe cobertura adicional para troubleshooting." : "TSplus documenta que los logs de Advanced Security están deshabilitados por defecto; ausencia de log no es falla.",
                "Sin logs, TDM puede identificar servicio/runtime pero tendrá menos detalle para atribuir Bruteforce/Geographic/Ransomware/Working Hours/Firewall.",
                [Check("Logs funcionales", observed > 0 ? "OBSERVADOS" : "NO OBSERVADOS", observed.ToString())],
                x.EvidenceFor("TSPLUS_ADVSEC_MODULE_STATE", "logs"),
                observed > 0 ? ["Conservar los logs sólo durante el periodo necesario de soporte."] : ["Si soporte necesita más detalle, habilitar temporalmente sólo el log del componente afectado y con el nivel indicado."],
                ["Reproducir el incidente y confirmar que el log seleccionado registra la señal."],
                ["No habilitar DEBUG/ALL de todos los módulos de forma permanente en producción."],
                "TSplus Advanced Security — Advanced Logs", "https://docs.tsplus.net/advanced-security/advanced-logs/", "Ruta predeterminada oficial de logs + cobertura modular TDM.");
        }

        return NoData(TsplusProduct.AdvancedSecurity, component, "Componente Advanced Security no reconocido.", "TSplus Advanced Security", "https://docs.tsplus.net/advanced-security/quickstart/");
    }

    private static GuidedResolutionResult Healthy(TsplusProduct product, string component, string cause, string source, string url, string coverage)
        => Build(product, component, GuidedResolutionState.Saludable, DiagnosticSeverity.Informativo, ConfidenceLevel.Media,
            "Sin falla activa identificada en esta capa.", cause, "Sin impacto atribuible a esta capa en la evidencia actual.",
            [Check(component, "OK", cause)], [], ["No se requiere corrección en esta capa con la evidencia actual."],
            ["Mantener Diagnóstico continuo y confirmar que no aparezcan nuevas señales."], ["No interpretar OK como garantía absoluta si la cobertura está limitada."], source, url, coverage);

    private static GuidedResolutionResult NotApplicable(TsplusProduct product, string component, string reason, string source, string url)
        => Build(product, component, GuidedResolutionState.NoAplica, DiagnosticSeverity.Informativo, ConfidenceLevel.Confirmada,
            "No aplica.", reason, "Sin impacto porque el producto no está instalado/detectado en esta ejecución.", [Check(component, "NO APLICA", reason)], [], [],
            ["No requiere validación mientras el producto no esté instalado."], ["No generar advertencias de módulos que no están instalados."], source, url, "Producto no instalado / no detectado.");

    private static GuidedResolutionResult NoData(TsplusProduct product, string component, string reason, string source, string url)
        => Build(product, component, GuidedResolutionState.NoEvaluado, DiagnosticSeverity.Informativo, ConfidenceLevel.EvidenciaInsuficiente,
            "No evaluado.", reason, "Impacto no determinado.", [Check(component, "N/D", reason)], [], ["Obtenga evidencia del flujo afectado y repita el diagnóstico."],
            ["Confirmar instalación/configuración y reproducir el síntoma de forma segura."], ["No convertir ausencia de datos en estado saludable."], source, url, "Cobertura insuficiente.");

    private static GuidedResolutionResult Build(
        TsplusProduct product, string component, GuidedResolutionState state, DiagnosticSeverity severity, ConfidenceLevel confidence,
        string symptom, string cause, string impact, IReadOnlyList<GuidedResolutionCheck> checks, IReadOnlyList<EvidenceItem> evidence,
        IReadOnlyList<string> fix, IReadOnlyList<string> validate, IReadOnlyList<string> doNot, string source, string url, string coverage)
        => new(product, component, state, severity, confidence, symptom, cause, impact, checks, evidence, fix, validate, doNot, source, url, coverage);

    private static GuidedResolutionCheck Check(string name, string state, string detail, DiagnosticSeverity severity = DiagnosticSeverity.Informativo)
        => new(name, state, detail, severity);

    private static int SeverityRank(DiagnosticSeverity s) => s switch
    {
        DiagnosticSeverity.Critico => 4,
        DiagnosticSeverity.Error => 3,
        DiagnosticSeverity.Advertencia => 2,
        _ => 1
    };

    private static int StateRank(GuidedResolutionState s) => s switch
    {
        GuidedResolutionState.Error => 5,
        GuidedResolutionState.Advertencia => 4,
        GuidedResolutionState.NoEvaluado => 3,
        GuidedResolutionState.Informativo => 2,
        GuidedResolutionState.NoAplica => 1,
        _ => 1
    };

    private static string StateLabel(GuidedResolutionState state) => state switch
    {
        GuidedResolutionState.Saludable => "OK",
        GuidedResolutionState.Error => "ERROR",
        GuidedResolutionState.Advertencia => "ADVERTENCIA",
        GuidedResolutionState.Informativo => "INFORMATIVO",
        GuidedResolutionState.NoAplica => "NO APLICA",
        _ => "N/D"
    };

    private static bool IsError(DiagnosticEvent e) => e.Severidad is DiagnosticSeverity.Error or DiagnosticSeverity.Critico;

    private static bool ContainsAny(DiagnosticEvent e, params string[] tokens)
        => tokens.Any(t => EventText(e).Contains(t, StringComparison.OrdinalIgnoreCase));

    private static string EventText(DiagnosticEvent e)
        => string.Join(" | ", new[] { e.Fuente, e.Componente, e.Tipo, e.Mensaje, e.Codigo ?? string.Empty, e.Archivo ?? string.Empty }
            .Concat((e.Evidencia ?? []).Select(v => $"{v.Clave}={v.Valor}")));

    public sealed class EvidenceIndex
    {
        private readonly DiagnosticReport _report;
        public EvidenceIndex(DiagnosticReport report) => _report = report;
        public DiagnosticReport Report => _report;

        public bool IsProductInstalled(TsplusProduct product)
        {
            if (product == TsplusProduct.RemoteAccess && _report.Sistema.TsplusDetectado) return true;

            // RC18.18.2: usa el estado explícito más reciente del producto. Esto evita que
            // una muestra histórica "Instalado" gane sobre un estado actual "No instalado"
            // durante Diagnóstico continuo o al fusionar evidencia de distintas ventanas.
            var states = _report.Eventos
                .Where(e => e.Tipo.Equals("TSPLUS_PRODUCT_STATE", StringComparison.OrdinalIgnoreCase) && e.Producto == product)
                .OrderByDescending(e => e.Timestamp ?? DateTimeOffset.MinValue);

            foreach (var state in states)
            {
                var installValues = (state.Evidencia ?? [])
                    .Where(v => v.Clave.Equals("Instalación", StringComparison.OrdinalIgnoreCase))
                    .Select(v => v.Valor)
                    .ToList();
                if (installValues.Count == 0) continue;

                if (installValues.Any(IsExplicitNotInstalledValue)) return false;
                if (installValues.Any(IsInstalledValue)) return true;
            }
            return false;
        }

        private static bool IsExplicitNotInstalledValue(string? value)
        {
            var normalized = (value ?? string.Empty).Trim();
            return normalized.StartsWith("No ", StringComparison.OrdinalIgnoreCase)
                   || normalized.Contains("no instalado", StringComparison.OrdinalIgnoreCase)
                   || normalized.Contains("no detectado", StringComparison.OrdinalIgnoreCase)
                   || normalized.Equals("No aplica", StringComparison.OrdinalIgnoreCase)
                   || normalized.Equals("Ausente", StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsInstalledValue(string? value)
        {
            var normalized = (value ?? string.Empty).Trim();
            if (IsExplicitNotInstalledValue(normalized)) return false;
            return normalized.Equals("Instalado", StringComparison.OrdinalIgnoreCase)
                   || normalized.StartsWith("Instalado ", StringComparison.OrdinalIgnoreCase)
                   || normalized.StartsWith("Detectado", StringComparison.OrdinalIgnoreCase);
        }

        public bool HasErrorType(params string[] types)
            => _report.Eventos.Any(e => types.Any(t => e.Tipo.Equals(t, StringComparison.OrdinalIgnoreCase)) && IsError(e));

        public bool EventEvidenceContains(string type, string key, string token)
            => _report.Eventos.Any(e => e.Tipo.Equals(type, StringComparison.OrdinalIgnoreCase)
                && (e.Evidencia ?? []).Any(v => v.Clave.Equals(key, StringComparison.OrdinalIgnoreCase)
                    && v.Valor.Contains(token, StringComparison.OrdinalIgnoreCase)));

        public IEnumerable<DiagnosticEvent> Matches(params string[] tokens)
            => _report.Eventos.Where(e => tokens.Any(t => EventText(e).Contains(t, StringComparison.OrdinalIgnoreCase)));

        public IEnumerable<DiagnosticEvent> MatchesType(params string[] types)
            => _report.Eventos.Where(e => types.Any(t => e.Tipo.Equals(t, StringComparison.OrdinalIgnoreCase)));

        public IEnumerable<DiagnosticEvent> EventsFor(string type)
            => _report.Eventos.Where(e => e.Tipo.Equals(type, StringComparison.OrdinalIgnoreCase));

        public bool HasType(params string[] types) => MatchesType(types).Any();

        public bool HasFinding(params string[] ids)
            => _report.Hallazgos.Any(f => ids.Any(id => f.Id.Equals(id, StringComparison.OrdinalIgnoreCase) || f.Id.StartsWith(id, StringComparison.OrdinalIgnoreCase)));

        public bool HasErrorFinding(params string[] ids)
            => _report.Hallazgos.Any(f => f.Severidad is DiagnosticSeverity.Error or DiagnosticSeverity.Critico
                && ids.Any(id => f.Id.Equals(id, StringComparison.OrdinalIgnoreCase) || f.Id.StartsWith(id, StringComparison.OrdinalIgnoreCase)));

        public bool Contains(params string[] tokens)
            => tokens.Any(t => _report.Eventos.Any(e => EventText(e).Contains(t, StringComparison.OrdinalIgnoreCase))
                || _report.Hallazgos.Any(f => FindingText(f).Contains(t, StringComparison.OrdinalIgnoreCase)));

        public bool AnyErrorContaining(params string[] tokens)
            => _report.Eventos.Any(e => IsError(e) && tokens.Any(t => EventText(e).Contains(t, StringComparison.OrdinalIgnoreCase)))
               || _report.Hallazgos.Any(f => f.Severidad is DiagnosticSeverity.Error or DiagnosticSeverity.Critico
                   && tokens.Any(t => FindingText(f).Contains(t, StringComparison.OrdinalIgnoreCase)));

        public bool EventError(params string[] types)
            => _report.Eventos.Any(e => types.Any(t => e.Tipo.Equals(t, StringComparison.OrdinalIgnoreCase)) && IsError(e));

        public bool EventHas(string type, params string[] tokens)
            => _report.Eventos.Any(e => e.Tipo.Equals(type, StringComparison.OrdinalIgnoreCase) && tokens.All(t => EventText(e).Contains(t, StringComparison.OrdinalIgnoreCase)));

        public IReadOnlyList<EvidenceItem> EvidenceFor(params string[] tokens)
        {
            var output = new List<EvidenceItem>();
            foreach (var e in Matches(tokens).Take(8))
            {
                output.Add(new EvidenceItem($"{e.Tipo} / {e.Componente}", e.Timestamp?.ToLocalTime().ToString("dd/MM HH:mm:ss") ?? "sin timestamp"));
                foreach (var item in (e.Evidencia ?? []).Take(2)) output.Add(item);
            }
            foreach (var f in _report.Hallazgos.Where(f => tokens.Any(t => FindingText(f).Contains(t, StringComparison.OrdinalIgnoreCase))).Take(4))
            {
                output.Add(new EvidenceItem($"Hallazgo {f.Id}", f.Resumen));
                foreach (var item in f.Evidencia.Take(2)) output.Add(item);
            }
            return output.Take(14).ToList();
        }

        public IReadOnlyList<EvidenceItem> EvidenceFrom(IEnumerable<DiagnosticEvent> events, int max)
        {
            var output = new List<EvidenceItem>();
            foreach (var e in events.Take(max))
            {
                output.Add(new EvidenceItem($"{e.Tipo} / {e.Componente}", e.Timestamp?.ToLocalTime().ToString("dd/MM HH:mm:ss") ?? "sin timestamp"));
                foreach (var item in (e.Evidencia ?? []).Take(2)) output.Add(item);
            }
            return output.Take(14).ToList();
        }

        private static string FindingText(DiagnosticFinding f)
            => string.Join(" | ", new[] { f.Id, f.Componente, f.Resumen, f.Detalle, f.SolucionSugerida ?? string.Empty }
                .Concat(f.Evidencia.Select(v => $"{v.Clave}={v.Valor}")));
    }
}
