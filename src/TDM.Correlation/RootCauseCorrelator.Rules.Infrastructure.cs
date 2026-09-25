using TDM.Models;

namespace TDM.Correlation;

public static partial class RootCauseCorrelator
{
    private static void AddBasicInfrastructureCandidates(DiagnosticReport report, List<CandidateDraft> drafts, IReadOnlyList<DiagnosticEvent> tsplusErrors, IReadOnlyList<DiagnosticEvent> rdpErrors, IReadOnlyList<DiagnosticEvent> schannelErrors)
    {
        var termService = report.Hallazgos.FirstOrDefault(x => x.Id == "RDP-TERMSERVICE-NOT-RUNNING");
        var rdpListener = report.Hallazgos.FirstOrDefault(x => x.Id == "RDP-LISTENER-NOT-LISTENING");

        if (termService is not null)
        {
            var temporal = ClosestBefore(rdpErrors, tsplusErrors, TimeSpan.FromMinutes(10));
            var score = temporal is null ? 86 : 97;
            drafts.Add(new CandidateDraft(
                "ROOT-RDP-TERMSERVICE",
                "Remote Desktop Services (TermService)",
                DiagnosticLayer.Rdp,
                score,
                // P13: la proximidad temporal RDP→TSplus no verifica identidad técnica compartida
                // (mismo host/servicio/endpoint); por eso nunca es CONFIRMADA, como máximo ALTA.
                ConfidenceLevel.Alta,
                "Remote Desktop Services es el candidato principal a causa raíz.",
                temporal is null
                    ? "TermService no está operativo. TSplus Remote Access depende de la pila de sesiones de Windows, por lo que esta falla debe investigarse antes de modificar TSplus."
                    : "TermService presentó una falla y existe evidencia TSplus posterior dentro de la ventana de correlación. La secuencia temporal refuerza la relación causal, sin identidad técnica compartida verificada.",
                Merge(termService.Evidencia,
                    new EvidenceItem("Errores RDP con timestamp", rdpErrors.Count.ToString()),
                    new EvidenceItem("Errores TSplus con timestamp", tsplusErrors.Count.ToString()),
                    new EvidenceItem("Identidad técnica compartida", temporal is null ? "No aplica (sin secuencia temporal)" : "No verificada (solo proximidad temporal RDP→TSplus ≤10 min)"),
                    temporal is null ? null : new EvidenceItem("Separación RDP → TSplus", temporal.Value.delta.ToString())),
                "MS-RDP-TERMSERVICE"));
        }

        if (rdpListener is not null)
        {
            var temporal = ClosestBefore(rdpErrors, tsplusErrors, TimeSpan.FromMinutes(10));
            var score = temporal is null ? 82 : 94;
            drafts.Add(new CandidateDraft(
                "ROOT-RDP-LISTENER",
                "RDP-Tcp Listener",
                DiagnosticLayer.Rdp,
                score,
                temporal is null ? ConfidenceLevel.Alta : ConfidenceLevel.Alta,
                "El listener RDP es candidato fuerte a causa raíz.",
                "TermService puede estar activo y aun así el listener RDP no aceptar conexiones. TDM detectó indisponibilidad del listener; si los errores TSplus aparecen después, Windows/RDP debe corregirse primero.",
                Merge(rdpListener.Evidencia,
                    new EvidenceItem("Errores RDP con timestamp", rdpErrors.Count.ToString()),
                    new EvidenceItem("Errores TSplus con timestamp", tsplusErrors.Count.ToString()),
                    new EvidenceItem("Identidad técnica compartida", temporal is null ? "No aplica (sin secuencia temporal)" : "No verificada (solo proximidad temporal RDP→TSplus ≤10 min)"),
                    temporal is null ? null : new EvidenceItem("Separación RDP → TSplus", temporal.Value.delta.ToString())),
                "MS-RDP-LISTENER"));
        }

        var apsDown = report.Hallazgos.FirstOrDefault(x => x.Id == "TSPLUS-APS-NOT-RUNNING");
        if (apsDown is not null)
        {
            drafts.Add(new CandidateDraft(
                "ROOT-TSPLUS-APS",
                "Application Publishing Service (APS)",
                DiagnosticLayer.Tsplus,
                96,
                ConfidenceLevel.Alta,
                "Application Publishing Service no está operativo y es candidato prioritario para fallas de Remote Access.",
                "TDM confirmó que APS no está Running. Esta dependencia debe investigarse antes de reinstalar o modificar TSplus. APS/APSC caído puede impedir funciones de publicación y control de sesión; TDM prioriza esta evidencia técnica sobre síntomas posteriores.",
                apsDown.Evidencia,
                null));
        }

        var printSpooler = report.Hallazgos.FirstOrDefault(x => x.Id == "PRINT-SPOOLER-DOWN");
        if (printSpooler is not null)
        {
            // Spooler detenido demuestra una dependencia Windows degradada, pero no demuestra
            // por sí solo que el incidente investigado sea de impresión. Sólo elevamos a Alta
            // cuando existe una señal de impresión TSplus/PrintService técnicamente relacionada
            // y cercana al final de la ventana; de lo contrario se conserva como hipótesis Media.
            var printingSymptom = report.Eventos
                .Where(e => e.Timestamp.HasValue && e.Severidad != DiagnosticSeverity.Informativo)
                .Where(e => IsNearAnalysisEnd(report, e, TimeSpan.FromMinutes(10)))
                .Where(e => e.Tipo.StartsWith("PRINT_EVENT_", StringComparison.OrdinalIgnoreCase)
                         || $"{e.Tipo} {e.Componente} {e.Mensaje}".Contains("Universal Printer", StringComparison.OrdinalIgnoreCase)
                         || $"{e.Tipo} {e.Componente} {e.Mensaje}".Contains("Virtual Printer", StringComparison.OrdinalIgnoreCase)
                         || $"{e.Tipo} {e.Componente} {e.Mensaje}".Contains("novaPDF", StringComparison.OrdinalIgnoreCase))
                .Where(e =>
                {
                    var text = $"{e.Componente} {e.Mensaje} {string.Join(" ", e.Evidencia?.Select(x => x.Valor) ?? [])}";
                    return e.Capa == DiagnosticLayer.Tsplus
                           || text.Contains("TSplus", StringComparison.OrdinalIgnoreCase)
                           || text.Contains("Universal", StringComparison.OrdinalIgnoreCase)
                           || text.Contains("Virtual", StringComparison.OrdinalIgnoreCase)
                           || text.Contains("novaPDF", StringComparison.OrdinalIgnoreCase);
                })
                .OrderByDescending(e => e.Timestamp)
                .FirstOrDefault();

            var correlated = printingSymptom is not null;
            drafts.Add(new CandidateDraft(
                "ROOT-PRINT-SPOOLER",
                "Print Spooler / impresión TSplus",
                DiagnosticLayer.Windows,
                correlated ? 92 : 78,
                correlated ? ConfidenceLevel.Alta : ConfidenceLevel.Media,
                correlated
                    ? "La pila de impresión de Windows es candidata fuerte para el incidente de Universal/Virtual Printer observado."
                    : "Print Spooler está degradado y puede afectar la impresión TSplus, pero falta un síntoma de impresión correlacionado para declararlo causa alta.",
                correlated
                    ? "TDM confirmó un componente de impresión TSplus, Spooler no operativo y una señal de impresión relacionada en la ventana. Windows/Print Spooler debe investigarse antes de modificar TSplus."
                    : "TDM confirmó la dependencia funcional TSplus → Spooler y el estado no operativo de Spooler. Sin un síntoma de impresión relacionado, permanece como hipótesis preventiva y no como causa raíz alta.",
                Merge(printSpooler.Evidencia, printingSymptom is null ? null : new EvidenceItem("Síntoma de impresión correlacionado", $"{printingSymptom.Tipo} · {printingSymptom.Componente}")),
                "MS-PRINT-SPOOLER",
                printingSymptom?.Timestamp,
                "WINDOWS",
                TsplusProduct.RemoteAccess));
        }

        // U6: ambos lados del par deben ser recientes (≤15 min del fin); un síntoma o un
        // Schannel rancios no pueden producir un candidato que domine por score.
        var tlsSymptoms = tsplusErrors
            .Where(e => e.Tipo is "WEB" or "CERTIFICATE_OR_TLS")
            .Where(e => IsNearAnalysisEnd(report, e, TimeSpan.FromMinutes(15)))
            .Where(e => $"{e.Mensaje} {e.Componente}".Contains("tls", StringComparison.OrdinalIgnoreCase)
                     || $"{e.Mensaje} {e.Componente}".Contains("ssl", StringComparison.OrdinalIgnoreCase)
                     || $"{e.Mensaje} {e.Componente}".Contains("https", StringComparison.OrdinalIgnoreCase)
                     || $"{e.Mensaje} {e.Componente}".Contains("certificate", StringComparison.OrdinalIgnoreCase))
            .ToList();
        var recentSchannel = schannelErrors
            .Where(e => IsNearAnalysisEnd(report, e, TimeSpan.FromMinutes(15)))
            .ToList();
        var tlsPair = ClosestBefore(recentSchannel, tlsSymptoms, TimeSpan.FromMinutes(5));
        if (tlsPair is not null && SharesTlsIdentity(tlsPair.Value.before, tlsPair.Value.after))
        {
            drafts.Add(new CandidateDraft(
                "ROOT-TLS-SCHANNEL",
                "TLS / Schannel",
                DiagnosticLayer.Rdp,
                72,
                ConfidenceLevel.Media,
                "TLS/Schannel es candidato a origen del incidente.",
                "Existe un error Schannel anterior y cercano a un error TSplus. La proximidad temporal justifica investigarlo, pero no basta para confirmar causalidad sin evidencia de certificado, handshake o endpoint afectado.",
                [
                    new EvidenceItem("Evento Schannel", tlsPair.Value.before.Tipo),
                    new EvidenceItem("Evento TSplus", tlsPair.Value.after.Tipo),
                    new EvidenceItem("Separación temporal", tlsPair.Value.delta.ToString()),
                    new EvidenceItem("Código Schannel", tlsPair.Value.before.Codigo ?? "N/D")
                ],
                "MS-SCHANNEL",
                // X5: el par ya es reciente por construcción (U6); fijar su hora evita que el
                // candidato ordene al fondo y reste calidad por "falta" de IncidentTime.
                tlsPair.Value.after.Timestamp));
        }

    }

    private static void AddRealServiceDependencyCandidates(
        DiagnosticReport report,
        List<CandidateDraft> drafts,
        IReadOnlyList<DiagnosticEvent> tsplusErrors,
        IReadOnlyList<DiagnosticEvent> rdpErrors)
    {
        var dependencyFindings = report.Hallazgos
            .Where(f => f.Id.StartsWith("SERVICE-DEPENDENCY-", StringComparison.OrdinalIgnoreCase))
            .Take(8)
            .ToList();

        foreach (var finding in dependencyFindings)
        {
            var service = finding.Evidencia.FirstOrDefault(x => x.Clave.Equals("Servicio", StringComparison.OrdinalIgnoreCase))?.Valor ?? finding.Componente;
            var dependency = finding.Evidencia.FirstOrDefault(x => x.Clave.Equals("Dependencia", StringComparison.OrdinalIgnoreCase))?.Valor ?? "Dependencia SCM";
            var depState = report.Eventos.LastOrDefault(e => e.Tipo == "SERVICE_STATE" &&
                e.Evidencia?.Any(x => x.Clave.Equals("Servicio", StringComparison.OrdinalIgnoreCase) && x.Valor.Equals(dependency, StringComparison.OrdinalIgnoreCase)) == true);
            var serviceState = report.Eventos.LastOrDefault(e => e.Tipo == "SERVICE_STATE" &&
                e.Evidencia?.Any(x => x.Clave.Equals("Servicio", StringComparison.OrdinalIgnoreCase) && x.Valor.Equals(service, StringComparison.OrdinalIgnoreCase)) == true);
            var serviceProduct = serviceState?.Producto ?? TsplusProduct.Ninguno;
            var dependencyProduct = depState?.Producto ?? TsplusProduct.Ninguno;
            var tsplusService = serviceProduct == TsplusProduct.RemoteAccess || service.Contains("TSplus", StringComparison.OrdinalIgnoreCase) || service.Contains("APSC", StringComparison.OrdinalIgnoreCase) || service.Contains("Application Publishing", StringComparison.OrdinalIgnoreCase);
            var rdpService = service.Equals("TermService", StringComparison.OrdinalIgnoreCase) || service.Equals("UmRdpService", StringComparison.OrdinalIgnoreCase);
            IReadOnlyList<DiagnosticEvent> signalPool = tsplusService ? tsplusErrors : rdpService ? rdpErrors : [];
            var compatibleSignal = signalPool
                .Where(e => IsNearAnalysisEnd(report, e, TimeSpan.FromMinutes(10)))
                .Where(e => $"{e.Componente} {e.Mensaje}".Contains(service, StringComparison.OrdinalIgnoreCase)
                         || $"{e.Componente} {e.Mensaje}".Contains(dependency, StringComparison.OrdinalIgnoreCase))
                .OrderByDescending(e => e.Timestamp)
                .FirstOrDefault();
            var scmFailure = report.Eventos
                .Where(e => e.Timestamp.HasValue && (e.Tipo is "SERVICE_TERMINATION" or "SERVICE_START_FAILURE"))
                .Where(e => IsNearAnalysisEnd(report, e, TimeSpan.FromMinutes(15)))
                .FirstOrDefault(e => $"{e.Componente} {e.Mensaje} {string.Join(" ", e.Evidencia?.Select(x => x.Valor) ?? [])}".Contains(service, StringComparison.OrdinalIgnoreCase)
                                  || $"{e.Componente} {e.Mensaje} {string.Join(" ", e.Evidencia?.Select(x => x.Valor) ?? [])}".Contains(dependency, StringComparison.OrdinalIgnoreCase));
            var origin = dependencyProduct != TsplusProduct.Ninguno && dependencyProduct != TsplusProduct.Desconocido
                ? "TSPLUS"
                : IsWindowsCoreService(dependency) ? "WINDOWS" : "INDETERMINADO";
            var product = serviceProduct is TsplusProduct.Ninguno or TsplusProduct.Desconocido ? TsplusProduct.RemoteAccess : serviceProduct;

            drafts.Add(new CandidateDraft(
                $"ROOT-SERVICE-DEPENDENCY-{SafeDependencyId(service)}-{SafeDependencyId(dependency)}",
                $"{dependency} → {service}",
                rdpService ? DiagnosticLayer.Rdp : tsplusService ? DiagnosticLayer.Tsplus : DiagnosticLayer.Windows,
                compatibleSignal is not null && scmFailure is not null ? 91 : scmFailure is not null ? 82 : 72,
                compatibleSignal is not null && scmFailure is not null ? ConfidenceLevel.Alta : ConfidenceLevel.Media,
                $"Una dependencia real del SCM requerida por {service} no está operativa.",
                compatibleSignal is null
                    ? "Service Control Manager confirmó la relación técnica y el estado no operativo de la dependencia. Sin una señal funcional compatible en la ventana, TDM la conserva como candidato y no como originador confirmado."
                    : "Service Control Manager confirmó que el servicio afectado depende realmente de este componente y TDM observó además una señal funcional compatible. La relación no proviene de una lista fija: fue leída del grafo SCM del servidor.",
                Merge(finding.Evidencia,
                    new EvidenceItem("Relación SCM", "Confirmada por ServicesDependedOn"),
                    new EvidenceItem("Señal funcional compatible", compatibleSignal?.Tipo ?? "No observada"),
                    new EvidenceItem("Falla SCM del mismo servicio/dependencia", scmFailure?.Tipo ?? "No observada"),
                    new EvidenceItem("Origen de la dependencia", origin)),
                null,
                compatibleSignal?.Timestamp,
                origin,
                product));
        }
    }

    private static bool IsWindowsCoreService(string name)
        => name.Equals("RpcSs", StringComparison.OrdinalIgnoreCase)
           || name.Equals("DcomLaunch", StringComparison.OrdinalIgnoreCase)
           || name.Equals("EventLog", StringComparison.OrdinalIgnoreCase)
           || name.Equals("Winmgmt", StringComparison.OrdinalIgnoreCase)
           || name.Equals("Spooler", StringComparison.OrdinalIgnoreCase)
           || name.Equals("BFE", StringComparison.OrdinalIgnoreCase)
           || name.Equals("MpsSvc", StringComparison.OrdinalIgnoreCase)
           || name.Equals("Nsi", StringComparison.OrdinalIgnoreCase)
           || name.Equals("TermService", StringComparison.OrdinalIgnoreCase)
           || name.Equals("UmRdpService", StringComparison.OrdinalIgnoreCase)
           || name.Equals("SessionEnv", StringComparison.OrdinalIgnoreCase)
           || name.Equals("ProfSvc", StringComparison.OrdinalIgnoreCase)
           || name.Equals("Netlogon", StringComparison.OrdinalIgnoreCase)
           || name.Equals("Dnscache", StringComparison.OrdinalIgnoreCase)
           || name.Equals("W32Time", StringComparison.OrdinalIgnoreCase)
           || name.Equals("RpcEptMapper", StringComparison.OrdinalIgnoreCase)
           || name.Equals("LanmanWorkstation", StringComparison.OrdinalIgnoreCase);

    private static string SafeDependencyId(string value)
    {
        var text = new string((value ?? string.Empty).Where(char.IsLetterOrDigit).Select(char.ToUpperInvariant).Take(20).ToArray());
        return string.IsNullOrWhiteSpace(text) ? "SERVICE" : text;
    }

    private static void AddScmServiceCandidates(DiagnosticReport report, List<CandidateDraft> drafts, IReadOnlyList<DiagnosticEvent> tsplusCrashEvents)
    {
        // Fallos explícitos de arranque/ejecución de servicios relacionados con TSplus.
        // Se mantienen en capa Windows/SCM porque el dato observado es la incapacidad del
        // Service Control Manager para iniciar/ejecutar el servicio; no implica que Windows
        // sea defectuoso, sino que ése es el primer nivel técnico que debe validarse.
        var scmServiceFailures = report.Eventos
            .Where(e => e.Timestamp.HasValue && e.Tipo == "SERVICE_START_FAILURE")
            .Where(e => e.Producto is not TsplusProduct.Ninguno and not TsplusProduct.Desconocido)
            .Where(HasActionableScmCause)
            .OrderByDescending(e => e.Timestamp)
            .GroupBy(e => e.Producto)
            .Select(g => g.First())
            .Take(3)
            .ToList();

        foreach (var failure in scmServiceFailures)
        {
            var product = failure.Producto;
            var pairedCrash = tsplusCrashEvents
                .Where(c => c.Producto == product || c.Mensaje.Contains(ProductName(product), StringComparison.OrdinalIgnoreCase))
                .Where(c => c.Timestamp.HasValue && failure.Timestamp.HasValue && c.Timestamp.Value >= failure.Timestamp.Value)
                .OrderBy(c => c.Timestamp!.Value - failure.Timestamp!.Value)
                .FirstOrDefault(c => c.Timestamp!.Value - failure.Timestamp!.Value <= TimeSpan.FromMinutes(5));
            var score = pairedCrash is null ? 78 : 90;
            var evidence = new List<EvidenceItem>
            {
                new("Producto relacionado", ProductName(product)),
                new("SCM Event ID", failure.Codigo ?? "N/D"),
                new("Hora SCM", failure.Timestamp!.Value.ToLocalTime().ToString("dd/MM/yyyy HH:mm:ss")),
                new("Crash posterior del mismo producto", pairedCrash is null ? "No" : "Sí"),
                new("Interpretación", "Service Control Manager observó un fallo de arranque/ejecución; validar servicio, cuenta, dependencias, ruta y código antes de reinstalar TSplus")
            };
            if (pairedCrash?.Timestamp is DateTimeOffset crashTs)
                evidence.Add(new("Separación SCM → crash", (crashTs - failure.Timestamp!.Value).ToString()));

            drafts.Add(new CandidateDraft(
                "ROOT-SCM-SERVICE-FAILURE",
                $"Service Control Manager / {ProductName(product)}",
                DiagnosticLayer.Windows,
                score,
                pairedCrash is null ? ConfidenceLevel.Media : ConfidenceLevel.Alta,
                $"Windows registró un fallo de servicio relacionado con {ProductName(product)}.",
                pairedCrash is null
                    ? "Existe un error explícito de Service Control Manager relacionado con el producto. Deben revisarse primero la configuración del servicio, ruta ejecutable, cuenta, dependencias y código del evento; sin un síntoma TSplus posterior no se declara causa primaria confirmada."
                    : "Service Control Manager registró un fallo del servicio y después apareció un crash del mismo producto dentro de cinco minutos. La secuencia orienta la investigación al ciclo de servicio/configuración antes de modificar otras capas.",
                evidence,
                null,
                failure.Timestamp,
                "WINDOWS",
                product));
        }

        AddMissionCoreServiceCandidates(report, drafts, tsplusCrashEvents);
    }

    /// <summary>
    /// Y2: fallos de arranque de servicios núcleo Windows (TermService, RpcSs, Spooler, ...)
    /// con causa accionable. No tienen producto TSplus asignable, así que se candidata el
    /// SERVICIO por nombre real (evidencia "Servicio" que el incremental ya extrae) con origen
    /// WINDOWS. Confianza máxima Media: visibles como hipótesis, nunca primary en solitario.
    /// </summary>
    private static readonly string[] MissionCoreServices =
    [
        "TermService", "UmRdpService", "SessionEnv", "TermServLicensing",
        "RpcSs", "RpcEptMapper", "DcomLaunch", "EventLog", "Winmgmt",
        "Spooler", "ProfSvc", "UserManager", "Netlogon", "Dnscache", "W32Time",
        "BFE", "MpsSvc", "Nsi", "CryptSvc", "LanmanWorkstation", "LanmanServer"
    ];

    private static void AddMissionCoreServiceCandidates(DiagnosticReport report, List<CandidateDraft> drafts, IReadOnlyList<DiagnosticEvent> tsplusCrashEvents)
    {
        var coreFailures = report.Eventos
            .Where(e => e.Timestamp.HasValue && e.Tipo == "SERVICE_START_FAILURE")
            .Where(e => e.Producto is TsplusProduct.Ninguno or TsplusProduct.Desconocido)
            .Where(HasActionableScmCause)
            .Where(e => MissionCoreServices.Any(n =>
                (EvidenceValue(e, "Servicio") ?? string.Empty).Equals(n, StringComparison.OrdinalIgnoreCase)
                || $"{e.Componente} {e.Mensaje}".Contains(n, StringComparison.OrdinalIgnoreCase)))
            .OrderByDescending(e => e.Timestamp)
            .Take(2)
            .ToList();

        foreach (var failure in coreFailures)
        {
            var service = EvidenceValue(failure, "Servicio") ?? failure.Componente;
            var pairedCrash = tsplusCrashEvents
                .Where(c => c.Timestamp.HasValue && failure.Timestamp.HasValue && c.Timestamp.Value >= failure.Timestamp.Value)
                .OrderBy(c => c.Timestamp!.Value - failure.Timestamp!.Value)
                .FirstOrDefault(c => c.Timestamp!.Value - failure.Timestamp!.Value <= TimeSpan.FromMinutes(5));
            drafts.Add(new CandidateDraft(
                $"ROOT-SCM-SERVICE-FAILURE-{SafeDependencyId(service)}",
                $"Service Control Manager / {service}",
                DiagnosticLayer.Windows,
                pairedCrash is null ? 76 : 86,
                ConfidenceLevel.Media,
                $"Windows registró un fallo de arranque del servicio del sistema {service}, dependencia de misión para RDP/TSplus.",
                pairedCrash is null
                    ? "Existe un error explícito de Service Control Manager con causa accionable en un servicio núcleo. Sin síntoma posterior cercano se conserva como hipótesis de dependencia Windows."
                    : "Al fallo del servicio núcleo siguió un crash del ecosistema TSplus dentro de cinco minutos. La secuencia orienta a validar el servicio antes de modificar TSplus, sin declarar causa primaria.",
                Merge(failure.Evidencia ?? [],
                    new EvidenceItem("Servicio de misión", service),
                    new EvidenceItem("SCM Event ID", failure.Codigo ?? "N/D"),
                    new EvidenceItem("Hora SCM", failure.Timestamp!.Value.ToLocalTime().ToString("dd/MM/yyyy HH:mm:ss")),
                    new EvidenceItem("Crash posterior cercano", pairedCrash is null ? "No" : "Sí")),
                null,
                failure.Timestamp,
                "WINDOWS",
                TsplusProduct.Ninguno));
        }
    }

    private static void AddCrashCandidates(DiagnosticReport report, List<CandidateDraft> drafts, IReadOnlyList<DiagnosticEvent> tsplusCrashEvents)
    {
        // Crashes de proceso / WER agrupados por aplicación/producto y por ráfagas temporales.
        // RC15 evita que un crash histórico bien sustentado oculte un incidente más reciente de otro producto.
        var crashIncidents = tsplusCrashEvents
            .Where(e => e.Tipo == "APPLICATION_CRASH")
            .GroupBy(e => EvidenceValue(e, "Aplicación") ?? e.Componente, StringComparer.OrdinalIgnoreCase)
            .SelectMany(g => ClusterCrashes(g, TimeSpan.FromMinutes(10)).Select(cluster => (AppName: g.Key, Crashes: cluster)))
            .ToList();

        foreach (var incidentGroup in crashIncidents)
        {
            var crashGroup = incidentGroup.Crashes;
            var appCrash = crashGroup.OrderBy(e => e.Timestamp).Last();
            var appName = incidentGroup.AppName;
            var product = appCrash.Producto == TsplusProduct.Ninguno ? ProductFromText($"{appName} {appCrash.Archivo}") : appCrash.Producto;
            var module = EvidenceValue(appCrash, "Módulo con error");
            var modulePath = EvidenceValue(appCrash, "Ruta del módulo");
            var exceptionCode = EvidenceValue(appCrash, "Código de excepción") ?? appCrash.Codigo;
            var dotnetClose = report.Eventos
                .Where(e => e.Tipo == "DOTNET_UNHANDLED_EXCEPTION" && e.Timestamp.HasValue && SameApplication(e, appName))
                .OrderBy(e => (e.Timestamp!.Value - appCrash.Timestamp!.Value).Duration())
                .FirstOrDefault(e => IsClose(e, appCrash, TimeSpan.FromSeconds(5)));
            var scmClose = report.Eventos
                .Where(e => e.Codigo == "7031" && e.Timestamp.HasValue && MentionsSameService(e, appName))
                .OrderBy(e => (e.Timestamp!.Value - appCrash.Timestamp!.Value).Duration())
                .FirstOrDefault(e => IsClose(e, appCrash, TimeSpan.FromSeconds(10)));
            var werClose = report.Eventos.FirstOrDefault(e => e.Tipo == "WER_REPORT" && e.Timestamp.HasValue && IsClose(e, appCrash, TimeSpan.FromMinutes(2)) && SameApplication(e, appName));
            var commonWindowsModule = IsCommonWindowsFaultModule(module, modulePath);
            var moduleUnderTsplus = IsUnderTsplus(modulePath, report.Sistema.TsplusRuta);
            var exceptionType = dotnetClose is null ? null : EvidenceValue(dotnetClose, "Tipo de excepción .NET") ?? ExtractDotNetType(dotnetClose.Mensaje);
            var mechanismWithServiceCycle = dotnetClose is not null && scmClose is not null;
            var recurrenceCount = crashGroup.Count;

            var incidentStart = crashGroup.Where(e => e.Timestamp.HasValue).Min(e => e.Timestamp!.Value);
            var incidentEnd = crashGroup.Where(e => e.Timestamp.HasValue).Max(e => e.Timestamp!.Value);
            var scmRecurrenceCount = report.Eventos.Count(e => e.Codigo == "7031" && e.Timestamp.HasValue && MentionsSameService(e, appName) &&
                e.Timestamp.Value >= incidentStart - TimeSpan.FromSeconds(10) && e.Timestamp.Value <= incidentEnd + TimeSpan.FromSeconds(10));

            var orderedCrashes = crashGroup.Where(e => e.Timestamp.HasValue).OrderBy(e => e.Timestamp).ToList();
            var tightCrashIntervals = 0;
            for (var i = 1; i < orderedCrashes.Count; i++)
                if (orderedCrashes[i].Timestamp!.Value - orderedCrashes[i - 1].Timestamp!.Value <= TimeSpan.FromMinutes(5)) tightCrashIntervals++;
            var recurrenceObserved = recurrenceCount >= 2;
            var crashLoopConfirmed = recurrenceCount >= 3 && (scmRecurrenceCount >= 2 || tightCrashIntervals >= 2);

            var causal = CausalChainAnalyzer.AnalyzeProcessCrash(report, appCrash, dotnetClose, scmClose, appName, product);
            var score = mechanismWithServiceCycle ? (crashLoopConfirmed ? 95 : 92) : dotnetClose is not null ? 86 : moduleUnderTsplus ? 84 : 72;
            if (causal.IndependentPrimaryEvidence) score = Math.Min(98, score + 5);
            var confidence = dotnetClose is not null ? ConfidenceLevel.Alta : ConfidenceLevel.Media;
            var relationshipNote = product == TsplusProduct.RemoteAccess ? "El evento pertenece a Remote Access." : "El evento pertenece a un producto complementario; no se ha demostrado impacto directo sobre Remote Access.";
            var explanation = mechanismWithServiceCycle
                ? "TDM correlacionó una excepción .NET no controlada con el crash del mismo proceso y la terminación/reinicio del servicio registrada por Service Control Manager. Esto confirma el mecanismo de caída, no necesariamente la causa primaria de la excepción. " + causal.OriginReason + " " + relationshipNote
                : commonWindowsModule
                    ? "Windows registró un crash del proceso. El módulo común de Windows identifica el punto donde se manifestó el fallo y no se considera automáticamente la causa primaria. " + causal.OriginReason
                    : "Windows registró un crash de un proceso del ecosistema TSplus. " + causal.OriginReason;

            var incidentId = $"{product}-{appCrash.Timestamp!.Value:yyyyMMdd-HHmmss}";
            var evidence = new List<EvidenceItem>
            {
                new("ID incidente", incidentId),
                new("Hora del incidente", appCrash.Timestamp!.Value.ToLocalTime().ToString("dd/MM/yyyy HH:mm:ss")),
                new("Producto", ProductName(product)),
                new("Aplicación", appName),
                new("Excepción .NET cercana", dotnetClose is null ? "No" : "Sí"),
                new("Tipo de excepción", exceptionType ?? "N/D"),
                new("Application Error 1000", "Sí"),
                new("WER 1001 cercano", werClose is null ? "No" : "Sí"),
                new("Service Control Manager 7031 cercano", scmClose is null ? "No" : "Sí"),
                new("Módulo con error", module ?? "N/D"),
                new("Código de excepción", exceptionCode ?? "N/D"),
                new("Recurrencia observada", recurrenceObserved ? $"Sí ({recurrenceCount} crashes en este incidente)" : "No"),
                new("Crash loop confirmado", crashLoopConfirmed ? "Sí" : "No"),
                new("Terminaciones SCM 7031 relacionadas", scmRecurrenceCount.ToString()),
                new("Módulo común de Windows", commonWindowsModule ? "Sí; punto de manifestación, no causa asumida" : "No"),
                new("Relación con Remote Access", product == TsplusProduct.RemoteAccess ? "Directa" : "No demostrada")
            };
            evidence.AddRange(causal.Evidence);

            drafts.Add(new CandidateDraft(
                "ROOT-PROCESS-CRASH",
                appName,
                DiagnosticLayer.Tsplus,
                score,
                confidence,
                causal.IndependentPrimaryEvidence
                    ? $"Existe evidencia causal adicional para el crash de {ProductName(product)}."
                    : $"Windows confirmó un crash en {ProductName(product)}; el origen técnico más bajo está {causal.OriginState.ToLowerInvariant()}.",
                explanation,
                evidence,
                "MS-APP-CRASH",
                appCrash.Timestamp,
                causal.OriginCategory,
                product));
        }

    }

    private static void AddDependencyCandidates(DiagnosticReport report, List<CandidateDraft> drafts, IReadOnlyList<DiagnosticEvent> tsplusCrashEvents)
    {
        // Dependencias / DLL / SideBySide relacionadas explícitamente con TSplus.
        var dependencyErrors = report.Eventos
            .Where(e => e.Timestamp.HasValue && e.Capa == DiagnosticLayer.Tsplus &&
                        e.Tipo is "SIDEBYSIDE_DEPENDENCY_FAILURE" or "DEPENDENCY_NOT_FOUND" or "DEPENDENCY_LOAD_FAILURE" or "DLL_NOT_FOUND" or "INVALID_IMAGE_FORMAT")
            .OrderBy(e => e.Timestamp)
            .ToList();

        if (dependencyErrors.Count > 0)
        {
            var dep = dependencyErrors[^1];
            var dependencyName = EvidenceValue(dep, "Dependencia detectada") ?? dep.Componente;
            // U2: el crash emparejado debe ser del mismo producto (o sin producto asignado);
            // antes, la dependencia de A se validaba con el crash de B si coincidían en 3 min.
            var pairedCrash = tsplusCrashEvents.LastOrDefault(c => IsClose(dep, c, TimeSpan.FromMinutes(3))
                && (c.Producto == dep.Producto || c.Producto == TsplusProduct.Ninguno || dep.Producto == TsplusProduct.Ninguno));
            var score = pairedCrash is null ? 84 : 93;
            // X2: sin crash emparejado no hay doble fuente; Media (el veto P15/R1 impide que un
            // 84/Media solitario se declare causa principal).
            var confidence = pairedCrash is null ? ConfidenceLevel.Media : ConfidenceLevel.Alta;
            var dependencyOrigin = EvidenceValue(dep, "Clasificación de dependencia") ?? "INDETERMINADO";
            var dependencySpecific = EvidenceValue(dep, "Originador específico") ?? dependencyName;
            var dependencyLayer = dependencyOrigin == "TSPLUS" ? DiagnosticLayer.Tsplus : DiagnosticLayer.Windows;
            drafts.Add(new CandidateDraft(
                "ROOT-DEPENDENCY-LOAD",
                dependencySpecific,
                dependencyLayer,
                score,
                confidence,
                "Windows registró una falla de carga de una dependencia utilizada por un componente TSplus.",
                pairedCrash is null
                    ? "Existe evidencia explícita de una dependencia/ensamblado/DLL que Windows no pudo cargar para un componente relacionado con TSplus. TDM clasifica el propietario técnico de la dependencia cuando puede hacerlo sin asumir que toda DLL ajena a TSplus pertenece a Windows."
                    : "La falla de carga de dependencia aparece temporalmente junto a un crash de proceso TSplus. La clasificación de origen se basa en la identidad de la dependencia, no en que Windows haya sido quien registró el evento.",
                CompactEvidence(
                    new EvidenceItem("Tipo", dep.Tipo),
                    new EvidenceItem("Dependencia", dependencyName),
                    new EvidenceItem("Originador específico", dependencySpecific),
                    new EvidenceItem("Clasificación de dependencia", dependencyOrigin),
                    new EvidenceItem("Provider", dep.Fuente),
                    new EvidenceItem("Event ID / código", dep.Codigo ?? "N/D"),
                    new EvidenceItem("Crash TSplus cercano", pairedCrash is null ? "No" : "Sí")),
                dep.Tipo == "SIDEBYSIDE_DEPENDENCY_FAILURE" ? "MS-SIDEBYSIDE" : "MS-DOTNET-FILELOAD",
                dep.Timestamp,
                dependencyOrigin == "EXTERNO" ? "EXTERNO" : dependencyOrigin,
                dep.Producto));
        }

    }
}
