using TDM.Models;

namespace TDM.Correlation;

public static partial class RootCauseCorrelator
{
    private static void AddWindowsCompatibilityCandidates(DiagnosticReport report, List<CandidateDraft> drafts)
    {
        // RC18.3.1: compatibilidad Windows documentada que puede afectar directamente a Remote Access.
        var rdpPolicy = report.Hallazgos.FirstOrDefault(f => f.Id == "WINDOWS-RDP-DISABLED-POLICY");
        if (rdpPolicy is not null)
        {
            drafts.Add(new CandidateDraft(
                "ROOT-WINDOWS-RDP-DISABLED-POLICY",
                "Windows / política RDP",
                DiagnosticLayer.Windows,
                96,
                ConfidenceLevel.Alta,
                "Windows tiene RDP deshabilitado por configuración o directiva efectiva.",
                "El estado fDenyTSConnections observado impide aceptar nuevas conexiones RDP. La condición está confirmada; TDM la eleva como causa del incidente sólo cuando el síntoma investigado requiere crear una sesión remota.",
                rdpPolicy.Evidencia,
                null,
                null,
                "WINDOWS",
                TsplusProduct.RemoteAccess));
        }

        var rdsConflict = report.Hallazgos.FirstOrDefault(f => f.Id == "WINDOWS-RDS-ROLE-CONFLICT");
        if (rdsConflict is not null)
        {
            drafts.Add(new CandidateDraft(
                "ROOT-WINDOWS-RDS-ROLE-CONFLICT",
                "Windows Server / roles RDS incompatibles",
                DiagnosticLayer.Windows,
                97,
                ConfidenceLevel.Alta,
                "La configuración de roles RDS de Windows es incompatible con los prerrequisitos documentados de TSplus Remote Access.",
                "TDM observó roles RDS que TSplus indica que no deben coexistir con Remote Access. Este es un problema de configuración Windows y debe resolverse antes de modificar componentes TSplus.",
                rdsConflict.Evidencia,
                null,
                null,
                "WINDOWS",
                TsplusProduct.RemoteAccess));
        }

        var winlogonIssue = report.Hallazgos.FirstOrDefault(f => f.Id == "WINDOWS-TSPLUS-WINLOGON-INTEGRATION");
        if (winlogonIssue is not null)
        {
            var filePresent = winlogonIssue.Evidencia.FirstOrDefault(e => e.Clave.Equals("logonsession.exe presente", StringComparison.OrdinalIgnoreCase))?.Valor;
            var userinit = winlogonIssue.Evidencia.FirstOrDefault(e => e.Clave.Contains("Userinit", StringComparison.OrdinalIgnoreCase))?.Valor;
            var origin = string.Equals(filePresent, "No", StringComparison.OrdinalIgnoreCase) ? "TSPLUS" : "WINDOWS";
            var layer = origin == "TSPLUS" ? DiagnosticLayer.Tsplus : DiagnosticLayer.Windows;
            drafts.Add(new CandidateDraft(
                "ROOT-WINLOGON-TSPLUS-INTEGRATION",
                "Winlogon / logonsession.exe",
                layer,
                91,
                ConfidenceLevel.Alta,
                origin == "WINDOWS"
                    ? "La integración de Winlogon con el inicializador de sesión TSplus está incompleta."
                    : "Falta el inicializador de sesión logonsession.exe esperado por la integración TSplus.",
                origin == "WINDOWS"
                    ? "El ejecutable TSplus existe, pero Windows Userinit no contiene la integración esperada. Esto orienta la corrección a la configuración Windows/Winlogon."
                    : "El ejecutable TSplus esperado no está presente. La instalación/integridad TSplus debe investigarse, salvo que exista evidencia de antivirus/EDR que explique su eliminación.",
                Merge(winlogonIssue.Evidencia, new EvidenceItem("Userinit observado", userinit ?? "N/D")),
                null,
                null,
                origin,
                TsplusProduct.RemoteAccess));
        }


    }

    private static void AddDirectorySessionAndFarmCandidates(DiagnosticReport report, List<CandidateDraft> drafts, IReadOnlyList<DiagnosticEvent> tsplusErrors)
    {
        // RC18.12.2: Active Directory/Netlogon/SPN como dependencia de Remote Access.
        var adSignals = report.Eventos
            .Where(e => e.Timestamp.HasValue && (e.Tipo == "WINDOWS_AD_AUTH_DEPENDENCY_FAILURE" || e.Tipo == "WINDOWS_AD_TERMSRV_SPN_FAILURE" || e.Tipo == "WINDOWS_AD_DOMAIN_CONNECTIVITY_FAILURE"))
            .OrderBy(e => e.Timestamp)
            .ToList();
        if (adSignals.Count > 0)
        {
            var remoteSymptoms = report.Eventos
                .Where(e => e.Timestamp.HasValue && e.Producto == TsplusProduct.RemoteAccess)
                .Where(IsStrongRemoteAccessSymptomForAd)
                .Where(e => e.Tipo is not "WINDOWS_AD_AUTH_DEPENDENCY_FAILURE" and not "WINDOWS_AD_TERMSRV_SPN_FAILURE" and not "WINDOWS_AD_DOMAIN_CONNECTIVITY_FAILURE")
                .OrderBy(e => e.Timestamp)
                .ToList();
            // U6: el síntoma posterior debe ser reciente (≤15 min del fin); un par rancio no
            // puede dominar el ranking con 95/Alta. Sin par reciente cae a antecedente Media.
            var rawPair = ClosestBefore(adSignals, remoteSymptoms, TimeSpan.FromMinutes(10));
            var pair = rawPair is not null && IsNearAnalysisEnd(report, rawPair.Value.after, TimeSpan.FromMinutes(15))
                ? rawPair
                : null;
            var recoveredBetween = pair is not null && report.Eventos.Any(e => e.Timestamp.HasValue
                && e.Timestamp.Value > pair.Value.before.Timestamp!.Value
                && e.Timestamp.Value < pair.Value.after.Timestamp!.Value
                && e.Tipo is "USER_LOGON_SUCCESS" or "RDP_AUTHENTICATION_STAGE" or "RDP_SESSION_LOGON_STAGE"
                && !e.Mensaje.Contains("incorrect", StringComparison.OrdinalIgnoreCase)
                && !e.Mensaje.Contains("fail", StringComparison.OrdinalIgnoreCase));
            var strongPair = pair is not null && !recoveredBetween;
            // U6: sin par reciente se prefiere la señal AD más cercana al fin; solo en última
            // instancia se usa la última señal histórica (78/Media, nunca dominante).
            var signal = pair?.before
                ?? adSignals.LastOrDefault(e => IsNearAnalysisEnd(report, e, TimeSpan.FromMinutes(15)))
                ?? adSignals[^1];
            // X6: si solo quedó la señal histórica (sin par y fuera de ventana), no compite como
            // "candidato principal" empatado: 68/Baja documenta el antecedente sin confundir el ranking.
            var historicFallback = pair is null && !IsNearAnalysisEnd(report, signal, TimeSpan.FromMinutes(15));
            var specific = EvidenceValue(signal, "Originador específico") ?? signal.Componente;
            drafts.Add(new CandidateDraft(
                "ROOT-WINDOWS-AD-RDP-DEPENDENCY",
                specific,
                DiagnosticLayer.Windows,
                strongPair ? 95 : pair is not null ? 82 : historicFallback ? 68 : 78,
                strongPair ? ConfidenceLevel.Alta : pair is not null ? ConfidenceLevel.Media : historicFallback ? ConfidenceLevel.Baja : ConfidenceLevel.Media,
                strongPair
                    ? "Una falla de Active Directory/Netlogon/SPN precede a un síntoma Remote Access fuerte sin recuperación intermedia observada."
                    : pair is not null && recoveredBetween
                        ? "Windows registró una falla AD/Netlogon y después un síntoma Remote Access, pero existió autenticación/sesión correcta entre ambos; la relación se conserva como intermitente, no como cadena causal fuerte."
                        : "Windows registró una anomalía de Active Directory/Netlogon/SPN relevante para RDP, sin síntoma Remote Access fuerte suficientemente cercano.",
                strongPair
                    ? "La infraestructura de autenticación/dominio falló antes del síntoma Remote Access sin evidencia de recuperación intermedia. TSplus actúa como consumidor/víctima de la dependencia Windows y debe revisarse AD/DNS/Netlogon/SPN antes de modificar TSplus."
                    : pair is not null && recoveredBetween
                        ? "La dependencia Windows presentó una anomalía real, pero una autenticación/sesión correcta posterior rompe la cadena causal directa hacia el síntoma siguiente. Investigue intermitencia de AD/DNS/Netlogon/NLA y mantenga alternativas abiertas."
                        : "La señal pertenece a Windows/AD y se conserva como antecedente. Sin un síntoma Remote Access fuerte correlacionado, TDM no la declara causa primaria.",
                CompactEvidence(
                    new EvidenceItem("Originador específico", specific),
                    // P13: la secuencia AD→síntoma no verifica mismo usuario/host; la confianza
                    // máxima por esta vía es ALTA con identidad parcial, nunca CONFIRMADA.
                    new EvidenceItem("Identidad técnica compartida", strongPair ? "Parcial (secuencia ≤10 min sin recuperación intermedia; usuario/host no verificado)" : "No verificada (solo proximidad temporal)"),
                    new EvidenceItem("Señal Windows/AD", signal.Tipo),
                    new EvidenceItem("EventId", signal.Codigo ?? "N/D"),
                    new EvidenceItem("Síntoma Remote Access posterior", pair is null ? "No correlacionado" : pair.Value.after.Tipo),
                    new EvidenceItem("Separación temporal", pair is null ? "N/D" : pair.Value.delta.ToString()),
                    new EvidenceItem("Recuperación entre señal y síntoma", recoveredBetween ? "Sí; login/sesión correcta observada" : "No observada"),
                    new EvidenceItem("Rol de TSplus", strongPair ? "VÍCTIMA / AFECTADO" : "Posible afectado; causalidad no cerrada")),
                null,
                signal.Timestamp,
                "WINDOWS",
                TsplusProduct.RemoteAccess));
        }

        // RC18.12.2: sesión autenticada que no completa shell (patrón compatible con pantalla negra).
        var shellPipeline = report.Hallazgos.FirstOrDefault(f => f.Id == "WINDOWS-RDP-SHELL-PIPELINE-DEGRADED");
        if (shellPipeline is not null)
        {
            // U3/U6: la brecha de shell debe ser reciente (≤15 min del fin); perfil/AD solo
            // corroboran anclados a esa brecha (antes, sin shellSignal, cualquier error de perfil
            // histórico fortalecía). Winlogon estático solo suma con brecha reciente.
            var shellSignal = report.Eventos
                .Where(e => e.Timestamp.HasValue && (e.Tipo == "RDP_SHELL_START_GAP" || e.Tipo == "RDP_SHELL_START_DELAY"))
                .Where(e => IsNearAnalysisEnd(report, e, TimeSpan.FromMinutes(15)))
                .OrderByDescending(e => e.Timestamp)
                .FirstOrDefault();
            var profileSignal = shellSignal?.Timestamp is DateTimeOffset shellTs0
                ? report.Eventos
                    .Where(e => e.Timestamp.HasValue && e.Tipo == "USER_PROFILE_SERVICE_EVENT" && e.Severidad != DiagnosticSeverity.Informativo)
                    .Where(e => (e.Timestamp!.Value - shellTs0).Duration() <= TimeSpan.FromMinutes(5))
                    .OrderByDescending(e => e.Timestamp)
                    .FirstOrDefault()
                : null;
            var winlogon = report.Hallazgos.FirstOrDefault(f => f.Id == "WINDOWS-TSPLUS-WINLOGON-INTEGRATION");
            var adNearShell = shellSignal?.Timestamp is DateTimeOffset shellTs
                ? adSignals.Where(e => e.Timestamp.HasValue && (e.Timestamp.Value - shellTs).Duration() <= TimeSpan.FromMinutes(5)).OrderByDescending(e => e.Timestamp).FirstOrDefault()
                : null;
            var specific = profileSignal is not null ? "Windows User Profile Service"
                : winlogon is not null ? "Windows Winlogon / Userinit"
                : adNearShell is not null ? (EvidenceValue(adNearShell, "Originador específico") ?? "Active Directory / Domain Controller / Netlogon")
                : "Windows RDS / pipeline de sesión y shell";
            var strengthened = profileSignal is not null || adNearShell is not null || (winlogon is not null && shellSignal is not null);
            drafts.Add(new CandidateDraft(
                "ROOT-WINDOWS-RDP-SHELL-PIPELINE",
                specific,
                DiagnosticLayer.Windows,
                strengthened ? 96 : 87,
                strengthened ? ConfidenceLevel.Alta : ConfidenceLevel.Media,
                "Windows creó/autenticó una sesión RDP, pero el shell no inició normalmente o se demoró de forma anómala.",
                strengthened
                    ? "La brecha de shell coincide con evidencia adicional de perfil, Winlogon/Userinit o Active Directory. Esta cadena es compatible con pantalla negra/post-logon y sitúa el origen por debajo de TSplus, en el pipeline de sesión Windows."
                    : "El patrón es compatible con pantalla negra o sesión detenida después del logon, pero sin una segunda evidencia independiente TDM mantiene la causa como probable y no atribuye automáticamente el síntoma a Windows.",
                Merge(shellPipeline.Evidencia,
                    new EvidenceItem("Originador específico", specific),
                    // P13: la coincidencia shell↔perfil/AD/Winlogon ≤5 min no verifica mismo usuario;
                    // la confianza máxima por esta vía es ALTA con identidad parcial.
                    new EvidenceItem("Identidad técnica compartida", strengthened ? "Parcial (coincidencia ≤5 min; usuario no verificado)" : "No verificada (patrón temporal compatible)"),
                    new EvidenceItem("Evento de shell", shellSignal?.Tipo ?? "N/D"),
                    new EvidenceItem("Error de perfil correlacionado", profileSignal is null ? "No" : "Sí"),
                    new EvidenceItem("Anomalía Winlogon/Userinit", winlogon is null ? "No" : "Sí"),
                    new EvidenceItem("Señal AD/Netlogon correlacionada <=5 min", adNearShell is null ? "No" : "Sí"),
                    new EvidenceItem("Rol de TSplus", "VÍCTIMA / sesión afectada")),
                null,
                shellSignal?.Timestamp,
                "WINDOWS",
                TsplusProduct.RemoteAccess));
        }

        var nlaPasswordIssue = report.Hallazgos.FirstOrDefault(f =>
            f.Id is "WINDOWS-2019-NLA-PASSWORD-CHANGE-COMPATIBILITY" or "WINDOWS-NLA-PASSWORD-CHANGE-AUTH");
        if (nlaPasswordIssue is not null)
        {
            var is2019 = nlaPasswordIssue.Id == "WINDOWS-2019-NLA-PASSWORD-CHANGE-COMPATIBILITY";
            var nlaEvent = report.Eventos
                .Where(e => e.Tipo == "WINDOWS_NLA_PASSWORD_CHANGE_CONFLICT" && e.Timestamp.HasValue)
                .OrderByDescending(e => e.Timestamp)
                .FirstOrDefault();
            drafts.Add(new CandidateDraft(
                "ROOT-WINDOWS-NLA-PASSWORD-CHANGE",
                "Windows NLA / Active Directory / contraseña",
                DiagnosticLayer.Windows,
                is2019 ? 98 : 91,
                is2019 ? ConfidenceLevel.Alta : ConfidenceLevel.Media,
                "Windows rechazó la autenticación remota por estado de contraseña antes de completar la sesión TSplus.",
                "La evidencia Security indica contraseña expirada o cambio obligatorio y TDM observó el estado de NLA. NLA autentica antes de crear la sesión RDP completa, por lo que TSplus queda clasificado como afectado/víctima cuando el rechazo ocurre en esta fase. El patrón específico de Windows Server 2019 se eleva sólo cuando el sistema, NLA y el código de autenticación coinciden.",
                Merge(
                    nlaPasswordIssue.Evidencia,
                    new EvidenceItem("Originador específico", "Windows NLA / autenticación de credenciales"),
                    new EvidenceItem("Rol de TSplus", "VÍCTIMA / sesión no completada"),
                    new EvidenceItem("Rol de Windows", "ORIGINADOR")),
                null,
                nlaEvent?.Timestamp,
                "WINDOWS",
                TsplusProduct.RemoteAccess));
        }

        var encodingRisk = report.Hallazgos.FirstOrDefault(f => f.Id == "TSPLUS-REMOTEAPP-ENCODING-RISK");
        var nonAsciiContext = report.Eventos
            .Where(e => e.Tipo is "REMOTEAPP_NONASCII_IDENTITY_CONTEXT" or "TSPLUS_REMOTEAPP_NONASCII_CONFIG_CONTEXT" or "REMOTEAPP_NONASCII_LOG_CONTEXT")
            .OrderByDescending(e => e.Timestamp)
            .FirstOrDefault();
        var remoteAppErrors = report.Eventos
            .Where(e => e.Timestamp.HasValue && e.Producto == TsplusProduct.RemoteAccess &&
                        e.Severidad != DiagnosticSeverity.Informativo &&
                        e.Tipo is "CONNECTION_CLIENT" or "APPLICATION_PUBLISHING" or "OPERATION_FAILED" or "SESSION")
            .OrderByDescending(e => e.Timestamp)
            .ToList();

        if (encodingRisk is not null && remoteAppErrors.Count > 0)
        {
            var err = remoteAppErrors[0];
            var riskyEvent = report.Eventos
                .Where(e => e.Tipo == "TSPLUS_STARTUP_CONFIG_ENCODING_RISK" && e.Timestamp.HasValue)
                .OrderByDescending(e => e.Timestamp)
                .FirstOrDefault();
            var close = riskyEvent is not null && err.Timestamp.HasValue &&
                        (riskyEvent.Timestamp!.Value - err.Timestamp.Value).Duration() <= TimeSpan.FromMinutes(10);
            drafts.Add(new CandidateDraft(
                "ROOT-TSPLUS-REMOTEAPP-ENCODING",
                "TSplus RemoteApp / codificación de cadena de inicio",
                DiagnosticLayer.Tsplus,
                close ? 94 : 84,
                close ? ConfidenceLevel.Alta : ConfidenceLevel.Media,
                "Existe un riesgo de codificación RemoteApp junto con un error operativo del cliente/publicación.",
                close
                    ? "startup.config contiene bytes no ASCII no válidos como UTF-8 y existe un error RemoteApp temporalmente compatible. Esto sustenta a TSplus RemoteApp/cadena de inicio como originador probable, sin extrapolar automáticamente el comportamiento a todos los clientes."
                    : "Se observó un riesgo de codificación en startup.config y errores RemoteApp en la ventana, pero la relación temporal no es suficientemente estrecha para confirmar causalidad.",
                Merge(
                    encodingRisk.Evidencia,
                    new EvidenceItem("Originador específico", "TSplus RemoteApp / startup.config / codificación"),
                    new EvidenceItem("Evento RemoteApp", err.Tipo),
                    new EvidenceItem("Error RemoteApp", err.Mensaje),
                    new EvidenceItem("Relación temporal <=10 min", close ? "Sí" : "No")),
                null,
                err.Timestamp,
                "TSPLUS",
                TsplusProduct.RemoteAccess));
        }
        else if (nonAsciiContext is not null && remoteAppErrors.Count > 0)
        {
            var err = remoteAppErrors[0];
            drafts.Add(new CandidateDraft(
                "ROOT-REMOTEAPP-UNICODE-COMPATIBILITY",
                "RemoteApp / compatibilidad Unicode",
                DiagnosticLayer.Tsplus,
                76,
                ConfidenceLevel.Media,
                "Se observaron caracteres no ASCII y un error RemoteApp compatible, pero no se dispone de evidencia suficiente para atribuir el fallo a TSplus o al cliente RDP.",
                "Los caracteres acentuados pueden ser relevantes en cadenas RemoteApp/RDP, pero TDM no inspecciona automáticamente el archivo .connect del equipo cliente. Sin startup.config anómalo o evidencia explícita del Connection Client, el origen permanece indeterminado.",
                [
                    new EvidenceItem("Originador específico", "Compatibilidad de codificación RemoteApp/RDP no determinada"),
                    new EvidenceItem("Contexto Unicode", nonAsciiContext.Mensaje),
                    new EvidenceItem("Evento RemoteApp", err.Tipo),
                    new EvidenceItem("Rol de TSplus", "POSIBLE ORIGEN / AFECTADO"),
                    new EvidenceItem("Evidencia cliente .connect", "No disponible desde el servidor")
                ],
                null,
                err.Timestamp,
                "INDETERMINADO",
                TsplusProduct.RemoteAccess));
        }

        // RC18.3.1: configuración de granja. La anomalía estática es fuerte sólo cuando coincide
        // con síntomas de portal/sesión; en ausencia de esos síntomas se conserva como candidato secundario.
        var farmIssue = report.Hallazgos.FirstOrDefault(f => (f.Id is "TSPLUS-FARM-BALANCE-NAME-MISMATCH" or "TSPLUS-FARM-NO-SERVERS") || f.Id.StartsWith("TSPLUS-FARM-BALANCE-INCOMPLETE-", StringComparison.OrdinalIgnoreCase));
        if (farmIssue is not null)
        {
            var webSymptoms = tsplusErrors
                .Where(e => e.Tipo is "WEB" or "SESSION" or "APPLICATION_PUBLISHING" or "OPERATION_FAILED" or "PORT_BIND")
                .Where(e => e.Timestamp.HasValue && IsNearAnalysisEnd(report, e, TimeSpan.FromMinutes(15)))
                .ToList();
            drafts.Add(new CandidateDraft(
                "ROOT-TSPLUS-FARM-CONFIG",
                "TSplus Farm / Load Balancing / Reverse Proxy",
                DiagnosticLayer.Tsplus,
                webSymptoms.Count > 0 ? 86 : 79,
                ConfidenceLevel.Media,
                webSymptoms.Count > 0
                    ? "Una inconsistencia local de la granja coincide con errores operativos TSplus recientes; se conserva como hipótesis prioritaria, no como causa alta."
                    : "Se detectó una inconsistencia de configuración de granja, sin un síntoma operativo correlacionado suficiente.",
                webSymptoms.Count > 0
                    ? "La configuración local de Load Balancing/Reverse Proxy no es coherente y existe evidencia reciente de portal/sesión/publicación. Como TDM no sondea todos los nodos de la granja, esta relación requiere validación distribuida antes de atribuir causa raíz."
                    : "La inconsistencia es real, pero TDM no la declara causa primaria de otro incidente sin evidencia temporal compatible.",
                Merge(farmIssue.Evidencia,
                    new EvidenceItem("Síntomas TSplus compatibles", webSymptoms.Count.ToString()),
                    // P13: coincidencia con errores web/sesión ≤15 min sin identidad de nodo/archivo.
                    new EvidenceItem("Identidad técnica compartida", "No verificada (solo proximidad temporal; requiere validación distribuida)")),
                null,
                webSymptoms.LastOrDefault()?.Timestamp,
                "TSPLUS",
                TsplusProduct.RemoteAccess));
        }

        var zeroBinary = report.Hallazgos.FirstOrDefault(f => f.Id.StartsWith("TSPLUS-ZERO-BINARY-", StringComparison.OrdinalIgnoreCase));
        if (zeroBinary is not null)
        {
            drafts.Add(new CandidateDraft(
                "ROOT-TSPLUS-INSTALL-INTEGRITY",
                zeroBinary.Componente,
                DiagnosticLayer.Tsplus,
                82,
                ConfidenceLevel.Media,
                "La instalación TSplus contiene un binario ejecutable vacío; sin correlación funcional se conserva como hipótesis de integridad.",
                "Un EXE/DLL/JAR de cero bytes es una inconsistencia física confirmada de la instalación. El componente debe validarse contra la versión instalada y el incidente antes de reparar o reinstalar.",
                zeroBinary.Evidencia,
                null,
                null,
                "TSPLUS",
                TsplusProduct.RemoteAccess));
        }

    }
}
