using TDM.Models;

namespace TDM.Correlation;

public static partial class RootCauseCorrelator
{
    private static void AddIdentityCandidates(DiagnosticReport report, List<CandidateDraft> drafts, IReadOnlyList<DiagnosticEvent> tsplusErrors, IReadOnlyList<DiagnosticEvent> rdpErrors, IReadOnlyList<DiagnosticEvent> defenderTsplusEvents, IReadOnlyList<DiagnosticEvent> schannelErrors)
    {
        // Mission Assurance: rechazos NLA/validación de credenciales sólo se elevan cuando el mismo usuario
        // aparece en un síntoma RDP/TSplus cercano. El evento aislado permanece como evidencia, no como originador.
        var credentialFailures = report.Eventos
            .Where(e => e.Timestamp.HasValue && e.Tipo is "USER_NLA_PASSWORD_FAILURE" or "WINDOWS_CREDENTIAL_VALIDATION_FAILURE")
            .OrderBy(e => e.Timestamp)
            .ToList();
        foreach (var failure in credentialFailures)
        {
            var user = failure.Evidencia?.FirstOrDefault(x => x.Clave == "Usuario")?.Valor;
            if (string.IsNullOrWhiteSpace(user) || user == "N/D") continue;
            var related = report.Eventos
                .Where(e => e.Timestamp.HasValue && e.Timestamp >= failure.Timestamp && e.Timestamp <= failure.Timestamp + TimeSpan.FromMinutes(3))
                .Where(e => e.Severidad != DiagnosticSeverity.Informativo)
                .Where(e => e.Capa is DiagnosticLayer.Rdp or DiagnosticLayer.Tsplus)
                .Where(e => !ReferenceEquals(e, failure))
                .FirstOrDefault(e => EventIdentity(e) is string candidate && SameIdentity(candidate, user));
            if (related is null) continue;
            var nla = failure.Tipo == "USER_NLA_PASSWORD_FAILURE";
            drafts.Add(new CandidateDraft(
                nla ? $"ROOT-WINDOWS-NLA-CREDENTIALS-{user}" : $"ROOT-WINDOWS-CREDENTIAL-VALIDATION-{user}",
                nla ? $"Windows NLA / credenciales / {user}" : $"Windows / validación de credenciales / {user}",
                DiagnosticLayer.Seguridad,
                nla ? 96 : 88,
                nla ? ConfidenceLevel.Alta : ConfidenceLevel.Media,
                nla
                    ? "Windows rechazó credenciales NLA del mismo usuario antes del síntoma RDP/TSplus."
                    : "Windows registró un rechazo de validación de credenciales del mismo usuario antes del síntoma RDP/TSplus.",
                nla
                    ? "La evidencia de Security identifica un rechazo previo a la creación de sesión y la identidad coincide con el síntoma posterior. La investigación debe comenzar por credenciales, estado de contraseña y políticas de autenticación."
                    : "El evento 4776 demuestra un rechazo de validación de credenciales y coincide en usuario/ventana con el síntoma. Puede involucrar cuenta, controlador de dominio o paquete de autenticación; TDM no lo eleva a origen confirmado sin evidencia adicional.",
                [
                    new EvidenceItem("Usuario", user),
                    new EvidenceItem("Evento Security", failure.Codigo ?? failure.Tipo),
                    new EvidenceItem("Hora evento", failure.Timestamp!.Value.ToLocalTime().ToString("dd/MM/yyyy HH:mm:ss")),
                    new EvidenceItem("Síntoma posterior", related.Tipo),
                    new EvidenceItem("Código Windows", failure.Evidencia?.FirstOrDefault(x => x.Clave is "Status" or "SubStatus" or "Código de error")?.Valor ?? "N/D")
                ],
                null,
                failure.Timestamp,
                "WINDOWS",
                TsplusProduct.RemoteAccess));
        }

        // Mission Assurance: bloqueo de cuenta y Kerberos sólo se elevan cuando el mismo usuario
        // aparece en un síntoma RDP/TSplus cercano. Evita convertir ruido general de dominio en originador.
        var identitySecurityFailures = report.Eventos
            .Where(e => e.Timestamp.HasValue && e.Tipo is "ACCOUNT_LOCKOUT" or "KERBEROS_PREAUTH_FAILURE")
            .OrderBy(e => e.Timestamp)
            .ToList();
        foreach (var failure in identitySecurityFailures)
        {
            var user = failure.Evidencia?.FirstOrDefault(x => x.Clave == "Usuario")?.Valor;
            if (string.IsNullOrWhiteSpace(user) || user == "N/D") continue;
            var related = report.Eventos
                .Where(e => e.Timestamp.HasValue && e.Timestamp >= failure.Timestamp && e.Timestamp <= failure.Timestamp + TimeSpan.FromMinutes(3))
                .Where(e => e.Severidad != DiagnosticSeverity.Informativo)
                .Where(e => e.Capa is DiagnosticLayer.Rdp or DiagnosticLayer.Tsplus)
                .FirstOrDefault(e => EventIdentity(e) is string candidate && SameIdentity(candidate, user));
            if (related is null) continue;
            var lockout = failure.Tipo == "ACCOUNT_LOCKOUT";
            drafts.Add(new CandidateDraft(
                lockout ? $"ROOT-WINDOWS-ACCOUNT-LOCKOUT-{user}" : $"ROOT-WINDOWS-KERBEROS-PREAUTH-{user}",
                lockout ? $"Windows / cuenta bloqueada / {user}" : $"Kerberos / preautenticación / {user}",
                DiagnosticLayer.Seguridad,
                lockout ? 98 : 89,
                lockout ? ConfidenceLevel.Alta : ConfidenceLevel.Media,
                lockout
                    ? "Windows bloqueó la cuenta del mismo usuario antes del síntoma RDP/TSplus."
                    : "Un fallo de preautenticación Kerberos del mismo usuario precede al síntoma RDP/TSplus.",
                lockout
                    ? "Security Event 4740 demuestra que la cuenta estaba bloqueada y la identidad coincide con el síntoma posterior. Debe resolverse la condición de cuenta/origen de bloqueos antes de reparar componentes TSplus."
                    : "Security Event 4771 precede al síntoma y coincide en usuario. Puede representar credenciales/preautenticación o infraestructura Kerberos; TDM lo mantiene como candidato y no como origen confirmado sin evidencia adicional.",
                [
                    new EvidenceItem("Usuario", user),
                    new EvidenceItem("Evento Security", failure.Codigo ?? failure.Tipo),
                    new EvidenceItem("Hora evento", failure.Timestamp!.Value.ToLocalTime().ToString("dd/MM/yyyy HH:mm:ss")),
                    new EvidenceItem("Síntoma posterior", related.Tipo),
                    new EvidenceItem("Originador observado", failure.Evidencia?.FirstOrDefault(x => x.Clave is "Equipo originador" or "IP origen")?.Valor ?? "N/D")
                ],
                null,
                failure.Timestamp,
                "WINDOWS",
                TsplusProduct.RemoteAccess));
            if (lockout) break;
        }

        // RC18.3.1: autenticación por usuario. Un 4625 aislado puede ser ruido; sólo se convierte en candidato
        // cuando el mismo usuario aparece en un síntoma RDP/TSplus cercano.
        var remoteLogonFailures = report.Eventos
            .Where(e => e.Timestamp.HasValue && e.Tipo == "USER_LOGON_FAILURE")
            .OrderBy(e => e.Timestamp)
            .ToList();
        foreach (var failure in remoteLogonFailures)
        {
            var user = failure.Evidencia?.FirstOrDefault(x => x.Clave == "Usuario")?.Valor;
            if (string.IsNullOrWhiteSpace(user) || user == "N/D") continue;
            var related = report.Eventos
                .Where(e => e.Timestamp.HasValue && e.Timestamp >= failure.Timestamp && e.Timestamp <= failure.Timestamp + TimeSpan.FromMinutes(2))
                .Where(e => e.Severidad != DiagnosticSeverity.Informativo)
                .Where(e => e.Capa is DiagnosticLayer.Rdp or DiagnosticLayer.Tsplus)
                .FirstOrDefault(e => EventIdentity(e) is string candidate && SameIdentity(candidate, user));
            if (related is null) continue;
            drafts.Add(new CandidateDraft(
                $"ROOT-WINDOWS-REMOTE-LOGON-{user}",
                $"Autenticación Windows / {user}",
                DiagnosticLayer.Windows,
                95,
                ConfidenceLevel.Alta,
                "Windows rechazó el inicio de sesión RemoteInteractive del mismo usuario antes del síntoma RDP/TSplus.",
                "El evento Security 4625 precede al síntoma correlacionado y corresponde al mismo usuario. La investigación debe comenzar por el motivo/status de autenticación, cuenta o política de inicio de sesión antes de reparar publicación de aplicaciones, perfil o componentes TSplus posteriores.",
                [
                    new EvidenceItem("Usuario", user),
                    new EvidenceItem("Hora fallo de autenticación", failure.Timestamp!.Value.ToLocalTime().ToString("dd/MM/yyyy HH:mm:ss")),
                    new EvidenceItem("Motivo", failure.Evidencia?.FirstOrDefault(x => x.Clave == "Motivo")?.Valor ?? "N/D"),
                    new EvidenceItem("Status", failure.Evidencia?.FirstOrDefault(x => x.Clave == "Status")?.Valor ?? "N/D"),
                    new EvidenceItem("SubStatus", failure.Evidencia?.FirstOrDefault(x => x.Clave == "SubStatus")?.Valor ?? "N/D"),
                    new EvidenceItem("Síntoma posterior", related.Tipo)
                ],
                null,
                failure.Timestamp,
                "WINDOWS",
                TsplusProduct.RemoteAccess));
            break;
        }

        // RC18.3.1: perfiles de usuario como capa causal entre autenticación y apertura de sesión/aplicación.
        var profileErrors = report.Eventos
            .Where(e => e.Timestamp.HasValue && e.Tipo == "USER_PROFILE_SERVICE_EVENT" && e.Severidad != DiagnosticSeverity.Informativo)
            .OrderBy(e => e.Timestamp)
            .ToList();
        var sessionSymptoms = report.Eventos
            .Where(e => e.Timestamp.HasValue && e.Severidad != DiagnosticSeverity.Informativo &&
                        (e.Capa == DiagnosticLayer.Rdp || (e.Capa == DiagnosticLayer.Tsplus && e.Tipo is "SESSION" or "WEB" or "APPLICATION_PUBLISHING")))
            .OrderBy(e => e.Timestamp)
            .ToList();

        (DiagnosticEvent before, DiagnosticEvent after, TimeSpan delta, string? user, bool identityMatched)? profilePair = null;
        foreach (var profileEvent in profileErrors)
        {
            var profileUser = EventIdentity(profileEvent);
            foreach (var symptom in sessionSymptoms.Where(e => e.Timestamp >= profileEvent.Timestamp && e.Timestamp <= profileEvent.Timestamp + TimeSpan.FromMinutes(5)))
            {
                var symptomUser = EventIdentity(symptom);
                var identityAvailable = !string.IsNullOrWhiteSpace(profileUser) && !string.IsNullOrWhiteSpace(symptomUser);
                if (identityAvailable && !SameIdentity(profileUser!, symptomUser!)) continue;
                var delta = symptom.Timestamp!.Value - profileEvent.Timestamp!.Value;
                if (profilePair is null || (identityAvailable && !profilePair.Value.identityMatched) || (identityAvailable == profilePair.Value.identityMatched && delta < profilePair.Value.delta))
                    profilePair = (profileEvent, symptom, delta, profileUser ?? symptomUser, identityAvailable);
            }
        }

        if (profilePair is not null)
        {
            var matched = profilePair.Value.identityMatched;
            drafts.Add(new CandidateDraft(
                "ROOT-WINDOWS-USER-PROFILE",
                string.IsNullOrWhiteSpace(profilePair.Value.user) ? "Windows User Profile Service" : $"Windows User Profile / {profilePair.Value.user}",
                DiagnosticLayer.Windows,
                matched ? 96 : 88,
                matched ? ConfidenceLevel.Alta : ConfidenceLevel.Media,
                matched
                    ? "Un error de perfil del mismo usuario precede a un síntoma de sesión RDP/TSplus."
                    : "Un error de perfil precede temporalmente a un síntoma RDP/TSplus, pero no fue posible demostrar identidad de usuario en ambos eventos.",
                matched
                    ? "User Profile Service registró un error para el mismo usuario y después apareció un fallo de sesión, portal o publicación dentro de cinco minutos. Esto sitúa la carga del perfil por delante del síntoma TSplus y justifica corregir primero el perfil del usuario afectado."
                    : "La secuencia temporal es compatible con un problema de perfil, pero falta identidad de usuario común. TDM mantiene el candidato como probable y no recomienda modificar el perfil hasta correlacionarlo con el usuario/sesión afectada.",
                [
                    new EvidenceItem("Evento de perfil", profilePair.Value.before.Codigo ?? profilePair.Value.before.Tipo),
                    new EvidenceItem("Usuario correlacionado", profilePair.Value.user ?? "No determinado"),
                    new EvidenceItem("Identidad coincidente", matched ? "Sí" : "No demostrada"),
                    new EvidenceItem("Síntoma posterior", profilePair.Value.after.Tipo),
                    new EvidenceItem("Separación", profilePair.Value.delta.ToString()),
                    new EvidenceItem("Fuente perfil", profilePair.Value.before.Fuente)
                ],
                null,
                profilePair.Value.before.Timestamp,
                "WINDOWS",
                TsplusProduct.RemoteAccess));
        }

        // Solo elevamos TSplus por logs internos cuando no existe una falla subyacente o un crash más fuerte.
        var underlyingStrong = drafts.Any(x => x.Score >= 80 && ProductFromText(x.Component) is not (TsplusProduct.ServerMonitoring or TsplusProduct.AdvancedSecurity or TsplusProduct.RemoteSupport or TsplusProduct.TwoFactorAuthentication)) ||
                               defenderTsplusEvents.Any(e => e.Tipo == "DEFENDER_ACTION_TAKEN") ||
                               report.Eventos.Any(e => e.Tipo == "THIRD_PARTY_MODULE_TSPLUS_CRASH" || e.Tipo == "THIRD_PARTY_SECURITY_INTERFERENCE_SIGNAL");
        if (tsplusErrors.Count > 0 && !underlyingStrong)
        {
            var distinctSources = tsplusErrors.Select(e => e.Archivo ?? e.Componente).Distinct(StringComparer.OrdinalIgnoreCase).Count();
            var score = Math.Min(68, 48 + (tsplusErrors.Count * 3) + (distinctSources * 4));
            drafts.Add(new CandidateDraft(
                "ROOT-TSPLUS-INTERNAL",
                "TSplus Remote Access",
                DiagnosticLayer.Tsplus,
                score,
                distinctSources >= 2 ? ConfidenceLevel.Media : ConfidenceLevel.Baja,
                "La evidencia disponible apunta primero a la capa TSplus.",
                "Se encontraron errores TSplus con timestamp verificable sin una falla RDP/TLS de mayor prioridad en la misma ventana. Esto convierte a TSplus en candidato, pero todavía no demuestra qué componente interno originó el problema.",
                [
                    new EvidenceItem("Errores TSplus", tsplusErrors.Count.ToString()),
                    new EvidenceItem("Fuentes TSplus distintas", distinctSources.ToString()),
                    new EvidenceItem("Errores RDP", rdpErrors.Count.ToString()),
                    new EvidenceItem("Errores Schannel", schannelErrors.Count.ToString())
                ],
                "TSPLUS-LOGS"));
        }


    }

    private static void AddExternalSecurityCandidates(DiagnosticReport report, List<CandidateDraft> drafts, IReadOnlyList<DiagnosticEvent> tsplusErrors, IReadOnlyList<DiagnosticEvent> defenderTsplusEvents)
    {
        // RC18.12.2: terceros específicos. La presencia de un producto instalado no es causal;
        // sólo se eleva cuando existe un módulo externo como faulting module del proceso TSplus
        // o cuando un evento del tercero menciona explícitamente una ruta/componente TSplus.
        var thirdPartySignals = report.Eventos
            .Where(e => e.Timestamp.HasValue && e.Tipo == "THIRD_PARTY_SECURITY_INTERFERENCE_SIGNAL")
            .OrderBy(e => e.Timestamp)
            .ToList();
        var thirdPartyModuleEvents = report.Eventos
            .Where(e => e.Timestamp.HasValue && e.Tipo == "THIRD_PARTY_MODULE_TSPLUS_CRASH")
            .OrderByDescending(e => e.Timestamp)
            .Take(3)
            .ToList();
        foreach (var third in thirdPartyModuleEvents)
        {
            var specific = EvidenceValue(third, "Originador específico") ?? third.Componente;
            var module = EvidenceValue(third, "Módulo con error") ?? third.Archivo ?? "N/D";
            var hasVendorSignal = thirdPartySignals.Any(e =>
                e.Timestamp.HasValue && third.Timestamp.HasValue &&
                (e.Timestamp.Value - third.Timestamp.Value).Duration() <= TimeSpan.FromMinutes(10) &&
                (EvidenceValue(e, "Originador específico") ?? e.Componente).Equals(specific, StringComparison.OrdinalIgnoreCase));
            var hasInternalStack = report.Eventos.Any(e =>
                e.Tipo == "DOTNET_UNHANDLED_EXCEPTION" && e.Timestamp.HasValue && third.Timestamp.HasValue &&
                (e.Timestamp.Value - third.Timestamp.Value).Duration() <= TimeSpan.FromSeconds(10) &&
                e.Producto == third.Producto &&
                !string.IsNullOrWhiteSpace(EvidenceValue(e, "Primer frame no framework")));
            var externalScore = hasInternalStack ? 82 : hasVendorSignal ? 97 : 90;
            var externalConfidence = hasInternalStack ? ConfidenceLevel.Media : hasVendorSignal ? ConfidenceLevel.Alta : ConfidenceLevel.Media;
            drafts.Add(new CandidateDraft(
                "ROOT-EXTERNAL-MODULE-TSPLUS-CRASH",
                specific,
                DiagnosticLayer.Seguridad,
                externalScore,
                externalConfidence,
                $"Un módulo externo identificado ({specific}) aparece como módulo con error dentro de un crash TSplus.",
                hasInternalStack
                    ? "El faulting module pertenece a un tercero, pero existe además una pila interna TSplus en el mismo episodio. TDM conserva al tercero como candidato y marca la competencia causal en lugar de asumir que el módulo externo es el originador por sí solo."
                    : hasVendorSignal
                        ? "Application Error sitúa el punto de fallo en un módulo externo y existe además una señal del mismo proveedor cerca del incidente. La convergencia eleva al tercero específico como originador probable, sin afirmar automáticamente un defecto del proveedor."
                        : "Application Error sitúa el punto de fallo en un módulo que no pertenece al árbol Windows ni al árbol TSplus. TDM identifica al tercero concreto cuando la metadata/ruta lo permite, pero mantiene confianza media porque un faulting module aislado puede ser punto de manifestación y no causa primaria.",
                CompactEvidence(
                    new EvidenceItem("Originador específico", specific),
                    new EvidenceItem("Módulo con error", module),
                    new EvidenceItem("Ruta del módulo", EvidenceValue(third, "Ruta del módulo") ?? third.Archivo ?? "N/D"),
                    new EvidenceItem("Empresa", EvidenceValue(third, "Empresa") ?? "No determinada"),
                    new EvidenceItem("Producto", EvidenceValue(third, "Producto") ?? "No determinado"),
                    new EvidenceItem("Señal del mismo proveedor <=10 min", hasVendorSignal ? "Sí" : "No"),
                    new EvidenceItem("Stack interno TSplus en el mismo episodio", hasInternalStack ? "Sí; existe conflicto causal" : "No observado"),
                    new EvidenceItem("Rol de TSplus", hasInternalStack ? "POSIBLE ORIGEN / AFECTADO" : "VÍCTIMA / proceso afectado"),
                    new EvidenceItem("Rol de Windows", "Registró el crash; no demostrado como originador")),
                null,
                third.Timestamp,
                "EXTERNO",
                third.Producto));
        }

        var thirdPartyPair = ClosestBefore(thirdPartySignals, report.Eventos
            .Where(e => e.Timestamp.HasValue && e.Producto is not TsplusProduct.Ninguno and not TsplusProduct.Desconocido)
            .Where(e => e.Severidad != DiagnosticSeverity.Informativo && e.Tipo != "THIRD_PARTY_SECURITY_INTERFERENCE_SIGNAL")
            .Where(e => !e.Fuente.Equals("TDM", StringComparison.OrdinalIgnoreCase))
            .OrderBy(e => e.Timestamp).ToList(), TimeSpan.FromMinutes(10));
        if (thirdPartyPair is not null)
        {
            var specific = EvidenceValue(thirdPartyPair.Value.before, "Originador específico") ?? thirdPartyPair.Value.before.Componente;
            drafts.Add(new CandidateDraft(
                "ROOT-EXTERNAL-SECURITY-INTERFERENCE",
                specific,
                DiagnosticLayer.Seguridad,
                91,
                ConfidenceLevel.Alta,
                $"{specific} generó una señal que menciona explícitamente TSplus antes de un error TSplus.",
                "La evidencia del producto de terceros referencia directamente una ruta o componente TSplus y precede al síntoma. TDM lo clasifica como originador externo probable; se mantiene por debajo de una evidencia de faulting module o bloqueo/cuarentena explícita.",
                [
                    new EvidenceItem("Originador específico", specific),
                    new EvidenceItem("Evento del tercero", thirdPartyPair.Value.before.Codigo ?? thirdPartyPair.Value.before.Tipo),
                    new EvidenceItem("Evento TSplus posterior", thirdPartyPair.Value.after.Tipo),
                    new EvidenceItem("Separación temporal", thirdPartyPair.Value.delta.ToString()),
                    new EvidenceItem("Rol de TSplus", "VÍCTIMA / AFECTADO")
                ],
                null,
                thirdPartyPair.Value.before.Timestamp,
                "EXTERNO",
                thirdPartyPair.Value.after.Producto));
        }

        // Defender/EDR: solo elevamos cuando el evento toca explícitamente rutas/componentes TSplus.
        var defenderPair = ClosestBefore(defenderTsplusEvents, tsplusErrors, TimeSpan.FromMinutes(15));
        var defenderAction = defenderTsplusEvents.LastOrDefault(e => e.Tipo == "DEFENDER_ACTION_TAKEN");
        var missingMatch = defenderAction is null ? null : FindMissingFileMatch(report, defenderAction);

        if (defenderAction is not null && missingMatch is not null)
        {
            drafts.Add(new CandidateDraft(
                "ROOT-SECURITY-DEFENDER-FILE",
                "Microsoft Defender / archivo TSplus",
                DiagnosticLayer.Seguridad,
                defenderPair is null ? 94 : 99,
                defenderPair is null ? ConfidenceLevel.Alta : ConfidenceLevel.Confirmada,
                "Defender actuó sobre un componente TSplus y el archivo ya no está presente.",
                defenderPair is null
                    ? "Existe evidencia de una acción de Microsoft Defender sobre una ruta o ejecutable TSplus y el archivo relacionado no está presente. La relación con la falla TSplus es fuerte, aunque no hay un error TSplus posterior con timestamp verificable en la ventana."
                    : "Microsoft Defender registró una acción sobre un componente TSplus, el archivo relacionado no está presente y posteriormente existe evidencia TSplus con timestamp. La secuencia temporal y la evidencia de archivo sustentan la causa raíz.",
                [
                    new EvidenceItem("Evento Defender", defenderAction.Tipo),
                    new EvidenceItem("Event ID", defenderAction.Codigo ?? "N/D"),
                    new EvidenceItem("Archivo relacionado", missingMatch.Archivo ?? "N/D"),
                    new EvidenceItem("Archivo presente", "No"),
                    new EvidenceItem("Error TSplus posterior", defenderPair is null ? "No verificable" : defenderPair.Value.after.Tipo),
                    new EvidenceItem("Separación", defenderPair is null ? "N/D" : defenderPair.Value.delta.ToString()),
                    new EvidenceItem("Originador específico", "Microsoft Defender"),
                    new EvidenceItem("Rol de TSplus", "VÍCTIMA / AFECTADO")
                ],
                "TSPLUS-DEFENDER-FILE",
                defenderAction.Timestamp,
                "WINDOWS",
                defenderAction.Producto == TsplusProduct.Ninguno ? TsplusProduct.Desconocido : defenderAction.Producto));
        }
        else if (defenderPair is not null)
        {
            drafts.Add(new CandidateDraft(
                "ROOT-SECURITY-DEFENDER",
                "Microsoft Defender / Seguridad",
                DiagnosticLayer.Seguridad,
                86,
                ConfidenceLevel.Alta,
                "Microsoft Defender es candidato fuerte a origen del incidente.",
                "Un evento de detección/acción de Defender sobre una ruta o componente TSplus ocurrió antes de un error TSplus dentro de la ventana de correlación. No se declara confirmada porque falta demostrar el efecto exacto sobre el archivo o proceso.",
                [
                    new EvidenceItem("Evento Defender", defenderPair.Value.before.Tipo),
                    new EvidenceItem("Event ID", defenderPair.Value.before.Codigo ?? "N/D"),
                    new EvidenceItem("Evento TSplus", defenderPair.Value.after.Tipo),
                    new EvidenceItem("Separación temporal", defenderPair.Value.delta.ToString()),
                    new EvidenceItem("Originador específico", "Microsoft Defender"),
                    new EvidenceItem("Rol de TSplus", "VÍCTIMA / AFECTADO")
                ],
                "TSPLUS-DEFENDER-FILE",
                defenderPair.Value.before.Timestamp,
                "WINDOWS",
                defenderPair.Value.after.Producto == TsplusProduct.Ninguno ? TsplusProduct.Desconocido : defenderPair.Value.after.Producto));
        }

    }
}
