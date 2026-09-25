using System.Diagnostics.Eventing.Reader;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Xml.Linq;
using Microsoft.Win32;
using TDM.Core;
using TDM.Models;

namespace TDM.Collectors.Rdp;

/// <summary>
/// Inventario local de cuentas, perfiles y sesiones RDP/TSplus en modo de solo lectura.
/// No consulta contraseñas, hashes ni secretos y no modifica sesiones/perfiles.
/// </summary>
public sealed class UserSessionProfileCollector : IReadOnlyCollector
{
    public string Nombre => "Usuarios, perfiles y sesiones";

    public Task<CollectorResult> CollectAsync(DiagnosticContext context, CancellationToken cancellationToken = default)
    {
        var findings = new List<DiagnosticFinding>();
        var events = new List<DiagnosticEvent>();

        var accountsProbe = EnumerateLocalUsers(cancellationToken);
        var profilesProbe = ReadProfiles(cancellationToken);
        var sessionsProbe = EnumerateSessions(cancellationToken);
        var accounts = accountsProbe.IsAvailable ? accountsProbe.Value ?? [] : [];
        var profiles = profilesProbe.IsAvailable ? profilesProbe.Value ?? [] : [];
        var sessions = sessionsProbe.IsAvailable ? sessionsProbe.Value ?? [] : [];

        AddInventoryCoverageFinding(findings, "USER-ACCOUNTS-COVERAGE", "Cuentas locales", accountsProbe);
        AddInventoryCoverageFinding(findings, "USER-PROFILES-COVERAGE", "Perfiles registrados", profilesProbe);
        AddInventoryCoverageFinding(findings, "USER-SESSIONS-COVERAGE", "Sesiones de Terminal Services", sessionsProbe);

        foreach (var account in accounts)
        {
            var profile = profiles.FirstOrDefault(p => p.Sid.Equals(account.Sid, StringComparison.OrdinalIgnoreCase));
            events.Add(new DiagnosticEvent(
                DateTimeOffset.Now,
                "Windows Accounts",
                account.Name,
                DiagnosticLayer.Rdp,
                DiagnosticSeverity.Informativo,
                "USER_ACCOUNT_STATE",
                "Cuenta local observada para diagnóstico de acceso remoto.",
                Evidencia:
                [
                    new EvidenceItem("Usuario", account.Name),
                    new EvidenceItem("Nombre completo", string.IsNullOrWhiteSpace(account.FullName) ? "N/D" : account.FullName),
                    new EvidenceItem("SID", account.Sid),
                    new EvidenceItem("Habilitada", account.Disabled ? "No" : "Sí"),
                    new EvidenceItem("Bloqueada", account.Locked ? "Sí" : "No"),
                    new EvidenceItem("Contraseña expirada", account.PasswordExpired ? "Sí" : "No"),
                    new EvidenceItem("Contraseña no expira", account.PasswordNeverExpires ? "Sí" : "No"),
                    new EvidenceItem("Cuenta expira", account.AccountExpires.HasValue ? account.AccountExpires.Value.ToLocalTime().ToString("dd/MM/yyyy HH:mm:ss") : "No/N.D."),
                    new EvidenceItem("Último logon local conocido", account.LastLogon.HasValue ? account.LastLogon.Value.ToLocalTime().ToString("dd/MM/yyyy HH:mm:ss") : "N/D"),
                    new EvidenceItem("Grupos locales", account.LocalGroups.Count == 0 ? "N/D" : string.Join(" | ", account.LocalGroups)),
                    new EvidenceItem("Directorio personal", string.IsNullOrWhiteSpace(account.HomeDirectory) ? "N/D" : account.HomeDirectory),
                    new EvidenceItem("Script de inicio", string.IsNullOrWhiteSpace(account.LogonScript) ? "N/D" : account.LogonScript),
                    new EvidenceItem("Estaciones permitidas", string.IsNullOrWhiteSpace(account.Workstations) ? "Todas/N.D." : account.Workstations),
                    new EvidenceItem("Perfil registrado", profile is null ? "No" : profile.Path)
                ],
                Producto: TsplusProduct.RemoteAccess));

            if (HasNonAscii(account.Name) || HasNonAscii(account.FullName))
            {
                events.Add(new DiagnosticEvent(
                    DateTimeOffset.Now,
                    "Windows Accounts",
                    "RemoteApp / identidad Unicode",
                    DiagnosticLayer.Rdp,
                    DiagnosticSeverity.Informativo,
                    "REMOTEAPP_NONASCII_IDENTITY_CONTEXT",
                    "La cuenta local contiene caracteres no ASCII en el nombre de cuenta o nombre completo. Se conserva como contexto para fallas RemoteApp/canales RDP; no constituye una falla por sí solo.",
                    Evidencia:
                    [
                        new EvidenceItem("Usuario", account.Name),
                        new EvidenceItem("Nombre completo", string.IsNullOrWhiteSpace(account.FullName) ? "N/D" : account.FullName),
                        new EvidenceItem("Caracteres no ASCII", "Sí"),
                        new EvidenceItem("Alcance", "Cuenta local del servidor; TDM no consulta Active Directory de forma remota en el diagnóstico normal")
                    ],
                    Producto: TsplusProduct.RemoteAccess));
            }
        }

        foreach (var profile in profiles)
            AuditProfile(profile, findings, events);

        foreach (var session in sessions)
        {
            var sid = TryResolveSid(session.Domain, session.UserName);
            var profile = sid is null ? null : profiles.FirstOrDefault(p => p.Sid.Equals(sid, StringComparison.OrdinalIgnoreCase));
            events.Add(new DiagnosticEvent(
                DateTimeOffset.Now,
                "Windows Terminal Services",
                string.IsNullOrWhiteSpace(session.UserName) ? $"Sesión {session.SessionId}" : $"{session.Domain}\\{session.UserName}",
                DiagnosticLayer.Rdp,
                DiagnosticSeverity.Informativo,
                "USER_SESSION_STATE",
                "Sesión interactiva observada en el servidor.",
                Evidencia:
                [
                    new EvidenceItem("SessionId", session.SessionId.ToString()),
                    new EvidenceItem("Estado", session.State),
                    new EvidenceItem("Usuario", string.IsNullOrWhiteSpace(session.UserName) ? "N/D" : session.UserName),
                    new EvidenceItem("Dominio", string.IsNullOrWhiteSpace(session.Domain) ? "N/D" : session.Domain),
                    new EvidenceItem("Cliente", string.IsNullOrWhiteSpace(session.ClientName) ? "N/D" : session.ClientName),
                    new EvidenceItem("Protocolo", session.Protocol),
                    new EvidenceItem("SID", sid ?? "N/D"),
                    new EvidenceItem("Perfil", profile?.Path ?? "N/D")
                ],
                Producto: TsplusProduct.RemoteAccess));

            if (HasNonAscii(session.UserName) || HasNonAscii(session.Domain) || HasNonAscii(session.ClientName))
            {
                events.Add(new DiagnosticEvent(
                    DateTimeOffset.Now,
                    "Windows Terminal Services",
                    "RemoteApp / identidad Unicode",
                    DiagnosticLayer.Rdp,
                    DiagnosticSeverity.Informativo,
                    "REMOTEAPP_NONASCII_IDENTITY_CONTEXT",
                    "La sesión contiene caracteres no ASCII en usuario, dominio o nombre de cliente. Se conserva como contexto para fallas RemoteApp/canales RDP; no constituye una falla por sí solo.",
                    Evidencia:
                    [
                        new EvidenceItem("SessionId", session.SessionId.ToString()),
                        new EvidenceItem("Usuario", string.IsNullOrWhiteSpace(session.UserName) ? "N/D" : session.UserName),
                        new EvidenceItem("Dominio", string.IsNullOrWhiteSpace(session.Domain) ? "N/D" : session.Domain),
                        new EvidenceItem("Cliente", string.IsNullOrWhiteSpace(session.ClientName) ? "N/D" : session.ClientName),
                        new EvidenceItem("Caracteres no ASCII", "Sí")
                    ],
                    Producto: TsplusProduct.RemoteAccess));
            }
        }

        ReadAuthenticationEvents(context, accounts, findings, events, cancellationToken);
        ReadAdAndDomainDependencySignals(context, findings, events, cancellationToken);
        ReadUserProfileEvents(context, findings, events, cancellationToken);

        var active = sessions.Count(s => s.State.Equals("Active", StringComparison.OrdinalIgnoreCase));
        var disconnected = sessions.Count(s => s.State.Equals("Disconnected", StringComparison.OrdinalIgnoreCase));
        events.Add(new DiagnosticEvent(
            DateTimeOffset.Now,
            "TDM",
            "Usuarios y sesiones",
            DiagnosticLayer.Rdp,
            DiagnosticSeverity.Informativo,
            "USER_SESSION_INVENTORY",
            "Inventario de cuentas, perfiles y sesiones capturado en modo de solo lectura.",
            Evidencia:
            [
                new EvidenceItem("Cuentas locales", accountsProbe.IsAvailable ? accounts.Count.ToString() : "No evaluado"),
                new EvidenceItem("Perfiles registrados", profilesProbe.IsAvailable ? profiles.Count.ToString() : "No evaluado"),
                new EvidenceItem("Sesiones observadas", sessionsProbe.IsAvailable ? sessions.Count.ToString() : "No evaluado"),
                new EvidenceItem("Sesiones activas", sessionsProbe.IsAvailable ? active.ToString() : "No evaluado"),
                new EvidenceItem("Sesiones desconectadas", sessionsProbe.IsAvailable ? disconnected.ToString() : "No evaluado"),
                new EvidenceItem("Cobertura cuentas", accountsProbe.StatusText),
                new EvidenceItem("Cobertura perfiles", profilesProbe.StatusText),
                new EvidenceItem("Cobertura sesiones", sessionsProbe.StatusText),
                new EvidenceItem("Privacidad", "No se recopilan contraseñas, hashes ni tokens")
            ],
            Producto: TsplusProduct.RemoteAccess));

        return Task.FromResult(new CollectorResult(findings, events));
    }

    private static void AddInventoryCoverageFinding<T>(List<DiagnosticFinding> findings, string id, string component, ProbeResult<T> probe)
    {
        if (probe.IsAvailable) return;
        findings.Add(new DiagnosticFinding(
            id,
            component,
            DiagnosticSeverity.Advertencia,
            $"No fue posible evaluar por completo {component.ToLowerInvariant()}.",
            "La ausencia de datos en esta fuente se interpreta como cobertura parcial, no como ausencia de usuarios, perfiles o sesiones.",
            [new EvidenceItem("Estado de lectura", probe.StatusText), new EvidenceItem("Detalle", probe.Detail ?? "Sin detalle adicional")],
            ConfidenceLevel.Confirmada,
            Capa: DiagnosticLayer.Rdp));
    }

    private static void AuditProfile(UserProfileInfo profile, List<DiagnosticFinding> findings, List<DiagnosticEvent> events)
    {
        var pathProbe = string.IsNullOrWhiteSpace(profile.Path)
            ? ProbeResult<bool>.Unavailable("ProfileImagePath vacío")
            : FileSystemProbe.Directory(profile.Path);
        var pathExists = pathProbe.IsAvailable;
        var ntUser = pathExists ? Path.Combine(profile.Path, "NTUSER.DAT") : string.Empty;
        var ntUserProbe = pathExists
            ? FileSystemProbe.File(ntUser)
            : pathProbe.IsAbsent
                ? ProbeResult<bool>.Absent("La carpeta del perfil está ausente")
                : ProbeResult<bool>.Unavailable("No se pudo evaluar la carpeta padre del perfil");
        var temporary = profile.IsBak || profile.Path.Contains("\\TEMP", StringComparison.OrdinalIgnoreCase) || profile.Path.EndsWith("\\Temp", StringComparison.OrdinalIgnoreCase);

        events.Add(new DiagnosticEvent(
            DateTimeOffset.Now,
            "Windows ProfileList",
            profile.Sid,
            DiagnosticLayer.Rdp,
            DiagnosticSeverity.Informativo,
            "USER_PROFILE_STATE",
            "Perfil de usuario registrado observado.",
            Archivo: profile.Path,
            Evidencia:
            [
                new EvidenceItem("SID", profile.Sid),
                new EvidenceItem("Ruta", profile.Path),
                new EvidenceItem("Carpeta del perfil", FileSystemProbe.Display(pathProbe, "Presente", "Ausente confirmado")),
                new EvidenceItem("NTUSER.DAT", FileSystemProbe.Display(ntUserProbe, "Presente", "Ausente confirmado")),
                new EvidenceItem("Clave .bak", profile.IsBak ? "Sí" : "No"),
                new EvidenceItem("State", profile.State?.ToString() ?? "N/D"),
                new EvidenceItem("RefCount", profile.RefCount?.ToString() ?? "N/D")
            ],
            Producto: TsplusProduct.RemoteAccess));

        if (profile.IsBak)
        {
            findings.Add(new DiagnosticFinding(
                $"USER-PROFILE-BAK-{Sanitize(profile.Sid)}",
                "Windows User Profile",
                DiagnosticSeverity.Advertencia,
                "Se detectó una entrada .bak de perfil de usuario en ProfileList.",
                "Una entrada .bak puede ser evidencia de un problema previo de carga del perfil. Debe correlacionarse con User Profile Service y con el usuario/sesión afectada antes de corregir el Registro.",
                [new EvidenceItem("SID", profile.Sid), new EvidenceItem("Ruta", profile.Path)],
                ConfidenceLevel.Media,
                "Microsoft Learn — Troubleshoot user profiles with events",
                "https://learn.microsoft.com/troubleshoot/windows-server/user-profiles-and-logon/troubleshoot-user-profiles-events",
                "Revise primero los eventos de User Profile Service alrededor del inicio de sesión afectado. TDM no modifica ProfileList.",
                DiagnosticLayer.Windows));
        }

        if (pathProbe.IsAbsent && !string.IsNullOrWhiteSpace(profile.Path))
        {
            findings.Add(new DiagnosticFinding(
                $"USER-PROFILE-PATH-MISSING-{Sanitize(profile.Sid)}",
                "Windows User Profile",
                DiagnosticSeverity.Advertencia,
                "Un perfil registrado apunta a una carpeta que no existe.",
                "La inconsistencia entre ProfileList y la carpeta del perfil puede impedir o degradar la carga de sesión del usuario.",
                [new EvidenceItem("SID", profile.Sid), new EvidenceItem("Ruta registrada", profile.Path)],
                ConfidenceLevel.Alta,
                "Microsoft Learn — Troubleshoot user profiles with events",
                "https://learn.microsoft.com/troubleshoot/windows-server/user-profiles-and-logon/troubleshoot-user-profiles-events",
                "Correlacione el SID con el usuario afectado y los eventos User Profile Service antes de crear, eliminar o renombrar perfiles.",
                DiagnosticLayer.Windows));
        }

        if (pathProbe.IsUnavailable)
        {
            findings.Add(new DiagnosticFinding(
                $"USER-PROFILE-PATH-NOT-EVALUATED-{Sanitize(profile.Sid)}",
                "Windows User Profile",
                DiagnosticSeverity.Advertencia,
                "No fue posible comprobar la carpeta registrada del perfil.",
                "TDM conserva este estado como NO EVALUADO; un error de permisos o E/S nunca se convierte en 'perfil ausente'.",
                [new EvidenceItem("SID", profile.Sid), new EvidenceItem("Ruta registrada", profile.Path), new EvidenceItem("Cobertura", pathProbe.StatusText), new EvidenceItem("Detalle", pathProbe.Detail ?? "N/D")],
                ConfidenceLevel.Confirmada,
                Capa: DiagnosticLayer.Windows));
        }
        else if (pathProbe.IsAvailable && ntUserProbe.IsUnavailable)
        {
            findings.Add(new DiagnosticFinding(
                $"USER-PROFILE-HIVE-NOT-EVALUATED-{Sanitize(profile.Sid)}",
                "Windows User Profile",
                DiagnosticSeverity.Advertencia,
                "No fue posible comprobar NTUSER.DAT del perfil.",
                "La colmena no se reporta como ausente cuando la lectura está bloqueada o falla por E/S.",
                [new EvidenceItem("SID", profile.Sid), new EvidenceItem("Archivo", ntUser), new EvidenceItem("Cobertura", ntUserProbe.StatusText), new EvidenceItem("Detalle", ntUserProbe.Detail ?? "N/D")],
                ConfidenceLevel.Confirmada,
                Capa: DiagnosticLayer.Windows));
        }

        if (temporary)
        {
            findings.Add(new DiagnosticFinding(
                $"USER-PROFILE-TEMP-{Sanitize(profile.Sid)}",
                "Windows User Profile",
                DiagnosticSeverity.Advertencia,
                "TDM detectó indicios de un perfil temporal o de recuperación.",
                "Los perfiles temporales pueden producir escritorios incompletos, pantallas negras/blancas o aplicaciones que no cargan como se espera porque la sesión no usa el entorno normal del usuario.",
                [new EvidenceItem("SID", profile.Sid), new EvidenceItem("Ruta", profile.Path), new EvidenceItem("Clave .bak", profile.IsBak ? "Sí" : "No")],
                ConfidenceLevel.Media,
                "Microsoft Learn — Troubleshoot user profiles with events",
                "https://learn.microsoft.com/troubleshoot/windows-server/user-profiles-and-logon/troubleshoot-user-profiles-events",
                "Confirme el usuario afectado y revise User Profile Service. No elimine perfiles ni claves .bak sin validar la causa y respaldar el perfil.",
                DiagnosticLayer.Windows));
        }
    }

    private static void ReadAuthenticationEvents(
        DiagnosticContext context,
        IReadOnlyList<LocalUserInfo> accounts,
        List<DiagnosticFinding> findings,
        List<DiagnosticEvent> events,
        CancellationToken ct)
    {
        var window = DiagnosticWindow.Resolve(context);
        var start = window.Start;
        var end = window.End;
        var timeClause = DiagnosticWindow.EventLogTimeClause(context);
        var authLimit = ResolveEventLimit(1_000, context.Lookback, 8_000);
        var authEvents = new List<DiagnosticEvent>();
        var status = "Disponible";
        var recordsRead = 0;
        var reachedWindowStart = false;
        var authLimitReached = false;

        try
        {
            var query = new EventLogQuery("Security", PathType.LogName, $"*[System[(EventID=4624 or EventID=4625 or EventID=4740 or EventID=4771 or EventID=4776) and {timeClause}]]")
            {
                ReverseDirection = true,
                TolerateQueryErrors = false
            };
            using var reader = new EventLogReader(query);
            for (var i = 0; i < authLimit; i++)
            {
                ct.ThrowIfCancellationRequested();
                using var record = reader.ReadEvent();
                if (record is null) break;
                recordsRead++;
                if (!record.TimeCreated.HasValue) continue;
                var ts = new DateTimeOffset(record.TimeCreated.Value);
                if (ts > end) continue;
                if (ts < start) { reachedWindowStart = true; break; }

                Dictionary<string, string> data;
                try { data = ParseEventData(record.ToXml()); }
                catch { data = []; }
                data.TryGetValue("LogonType", out var logonType);
                string V(string key) => data.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value) ? value : "N/D";

                if (record.Id == 4740)
                {
                    authEvents.Add(new DiagnosticEvent(
                        ts,
                        "Microsoft-Windows-Security-Auditing",
                        "Cuenta de usuario bloqueada",
                        DiagnosticLayer.Seguridad,
                        DiagnosticSeverity.Advertencia,
                        "ACCOUNT_LOCKOUT",
                        $"Windows registró el bloqueo de la cuenta {V("TargetDomainName")}\\{V("TargetUserName")}. La relevancia para Remote Access se determina correlacionando usuario y hora con el síntoma.",
                        record.Id.ToString(),
                        Evidencia:
                        [
                            new EvidenceItem("Usuario", V("TargetUserName")),
                            new EvidenceItem("Dominio", V("TargetDomainName")),
                            new EvidenceItem("Equipo originador", V("CallerComputerName")),
                            new EvidenceItem("RecordId", record.RecordId?.ToString() ?? "N/D")
                        ],
                        Producto: TsplusProduct.RemoteAccess));
                    continue;
                }

                if (record.Id == 4771)
                {
                    authEvents.Add(new DiagnosticEvent(
                        ts,
                        "Microsoft-Windows-Security-Auditing",
                        "Kerberos / preautenticación",
                        DiagnosticLayer.Seguridad,
                        DiagnosticSeverity.Advertencia,
                        "KERBEROS_PREAUTH_FAILURE",
                        $"Windows registró un fallo de preautenticación Kerberos para {V("TargetUserName")}. No se atribuye automáticamente a TSplus ni a RDP sin correlación temporal y de identidad.",
                        record.Id.ToString(),
                        Evidencia:
                        [
                            new EvidenceItem("Usuario", V("TargetUserName")),
                            new EvidenceItem("IP origen", V("IpAddress")),
                            new EvidenceItem("Código de falla", V("Status") != "N/D" ? V("Status") : V("FailureCode")),
                            new EvidenceItem("Tipo preautenticación", V("PreAuthType")),
                            new EvidenceItem("RecordId", record.RecordId?.ToString() ?? "N/D")
                        ],
                        Producto: TsplusProduct.RemoteAccess));
                    continue;
                }

                if (record.Id == 4776)
                {
                    var validationCode = V("Status") != "N/D" ? V("Status") : V("ErrorCode");
                    if (validationCode.Equals("0x0", StringComparison.OrdinalIgnoreCase) || validationCode == "0")
                        continue; // La validación correcta de credenciales es contexto sano, no incidente.
                    authEvents.Add(new DiagnosticEvent(
                        ts,
                        "Microsoft-Windows-Security-Auditing",
                        "Validación de credenciales Windows",
                        DiagnosticLayer.Seguridad,
                        DiagnosticSeverity.Advertencia,
                        "WINDOWS_CREDENTIAL_VALIDATION_FAILURE",
                        $"Windows rechazó la validación de credenciales para {V("TargetUserName")}. TDM exige correlación de usuario y tiempo con un síntoma RDP/TSplus antes de elevar esta señal como causa.",
                        record.Id.ToString(),
                        Evidencia:
                        [
                            new EvidenceItem("Usuario", V("TargetUserName")),
                            new EvidenceItem("Estación", V("Workstation")),
                            new EvidenceItem("Paquete de autenticación", V("PackageName") != "N/D" ? V("PackageName") : V("AuthenticationPackageName")),
                            new EvidenceItem("Código de error", validationCode),
                            new EvidenceItem("RecordId", record.RecordId?.ToString() ?? "N/D")
                        ],
                        Producto: TsplusProduct.RemoteAccess));
                    continue;
                }

                var failed = record.Id == 4625;
                var passwordState = failed ? PasswordState(V("Status"), V("SubStatus")) : null;
                var remoteInteractive = string.Equals(logonType, "10", StringComparison.OrdinalIgnoreCase);
                // Con NLA, un rechazo de credenciales puede ocurrir antes de crear la sesión RemoteInteractive.
                // Conservamos LogonType 3 únicamente cuando Windows devuelve un estado explícito de contraseña.
                var nlaPasswordPreAuth = failed && passwordState is not null &&
                                         string.Equals(logonType, "3", StringComparison.OrdinalIgnoreCase);
                if (!remoteInteractive && !nlaPasswordPreAuth) continue;

                var eventType = nlaPasswordPreAuth
                    ? "USER_NLA_PASSWORD_FAILURE"
                    : failed ? "USER_LOGON_FAILURE" : "USER_LOGON_SUCCESS";
                var component = nlaPasswordPreAuth ? "Windows NLA / credenciales" : "Windows RemoteInteractive Logon";
                var severity = failed ? DiagnosticSeverity.Advertencia
                    : DiagnosticSeverity.Informativo;
                var message = nlaPasswordPreAuth
                    ? $"Windows rechazó credenciales antes de crear la sesión RDP para {V("TargetDomainName")}\\{V("TargetUserName")} por estado de contraseña: {passwordState}."
                    : failed
                        ? $"Falló un inicio de sesión RemoteInteractive para {V("TargetDomainName")}\\{V("TargetUserName")}."
                        : $"Windows creó un inicio de sesión RemoteInteractive para {V("TargetDomainName")}\\{V("TargetUserName")}";

                authEvents.Add(new DiagnosticEvent(
                    ts,
                    "Microsoft-Windows-Security-Auditing",
                    component,
                    DiagnosticLayer.Rdp,
                    severity,
                    eventType,
                    message,
                    record.Id.ToString(),
                    Evidencia:
                    [
                        new EvidenceItem("Usuario", V("TargetUserName")),
                        new EvidenceItem("Dominio", V("TargetDomainName")),
                        new EvidenceItem("LogonType", V("LogonType")),
                        new EvidenceItem("IP origen", V("IpAddress")),
                        new EvidenceItem("Estación", V("WorkstationName")),
                        new EvidenceItem("Proceso", V("ProcessName")),
                        new EvidenceItem("Paquete de autenticación", V("AuthenticationPackageName")),
                        new EvidenceItem("Motivo", V("FailureReason")),
                        new EvidenceItem("Status", V("Status")),
                        new EvidenceItem("SubStatus", V("SubStatus")),
                        new EvidenceItem("Estado de contraseña", passwordState ?? "N/D"),
                        new EvidenceItem("Preautenticación NLA candidata", nlaPasswordPreAuth ? "Sí" : "No"),
                        new EvidenceItem("RecordId", record.RecordId?.ToString() ?? "N/D")
                    ],
                    Producto: TsplusProduct.RemoteAccess));
            }
            authLimitReached = recordsRead >= authLimit && !reachedWindowStart;
            if (authLimitReached) status = $"Parcial: límite adaptativo de {authLimit} eventos Security alcanzado";
        }
        catch (UnauthorizedAccessException) { status = "Sin permisos de lectura"; }
        catch (EventLogNotFoundException) { status = "No disponible"; }
        // Y1: el genérico enmascaraba una lectura corrupta como "indeterminado"; se declara.
        catch (EventLogException ex) { status = "No legible: " + ex.Message; }
        catch { status = "No determinado"; }

        events.AddRange(authEvents);
        var failures = authEvents.Where(e => e.Tipo == "USER_LOGON_FAILURE").ToList();
        var successes = authEvents.Count(e => e.Tipo == "USER_LOGON_SUCCESS");
        events.Add(new DiagnosticEvent(DateTimeOffset.Now, "TDM", "Auditoría de autenticación remota", DiagnosticLayer.Rdp,
            DiagnosticSeverity.Informativo, "USER_AUTH_AUDIT_COVERAGE",
            "Cobertura de eventos Security para inicios de sesión RemoteInteractive y rechazos de contraseña previos a sesión.",
            Evidencia:
            [
                new EvidenceItem("Security log", status),
                new EvidenceItem("Logons RemoteInteractive exitosos", successes.ToString()),
                new EvidenceItem("Logons RemoteInteractive fallidos", failures.Count.ToString()),
                new EvidenceItem("Rechazos NLA/contraseña pre-sesión", authEvents.Count(e => e.Tipo == "USER_NLA_PASSWORD_FAILURE").ToString()),
                new EvidenceItem("Bloqueos de cuenta (4740)", authEvents.Count(e => e.Tipo == "ACCOUNT_LOCKOUT").ToString()),
                new EvidenceItem("Fallos Kerberos preautenticación (4771)", authEvents.Count(e => e.Tipo == "KERBEROS_PREAUTH_FAILURE").ToString()),
                new EvidenceItem("Fallos de validación de credenciales (4776)", authEvents.Count(e => e.Tipo == "WINDOWS_CREDENTIAL_VALIDATION_FAILURE").ToString()),
                new EvidenceItem("Eventos Security examinados", recordsRead.ToString()),
                new EvidenceItem("Límite de lectura alcanzado", authLimitReached ? "Sí; cobertura parcial" : "No")
            ], Producto: TsplusProduct.RemoteAccess));

        EvaluateNlaPasswordChangeCompatibility(context, authEvents, findings, events);

        foreach (var group in failures.GroupBy(e =>
                     e.Evidencia?.FirstOrDefault(x => x.Clave == "Usuario")?.Valor ?? "N/D",
                     StringComparer.OrdinalIgnoreCase))
        {
            var user = group.Key;
            var account = accounts.FirstOrDefault(a => a.Name.Equals(user, StringComparison.OrdinalIgnoreCase));
            var state = account is null ? "No determinado" :
                account.Disabled ? "Cuenta deshabilitada" :
                account.Locked ? "Cuenta bloqueada" :
                account.PasswordExpired ? "Contraseña expirada" :
                account.AccountExpires.HasValue && account.AccountExpires.Value <= DateTimeOffset.Now ? "Cuenta expirada" :
                "Cuenta local sin bloqueo observado";
            var latest = group.OrderByDescending(e => e.Timestamp).First();
            findings.Add(new DiagnosticFinding(
                $"USER-REMOTE-LOGON-FAILURE-{Sanitize(user)}",
                string.IsNullOrWhiteSpace(user) || user == "N/D" ? "Windows RemoteInteractive Logon" : user,
                DiagnosticSeverity.Advertencia,
                $"Se detectaron {group.Count()} fallos de inicio de sesión RemoteInteractive para '{user}' en la ventana.",
                "La autenticación Windows falló antes de completar la sesión. Si el síntoma de TSplus corresponde al mismo usuario y hora, esta evidencia debe investigarse antes de la carga del perfil o de la aplicación publicada.",
                [
                    new EvidenceItem("Usuario", user),
                    new EvidenceItem("Estado local observado", state),
                    new EvidenceItem("Grupos locales", account is null || account.LocalGroups.Count == 0 ? "N/D" : string.Join(" | ", account.LocalGroups)),
                    new EvidenceItem("Cuenta expira", account?.AccountExpires?.ToLocalTime().ToString("dd/MM/yyyy HH:mm:ss") ?? "No/N.D."),
                    new EvidenceItem("Último intento", latest.Timestamp?.ToLocalTime().ToString("dd/MM/yyyy HH:mm:ss") ?? "N/D"),
                    new EvidenceItem("Motivo", latest.Evidencia?.FirstOrDefault(x => x.Clave == "Motivo")?.Valor ?? "N/D"),
                    new EvidenceItem("Status", latest.Evidencia?.FirstOrDefault(x => x.Clave == "Status")?.Valor ?? "N/D"),
                    new EvidenceItem("SubStatus", latest.Evidencia?.FirstOrDefault(x => x.Clave == "SubStatus")?.Valor ?? "N/D")
                ],
                account is { Disabled: true } or { Locked: true } or { PasswordExpired: true } || (account?.AccountExpires is DateTimeOffset expiry && expiry <= DateTimeOffset.Now) ? ConfidenceLevel.Alta : ConfidenceLevel.Media,
                "Microsoft Learn — Event 4625: An account failed to log on",
                "https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4625",
                "Revise el motivo/status del evento 4625 y el estado de la cuenta. TDM no desbloquea cuentas ni cambia contraseñas/políticas.",
                DiagnosticLayer.Windows));
        }
    }

    private static void EvaluateNlaPasswordChangeCompatibility(
        DiagnosticContext context,
        IReadOnlyList<DiagnosticEvent> authEvents,
        List<DiagnosticFinding> findings,
        List<DiagnosticEvent> events)
    {
        var passwordFailures = authEvents
            .Where(e => e.Tipo is "USER_NLA_PASSWORD_FAILURE" or "USER_LOGON_FAILURE")
            .Where(e => !string.Equals(Evidence(e, "Estado de contraseña"), "N/D", StringComparison.OrdinalIgnoreCase))
            .OrderBy(e => e.Timestamp)
            .ToList();

        var nla = ReadNlaState();
        var server2019 = context.Sistema.SistemaOperativo.Contains("Windows Server 2019", StringComparison.OrdinalIgnoreCase);
        var latest = passwordFailures.LastOrDefault();
        var domainAccount = latest is not null && IsLikelyDomainAccount(Evidence(latest, "Dominio"));

        events.Add(new DiagnosticEvent(
            DateTimeOffset.Now,
            "Windows RDP configuration",
            "NLA / cambio de contraseña",
            DiagnosticLayer.Rdp,
            nla.Evaluated ? DiagnosticSeverity.Informativo : DiagnosticSeverity.Advertencia,
            "WINDOWS_NLA_PASSWORD_COMPAT_STATE",
            nla.Evaluated
                ? "Estado de NLA y evidencia de rechazos por contraseña capturados en modo de solo lectura."
                : "La configuración NLA quedó parcialmente no evaluada; los rechazos de autenticación se conservan sin asumir el estado de la directiva.",
            Evidencia:
            [
                new EvidenceItem("Windows Server 2019", server2019 ? "Sí" : "No"),
                new EvidenceItem("NLA requerido efectivo", !nla.Evaluated ? "No evaluado" : nla.Required ? "Sí" : "No"),
                new EvidenceItem("Policy UserAuthentication", nla.PolicyUserAuthentication?.ToString() ?? (nla.Evaluated ? "No configurada" : "No evaluado")),
                new EvidenceItem("RDP-Tcp UserAuthentication", nla.LocalUserAuthentication?.ToString() ?? (nla.Evaluated ? "No configurada" : "No evaluado")),
                new EvidenceItem("SecurityLayer", nla.SecurityLayer?.ToString() ?? "No determinado"),
                new EvidenceItem("Cobertura", nla.Evaluated ? "Completa" : $"Parcial · {nla.Detail}"),
                new EvidenceItem("Rechazos por contraseña en ventana", passwordFailures.Count.ToString()),
                new EvidenceItem("Cuenta de dominio observada", domainAccount ? "Sí" : "No/No determinado")
            ],
            Producto: TsplusProduct.RemoteAccess));

        if (passwordFailures.Count == 0) return;

        var passwordKind = Evidence(latest!, "Estado de contraseña");
        var severity = nla.Required ? DiagnosticSeverity.Error : DiagnosticSeverity.Advertencia;
        var confidence = server2019 && nla.Required ? ConfidenceLevel.Alta : ConfidenceLevel.Media;
        var id = server2019 && nla.Required
            ? "WINDOWS-2019-NLA-PASSWORD-CHANGE-COMPATIBILITY"
            : "WINDOWS-NLA-PASSWORD-CHANGE-AUTH";
        var summary = server2019 && nla.Required
            ? "Windows Server 2019 con NLA requerido rechazó credenciales por contraseña expirada o cambio obligatorio antes de completar una sesión RDP."
            : "Windows registró un rechazo de autenticación RDP relacionado con contraseña expirada o cambio obligatorio.";

        findings.Add(new DiagnosticFinding(
            id,
            "Windows NLA / Active Directory / contraseña",
            severity,
            summary,
            "NLA autentica al usuario antes de crear la sesión completa. Cuando Windows devuelve STATUS_PASSWORD_EXPIRED o STATUS_PASSWORD_MUST_CHANGE, TDM clasifica el rechazo como originado en la capa de autenticación Windows. En Windows Server 2019 se marca además el patrón de compatibilidad para investigación cuando coincide con NLA y Remote Access; TDM no afirma que toda pantalla negra en Server 2019 tenga esta causa sin la evidencia de autenticación correspondiente.",
            [
                new EvidenceItem("Sistema", $"{context.Sistema.SistemaOperativo} {context.Sistema.Version}"),
                new EvidenceItem("NLA requerido efectivo", !nla.Evaluated ? "No evaluado" : nla.Required ? "Sí" : "No"),
                new EvidenceItem("Estado de contraseña", passwordKind),
                new EvidenceItem("Usuario", Evidence(latest!, "Usuario")),
                new EvidenceItem("Dominio", Evidence(latest!, "Dominio")),
                new EvidenceItem("LogonType", Evidence(latest!, "LogonType")),
                new EvidenceItem("Status", Evidence(latest!, "Status")),
                new EvidenceItem("SubStatus", Evidence(latest!, "SubStatus")),
                new EvidenceItem("Último evento", latest!.Timestamp?.ToLocalTime().ToString("dd/MM/yyyy HH:mm:ss") ?? "N/D"),
                new EvidenceItem("Cuenta de dominio observada", domainAccount ? "Sí" : "No/No determinado"),
                new EvidenceItem("Rol de TSplus", "Víctima / sesión no completada")
            ],
            confidence,
            "TSplus Helpdesk — NLA / cambio de contraseña + Microsoft NTSTATUS",
            "https://support.tsplus.net/support/solutions/articles/44000038556-what-about-network-level-authentication-messages-",
            "Revise la política de cambio/expiración de contraseña, el estado de la cuenta y la configuración NLA/RDP de Windows. No deshabilite NLA como corrección permanente sin evaluar el impacto de seguridad. TDM no cambia contraseñas, NLA ni directivas.",
            DiagnosticLayer.Windows));

        events.Add(new DiagnosticEvent(
            latest!.Timestamp,
            "Windows Security / RDP",
            "NLA / contraseña",
            DiagnosticLayer.Windows,
            severity,
            "WINDOWS_NLA_PASSWORD_CHANGE_CONFLICT",
            summary,
            latest.Codigo,
            Evidencia:
            [
                new EvidenceItem("Originador específico", "Windows NLA / autenticación de credenciales"),
                new EvidenceItem("Estado de contraseña", passwordKind),
                new EvidenceItem("Usuario", Evidence(latest, "Usuario")),
                new EvidenceItem("Dominio", Evidence(latest, "Dominio")),
                new EvidenceItem("Status", Evidence(latest, "Status")),
                new EvidenceItem("SubStatus", Evidence(latest, "SubStatus")),
                new EvidenceItem("TSplus", "Afectado / sesión no completada")
            ],
            Producto: TsplusProduct.RemoteAccess));
    }

    private sealed record NlaState(bool Evaluated, bool Required, int? PolicyUserAuthentication, int? LocalUserAuthentication, int? SecurityLayer, string Detail);

    private static NlaState ReadNlaState()
    {
        var policyProbe = ReadRegistryValues(@"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services", "UserAuthentication");
        var localProbe = ReadRegistryValues(@"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp", "UserAuthentication", "SecurityLayer");
        var policy = policyProbe.IsAvailable ? policyProbe.Value?.GetValueOrDefault("UserAuthentication") : null;
        var local = localProbe.IsAvailable ? localProbe.Value?.GetValueOrDefault("UserAuthentication") : null;
        var securityLayer = localProbe.IsAvailable ? localProbe.Value?.GetValueOrDefault("SecurityLayer") : null;
        var evaluated = policyProbe.IsAvailable && (policy.HasValue || localProbe.IsAvailable);
        var required = evaluated && (policy == 1 || (policy is null && local == 1));
        var detail = evaluated ? "Disponible" : $"Directiva={policyProbe.StatusText}; RDP-Tcp={localProbe.StatusText}";
        return new NlaState(evaluated, required, policy, local, securityLayer, detail);
    }

    private static ProbeResult<Dictionary<string, int?>> ReadRegistryValues(string path, params string[] names)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(path);
            var values = names.ToDictionary(name => name, name => key?.GetValue(name) is int value ? (int?)value : null, StringComparer.OrdinalIgnoreCase);
            return ProbeResult<Dictionary<string, int?>>.Available(values);
        }
        catch (UnauthorizedAccessException ex) { return ProbeResult<Dictionary<string, int?>>.AccessDenied(ex.Message); }
        catch (Exception ex) { return ProbeResult<Dictionary<string, int?>>.Error(ex.Message); }
    }

    private static string? PasswordState(string status, string subStatus)
    {
        foreach (var raw in new[] { status, subStatus })
        {
            var value = raw?.Trim() ?? string.Empty;
            if (value.Equals("0xC0000071", StringComparison.OrdinalIgnoreCase)) return "Contraseña expirada (STATUS_PASSWORD_EXPIRED)";
            if (value.Equals("0xC0000224", StringComparison.OrdinalIgnoreCase)) return "Cambio de contraseña obligatorio (STATUS_PASSWORD_MUST_CHANGE)";
        }
        return null;
    }

    private static string Evidence(DiagnosticEvent e, string key) =>
        e.Evidencia?.FirstOrDefault(x => x.Clave.Equals(key, StringComparison.OrdinalIgnoreCase))?.Valor ?? "N/D";

    private static bool IsLikelyDomainAccount(string domain) =>
        !string.IsNullOrWhiteSpace(domain) &&
        !domain.Equals("N/D", StringComparison.OrdinalIgnoreCase) &&
        !domain.Equals(".", StringComparison.OrdinalIgnoreCase) &&
        !domain.Equals(Environment.MachineName, StringComparison.OrdinalIgnoreCase) &&
        !domain.Equals("NT AUTHORITY", StringComparison.OrdinalIgnoreCase);

    private static bool HasNonAscii(string? value) =>
        !string.IsNullOrEmpty(value) && value.Any(ch => ch > 127);

    private static Dictionary<string, string> ParseEventData(string xml)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var doc = XDocument.Parse(xml, LoadOptions.None);
        XNamespace ns = "http://schemas.microsoft.com/win/2004/08/events/event";
        foreach (var item in doc.Descendants(ns + "Data"))
        {
            var name = item.Attribute("Name")?.Value;
            if (string.IsNullOrWhiteSpace(name)) continue;
            result[name] = item.Value;
        }
        return result;
    }


    private static void ReadAdAndDomainDependencySignals(
        DiagnosticContext context,
        List<DiagnosticFinding> findings,
        List<DiagnosticEvent> events,
        CancellationToken ct)
    {
        var window = DiagnosticWindow.Resolve(context);
        var start = window.Start;
        var end = window.End;
        var timeClause = DiagnosticWindow.EventLogTimeClause(context);
        var securityLimit = ResolveEventLimit(1_000, context.Lookback, 8_000);
        var systemLimit = ResolveEventLimit(1_200, context.Lookback, 9_600);
        var signals = new List<DiagnosticEvent>();

        // Security 4625/4776: sólo se conservan estados que apuntan a disponibilidad/restricción
        // de dominio; no se duplica el tratamiento específico de contraseña expirada/cambio obligatorio.
        try
        {
            var query = new EventLogQuery("Security", PathType.LogName, $"*[System[(EventID=4625 or EventID=4776) and {timeClause}]]")
            {
                ReverseDirection = true,
                TolerateQueryErrors = false
            };
            using var reader = new EventLogReader(query);
            for (var i = 0; i < securityLimit; i++)
            {
                ct.ThrowIfCancellationRequested();
                using var record = reader.ReadEvent();
                if (record is null) break;
                if (!record.TimeCreated.HasValue) continue;
                var ts = new DateTimeOffset(record.TimeCreated.Value);
                if (ts > end) continue;
                if (ts < start) break;

                Dictionary<string, string> data;
                try { data = ParseEventData(record.ToXml()); }
                catch { data = []; }
                string V(string key) => data.TryGetValue(key, out var v) && !string.IsNullOrWhiteSpace(v) ? v.Trim() : "N/D";
                var status = V("Status");
                var subStatus = V("SubStatus");
                var state = DomainAuthenticationState(status, subStatus);
                if (state is null) continue;

                var user = V("TargetUserName");
                var domain = V("TargetDomainName");
                var workstation = record.Id == 4776 ? V("Workstation") : V("WorkstationName");
                signals.Add(new DiagnosticEvent(
                    ts,
                    "Microsoft-Windows-Security-Auditing",
                    "Active Directory / autenticación de dominio",
                    DiagnosticLayer.Windows,
                    DiagnosticSeverity.Error,
                    "WINDOWS_AD_AUTH_DEPENDENCY_FAILURE",
                    $"Windows no pudo completar la autenticación contra la infraestructura de dominio: {state}.",
                    record.Id.ToString(),
                    Evidencia:
                    [
                        new EvidenceItem("Originador específico", "Active Directory / Domain Controller / Netlogon"),
                        new EvidenceItem("Estado", state),
                        new EvidenceItem("Status", status),
                        new EvidenceItem("SubStatus", subStatus),
                        new EvidenceItem("Usuario", user),
                        new EvidenceItem("Dominio", domain),
                        new EvidenceItem("Estación", workstation),
                        new EvidenceItem("EventId", record.Id.ToString()),
                        new EvidenceItem("Rol de TSplus", "Víctima si la sesión Remote Access coincide en usuario/hora")
                    ],
                    Producto: TsplusProduct.RemoteAccess));
            }
        }
        catch (EventLogNotFoundException ex)
        {
            AddEventLogCoverageFinding(findings, "WINDOWS-AD-SECURITY-LOG-COVERAGE", "Security", ex.Message);
        }
        catch (UnauthorizedAccessException ex)
        {
            AddEventLogCoverageFinding(findings, "WINDOWS-AD-SECURITY-LOG-COVERAGE", "Security", ex.Message);
        }
        catch (EventLogException ex)
        {
            // Y1: lectura corrupta a mitad de canal Security/AD.
            AddEventLogCoverageFinding(findings, "WINDOWS-AD-SECURITY-LOG-COVERAGE", "Security", "No legible: " + ex.Message);
        }

        // System: señales explícitas de Netlogon/SPN/TERMSRV o dominio/DC no disponible.
        try
        {
            var query = new EventLogQuery("System", PathType.LogName, $"*[System[(Level=1 or Level=2 or Level=3) and {timeClause}]]")
            {
                ReverseDirection = true,
                TolerateQueryErrors = false
            };
            using var reader = new EventLogReader(query);
            for (var i = 0; i < systemLimit; i++)
            {
                ct.ThrowIfCancellationRequested();
                using var record = reader.ReadEvent();
                if (record is null) break;
                if (!record.TimeCreated.HasValue) continue;
                var ts = new DateTimeOffset(record.TimeCreated.Value);
                if (ts > end) continue;
                if (ts < start) break;
                string message;
                try { message = record.FormatDescription() ?? string.Empty; }
                catch { message = string.Empty; }
                if (string.IsNullOrWhiteSpace(message)) continue;
                var provider = record.ProviderName ?? "System";
                var text = $"{provider} {message}";
                var explicitDomainFailure = ContainsAny(text,
                    "no logon servers", "no hay servidores de inicio de sesión", "domain controller was not found",
                    "controlador de dominio", "domain specified either does not exist or could not be contacted",
                    "el dominio especificado no existe o no se pudo poner en contacto", "NETLOGON");
                var termsrvSpn = text.Contains("TERMSRV", StringComparison.OrdinalIgnoreCase) &&
                                 ContainsAny(text, "service principal name", "nombre de entidad de seguridad de servicio", "SPN");
                if (!explicitDomainFailure && !termsrvSpn) continue;

                var specific = termsrvSpn ? "Active Directory / SPN TERMSRV" : "Active Directory / Domain Controller / Netlogon";
                signals.Add(new DiagnosticEvent(
                    ts,
                    provider,
                    specific,
                    DiagnosticLayer.Windows,
                    DiagnosticSeverity.Advertencia,
                    termsrvSpn ? "WINDOWS_AD_TERMSRV_SPN_FAILURE" : "WINDOWS_AD_DOMAIN_CONNECTIVITY_FAILURE",
                    message,
                    record.Id.ToString(),
                    Evidencia:
                    [
                        new EvidenceItem("Originador específico", specific),
                        new EvidenceItem("Provider", provider),
                        new EvidenceItem("EventId", record.Id.ToString()),
                        new EvidenceItem("TERMSRV/SPN", termsrvSpn ? "Sí" : "No"),
                        new EvidenceItem("Rol de TSplus", "Víctima potencial; requiere correlación con sesión Remote Access")
                    ],
                    Producto: TsplusProduct.RemoteAccess));
            }
        }
        catch (EventLogNotFoundException ex)
        {
            AddEventLogCoverageFinding(findings, "WINDOWS-AD-SYSTEM-LOG-COVERAGE", "System", ex.Message);
        }
        catch (UnauthorizedAccessException ex)
        {
            AddEventLogCoverageFinding(findings, "WINDOWS-AD-SYSTEM-LOG-COVERAGE", "System", ex.Message);
        }

        if (signals.Count == 0) return;
        events.AddRange(signals);
        var latest = signals.OrderByDescending(x => x.Timestamp).First();
        findings.Add(new DiagnosticFinding(
            "WINDOWS-AD-RDP-DEPENDENCY-SIGNALS",
            "Windows / Active Directory / RDP",
            signals.Any(x => x.Tipo == "WINDOWS_AD_AUTH_DEPENDENCY_FAILURE") ? DiagnosticSeverity.Error : DiagnosticSeverity.Advertencia,
            $"Se detectaron {signals.Count} señal(es) de Active Directory/Netlogon/SPN relevantes para autenticación o sesiones RDP.",
            "Estas señales pertenecen a la infraestructura Windows/AD. TDM sólo las eleva a causa raíz cuando preceden y coinciden con el usuario/sesión o síntoma Remote Access; fuera de esa correlación se mantienen como contexto operativo.",
            [
                new EvidenceItem("Señales AD/RDP", signals.Count.ToString()),
                new EvidenceItem("Última señal", latest.Timestamp?.ToLocalTime().ToString("dd/MM/yyyy HH:mm:ss") ?? "N/D"),
                new EvidenceItem("Último tipo", latest.Tipo),
                new EvidenceItem("Originador específico", Evidence(latest, "Originador específico")),
                new EvidenceItem("TSplus", "No se considera originador por la sola presencia de estas señales")
            ],
            ConfidenceLevel.Alta,
            "Microsoft Learn — NTSTATUS / Remote Desktop authentication",
            "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55",
            "Revise conectividad con controladores de dominio, DNS, Netlogon, SPN TERMSRV y el usuario/sesión afectada antes de modificar TSplus.",
            DiagnosticLayer.Windows));
    }

    private static void AddEventLogCoverageFinding(List<DiagnosticFinding> findings, string id, string channel, string detail)
    {
        if (findings.Any(x => x.Id.Equals(id, StringComparison.OrdinalIgnoreCase))) return;
        findings.Add(new DiagnosticFinding(
            id,
            $"Windows Event Log / {channel}",
            DiagnosticSeverity.Advertencia,
            $"No fue posible evaluar por completo el registro {channel} para señales de dominio/RDP.",
            "TDM conserva esta fuente como cobertura parcial. La ausencia de señales correlacionadas no se interpreta como ausencia confirmada de problemas de Active Directory.",
            [new EvidenceItem("Canal", channel), new EvidenceItem("Detalle", detail)],
            ConfidenceLevel.Confirmada,
            Capa: DiagnosticLayer.Windows));
    }

    private static string? DomainAuthenticationState(string status, string subStatus)
    {
        foreach (var raw in new[] { status, subStatus })
        {
            var value = raw?.Trim() ?? string.Empty;
            if (value.Equals("0xC000005E", StringComparison.OrdinalIgnoreCase)) return "No hay servidores de inicio de sesión disponibles (STATUS_NO_LOGON_SERVERS)";
            if (value.Equals("0xC0000233", StringComparison.OrdinalIgnoreCase)) return "No se encontró un controlador de dominio (STATUS_DOMAIN_CONTROLLER_NOT_FOUND)";
        }
        return null;
    }

    private static bool ContainsAny(string value, params string[] terms) =>
        terms.Any(t => value.Contains(t, StringComparison.OrdinalIgnoreCase));

    private static void ReadUserProfileEvents(DiagnosticContext context, List<DiagnosticFinding> findings, List<DiagnosticEvent> events, CancellationToken ct)
    {
        var window = DiagnosticWindow.Resolve(context);
        var from = window.Start;
        var to = window.End;
        var profileEvents = new List<DiagnosticEvent>();

        // Y1: cada canal informa su estado; un EventLogException a mitad de canal ya no
        // pierde todo el collector en silencio (patrón S2 de RdpEventCollector).
        var channelStatus = new List<(string Channel, string Detail)>();
        channelStatus.Add(("Microsoft-Windows-User Profiles Service/Operational",
            ReadChannel("Microsoft-Windows-User Profiles Service/Operational", null, from, to, profileEvents, ct)));
        channelStatus.Add(("Application/User Profiles Service",
            ReadChannel("Application", "Microsoft-Windows-User Profiles Service", from, to, profileEvents, ct)));

        var unreadableProfileChannels = channelStatus.Count(x => !x.Detail.StartsWith("Disponible", StringComparison.OrdinalIgnoreCase));
        if (unreadableProfileChannels > 0)
        {
            events.Add(new DiagnosticEvent(
                DateTimeOffset.Now, "TDM", "Cobertura User Profile Service", DiagnosticLayer.Windows,
                DiagnosticSeverity.Advertencia, "USER_PROFILE_EVENT_COVERAGE",
                $"{unreadableProfileChannels} canal(es) de perfil quedaron no evaluados; la ausencia de eventos no es evidencia de salud.",
                Evidencia:
                [
                    new EvidenceItem("Cobertura", "Parcial"),
                    .. channelStatus.Select(x => new EvidenceItem(x.Channel, x.Detail))
                ],
                Producto: TsplusProduct.RemoteAccess));
        }

        events.AddRange(profileEvents);
        var errors = profileEvents.Where(e => e.Severidad != DiagnosticSeverity.Informativo).ToList();
        if (errors.Count == 0) return;

        var latest = errors.OrderByDescending(e => e.Timestamp).First();
        findings.Add(new DiagnosticFinding(
            "USER-PROFILE-SERVICE-ERRORS",
            "Windows User Profile Service",
            errors.Any(e => e.Severidad == DiagnosticSeverity.Critico)
                ? DiagnosticSeverity.Critico
                : errors.Any(e => e.Severidad == DiagnosticSeverity.Error)
                    ? DiagnosticSeverity.Error
                    : DiagnosticSeverity.Advertencia,
            $"Se detectaron {errors.Count} errores/advertencias de User Profile Service en la ventana analizada.",
            "Estos eventos pueden explicar fallas posteriores a la autenticación: carga incompleta del escritorio, perfil temporal, pantalla negra/blanca o aplicación que no termina de iniciar. Deben correlacionarse por hora y usuario con RDP/HTML5 y logs TSplus.",
            [
                new EvidenceItem("Eventos", errors.Count.ToString()),
                new EvidenceItem("Último evento", latest.Timestamp?.ToLocalTime().ToString("dd/MM/yyyy HH:mm:ss") ?? "N/D"),
                new EvidenceItem("EventId", latest.Codigo ?? "N/D"),
                new EvidenceItem("Fuente", latest.Fuente)
            ],
            ConfidenceLevel.Alta,
            "Microsoft Learn — Troubleshoot user profiles with events",
            "https://learn.microsoft.com/troubleshoot/windows-server/user-profiles-and-logon/troubleshoot-user-profiles-events",
            "Identifique el usuario/SID afectado y revise los eventos inmediatamente anteriores y posteriores al inicio de sesión. Corrija primero la causa del perfil si precede al síntoma TSplus.",
            DiagnosticLayer.Windows));
    }

    private static string ReadChannel(string channel, string? provider, DateTimeOffset from, DateTimeOffset to, List<DiagnosticEvent> output, CancellationToken ct)
    {
        var read = 0;
        try
        {
            var timeClause = $"TimeCreated[@SystemTime >= '{DiagnosticWindow.FormatUtc(from)}' and @SystemTime <= '{DiagnosticWindow.FormatUtc(to)}']";
            var xpath = provider is null
                ? $"*[System[(Level=1 or Level=2 or Level=3) and {timeClause}]]"
                : $"*[System[Provider[@Name='{provider}'] and (Level=1 or Level=2 or Level=3) and {timeClause}]]";
            var query = new EventLogQuery(channel, PathType.LogName, xpath) { ReverseDirection = true, TolerateQueryErrors = false };
            using var reader = new EventLogReader(query);
            var max = ResolveEventLimit(500, to - from, 4_000);
            for (var i = 0; i < max; i++)
            {
                ct.ThrowIfCancellationRequested();
                using var record = reader.ReadEvent();
                if (record is null) break;
                if (!record.TimeCreated.HasValue) continue;
                var ts = new DateTimeOffset(record.TimeCreated.Value);
                if (ts > to) continue;
                if (ts < from) break;
                if (record.Id == 1530) continue; // Microsoft documenta que normalmente puede ignorarse.

                string message;
                try { message = record.FormatDescription() ?? "Evento User Profile Service sin descripción disponible."; }
                catch { message = "No fue posible obtener la descripción del evento User Profile Service."; }

                var evidence = BuildProfileEventEvidence(record, channel, message);
                output.Add(new DiagnosticEvent(
                    ts,
                    record.ProviderName ?? "User Profile Service",
                    "Windows User Profile Service",
                    DiagnosticLayer.Windows,
                    record.Level switch
                    {
                        1 => DiagnosticSeverity.Critico,
                        2 => DiagnosticSeverity.Error,
                        3 => DiagnosticSeverity.Advertencia,
                        _ => DiagnosticSeverity.Informativo
                    },
                    "USER_PROFILE_SERVICE_EVENT",
                    message,
                    record.Id.ToString(),
                    Evidencia: evidence,
                    Producto: TsplusProduct.RemoteAccess));
                read++;
            }
            return $"Disponible; eventos={read}";
        }
        catch (EventLogNotFoundException) { return "Canal no disponible"; }
        catch (UnauthorizedAccessException) { return "Sin permisos de lectura"; }
        catch (EventLogException ex) { return "No legible: " + ex.Message; }
    }


    private static IReadOnlyList<EvidenceItem> BuildProfileEventEvidence(EventRecord record, string channel, string message)
    {
        var evidence = new List<EvidenceItem>
        {
            new("Canal", channel),
            new("Provider", record.ProviderName ?? "N/D"),
            new("RecordId", record.RecordId?.ToString() ?? "N/D")
        };

        string? sid = null;
        string? user = null;
        try
        {
            var doc = XDocument.Parse(record.ToXml(), LoadOptions.None);
            XNamespace ns = "http://schemas.microsoft.com/win/2004/08/events/event";
            foreach (var data in doc.Descendants(ns + "Data"))
            {
                var name = data.Attribute("Name")?.Value ?? string.Empty;
                var value = data.Value?.Trim() ?? string.Empty;
                if (string.IsNullOrWhiteSpace(value)) continue;
                if (sid is null && (name.Contains("Sid", StringComparison.OrdinalIgnoreCase) || value.StartsWith("S-1-5-", StringComparison.OrdinalIgnoreCase)))
                    sid = value;
                if (user is null && (name.Contains("User", StringComparison.OrdinalIgnoreCase) || name.Contains("Account", StringComparison.OrdinalIgnoreCase)) && !value.StartsWith("S-1-5-", StringComparison.OrdinalIgnoreCase))
                    user = value;
            }
        }
        catch { }

        if (sid is null)
        {
            var marker = "S-1-5-";
            var idx = message.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
            if (idx >= 0)
            {
                var end = idx;
                while (end < message.Length && (char.IsDigit(message[end]) || message[end] is 'S' or 's' or '-')) end++;
                if (end > idx) sid = message[idx..end];
            }
        }

        if (!string.IsNullOrWhiteSpace(sid))
        {
            evidence.Add(new EvidenceItem("SID", sid));
            user ??= TryResolveAccountName(sid);
        }
        if (!string.IsNullOrWhiteSpace(user)) evidence.Add(new EvidenceItem("Usuario", user));
        return evidence;
    }

    private static string? TryResolveAccountName(string sid)
    {
        try { return ((NTAccount)new SecurityIdentifier(sid).Translate(typeof(NTAccount))).Value; }
        catch { return null; }
    }

    private static ProbeResult<IReadOnlyList<UserProfileInfo>> ReadProfiles(CancellationToken ct)
    {
        var result = new List<UserProfileInfo>();
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var root = baseKey.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList", false);
            if (root is null) return ProbeResult<IReadOnlyList<UserProfileInfo>>.Available(result);
            foreach (var subName in root.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                using var sub = root.OpenSubKey(subName, false);
                if (sub is null) continue;
                var sid = subName.EndsWith(".bak", StringComparison.OrdinalIgnoreCase) ? subName[..^4] : subName;
                var path = Environment.ExpandEnvironmentVariables(sub.GetValue("ProfileImagePath") as string ?? string.Empty);
                if (string.IsNullOrWhiteSpace(path)) continue;
                result.Add(new UserProfileInfo(sid, path, subName.EndsWith(".bak", StringComparison.OrdinalIgnoreCase), AsInt(sub.GetValue("State")), AsInt(sub.GetValue("RefCount"))));
            }
            return ProbeResult<IReadOnlyList<UserProfileInfo>>.Available(result);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (UnauthorizedAccessException ex) { return ProbeResult<IReadOnlyList<UserProfileInfo>>.AccessDenied(ex.Message); }
        catch (Exception ex) { return ProbeResult<IReadOnlyList<UserProfileInfo>>.Error(ex.Message); }
    }

    private static int? AsInt(object? value) => value switch { int i => i, long l when l <= int.MaxValue => (int)l, _ => null };

    private static ProbeResult<IReadOnlyList<LocalUserInfo>> EnumerateLocalUsers(CancellationToken ct)
    {
        var result = new List<LocalUserInfo>();
        try
        {
            var resume = 0;
            do
            {
                ct.ThrowIfCancellationRequested();
                var status = NetUserEnum(null, 2, 2, out var buffer, -1, out var read, out _, ref resume);
                if (status != 0 && status != 234)
                    return ProbeResult<IReadOnlyList<LocalUserInfo>>.Unavailable($"NetUserEnum devolvió código {status}.");
                try
                {
                    var size = Marshal.SizeOf<USER_INFO_2>();
                    var ptr = buffer;
                    for (var i = 0; i < read; i++)
                    {
                        var ui = Marshal.PtrToStructure<USER_INFO_2>(ptr);
                        var name = ui.usri2_name ?? string.Empty;
                        if (!string.IsNullOrWhiteSpace(name))
                        {
                            var sid = TryResolveSid(Environment.MachineName, name) ?? "N/D";
                            result.Add(new LocalUserInfo(
                                name,
                                ui.usri2_full_name ?? string.Empty,
                                sid,
                                (ui.usri2_flags & 0x0002) != 0,
                                (ui.usri2_flags & 0x0010) != 0,
                                (ui.usri2_flags & 0x800000) != 0,
                                (ui.usri2_flags & 0x10000) != 0,
                                UnixSeconds(ui.usri2_last_logon),
                                AccountExpiry(ui.usri2_acct_expires),
                                ReadLocalGroups(name),
                                ui.usri2_home_dir ?? string.Empty,
                                ui.usri2_script_path ?? string.Empty,
                                ui.usri2_workstations ?? string.Empty));
                        }
                        ptr = IntPtr.Add(ptr, size);
                    }
                }
                finally { if (buffer != IntPtr.Zero) NetApiBufferFree(buffer); }
            } while (resume != 0);
            return ProbeResult<IReadOnlyList<LocalUserInfo>>.Available(result);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (UnauthorizedAccessException ex) { return ProbeResult<IReadOnlyList<LocalUserInfo>>.AccessDenied(ex.Message); }
        catch (Exception ex) { return ProbeResult<IReadOnlyList<LocalUserInfo>>.Error(ex.Message); }
    }

    private static DateTimeOffset? UnixSeconds(uint seconds)
    {
        if (seconds == 0) return null;
        try { return DateTimeOffset.FromUnixTimeSeconds(seconds); }
        catch { return null; }
    }

    private static DateTimeOffset? AccountExpiry(uint seconds)
    {
        if (seconds is 0 or uint.MaxValue) return null;
        try { return DateTimeOffset.FromUnixTimeSeconds(seconds); }
        catch { return null; }
    }

    private static IReadOnlyList<string> ReadLocalGroups(string userName)
    {
        var groups = new List<string>();
        IntPtr buffer = IntPtr.Zero;
        try
        {
            const int LG_INCLUDE_INDIRECT = 0x0001;
            var status = NetUserGetLocalGroups(null, userName, 0, LG_INCLUDE_INDIRECT, out buffer, -1, out var read, out _);
            if (status != 0 || buffer == IntPtr.Zero) return groups;
            var size = Marshal.SizeOf<LOCALGROUP_USERS_INFO_0>();
            var current = buffer;
            for (var i = 0; i < read; i++)
            {
                var info = Marshal.PtrToStructure<LOCALGROUP_USERS_INFO_0>(current);
                if (!string.IsNullOrWhiteSpace(info.lgrui0_name)) groups.Add(info.lgrui0_name);
                current = IntPtr.Add(current, size);
            }
        }
        catch { }
        finally { if (buffer != IntPtr.Zero) NetApiBufferFree(buffer); }
        return groups.Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToList();
    }

    private static ProbeResult<IReadOnlyList<SessionInfo>> EnumerateSessions(CancellationToken ct)
    {
        var result = new List<SessionInfo>();
        if (!WTSEnumerateSessions(IntPtr.Zero, 0, 1, out var buffer, out var count))
            return ProbeResult<IReadOnlyList<SessionInfo>>.Unavailable($"WTSEnumerateSessions falló con código {Marshal.GetLastWin32Error()}.");
        try
        {
            var size = Marshal.SizeOf<WTS_SESSION_INFO>();
            var current = buffer;
            for (var i = 0; i < count; i++)
            {
                ct.ThrowIfCancellationRequested();
                var s = Marshal.PtrToStructure<WTS_SESSION_INFO>(current);
                var user = QueryString(s.SessionID, WTS_INFO_CLASS.WTSUserName);
                var domain = QueryString(s.SessionID, WTS_INFO_CLASS.WTSDomainName);
                var client = QueryString(s.SessionID, WTS_INFO_CLASS.WTSClientName);
                var protocolRaw = QueryUShort(s.SessionID, WTS_INFO_CLASS.WTSClientProtocolType);
                var protocol = protocolRaw switch { 0 => "Console", 2 => "RDP", _ => protocolRaw.HasValue ? $"{protocolRaw}" : "N/D" };
                result.Add(new SessionInfo(s.SessionID, s.State.ToString().Replace("WTS", string.Empty), user, domain, client, protocol));
                current = IntPtr.Add(current, size);
            }
            return ProbeResult<IReadOnlyList<SessionInfo>>.Available(result);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex) { return ProbeResult<IReadOnlyList<SessionInfo>>.Error(ex.Message); }
        finally { WTSFreeMemory(buffer); }
    }

    private static string QueryString(int sessionId, WTS_INFO_CLASS infoClass)
    {
        if (!WTSQuerySessionInformation(IntPtr.Zero, sessionId, infoClass, out var buffer, out _)) return string.Empty;
        try { return Marshal.PtrToStringUni(buffer) ?? string.Empty; }
        finally { WTSFreeMemory(buffer); }
    }

    private static ushort? QueryUShort(int sessionId, WTS_INFO_CLASS infoClass)
    {
        if (!WTSQuerySessionInformation(IntPtr.Zero, sessionId, infoClass, out var buffer, out var bytes) || buffer == IntPtr.Zero || bytes < 2) return null;
        try { return unchecked((ushort)Marshal.ReadInt16(buffer)); }
        finally { WTSFreeMemory(buffer); }
    }

    private static string? TryResolveSid(string? domain, string? user)
    {
        if (string.IsNullOrWhiteSpace(user)) return null;
        try
        {
            var account = string.IsNullOrWhiteSpace(domain) ? user : $"{domain}\\{user}";
            return ((SecurityIdentifier)new NTAccount(account).Translate(typeof(SecurityIdentifier))).Value;
        }
        catch { return null; }
    }

    private static int ResolveEventLimit(int baseLimit, TimeSpan lookback, int hardMax)
    {
        var factor = lookback.TotalHours switch
        {
            <= 4 => 1,
            <= 12 => 2,
            <= 24 => 4,
            _ => 8
        };
        return Math.Min(hardMax, Math.Max(baseLimit, baseLimit * factor));
    }

    private static string Sanitize(string value) => new(value.Where(char.IsLetterOrDigit).Select(char.ToUpperInvariant).Take(28).ToArray());

    private sealed record LocalUserInfo(
        string Name,
        string FullName,
        string Sid,
        bool Disabled,
        bool Locked,
        bool PasswordExpired,
        bool PasswordNeverExpires,
        DateTimeOffset? LastLogon,
        DateTimeOffset? AccountExpires,
        IReadOnlyList<string> LocalGroups,
        string HomeDirectory,
        string LogonScript,
        string Workstations);
    private sealed record UserProfileInfo(string Sid, string Path, bool IsBak, int? State, int? RefCount);
    private sealed record SessionInfo(int SessionId, string State, string UserName, string Domain, string ClientName, string Protocol);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct USER_INFO_2
    {
        [MarshalAs(UnmanagedType.LPWStr)] public string? usri2_name;
        [MarshalAs(UnmanagedType.LPWStr)] public string? usri2_password;
        public uint usri2_password_age;
        public uint usri2_priv;
        [MarshalAs(UnmanagedType.LPWStr)] public string? usri2_home_dir;
        [MarshalAs(UnmanagedType.LPWStr)] public string? usri2_comment;
        public uint usri2_flags;
        [MarshalAs(UnmanagedType.LPWStr)] public string? usri2_script_path;
        public uint usri2_auth_flags;
        [MarshalAs(UnmanagedType.LPWStr)] public string? usri2_full_name;
        [MarshalAs(UnmanagedType.LPWStr)] public string? usri2_usr_comment;
        [MarshalAs(UnmanagedType.LPWStr)] public string? usri2_parms;
        [MarshalAs(UnmanagedType.LPWStr)] public string? usri2_workstations;
        public uint usri2_last_logon;
        public uint usri2_last_logoff;
        public uint usri2_acct_expires;
        public uint usri2_max_storage;
        public uint usri2_units_per_week;
        public IntPtr usri2_logon_hours;
        public uint usri2_bad_pw_count;
        public uint usri2_num_logons;
        [MarshalAs(UnmanagedType.LPWStr)] public string? usri2_logon_server;
        public uint usri2_country_code;
        public uint usri2_code_page;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct LOCALGROUP_USERS_INFO_0
    {
        [MarshalAs(UnmanagedType.LPWStr)] public string? lgrui0_name;
    }

    [DllImport("Netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int NetUserEnum(string? servername, int level, int filter, out IntPtr bufptr, int prefmaxlen, out int entriesread, out int totalentries, ref int resume_handle);

    [DllImport("Netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int NetUserGetLocalGroups(string? servername, string username, int level, int flags, out IntPtr bufptr, int prefmaxlen, out int entriesread, out int totalentries);

    [DllImport("Netapi32.dll")]
    private static extern int NetApiBufferFree(IntPtr buffer);

    private enum WTS_CONNECTSTATE_CLASS { WTSActive, WTSConnected, WTSConnectQuery, WTSShadow, WTSDisconnected, WTSIdle, WTSListen, WTSReset, WTSDown, WTSInit }
    private enum WTS_INFO_CLASS { WTSInitialProgram, WTSApplicationName, WTSWorkingDirectory, WTSOEMId, WTSSessionId, WTSUserName, WTSWinStationName, WTSDomainName, WTSConnectState, WTSClientBuildNumber, WTSClientName, WTSClientDirectory, WTSClientProductId, WTSClientHardwareId, WTSClientAddress, WTSClientDisplay, WTSClientProtocolType }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WTS_SESSION_INFO
    {
        public int SessionID;
        [MarshalAs(UnmanagedType.LPWStr)] public string? pWinStationName;
        public WTS_CONNECTSTATE_CLASS State;
    }

    [DllImport("Wtsapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool WTSEnumerateSessions(IntPtr hServer, int reserved, int version, out IntPtr ppSessionInfo, out int pCount);

    [DllImport("Wtsapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool WTSQuerySessionInformation(IntPtr hServer, int sessionId, WTS_INFO_CLASS wtsInfoClass, out IntPtr ppBuffer, out int pBytesReturned);

    [DllImport("Wtsapi32.dll")]
    private static extern void WTSFreeMemory(IntPtr pointer);
}
