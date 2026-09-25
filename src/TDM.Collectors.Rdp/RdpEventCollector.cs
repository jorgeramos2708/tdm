using System.Diagnostics.Eventing.Reader;
using System.Xml.Linq;
using TDM.Core;
using TDM.Models;

namespace TDM.Collectors.Rdp;

public sealed class RdpEventCollector : IReadOnlyCollector
{
    public string Nombre => "RDP Event Logs";

    private static readonly string[] Channels =
    [
        "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
        "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
        "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational"
    ];

    public Task<CollectorResult> CollectAsync(DiagnosticContext context, CancellationToken cancellationToken)
    {
        var events = new List<DiagnosticEvent>();
        var findings = new List<DiagnosticFinding>();
        var start = ResolveStart(context);
        var end = ResolveEnd(context);

        // S2: cada canal informa su estado; antes los catch vacíos hacían invisible la pérdida RDP.
        var channelStatus = new List<(string Channel, string Detail)>();
        foreach (var channel in Channels)
            channelStatus.Add((channel, ReadChannel(channel, start, end, events, cancellationToken)));

        EvaluateSessionPipeline(events, findings, end);

        var unavailableChannels = channelStatus.Count(x => !x.Detail.StartsWith("Disponible", StringComparison.OrdinalIgnoreCase));
        events.Add(new DiagnosticEvent(
            DateTimeOffset.Now,
            "TDM",
            "Cobertura RDP / Terminal Services",
            DiagnosticLayer.Rdp,
            unavailableChannels > 0 ? DiagnosticSeverity.Advertencia : DiagnosticSeverity.Informativo,
            "RDP_EVENT_COVERAGE",
            unavailableChannels > 0
                ? $"{unavailableChannels} canal(es) RDP quedaron no evaluados; la ausencia de eventos no es evidencia de salud."
                : "Canales RDP de Terminal Services evaluados dentro de la ventana solicitada.",
            Evidencia:
            [
                new EvidenceItem("Cobertura", unavailableChannels > 0 ? "Parcial" : "Disponible"),
                .. channelStatus.Select(x => new EvidenceItem(x.Channel, x.Detail))
            ]));

        var failures = events.Where(e => e.Severidad is DiagnosticSeverity.Error or DiagnosticSeverity.Critico).ToList();
        if (context.Sistema.TsplusDetectado && failures.Count > 0)
        {
            var findingSeverity = failures.Any(e => e.Severidad == DiagnosticSeverity.Critico)
                ? DiagnosticSeverity.Critico
                : DiagnosticSeverity.Error;
            findings.Add(new DiagnosticFinding(
                "RDP-EVENTS-FAILURE",
                "Remote Desktop Services",
                findingSeverity,
                $"Se detectaron {failures.Count} eventos de error/críticos de RDP en la ventana analizada.",
                "Los eventos de Terminal Services pueden explicar fallas de conexión o creación de sesión antes de que TSplus reporte el síntoma.",
                [
                    new EvidenceItem("Eventos de error/críticos", failures.Count.ToString()),
                    new EvidenceItem("Primer evento", failures.Min(x => x.Timestamp)?.ToLocalTime().ToString("dd/MM/yyyy HH:mm:ss") ?? "N/D"),
                    new EvidenceItem("Último evento", failures.Max(x => x.Timestamp)?.ToLocalTime().ToString("dd/MM/yyyy HH:mm:ss") ?? "N/D")
                ],
                ConfidenceLevel.Media,
                "Microsoft Learn",
                "https://learn.microsoft.com/troubleshoot/windows-server/remote/rdp-error-general-troubleshooting",
                "Revisar primero los eventos de Remote Desktop Services y validar el listener RDP antes de modificar TSplus.",
                DiagnosticLayer.Rdp));
        }

        return Task.FromResult(new CollectorResult(findings, events));
    }


    private static void EvaluateSessionPipeline(List<DiagnosticEvent> events, List<DiagnosticFinding> findings, DateTimeOffset analysisEnd)
    {
        var logons = events
            .Where(e => e.Tipo == "RDP_SESSION_LOGON_STAGE" && e.Timestamp.HasValue)
            .OrderBy(e => e.Timestamp)
            .ToList();
        var shells = events
            .Where(e => e.Tipo == "RDP_SHELL_START_STAGE" && e.Timestamp.HasValue)
            .OrderBy(e => e.Timestamp)
            .ToList();
        var endings = events
            .Where(e => e.Tipo is "RDP_SESSION_LOGOFF_STAGE" or "RDP_SESSION_DISCONNECT_STAGE")
            .Where(e => e.Timestamp.HasValue)
            .OrderBy(e => e.Timestamp)
            .ToList();

        var missing = new List<(DiagnosticEvent Logon, string Identity)>();
        var delayed = new List<(DiagnosticEvent Logon, DiagnosticEvent Shell, TimeSpan Delay, string Identity)>();

        foreach (var logon in logons)
        {
            var identity = SessionIdentity(logon);
            var shell = shells.FirstOrDefault(s => IsSameSession(logon, s) &&
                                                   s.Timestamp!.Value >= logon.Timestamp!.Value &&
                                                   s.Timestamp.Value - logon.Timestamp.Value <= TimeSpan.FromMinutes(3));
            if (shell is not null)
            {
                var delay = shell.Timestamp!.Value - logon.Timestamp!.Value;
                if (delay >= TimeSpan.FromSeconds(45)) delayed.Add((logon, shell, delay, identity));
                continue;
            }

            // Un logoff/desconexión inmediata puede corresponder a una sesión cancelada y no a pantalla negra.
            var endedQuickly = endings.Any(e => IsSameSession(logon, e) &&
                                                e.Timestamp!.Value >= logon.Timestamp!.Value &&
                                                e.Timestamp.Value - logon.Timestamp.Value <= TimeSpan.FromSeconds(45));
            if (endedQuickly) continue;

            // No declarar un gap antes de que realmente venza el SLA de tres minutos.
            // Durante ese intervalo la sesión permanece pendiente, no degradada.
            if (analysisEnd < logon.Timestamp!.Value + TimeSpan.FromMinutes(3)) continue;
            missing.Add((logon, identity));
        }

        events.Add(new DiagnosticEvent(
            DateTimeOffset.Now,
            "TDM",
            "RDP / creación de sesión y shell",
            DiagnosticLayer.Rdp,
            DiagnosticSeverity.Informativo,
            "RDP_SESSION_PIPELINE_STATE",
            "TDM correlacionó logon de sesión y notificación de inicio de shell para detectar sesiones que quedan autenticadas sin completar el escritorio.",
            Evidencia:
            [
                new EvidenceItem("Logons de sesión observados", logons.Count.ToString()),
                new EvidenceItem("Shell starts observados", shells.Count.ToString()),
                new EvidenceItem("Shell start ausente >3 min", missing.Count.ToString()),
                new EvidenceItem("Shell start demorado >=45 s", delayed.Count.ToString()),
                new EvidenceItem("Interpretación", "Ausencia/demora es señal de pipeline de sesión; no se etiqueta automáticamente como pantalla negra sin correlación adicional")
            ],
            Producto: TsplusProduct.RemoteAccess));

        foreach (var item in missing.Take(12))
        {
            var ev = new DiagnosticEvent(
                item.Logon.Timestamp,
                "TDM",
                "Windows RDS / shell de sesión",
                DiagnosticLayer.Rdp,
                DiagnosticSeverity.Advertencia,
                "RDP_SHELL_START_GAP",
                "Windows registró un logon de sesión RDP, pero TDM no encontró la notificación de inicio de shell de la misma sesión dentro de los 3 minutos siguientes.",
                item.Logon.Codigo,
                Evidencia:
                [
                    new EvidenceItem("Identidad/sesión", item.Identity),
                    new EvidenceItem("Hora de logon", item.Logon.Timestamp?.ToLocalTime().ToString("dd/MM/yyyy HH:mm:ss") ?? "N/D"),
                    new EvidenceItem("Shell start <=3 min", "No observado"),
                    new EvidenceItem("Originador específico", "Windows RDS / pipeline de sesión y shell"),
                    new EvidenceItem("Síntoma compatible", "Sesión conectada sin escritorio/aplicación visible, incluida pantalla negra; requiere correlación")
                ],
                Producto: TsplusProduct.RemoteAccess);
            events.Add(ev);
        }

        foreach (var item in delayed.Take(12))
        {
            events.Add(new DiagnosticEvent(
                item.Logon.Timestamp,
                "TDM",
                "Windows RDS / shell de sesión",
                DiagnosticLayer.Rdp,
                DiagnosticSeverity.Advertencia,
                "RDP_SHELL_START_DELAY",
                $"El inicio del shell de la sesión RDP se demoró {item.Delay.TotalSeconds:F0} segundos después del logon.",
                item.Logon.Codigo,
                Evidencia:
                [
                    new EvidenceItem("Identidad/sesión", item.Identity),
                    new EvidenceItem("Demora de shell", item.Delay.ToString()),
                    new EvidenceItem("Originador específico", "Windows RDS / pipeline de sesión y shell"),
                    new EvidenceItem("Síntoma compatible", "Espera prolongada o pantalla negra durante inicialización de sesión")
                ],
                Producto: TsplusProduct.RemoteAccess));
        }

        if (missing.Count > 0 || delayed.Count > 0)
        {
            findings.Add(new DiagnosticFinding(
                "WINDOWS-RDP-SHELL-PIPELINE-DEGRADED",
                "Windows RDS / creación de sesión y shell",
                DiagnosticSeverity.Advertencia,
                missing.Count > 0
                    ? $"Se detectaron {missing.Count} sesión(es) RDP con logon registrado pero sin shell start observado dentro de 3 minutos."
                    : $"Se detectaron {delayed.Count} sesión(es) con inicio de shell demorado.",
                "Este patrón sitúa el problema después de la autenticación y antes/durante la creación del escritorio o shell. Es compatible con pantalla negra, perfil incompleto, Winlogon/Userinit o dependencias de sesión. TDM debe correlacionarlo con User Profile Service, NLA/AD y logs TSplus antes de declarar la causa primaria.",
                [
                    new EvidenceItem("Shell start ausente", missing.Count.ToString()),
                    new EvidenceItem("Shell start demorado", delayed.Count.ToString()),
                    new EvidenceItem("Ejemplos", string.Join(" | ", missing.Select(x => x.Identity).Concat(delayed.Select(x => x.Identity)).Distinct(StringComparer.OrdinalIgnoreCase).Take(8))),
                    new EvidenceItem("Rol potencial de TSplus", "Víctima si la falla se origina en el pipeline Windows/RDS")
                ],
                missing.Count > 0 ? ConfidenceLevel.Alta : ConfidenceLevel.Media,
                "Microsoft Learn — Remote Desktop Services troubleshooting",
                "https://learn.microsoft.com/troubleshoot/windows-server/remote/rdp-error-general-troubleshooting",
                "Correlacione Event ID 21/22, User Profile Service, Winlogon/Userinit y el usuario/sesión afectada. No reinicie servicios ni elimine perfiles sólo por esta señal.",
                DiagnosticLayer.Windows));
        }
    }

    private static bool IsSameSession(DiagnosticEvent left, DiagnosticEvent right)
    {
        static string E(DiagnosticEvent e, string key) => e.Evidencia?.FirstOrDefault(x => x.Clave.Equals(key, StringComparison.OrdinalIgnoreCase))?.Valor ?? string.Empty;
        var leftSession = E(left, "SessionId");
        var rightSession = E(right, "SessionId");
        if (!string.IsNullOrWhiteSpace(leftSession) && !string.IsNullOrWhiteSpace(rightSession))
            return leftSession.Equals(rightSession, StringComparison.OrdinalIgnoreCase);

        var leftUser = E(left, "Usuario");
        var rightUser = E(right, "Usuario");
        var leftDomain = E(left, "Dominio");
        var rightDomain = E(right, "Dominio");
        return !string.IsNullOrWhiteSpace(leftUser) && !string.IsNullOrWhiteSpace(rightUser) &&
               leftUser.Equals(rightUser, StringComparison.OrdinalIgnoreCase) &&
               (string.IsNullOrWhiteSpace(leftDomain) || string.IsNullOrWhiteSpace(rightDomain) || leftDomain.Equals(rightDomain, StringComparison.OrdinalIgnoreCase));
    }

    private static string SessionIdentity(DiagnosticEvent e)
    {
        string E(string key) => e.Evidencia?.FirstOrDefault(x => x.Clave.Equals(key, StringComparison.OrdinalIgnoreCase))?.Valor ?? string.Empty;
        var sid = E("SessionId");
        var user = E("Usuario");
        var domain = E("Dominio");
        var identity = !string.IsNullOrWhiteSpace(user)
            ? (string.IsNullOrWhiteSpace(domain) ? user : $"{domain}\\{user}")
            : "Usuario no determinado";
        return string.IsNullOrWhiteSpace(sid) ? identity : $"{identity} / SessionId={sid}";
    }

    private static string ReadChannel(
        string channel,
        DateTimeOffset start,
        DateTimeOffset end,
        List<DiagnosticEvent> output,
        CancellationToken ct)
    {
        try
        {
            var timeClause = $"TimeCreated[@SystemTime >= '{DiagnosticWindow.FormatUtc(start)}' and @SystemTime <= '{DiagnosticWindow.FormatUtc(end)}']";
            var query = new EventLogQuery(channel, PathType.LogName,
                $"*[System[(Level=1 or Level=2 or Level=3 or EventID=1149 or EventID=21 or EventID=22 or EventID=23 or EventID=24 or EventID=25) and {timeClause}]]")
            {
                ReverseDirection = true,
                TolerateQueryErrors = false
            };

            using var reader = new EventLogReader(query);
            var lookback = end - start;
            var max = lookback.TotalHours switch
            {
                <= 4 => 1_000,
                <= 12 => 2_000,
                <= 24 => 4_000,
                _ => 8_000
            };
            var read = 0;
            for (var i = 0; i < max; i++)
            {
                ct.ThrowIfCancellationRequested();
                using var record = reader.ReadEvent();
                if (record is null) break;
                if (!record.TimeCreated.HasValue) continue;

                var timestamp = new DateTimeOffset(record.TimeCreated.Value);
                if (timestamp > end) continue;
                if (timestamp < start) break;

                string message;
                try { message = record.FormatDescription() ?? "Evento sin descripción disponible."; }
                catch { message = "No fue posible obtener la descripción del evento."; }

                var severity = ClassifySeverity(channel, record.Id, record.Level, message);

                output.Add(new DiagnosticEvent(
                    timestamp,
                    channel,
                    "Remote Desktop Services",
                    DiagnosticLayer.Rdp,
                    severity,
                    ClassifyType(channel, record.Id),
                    message,
                    record.Id.ToString(),
                    Evidencia: BuildEvidence(record),
                    Producto: TsplusProduct.RemoteAccess));
                read++;
            }
            return $"Disponible; eventos={read}";
        }
        catch (EventLogNotFoundException)
        {
            // Algunos canales no existen o no están habilitados según versión/rol de Windows.
            return "Canal no disponible";
        }
        catch (UnauthorizedAccessException)
        {
            // No se modifica seguridad para obtener acceso; se declara en vez de silenciarse.
            return "Sin permisos de lectura";
        }
        catch (EventLogException ex)
        {
            // V5: una query corrupta o un fallo a mitad de lectura no debe tumbar el canal en
            // silencio (antes el engine lo volvía COLLECTOR-ERROR y se perdía hasta la cobertura).
            return "No legible: " + ex.Message;
        }
    }


    private static IReadOnlyList<EvidenceItem> BuildEvidence(EventRecord record)
    {
        var evidence = new List<EvidenceItem>
        {
            new("Provider", record.ProviderName ?? "N/D"),
            new("RecordId", record.RecordId?.ToString() ?? "N/D")
        };

        try
        {
            var doc = XDocument.Parse(record.ToXml(), LoadOptions.None);
            XNamespace ns = "http://schemas.microsoft.com/win/2004/08/events/event";
            var eventData = doc.Descendants(ns + "Data")
                .Select(x => new
                {
                    Name = x.Attribute("Name")?.Value ?? string.Empty,
                    Value = x.Value?.Trim() ?? string.Empty
                })
                .Where(x => !string.IsNullOrWhiteSpace(x.Value))
                .ToList();

            string? Named(params string[] names) => eventData
                .FirstOrDefault(x => names.Any(n => x.Name.Equals(n, StringComparison.OrdinalIgnoreCase)))?.Value;

            var user = Named("User", "UserName", "Username", "TargetUserName");
            var domain = Named("Domain", "DomainName", "TargetDomainName");
            var session = Named("SessionID", "SessionId", "Session");
            var address = Named("Address", "IpAddress", "ClientAddress");

            // RemoteConnectionManager/1149 suele publicar Param1/Param2/Param3.
            if (record.Id == 1149)
            {
                user ??= Named("Param1");
                domain ??= Named("Param2");
                address ??= Named("Param3");
            }

            foreach (var element in doc.Descendants())
            {
                var name = element.Name.LocalName;
                var value = element.Value?.Trim();
                if (string.IsNullOrWhiteSpace(value)) continue;
                if (user is null && name.Equals("User", StringComparison.OrdinalIgnoreCase)) user = value;
                if (domain is null && name.Contains("Domain", StringComparison.OrdinalIgnoreCase)) domain = value;
                if (session is null && name.Contains("SessionID", StringComparison.OrdinalIgnoreCase)) session = value;
                if (address is null && (name.Equals("Address", StringComparison.OrdinalIgnoreCase) || name.Contains("ClientAddress", StringComparison.OrdinalIgnoreCase))) address = value;
            }

            if (!string.IsNullOrWhiteSpace(user)) evidence.Add(new EvidenceItem("Usuario", user));
            if (!string.IsNullOrWhiteSpace(domain)) evidence.Add(new EvidenceItem("Dominio", domain));
            if (!string.IsNullOrWhiteSpace(session)) evidence.Add(new EvidenceItem("SessionId", session));
            if (!string.IsNullOrWhiteSpace(address)) evidence.Add(new EvidenceItem("IP/Cliente", address));
        }
        catch { }

        return evidence;
    }

    private static string ClassifyType(string channel, int eventId) => eventId switch
    {
        1149 => "RDP_AUTHENTICATION_STAGE",
        21 => "RDP_SESSION_LOGON_STAGE",
        22 => "RDP_SHELL_START_STAGE",
        23 => "RDP_SESSION_LOGOFF_STAGE",
        24 => "RDP_SESSION_DISCONNECT_STAGE",
        25 => "RDP_SESSION_RECONNECT_STAGE",
        _ => $"Event ID {eventId}"
    };

    private static DiagnosticSeverity ClassifySeverity(string channel, int eventId, byte? level, string message)
    {
        // Event ID 36 con ERROR_INVALID_STATE (0x8007139F) puede aparecer durante
        // transiciones DesktopLocked/Unlocked. Por sí solo no demuestra una caída RDP.
        if (eventId == 36 && message.Contains("0x8007139F", StringComparison.OrdinalIgnoreCase))
            return DiagnosticSeverity.Informativo;
        if (eventId is 1149 or 21 or 22 or 23 or 24 or 25)
            return DiagnosticSeverity.Informativo;

        return level switch
        {
            1 => DiagnosticSeverity.Critico,
            2 => DiagnosticSeverity.Error,
            3 => DiagnosticSeverity.Advertencia,
            _ => DiagnosticSeverity.Informativo
        };
    }

    private static DateTimeOffset ResolveStart(DiagnosticContext c) => DiagnosticWindow.Resolve(c).Start;

    private static DateTimeOffset ResolveEnd(DiagnosticContext c) => DiagnosticWindow.Resolve(c).End;
}
