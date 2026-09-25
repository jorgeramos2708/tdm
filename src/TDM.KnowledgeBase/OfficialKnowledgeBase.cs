using TDM.Models;

namespace TDM.KnowledgeBase;

public sealed record OfficialGuidance(
    string Id,
    string Vendor,
    string Titulo,
    string SolucionSugerida,
    string Url,
    string Alcance);

public static class OfficialKnowledgeBase
{
    private static readonly IReadOnlyDictionary<string, OfficialGuidance> Entries =
        new Dictionary<string, OfficialGuidance>(StringComparer.OrdinalIgnoreCase)
        {
            ["MS-RDP-TERMSERVICE"] = new(
                "MS-RDP-TERMSERVICE",
                "Microsoft",
                "Remote Desktop no puede conectarse al equipo remoto",
                "Verifica el estado de Remote Desktop Services (TermService) y Remote Desktop Services UserMode Port Redirector (UmRdpService), así como la configuración del listener RDP-Tcp. TDM solo muestra la recomendación; no inicia ni reinicia servicios.",
                "https://learn.microsoft.com/en-us/troubleshoot/windows-server/remote/remote-desktop-cannot-connect-remote-computer",
                "Windows Server / RDP"),

            ["MS-RDP-LISTENER"] = new(
                "MS-RDP-LISTENER",
                "Microsoft",
                "Solución de problemas de desconexiones de Escritorio remoto",
                "Comprueba que el listener RDP-Tcp esté en estado Listen y que el puerto configurado esté realmente escuchando. Microsoft recomienda validar el listener con herramientas como qwinsta/netstat y revisar conflictos de puerto antes de modificar otras capas.",
                "https://learn.microsoft.com/en-us/troubleshoot/windows-server/remote/troubleshoot-remote-desktop-disconnected-errors",
                "Windows Server / RDP Listener"),

            ["MS-SCHANNEL"] = new(
                "MS-SCHANNEL",
                "Microsoft",
                "Registro de eventos Schannel",
                "Revisa los eventos Schannel y la configuración/certificados TLS relacionados con el momento del incidente. La presencia de un evento Schannel cercano a una falla TSplus es evidencia correlativa, no confirmación por sí sola.",
                "https://learn.microsoft.com/en-us/troubleshoot/developer/webapps/iis/health-diagnostic-performance/enable-schannel-event-logging",
                "Windows / TLS / Schannel"),

            ["TSPLUS-LOGS"] = new(
                "TSPLUS-LOGS",
                "TSplus",
                "Advanced Features - Logs",
                "Revisa los logs de apertura de sesión, control de sesión, portal web, balanceo y AdminTool que ya estén habilitados. Si faltan logs, TDM debe reportar cobertura incompleta en vez de asumir que no hubo errores.",
                "https://docs.tsplus.net/tsplus/advanced-features-logs/",
                "TSplus Remote Access"),

            ["TSPLUS-ANTIVIRUS"] = new(
                "TSPLUS-ANTIVIRUS",
                "TSplus",
                "TSplus Remote Access Antivirus / Firewall Exclusions",
                "Si la evidencia muestra archivos de TSplus bloqueados, eliminados o puestos en cuarentena, revisa el historial del antivirus/EDR y las exclusiones recomendadas por TSplus. TDM no crea exclusiones ni restaura archivos.",
                "https://support.tsplus.net/support/solutions/articles/44002467672-tsplus-remote-access-antivirus-firewall-exclusions",
                "TSplus Remote Access / Seguridad"),


            ["MS-DEFENDER-EVENTS"] = new(
                "MS-DEFENDER-EVENTS",
                "Microsoft",
                "Microsoft Defender Antivirus event IDs and error codes",
                "Revisa los eventos 1116 (detección) y 1117 (acción) del canal operacional de Microsoft Defender para determinar qué recurso fue detectado y qué acción se aplicó. TDM solo lee esta evidencia y no restaura, permite ni pone archivos en cuarentena.",
                "https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus",
                "Windows / Microsoft Defender"),

            ["TSPLUS-DEFENDER-FILE"] = new(
                "TSPLUS-DEFENDER-FILE",
                "TSplus",
                "Black screen and impossible to login - error on logonsession.exe",
                "Si Defender/antivirus bloqueó o removió logonsession.exe u otro componente TSplus, revisa el historial del producto de seguridad y las exclusiones oficiales de TSplus. La corrección debe realizarse manualmente conforme a la política del cliente; TDM no restaura archivos ni crea exclusiones.",
                "https://support.tsplus.net/support/solutions/articles/44002222051-black-screen-and-impossible-to-login-error-on-logonsession-exe",
                "TSplus Remote Access / Seguridad / Inicio de sesión"),

            ["MS-APP-CRASH"] = new(
                "MS-APP-CRASH",
                "Microsoft",
                "The application or service crashing behavior troubleshooting guidance",
                "Microsoft recomienda correlacionar Application Error 1000 con Windows Error Reporting 1001 para confirmar el proceso que se bloquea y revisar aplicación, módulo y código de excepción. El módulo con error indica dónde se manifestó el fallo, pero puede requerirse un dump para determinar la causa exacta. TDM no habilita LocalDumps, no modifica WER y no instala herramientas de depuración.",
                "https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-application-service-crashing-behavior",
                "Windows Server y Windows Client / Application Error / WER"),

            ["MS-DOTNET-FILELOAD"] = new(
                "MS-DOTNET-FILELOAD",
                "Microsoft",
                "FileLoadException / FileNotFoundException",
                "Valida que el archivo o ensamblado señalado exista, sea una dependencia válida y pueda cargarse. Microsoft distingue entre FileNotFoundException (archivo no localizado) y FileLoadException (archivo localizado pero no cargable). TDM no copia, registra ni reemplaza DLL/ensamblados.",
                "https://learn.microsoft.com/en-us/dotnet/api/system.io.fileloadexception",
                ".NET / carga de ensamblados"),

            ["MS-SIDEBYSIDE"] = new(
                "MS-SIDEBYSIDE",
                "Microsoft",
                "Side-by-side assemblies",
                "Revisa la dependencia Side-by-Side indicada por Windows y valida que el runtime/ensamblado requerido corresponda con la aplicación afectada. TDM conserva el evento como evidencia y no instala ni repara runtimes automáticamente.",
                "https://learn.microsoft.com/en-us/windows/win32/sbscs/installing-side-by-side-assemblies",
                "Windows / Side-by-Side assemblies"),

            ["MS-PRINT-SPOOLER"] = new(
                "MS-PRINT-SPOOLER",
                "Microsoft",
                "Printing issues caused by Print Spooler service not running",
                "Si Spooler no está operativo, investiga primero el servicio, PrintService, controladores, estabilidad del sistema y posibles interferencias de seguridad. TDM no reinicia Spooler ni elimina trabajos de impresión.",
                "https://learn.microsoft.com/en-us/troubleshoot/windows-server/printing/print-spooler-service-not-running",
                "Windows Server / Printing"),

            ["TSPLUS-UNIVERSAL-PRINTER"] = new(
                "TSPLUS-UNIVERSAL-PRINTER",
                "TSplus",
                "Universal Printer (novaPDF)",
                "Valida que Universal Printer esté instalado/configurado y correlaciona cualquier falla con la pila de impresión de Windows antes de reinstalar componentes TSplus.",
                "https://docs.tsplus.net/tsplus/universal-printer/",
                "TSplus Remote Access / Universal Printer"),

            ["TSPLUS-VIRTUAL-PRINTER"] = new(
                "TSPLUS-VIRTUAL-PRINTER",
                "TSplus",
                "Virtual Printer",
                "Revisa la instalación y estado del componente Virtual Printer y su aplicación cliente. TDM conserva esta recomendación como guía y no instala ni actualiza componentes.",
                "https://docs.tsplus.net/tsplus/virtual-printer/",
                "TSplus Remote Access / Virtual Printer"),

            ["TSPLUS-WEB-PORT"] = new(
                "TSPLUS-WEB-PORT",
                "TSplus",
                "Web server configuration",
                "Comprueba que el puerto HTTP/HTTPS configurado para el servidor web TSplus no esté ocupado por otra aplicación. Un conflicto de puerto puede impedir que el servidor web TSplus funcione.",
                "https://support.tsplus.net/support/solutions/articles/44000037656-how-do-i-change-the-port-of-the-web-server-",
                "TSplus Web Server"),

            ["TSPLUS-UPDATE-REBOOT-REQUIRED"] = new(
                "TSPLUS-UPDATE-REBOOT-REQUIRED",
                "TSplus",
                "Updating Remote Access / reboot_required.dat",
                "Si la actualización está bloqueada y existe reboot_required.dat en la raíz de TSplus, siga el procedimiento oficial de mantenimiento/reinicio de TSplus antes de reintentar Update Release. TDM sólo informa; no elimina el archivo ni reinicia el equipo.",
                "https://docs.tsplus.net/tsplus/updating-terminal-service-plus/",
                "TSplus Remote Access / Update Release"),

            ["TSPLUS-FARM-CONFIG"] = new(
                "TSPLUS-FARM-CONFIG",
                "TSplus",
                "Farm / Load Balancing / Reverse Proxy",
                "Verifica GatewayPortalLoadBalancing.ini, balance.bin, nombres internos y puertos de cada Application Server. TDM no modifica la granja ni realiza cambios remotos.",
                "https://support.tsplus.net/support/solutions/articles/44002263273-load-balancing-and-reverse-proxy-config-files",
                "TSplus Remote Access / Farm"),

            ["TSPLUS-LTS"] = new(
                "TSPLUS-LTS",
                "TSplus",
                "Long Term Support (LTS)",
                "Interpreta las comprobaciones según la familia de versión instalada; no declares ausente un componente exclusivo de otra rama como una falla.",
                "https://docs.tsplus.net/tsplus/long-term-support-lts/",
                "TSplus Remote Access / LTS"),

            ["MS-REBOOT-PENDING"] = new(
                "MS-REBOOT-PENDING",
                "Microsoft",
                "Reboot pending state",
                "Comprueba si Windows mantiene operaciones pendientes de reinicio (CBS, Windows Update, PendingFileRenameOperations o cambios de nombre). Correlaciónalas con el inicio del incidente antes de responsabilizar al sistema operativo.",
                "https://learn.microsoft.com/en-us/powershell/dsc/reference/resources/microsoft/windows/rebootpending/",
                "Windows / mantenimiento / reinicio"),

            ["MS-USER-PROFILE"] = new(
                "MS-USER-PROFILE",
                "Microsoft",
                "Troubleshoot user profiles with events",
                "Correlaciona User Profile Service, Application y el canal operacional del perfil con el usuario y la sesión afectada antes de modificar el perfil.",
                "https://learn.microsoft.com/en-us/troubleshoot/windows-server/user-profiles-and-logon/troubleshoot-user-profiles-events",
                "Windows / perfiles de usuario")
        };

    public static OfficialGuidance? Get(string id) => Entries.TryGetValue(id, out var value) ? value : null;
}
