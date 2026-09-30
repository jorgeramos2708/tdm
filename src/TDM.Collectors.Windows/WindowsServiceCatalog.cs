using Microsoft.Win32;
using System.ServiceProcess;
using TDM.Models;

namespace TDM.Collectors.Windows;

/// <summary>
/// Catálogo de servicios Windows relevantes para Remote Desktop, TSplus y sus dependencias.
/// No pretende inventariar todos los servicios del sistema: concentra servicios con impacto
/// directo o frecuente sobre sesión remota, autenticación, red, perfiles, impresión y tiempo.
/// </summary>
public static class WindowsServiceCatalog
{
    internal sealed record Target(string Name, string Area, bool RequiredWhenTsplus = false);

    internal static readonly IReadOnlyList<Target> Targets =
    [
        // Núcleo RDP / sesión remota
        new("TermService", "RDP", true),
        new("UmRdpService", "RDP"),
        new("SessionEnv", "RDP"),
        new("TermServLicensing", "RDP"),
        new("Tssdis", "RDP"),
        new("RDMS", "RDP"),
        new("TSGateway", "RDP"),

        // RPC / COM / observabilidad base
        new("RpcSs", "Windows", true),
        new("RpcEptMapper", "Windows"),
        new("DcomLaunch", "Windows", true),
        new("EventLog", "Windows"),
        new("Winmgmt", "Windows"),
        new("Schedule", "Windows"),
        new("SENS", "Windows"),

        // Red / firewall / resolución
        new("BFE", "Red"),
        new("MpsSvc", "Red"),
        new("Nsi", "Red"),
        new("Dnscache", "Red"),
        new("NlaSvc", "Red"),
        new("Dhcp", "Red"),
        new("Netman", "Red"),
        new("iphlpsvc", "Red"),
        new("WinHttpAutoProxySvc", "Red"),
        new("LanmanWorkstation", "Red"),
        new("LanmanServer", "Red"),

        // Identidad, perfiles, políticas y criptografía
        new("ProfSvc", "Identidad"),
        new("UserManager", "Identidad"),
        new("gpsvc", "Identidad"),
        new("SamSs", "Identidad"),
        new("CryptSvc", "Identidad"),
        new("KeyIso", "Identidad"),
        new("W32Time", "Identidad"),
        new("Netlogon", "Identidad"),

        // TSplus Web/HTML5 (detección explícita; el clasificador dinámico sigue como respaldo)
        new("TSplus-HTML5Service", "TSplus", true),
        new("TSplus-WebPortal", "TSplus", true),
        new("TSplus-WebServer", "TSplus", true),

        // Impresión
        new("Spooler", "Impresión")
    ];

    internal static bool IsRelevant(string name)
        => Targets.Any(x => x.Name.Equals(name, StringComparison.OrdinalIgnoreCase));

    internal static Target? Find(string name)
        => Targets.FirstOrDefault(x => x.Name.Equals(name, StringComparison.OrdinalIgnoreCase));

    internal static string ReadStartMode(string serviceName)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{serviceName}", writable: false);
            var start = key?.GetValue("Start");
            var value = start is int i ? i : start is not null && int.TryParse(start.ToString(), out var parsed) ? parsed : -1;
            return value switch
            {
                0 => "Boot",
                1 => "System",
                2 => "Automático",
                3 => "Manual",
                4 => "Deshabilitado",
                _ => "N/D"
            };
        }
        catch
        {
            return "N/D";
        }
    }

    internal static string PresentationState(ServiceControllerStatus status, string startMode, bool requiredNow)
    {
        if (status == ServiceControllerStatus.Running) return "Running";
        if (requiredNow) return $"{status} · requerido";
        if (startMode.Equals("Automático", StringComparison.OrdinalIgnoreCase)) return $"{status} · Automático";
        if (startMode.Equals("Manual", StringComparison.OrdinalIgnoreCase)) return "Saludable · Bajo demanda (Manual)";
        if (startMode.Equals("Deshabilitado", StringComparison.OrdinalIgnoreCase)) return "No requerido · Deshabilitado";
        return status.ToString();
    }

    internal static bool ShouldWarnWhenStopped(ServiceControllerStatus status, string startMode, bool requiredNow)
        => status != ServiceControllerStatus.Running &&
           (requiredNow || startMode.Equals("Automático", StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// Única regla de "requerido ahora" compartida por WindowsServiceCollector,
    /// el grafo de dependencias y el recorrido a profundidad: un servicio TSplus
    /// relacionado sólo se exige si no es complementario y su inicio es Automático.
    /// </summary>
    public static bool RequiredNow(bool catalogRequired, bool tsplusDetected, bool tsplusRelated, bool complementary, bool autoStart)
        => (catalogRequired && tsplusDetected) || (tsplusRelated && !complementary && autoStart);

    /// <summary>
    /// Única regla de severidad de estado detenido: Crítico sólo cuando el catálogo
    /// marca el servicio como requerido con TSplus y además está requerido ahora;
    /// cualquier otro estado con advertencia se reporta como Advertencia.
    /// </summary>
    public static DiagnosticSeverity StoppedSeverity(bool catalogRequired, bool requiredNow)
        => catalogRequired && requiredNow ? DiagnosticSeverity.Critico : DiagnosticSeverity.Advertencia;
}
