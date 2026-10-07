using Microsoft.Win32;
using System.Runtime.InteropServices;
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
            // H11 (F32): delayed-auto y trigger-start sólo se distinguen vía SCM —
            // QueryServiceConfig2 niveles 3 y 8 (docs: QueryServiceConfig2, service-trigger-events).
            var (delayed, trigger) = value is 2 or 3 ? ReadStartFlags(serviceName) : (false, false);
            if (trigger) return "Trigger";
            return value switch
            {
                0 => "Boot",
                1 => "System",
                2 => delayed ? "Automático (retrasado)" : "Automático",
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

    /// <summary>
    /// H11 (F32): un servicio es auto-start si su configuración SCM dice Automático o
    /// Automático retrasado (doc: start= delayed-auto); Manual/Deshabilitado/Trigger no.
    /// </summary>
    public static bool IsAutoStart(string startMode)
        => startMode.Equals("Automático", StringComparison.OrdinalIgnoreCase)
           || startMode.Equals("Automático (retrasado)", StringComparison.OrdinalIgnoreCase);

    internal static string PresentationState(ServiceControllerStatus status, string startMode, bool requiredNow)
    {
        if (status == ServiceControllerStatus.Running) return "Running";
        if (requiredNow) return $"{status} · requerido";
        if (IsAutoStart(startMode)) return $"{status} · {startMode}";
        if (startMode.Equals("Manual", StringComparison.OrdinalIgnoreCase)) return "Saludable · Bajo demanda (Manual)";
        if (startMode.Equals("Trigger", StringComparison.OrdinalIgnoreCase)) return "Saludable · Bajo demanda (Trigger)";
        if (startMode.Equals("Deshabilitado", StringComparison.OrdinalIgnoreCase)) return "No requerido · Deshabilitado";
        return status.ToString();
    }

    internal static bool ShouldWarnWhenStopped(ServiceControllerStatus status, string startMode, bool requiredNow)
        => status != ServiceControllerStatus.Running &&
           (requiredNow || IsAutoStart(startMode));

    // H11 (F32): niveles de QueryServiceConfig2 (doc oficial: dwInfoLevel 1–4 y 8) y
    // permisos SCM mínimos para leerlos en modo sólo consulta.
    private const uint ScManagerConnect = 0x0001;
    private const uint ServiceQueryConfig = 0x0001;
    private const uint ServiceConfigFailureActions = 2;
    private const uint ServiceConfigDelayedAutoStartInfo = 3;
    private const uint ServiceConfigFailureActionsFlag = 4;
    private const uint ServiceConfigTriggerInfo = 8;

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr OpenSCManagerW(string? machineName, string? databaseName, uint dwDesiredAccess);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr OpenServiceW(IntPtr hSCManager, string lpServiceName, uint dwDesiredAccess);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool QueryServiceConfig2W(IntPtr hService, uint dwInfoLevel, IntPtr lpBuffer, uint cbBufSize, out uint pcbBytesNeeded);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool CloseServiceHandle(IntPtr hSCObject);

    /// <summary>
    /// Arranque retrasado (nivel 3, BOOL fDelayedAutostart) y trigger-start (nivel 8,
    /// SERVICE_TRIGGER_INFO.cTriggers &gt; 0) leídos del SCM. Cualquier fallo de consulta
    /// devuelve (false, false): el modo de inicio sigue siendo el del registro, sin regresión.
    /// </summary>
    internal static (bool Delayed, bool Trigger) ReadStartFlags(string serviceName)
    {
        var scm = OpenSCManagerW(null, null, ScManagerConnect);
        if (scm == IntPtr.Zero) return (false, false);
        try
        {
            var service = OpenServiceW(scm, serviceName, ServiceQueryConfig);
            if (service == IntPtr.Zero) return (false, false);
            try
            {
                var delayed = false;
                var buffer = Marshal.AllocHGlobal(4);
                try
                {
                    if (QueryServiceConfig2W(service, ServiceConfigDelayedAutoStartInfo, buffer, 4, out _))
                        delayed = Marshal.ReadInt32(buffer) != 0;
                }
                finally { Marshal.FreeHGlobal(buffer); }

                var trigger = false;
                QueryServiceConfig2W(service, ServiceConfigTriggerInfo, IntPtr.Zero, 0, out var needed);
                var headSize = IntPtr.Size == 8 ? 32 : 16;
                if (needed >= headSize && needed <= 65_536)
                {
                    var info = Marshal.AllocHGlobal((int)needed);
                    try
                    {
                        // SERVICE_TRIGGER_INFO: primer campo DWORD cTriggers.
                        if (QueryServiceConfig2W(service, ServiceConfigTriggerInfo, info, needed, out _))
                            trigger = Marshal.ReadInt32(info, 0) > 0;
                    }
                    finally { Marshal.FreeHGlobal(info); }
                }
                return (delayed, trigger);
            }
            finally { _ = CloseServiceHandle(service); }
        }
        finally { _ = CloseServiceHandle(scm); }
    }

    /// <summary>
    /// H11 (F32): acciones de recuperación declaradas en el SCM (QueryServiceConfig2
    /// niveles 2 y 4 — docs 3 y 5: sc failure / sc failureflag). Texto puro y pineado por tests.
    /// </summary>
    public static string FormatRecoveryActions(int resetPeriodSeconds, IReadOnlyList<(int Type, int DelayMs)> actions, bool alsoWhenStoppedWithError)
    {
        if (actions.Count == 0) return "Sin acciones de recuperación declaradas";
        var names = actions.Select(a => a.Type switch
        {
            1 => a.DelayMs > 0 ? $"reinicio/{a.DelayMs} ms" : "reinicio",
            2 => "reinicio de equipo",
            3 => "comando",
            _ => "ninguna"
        });
        var reset = resetPeriodSeconds > 0 ? $" · reset {resetPeriodSeconds} s" : string.Empty;
        var flag = alsoWhenStoppedWithError ? " · también al detenerse por error" : string.Empty;
        return $"{string.Join(" → ", names)}{reset}{flag}";
    }

    internal static string ReadRecovery(string serviceName)
    {
        try
        {
            var scm = OpenSCManagerW(null, null, ScManagerConnect);
            if (scm == IntPtr.Zero) return "N/D";
            try
            {
                var service = OpenServiceW(scm, serviceName, ServiceQueryConfig);
                if (service == IntPtr.Zero) return "N/D";
                try
                {
                    var alsoWhenStoppedWithError = false;
                    var flagBuffer = Marshal.AllocHGlobal(4);
                    try
                    {
                        if (QueryServiceConfig2W(service, ServiceConfigFailureActionsFlag, flagBuffer, 4, out _))
                            alsoWhenStoppedWithError = Marshal.ReadInt32(flagBuffer) != 0;
                    }
                    finally { Marshal.FreeHGlobal(flagBuffer); }

                    var resetPeriod = 0;
                    var actions = new List<(int Type, int DelayMs)>();
                    QueryServiceConfig2W(service, ServiceConfigFailureActions, IntPtr.Zero, 0, out var needed);
                    var minSize = IntPtr.Size == 8 ? 40 : 20;
                    if (needed >= minSize && needed <= 65_536)
                    {
                        var info = Marshal.AllocHGlobal((int)needed);
                        try
                        {
                            if (QueryServiceConfig2W(service, ServiceConfigFailureActions, info, needed, out _))
                            {
                                // SERVICE_FAILURE_ACTIONS: dwResetPeriod @0; cActions/lpsaActions
                                // tras los dos punteros de cadena (layout x64/x86 según IntPtr.Size).
                                resetPeriod = Marshal.ReadInt32(info, 0);
                                var offCActions = IntPtr.Size == 8 ? 24 : 12;
                                var offActions = IntPtr.Size == 8 ? 32 : 16;
                                if (needed >= offActions + IntPtr.Size)
                                {
                                    var count = Marshal.ReadInt32(info, offCActions);
                                    var array = Marshal.ReadIntPtr(info, offActions);
                                    if (count > 0 && count <= 16 && array != IntPtr.Zero
                                        && (long)array >= (long)info
                                        && (long)array + count * 8L <= (long)info + needed)
                                    {
                                        for (var i = 0; i < count; i++)
                                            actions.Add((Marshal.ReadInt32(array, i * 8), Marshal.ReadInt32(array, i * 8 + 4)));
                                    }
                                }
                            }
                        }
                        finally { Marshal.FreeHGlobal(info); }
                    }
                    return FormatRecoveryActions(resetPeriod, actions, alsoWhenStoppedWithError);
                }
                finally { _ = CloseServiceHandle(service); }
            }
            finally { _ = CloseServiceHandle(scm); }
        }
        catch { return "N/D"; }
    }

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
