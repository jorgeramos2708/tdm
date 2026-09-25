using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32;

#pragma warning disable CA1416 // Windows-only APIs

namespace TDM.Core;

/// <summary>
/// Startup dependency check - verifica que todas las dependencias externas estén disponibles.
/// Lanza excepción con diagnóstico detallado si falta algo crítico.
/// </summary>
public static class StartupDependencyChecker
{
    public sealed record CheckResult(
        bool AllCriticalPassed,
        IReadOnlyList<DependencyCheck> Checks);

    public sealed record DependencyCheck(
        string Name,
        bool IsCritical,
        bool Passed,
        string Detail,
        string? Remediation = null);

    /// <summary>
    /// Ejecuta todos los checks de dependencias al arranque.
    /// Lanza StartupDependencyException si falla algo crítico.
    /// </summary>
    public static CheckResult RunAll(bool throwOnCritical = true)
    {
        var checks = new List<DependencyCheck>();

        // 1. WMI disponible
        checks.Add(CheckWmi());

        // 2. EventLog System accesible
        checks.Add(CheckEventLog());

        // 3. Registry acceso (HKLM\SYSTEM\CurrentControlSet)
        checks.Add(CheckRegistry());

        // 4. netstat.exe disponible
        checks.Add(CheckNetstat());

        // 5. TSplus install path (si detectado) - se valida en collectors, no aquí para evitar dependencia circular
        // checks.Add(CheckTsplusPath());

        // 6. Disco espacio suficiente (> 100MB en root)
        checks.Add(CheckDiskSpace());

        // 7. Permisos admin (para ETW, netstat, EventLog completo)
        checks.Add(CheckAdminRights());

        var allCriticalPassed = checks.Where(c => c.IsCritical).All(c => c.Passed);

        var result = new CheckResult(allCriticalPassed, checks);

        if (throwOnCritical && !allCriticalPassed)
        {
            var failed = checks.Where(c => c.IsCritical && !c.Passed).ToList();
            var msg = "DEPENDENCIAS CRÍTICAS NO DISPONIBLES:\n" +
                      string.Join("\n", failed.Select(f =>
                          $"  - {f.Name}: {f.Detail}" + (f.Remediation != null ? $"\n    Acción: {f.Remediation}" : "")));
            throw new StartupDependencyException(msg, failed);
        }

        return result;
    }

    private static DependencyCheck CheckWmi()
    {
        try
        {
            using var searcher = new ManagementObjectSearcher("SELECT Name FROM Win32_OperatingSystem");
            using var results = searcher.Get();
            return new DependencyCheck("WMI", true, results.Count > 0,
                results.Count > 0 ? "WMI operativo" : "WMI no devolvió resultados",
                results.Count == 0 ? "Verificar servicio 'Winmgmt' (WMI) esté Running" : null);
        }
        catch (Exception ex)
        {
            return new DependencyCheck("WMI", true, false,
                $"WMI falló: {ex.Message}",
                "Verificar servicio 'Winmgmt' (WMI) esté Running y permisos DCOM");
        }
    }

    private static DependencyCheck CheckEventLog()
    {
        try
        {
            using var log = new System.Diagnostics.EventLog("System");
            _ = log.Entries.Count; // fuerza acceso
            return new DependencyCheck("EventLog (System)", true, true,
                "EventLog System accesible",
                null);
        }
        catch (Exception ex)
        {
            return new DependencyCheck("EventLog (System)", true, false,
                $"EventLog System inaccesible: {ex.Message}",
                "Ejecutar como Administrador o verificar permisos en Security log");
        }
    }

    private static DependencyCheck CheckRegistry()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control", false);
            return new DependencyCheck("Registry (HKLM)", true, key is not null,
                key is not null ? "Registry HKLM accesible" : "Registry HKLM inaccesible",
                key is null ? "Verificar permisos de lectura en HKLM\\SYSTEM" : null);
        }
        catch (Exception ex)
        {
            return new DependencyCheck("Registry (HKLM)", true, false,
                $"Registry falló: {ex.Message}",
                "Verificar permisos de lectura en HKLM");
        }
    }

    private static DependencyCheck CheckNetstat()
    {
        var netstat = Path.Combine(Environment.SystemDirectory, "netstat.exe");
        var exists = File.Exists(netstat);
        return new DependencyCheck("netstat.exe", true, exists,
            exists ? "netstat.exe encontrado" : "netstat.exe NO encontrado",
            !exists ? "Verificar que %SystemRoot%\\System32\\netstat.exe existe" : null);
    }

    private static DependencyCheck CheckDiskSpace()
    {
        try
        {
            var root = Path.GetPathRoot(Environment.SystemDirectory)!;
            var drive = new DriveInfo(root);
            var freeGb = drive.AvailableFreeSpace / 1024 / 1024 / 1024;
            var passed = freeGb >= 1; // al menos 1GB libre
            return new DependencyCheck("Disk Space", true, passed,
                $"{freeGb:F1} GB libres en {root}",
                passed ? null : "Liberar espacio en disco (mín 1 GB requerido)");
        }
        catch (Exception ex)
        {
            return new DependencyCheck("Disk Space", true, false,
                $"Disk space check falló: {ex.Message}", null);
        }
    }

    private static DependencyCheck CheckAdminRights()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            var isAdmin = principal.IsInRole(WindowsBuiltInRole.Administrator);
            return new DependencyCheck("Admin Rights", false, isAdmin,
                isAdmin ? "Ejecutando como Administrador" : "NO es Administrador (algunas funciones limitadas)",
                isAdmin ? null : "Ejecutar como Administrador para ETW, netstat completo, EventLog completo");
        }
        catch (Exception ex)
        {
            return new DependencyCheck("Admin Rights", false, false,
                $"Admin check falló: {ex.Message}", null);
        }
    }
}

public sealed class StartupDependencyException : Exception
{
    public IReadOnlyList<StartupDependencyChecker.DependencyCheck> FailedChecks { get; }
    public StartupDependencyException(string message, IReadOnlyList<StartupDependencyChecker.DependencyCheck> failed)
        : base(message)
    {
        FailedChecks = failed;
    }
}