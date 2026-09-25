using Microsoft.Win32;
using TDM.Core;
using TDM.Models;

namespace TDM.Collectors.Windows;

public sealed record TsplusInstallInfo(bool Detectado, string? RutaInstalacion, string? Version, string? Fuente, TsplusDetectionState Estado = TsplusDetectionState.ConfirmedAbsent, string? Detalle = null);

public static class TsplusInstallDiscovery
{
    public static TsplusInstallInfo Discover()
    {
        var uninstall = DiscoverFromUninstall();
        if (uninstall.Detectado) return uninstall;

        var accessProblem = uninstall.Estado == TsplusDetectionState.NotEvaluated;
        string? accessDetail = uninstall.Detalle;
        foreach (var path in KnownPaths())
        {
            var probe = ProbeRemoteAccessRoot(path);
            if (probe.State == ProbeState.AccessDenied || probe.State == ProbeState.Error)
            {
                accessProblem = true; accessDetail = probe.Detail; continue;
            }
            if (!probe.IsAvailable || probe.Value != true) continue;
            return new TsplusInstallInfo(true, path, TryFindVersion(path), "Ruta conocida validada por artefactos Remote Access", TsplusDetectionState.ConfirmedPresent);
        }

        return accessProblem
            ? new TsplusInstallInfo(false, null, null, "No evaluado", TsplusDetectionState.NotEvaluated, accessDetail)
            : new TsplusInstallInfo(false, null, null, null, TsplusDetectionState.ConfirmedAbsent);
    }

    private static IEnumerable<string> KnownPaths()
    {
        var pf86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        var pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        if (!string.IsNullOrWhiteSpace(pf86)) yield return Path.Combine(pf86, "TSplus");
        if (!string.IsNullOrWhiteSpace(pf)) yield return Path.Combine(pf, "TSplus");
    }

    private static TsplusInstallInfo DiscoverFromUninstall()
    {
        var accessProblem = false;
        string? accessDetail = null;
        foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
        {
            try
            {
                using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
                using var uninstall = hklm.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", false);
                if (uninstall is null) continue;
                foreach (var name in uninstall.GetSubKeyNames())
                {
                    using var sub = uninstall.OpenSubKey(name, false);
                    var displayName = sub?.GetValue("DisplayName")?.ToString() ?? string.Empty;
                    if (!IsRemoteAccessProduct(displayName)) continue;
                    var installLocation = sub?.GetValue("InstallLocation")?.ToString()?.Trim();
                    var version = sub?.GetValue("DisplayVersion")?.ToString()?.Trim();
                    if (string.IsNullOrWhiteSpace(installLocation)) installLocation = KnownPaths().FirstOrDefault(p => ProbeRemoteAccessRoot(p).IsAvailable && ProbeRemoteAccessRoot(p).Value == true);
                    if (string.IsNullOrWhiteSpace(installLocation)) continue;
                    var probe = ProbeRemoteAccessRoot(installLocation);
                    if (probe.State == ProbeState.AccessDenied || probe.State == ProbeState.Error)
                    { accessProblem = true; accessDetail = probe.Detail; continue; }
                    if (probe.IsAvailable && probe.Value == true)
                        return new TsplusInstallInfo(true, installLocation, version, $"Uninstall validado por artefactos Remote Access ({view})", TsplusDetectionState.ConfirmedPresent);
                }
            }
            catch (UnauthorizedAccessException ex) { accessProblem = true; accessDetail = ex.Message; }
            catch (System.Security.SecurityException ex) { accessProblem = true; accessDetail = ex.Message; }
            catch (IOException ex) { accessProblem = true; accessDetail = ex.Message; }
            catch (InvalidOperationException ex) { accessProblem = true; accessDetail = ex.Message; }
        }
        return accessProblem
            ? new TsplusInstallInfo(false, null, null, "No evaluado", TsplusDetectionState.NotEvaluated, accessDetail)
            : new TsplusInstallInfo(false, null, null, null, TsplusDetectionState.ConfirmedAbsent);
    }

    private static bool IsRemoteAccessProduct(string displayName)
    {
        if (!displayName.Contains("TSplus", StringComparison.OrdinalIgnoreCase)) return false;
        if (displayName.Contains("Advanced Security", StringComparison.OrdinalIgnoreCase) || displayName.Contains("Server Monitoring", StringComparison.OrdinalIgnoreCase) || displayName.Contains("Remote Work", StringComparison.OrdinalIgnoreCase) || displayName.Contains("Remote Support", StringComparison.OrdinalIgnoreCase)) return false;
        return displayName.Contains("Remote Access", StringComparison.OrdinalIgnoreCase) || displayName.Equals("TSplus", StringComparison.OrdinalIgnoreCase) || displayName.StartsWith("TSplus ", StringComparison.OrdinalIgnoreCase);
    }

    private static ProbeResult<bool> ProbeRemoteAccessRoot(string path)
    {
        var root = FileSystemProbe.Directory(path);
        if (!root.IsAvailable) return root;
        var admin = FileSystemProbe.File(Path.Combine(path, "UserDesktop", "files", "AdminTool.exe"));
        var uninstaller = FileSystemProbe.File(Path.Combine(path, "unins000.exe"));
        var files = FileSystemProbe.Directory(Path.Combine(path, "UserDesktop", "files"));
        if (admin.IsAvailable || uninstaller.IsAvailable || files.IsAvailable) return ProbeResult<bool>.Available(true);
        if (new[] { admin, uninstaller, files }.Any(x => x.State is ProbeState.AccessDenied or ProbeState.Error))
            return ProbeResult<bool>.Error("No fue posible comprobar completamente los artefactos de Remote Access.");
        return ProbeResult<bool>.Absent();
    }

    private static string? TryFindVersion(string path)
    {
        var candidates = new[] { Path.Combine(path, "UserDesktop", "files", "AdminTool.exe"), Path.Combine(path, "AdminTool.exe"), Path.Combine(path, "UserDesktop", "files", "Setup-ConnectionClient.exe") };
        foreach (var candidate in candidates)
        {
            var probe = FileSystemProbe.File(candidate);
            if (!probe.IsAvailable) continue;
            try
            {
                var info = System.Diagnostics.FileVersionInfo.GetVersionInfo(candidate);
                var version = info.ProductVersion ?? info.FileVersion;
                if (!string.IsNullOrWhiteSpace(version)) return version;
            }
            catch { }
        }
        return null;
    }
}
