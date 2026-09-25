using TDM.Core;
using Microsoft.Win32;
using TDM.Models;

namespace TDM.Collectors.Windows;

public static class SystemSnapshotReader
{
    public static SystemSnapshot Capture()
    {
        var os = ReadOperatingSystem();
        var tsplus = TsplusInstallDiscovery.Discover();

        return new SystemSnapshot(
            Environment.MachineName,
            os.Caption,
            os.DisplayVersion,
            os.Build,
            Environment.Is64BitOperatingSystem ? "x64" : "x86",
            TimeSpan.FromMilliseconds(Environment.TickCount64),
            DateTimeOffset.Now,
            tsplus.Detectado,
            tsplus.RutaInstalacion,
            tsplus.Version) with { TsplusEstadoDeteccion = tsplus.Estado };
    }

    private static (string Caption, string DisplayVersion, string Build) ReadOperatingSystem()
    {
        string caption = "Windows";
        string displayVersion = "N/D";
        string build = Environment.OSVersion.Version.Build.ToString();

        // WMI es preferible para el nombre comercial. En Windows 11 algunas claves
        // históricas del Registro pueden conservar "Windows 10" por compatibilidad.
        var wmi = SafeWmi.Query(
            "SELECT Caption, BuildNumber FROM Win32_OperatingSystem",
            o => (Caption: o["Caption"]?.ToString()?.Trim() ?? "Windows", Build: o["BuildNumber"]?.ToString()?.Trim() ?? build));
        if (wmi.Count > 0)
        {
            caption = wmi[0].Caption;
            build = wmi[0].Build;
        }

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion", false);
            displayVersion = key?.GetValue("DisplayVersion")?.ToString()
                ?? key?.GetValue("ReleaseId")?.ToString()
                ?? displayVersion;
            build = key?.GetValue("CurrentBuildNumber")?.ToString()
                ?? key?.GetValue("CurrentBuild")?.ToString()
                ?? build;

            var ubr = key?.GetValue("UBR")?.ToString();
            if (!string.IsNullOrWhiteSpace(ubr)) build = $"{build}.{ubr}";
        }
        catch { }

        // Salvaguarda para equipos Windows 11 donde una fuente heredada reporte Windows 10.
        if (caption.Contains("Windows 10", StringComparison.OrdinalIgnoreCase)
            && int.TryParse(build.Split('.')[0], out var majorBuild)
            && majorBuild >= 22000)
        {
            caption = caption.Replace("Windows 10", "Windows 11", StringComparison.OrdinalIgnoreCase);
        }

        return (caption, displayVersion, build);
    }
}
