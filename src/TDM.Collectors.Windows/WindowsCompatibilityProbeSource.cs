using Microsoft.Win32;
using TDM.Core;

namespace TDM.Collectors.Windows;

/// <summary>
/// Fuente desacoplada de probes de compatibilidad Windows. Permite probar la lógica de
/// interpretación sin depender del Registro/WMI reales y mantiene todas las lecturas en un lugar.
/// </summary>
public interface IWindowsCompatibilityProbeSource
{
    ProbeResult<bool> CbsRebootPending();
    ProbeResult<bool> WindowsUpdateRebootPending();
    ProbeResult<bool> PendingFileRename();
    ProbeResult<bool> PendingComputerRename();
    ProbeResult<int?> RdpPolicyDenyConnections();
    ProbeResult<int?> RdpLocalDenyConnections();
    ProbeResult<string?> WinlogonUserinit();
    ProbeResult<bool> LogonSessionFileExists();
    ProbeResult<IReadOnlyList<string>> RdsConflictingRoles(CancellationToken ct);
}

public sealed class WindowsCompatibilityProbeSource : IWindowsCompatibilityProbeSource
{
    private const string LogonSessionPath = @"C:\wsession\logonsession.exe";

    public ProbeResult<bool> CbsRebootPending()
        => TryRegistryKeyExists(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending");

    public ProbeResult<bool> WindowsUpdateRebootPending()
        => TryRegistryKeyExists(@"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired");

    public ProbeResult<bool> PendingFileRename()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Session Manager");
            return ProbeResult<bool>.Available(key?.GetValue("PendingFileRenameOperations") is string[] pending && pending.Length > 0);
        }
        catch (UnauthorizedAccessException ex) { return ProbeResult<bool>.AccessDenied(ex.Message); }
        catch (Exception ex) { return ProbeResult<bool>.Error(ex.Message); }
    }

    public ProbeResult<bool> PendingComputerRename()
    {
        try
        {
            using var active = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName");
            using var configured = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName");
            var current = active?.GetValue("ComputerName")?.ToString();
            var next = configured?.GetValue("ComputerName")?.ToString();
            var pending = !string.IsNullOrWhiteSpace(current) && !string.IsNullOrWhiteSpace(next) && !current.Equals(next, StringComparison.OrdinalIgnoreCase);
            return ProbeResult<bool>.Available(pending);
        }
        catch (UnauthorizedAccessException ex) { return ProbeResult<bool>.AccessDenied(ex.Message); }
        catch (Exception ex) { return ProbeResult<bool>.Error(ex.Message); }
    }

    public ProbeResult<int?> RdpPolicyDenyConnections()
        => TryRegistryInt(@"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services", "fDenyTSConnections");

    public ProbeResult<int?> RdpLocalDenyConnections()
        => TryRegistryInt(@"SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections");

    public ProbeResult<string?> WinlogonUserinit()
        => TryRegistryString(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "Userinit");

    public ProbeResult<bool> LogonSessionFileExists()
    {
        try
        {
            _ = File.GetAttributes(LogonSessionPath);
            return ProbeResult<bool>.Available(true);
        }
        catch (FileNotFoundException) { return ProbeResult<bool>.Available(false); }
        catch (DirectoryNotFoundException) { return ProbeResult<bool>.Available(false); }
        catch (UnauthorizedAccessException ex) { return ProbeResult<bool>.AccessDenied(ex.Message); }
        catch (IOException ex) { return ProbeResult<bool>.Error(ex.Message); }
        catch (Exception ex) { return ProbeResult<bool>.Error(ex.Message); }
    }

    public ProbeResult<IReadOnlyList<string>> RdsConflictingRoles(CancellationToken ct)
    {
        try
        {
            var detected = new List<string>();
            var features = SafeWmi.Query(
                "SELECT Name, ID FROM Win32_ServerFeature",
                o => o["Name"]?.ToString() ?? string.Empty);
            foreach (var name in features)
            {
                ct.ThrowIfCancellationRequested();
                if (name.Contains("Remote Desktop Session Host", StringComparison.OrdinalIgnoreCase) ||
                    name.Contains("Remote Desktop Licensing", StringComparison.OrdinalIgnoreCase) ||
                    name.Contains("Host de sesión de Escritorio remoto", StringComparison.OrdinalIgnoreCase) ||
                    name.Contains("Licencias de Escritorio remoto", StringComparison.OrdinalIgnoreCase))
                    detected.Add(name);
            }
            return ProbeResult<IReadOnlyList<string>>.Available(detected);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex) { return ProbeResult<IReadOnlyList<string>>.Error(ex.Message); }
    }

    private static ProbeResult<bool> TryRegistryKeyExists(string path)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(path);
            return ProbeResult<bool>.Available(key is not null);
        }
        catch (UnauthorizedAccessException ex) { return ProbeResult<bool>.AccessDenied(ex.Message); }
        catch (Exception ex) { return ProbeResult<bool>.Error(ex.Message); }
    }

    private static ProbeResult<int?> TryRegistryInt(string path, string name)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(path);
            if (key is null) return ProbeResult<int?>.Available(null);
            var raw = key.GetValue(name);
            return raw is int value ? ProbeResult<int?>.Available(value) : ProbeResult<int?>.Available(null);
        }
        catch (UnauthorizedAccessException ex) { return ProbeResult<int?>.AccessDenied(ex.Message); }
        catch (Exception ex) { return ProbeResult<int?>.Error(ex.Message); }
    }

    private static ProbeResult<string?> TryRegistryString(string path, string name)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(path);
            return ProbeResult<string?>.Available(key?.GetValue(name)?.ToString());
        }
        catch (UnauthorizedAccessException ex) { return ProbeResult<string?>.AccessDenied(ex.Message); }
        catch (Exception ex) { return ProbeResult<string?>.Error(ex.Message); }
    }
}
