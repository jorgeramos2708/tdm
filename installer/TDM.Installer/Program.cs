using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

namespace TDM.Installer;

internal static class Program
{
    private const string PayloadResource = "TDM.Payload.zip";
    private const string ScriptResource = "TDM.Install.cmd";
    private const uint MbIconInformation = 0x00000040;
    private const uint MbIconError = 0x00000010;

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int MessageBoxW(IntPtr hWnd, string text, string caption, uint type);

    [STAThread]
    private static async Task<int> Main()
    {
        var logPath = Path.Combine(Path.GetTempPath(), "TDM-Setup.log");
        var workingPath = Path.Combine(Path.GetTempPath(), $"TDM-Setup-{Guid.NewGuid():N}");

        try
        {
            File.WriteAllText(logPath, $"TDM Setup iniciado: {DateTimeOffset.Now:O}{Environment.NewLine}", Encoding.UTF8);
            EnsureAdministrator();
            Directory.CreateDirectory(workingPath);

            var payloadPath = Path.Combine(workingPath, "payload.zip");
            var scriptPath = Path.Combine(workingPath, "Install-TDM.cmd");
            ExtractResource(PayloadResource, payloadPath);
            ExtractResource(ScriptResource, scriptPath);

            var commandProcessor = Environment.GetEnvironmentVariable("COMSPEC") ?? "cmd.exe";
            var startInfo = new ProcessStartInfo
            {
                FileName = commandProcessor,
                Arguments = $"/d /s /c \"\"{scriptPath}\"\"",
                WorkingDirectory = workingPath,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };

            using var process = Process.Start(startInfo)
                ?? throw new InvalidOperationException("Windows no pudo iniciar el proceso de instalación.");
            var standardOutput = process.StandardOutput.ReadToEndAsync();
            var standardError = process.StandardError.ReadToEndAsync();
            await process.WaitForExitAsync().ConfigureAwait(false);
            var output = await standardOutput.ConfigureAwait(false);
            var error = await standardError.ConfigureAwait(false);

            File.AppendAllText(
                logPath,
                $"{output}{Environment.NewLine}{error}{Environment.NewLine}ExitCode={process.ExitCode}{Environment.NewLine}",
                Encoding.UTF8);

            if (process.ExitCode != 0)
            {
                throw new InvalidOperationException($"La instalación devolvió el código {process.ExitCode}.");
            }

            MessageBoxW(
                IntPtr.Zero,
                "TDM se instaló correctamente. La aplicación y el notificador se iniciarán automáticamente.",
                "Instalación de TDM",
                MbIconInformation);
            return 0;
        }
        catch (Exception ex)
        {
            try
            {
                File.AppendAllText(logPath, $"ERROR: {ex}{Environment.NewLine}", Encoding.UTF8);
            }
            catch
            {
                // El mensaje principal todavía informa la ubicación prevista del registro.
            }

            MessageBoxW(
                IntPtr.Zero,
                $"No se pudo instalar TDM.{Environment.NewLine}{Environment.NewLine}{ex.Message}{Environment.NewLine}{Environment.NewLine}Registro: {logPath}",
                "Error de instalación de TDM",
                MbIconError);
            return 1;
        }
        finally
        {
            try
            {
                if (Directory.Exists(workingPath))
                {
                    Directory.Delete(workingPath, true);
                }
            }
            catch
            {
                // Windows limpiará posteriormente cualquier temporal que todavía esté bloqueado.
            }
        }
    }

    private static void EnsureAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        if (!principal.IsInRole(WindowsBuiltInRole.Administrator))
        {
            throw new UnauthorizedAccessException("El instalador debe ejecutarse con permisos de administrador.");
        }
    }

    private static void ExtractResource(string resourceName, string destination)
    {
        using var source = Assembly.GetExecutingAssembly().GetManifestResourceStream(resourceName)
            ?? throw new InvalidOperationException($"El instalador no contiene el recurso requerido: {resourceName}.");
        using var target = new FileStream(destination, FileMode.Create, FileAccess.Write, FileShare.None);
        source.CopyTo(target);
    }
}
