using Avalonia;
using System;
using System.IO;
using System.Runtime.InteropServices;
using TDM.Application;
using TDM.Persistence;

namespace TDM.Gui.Avalonia;

internal static class Program
{
    [STAThread]
    public static int Main(string[] args)
    {
        // Mini-CLI de feedback: registra el veredicto del técnico sin abrir la GUI,
        // para alimentar el historial que pondera el ranking. Cualquier otro argumento
        // sigue la ruta normal de Avalonia.
        if (FeedbackCommandParser.IsFeedbackInvocation(args))
            return RunFeedbackCommand(args);
        BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);
        return 0;
    }

    [DllImport("kernel32.dll")]
    private static extern bool AttachConsole(int dwProcessId);

    private static int RunFeedbackCommand(string[] args)
    {
        // TDM.exe es WinExe: sin consola adjunta la salida se perdería.
        try { AttachConsole(-1); } catch { }
        if (!FeedbackCommandParser.TryParse(args, out var command, out var error) || command is null)
        {
            Console.Error.WriteLine(FeedbackCommandParser.Usage);
            if (!string.IsNullOrWhiteSpace(error)) Console.Error.WriteLine("Error: " + error);
            return 2;
        }
        if (command.Help)
        {
            Console.WriteLine(FeedbackCommandParser.Usage);
            return 0;
        }
        try
        {
            var store = new DiagnosticFeedbackStore(
                string.IsNullOrWhiteSpace(command.Root) ? TdmDataPaths.MachineRootPath : command.Root);
            var recorded = store.RecordAsync(
                command.CandidateId, command.Componente, command.Puntaje, command.Confianza,
                command.Confirm ? FeedbackVerdict.Confirmada : FeedbackVerdict.Descartada,
                command.Nota,
                string.IsNullOrWhiteSpace(command.Tecnico) ? Environment.UserName : command.Tecnico)
                .GetAwaiter().GetResult();
            Console.WriteLine($"Veredicto registrado: {recorded.Id} ({recorded.Verdicto}) para {recorded.CandidateId}. Aplica al ranking desde la próxima muestra.");
            return 0;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            Console.Error.WriteLine("No se pudo registrar (revise permisos sobre la raíz de máquina): " + ex.Message);
            return 1;
        }
    }

    public static AppBuilder BuildAvaloniaApp()
        => AppBuilder.Configure<App>()
            .UsePlatformDetect()
            .WithInterFont()
            .ConfigureFonts(fontManager =>
                fontManager.AddFontCollection(new TdmFontCollection()))
            .LogToTrace();
}
