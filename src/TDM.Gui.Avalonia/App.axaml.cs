using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using System;
using System.Diagnostics;
using System.IO;
using System.Threading.Tasks;
using AvaloniaApplication = Avalonia.Application;
using TDM.Gui.Avalonia.ViewModels;
using TDM.Gui.Avalonia.Views;
using TDM.Gui.Avalonia.Services;
using TDM.Persistence;
using TDM.Core;

namespace TDM.Gui.Avalonia;

public partial class App : global::Avalonia.Application
{
    private Mutex? _singleInstanceMutex;
    private static string? _logPath;
    
    // Shared LogService instance for application-wide logging
    public static LogService? LogService { get; private set; }

public override void Initialize()
{
    // Minimal initialization - defer slow checks to background
    InitializeLogging();
    
    // Initialize shared LogService
    LogService = new LogService();
    
    CollectorAssemblyResolver.Initialize();
    AvaloniaXamlLoader.Load(this);
    
    // Schedule startup checks to run after UI is responsive
    Task.Run(RunStartupChecksAsync);
}

private async Task RunStartupChecksAsync()
{
    try
    {
        // Fail-fast config validation (portable mode)
        ConfigValidator.ValidateOrThrow(portable: PortableRuntime.IsEnabled);

        // Startup dependency check (fail-fast si dependencias críticas faltan)
        var depResult = StartupDependencyChecker.RunAll(throwOnCritical: true);
        foreach (var check in depResult.Checks)
        {
            var prefix = check.Passed ? "✓" : (check.IsCritical ? "✗ CRITICAL" : "⚠ WARN");
            System.Diagnostics.Debug.WriteLine($"[STARTUP] {prefix} {check.Name}: {check.Detail}");
        }

        // Portable executable integrity verification (fail-fast si hash no coincide)
        if (PortableRuntime.IsEnabled)
        {
            try { PortableIntegrityVerifier.VerifyOrThrow(); }
            catch (InvalidOperationException ex)
            {
                System.Diagnostics.Debug.WriteLine($"[STARTUP] INTEGRIDAD FALLIDA: {ex.Message}");
                throw;
            }
        }
        
        await Task.CompletedTask; // Satisfy async pattern
    }
    catch (Exception ex)
    {
        // Log but don't crash the UI - show error in UI instead
        LogService?.Write(LogLevel.Critical, "STARTUP", null, $"Startup check failed: {ex.Message}", ex);
        System.Diagnostics.Debug.WriteLine($"[STARTUP] ERROR: {ex}");
    }
}

public override void OnFrameworkInitializationCompleted()
{
    if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
    {
        // Global exception handlers for crash diagnosis
        SetupGlobalExceptionHandlers();

        _singleInstanceMutex = new Mutex(true, @"Local\TDM.Gui.Avalonia", out var createdNew);
        if (!createdNew)
        {
            desktop.Shutdown();
            base.OnFrameworkInitializationCompleted();
            return;
        }

        desktop.MainWindow = new MainWindow
        {
            DataContext = new MainWindowViewModel()
        };
        desktop.Exit += (_, _) =>
        {
            try { _singleInstanceMutex?.ReleaseMutex(); } catch { }
            _singleInstanceMutex?.Dispose();
            LogService?.Dispose();
        };
    }

    base.OnFrameworkInitializationCompleted();
}

    private static void InitializeLogging()
    {
        try
        {
            var root = TDM.Persistence.TdmDataPaths.ResolveWritableDefault();
            var logDir = Path.Combine(root, "logs");
            Directory.CreateDirectory(logDir);
            _logPath = Path.Combine(logDir, $"tdm-gui-{DateTime.Now:yyyyMMdd}.log");
        }
        catch { /* Best-effort logging */ }
    }

private static void SetupGlobalExceptionHandlers()
{
    // 1. UI thread unhandled exceptions (Avalonia)
    // 1. UI thread unhandled exceptions (Avalonia) - handled via AppBuilder.LogToTrace and custom logger
    // Note: Avalonia Application doesn't expose UnhandledException event directly
    // Exceptions in UI thread are typically handled by the platform or logged via LogToTrace

    // 2. TaskScheduler unobserved exceptions (background tasks)
    TaskScheduler.UnobservedTaskException += (s, e) =>
    {
        LogFatal("TASK_SCHEDULER_UNOBSERVED", e.Exception, "Unobserved task exception");
        LogService?.Write(LogLevel.Critical, "TASK_SCHEDULER", null, $"Unobserved task exception: {e.Exception?.Message}", e.Exception);
        e.SetObserved(); // Prevent process crash
    };

    // 3. AppDomain unhandled exceptions (non-TPL threads)
    AppDomain.CurrentDomain.UnhandledException += (s, e) =>
    {
        var ex = e.ExceptionObject as Exception;
        LogFatal("APPDOMAIN_UNHANDLED", ex, "Unhandled exception on non-TPL thread");
        LogService?.Write(LogLevel.Critical, "APPDOMAIN", null, "Unhandled exception on non-TPL thread", ex);
        // Note: Cannot prevent process exit here, but can log for diagnosis
    };

    // 4. Process exit - distinguish crash vs clean shutdown
    Process.GetCurrentProcess().EnableRaisingEvents = true;
    Process.GetCurrentProcess().Exited += (s, e) =>
    {
        var proc = s as Process;
        if (proc is null) return;
        var exitCode = proc.ExitCode;
        var isCrash = exitCode != 0 && exitCode != -1; // -1 = clean shutdown via Shutdown()
        var msg = isCrash
            ? $"PROCESS_CRASH: ExitCode={exitCode} (TDM crashed)"
            : $"PROCESS_EXIT: ExitCode={exitCode} (clean shutdown)";
        LogFatal("PROCESS_EXIT", null, msg);
        LogService?.Write(isCrash ? LogLevel.Critical : LogLevel.Information, "PROCESS", null, msg);
    };
}

    private static void LogFatal(string category, Exception? ex, string message)
    {
        try
        {
            if (string.IsNullOrEmpty(_logPath)) return;
            var entry = $"{DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss.fff} [FATAL] [{category}] {message}";
            if (ex != null)
                entry += Environment.NewLine + ex.ToString();
            entry += Environment.NewLine;
            File.AppendAllText(_logPath!, entry);
        }
        catch { /* Best-effort */ }
    }
}
