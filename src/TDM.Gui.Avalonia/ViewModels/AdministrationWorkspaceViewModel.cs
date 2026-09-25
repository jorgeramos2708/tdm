using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using TDM.Core;
using TDM.Gui.Avalonia.Services;
using TDM.Persistence;

namespace TDM.Gui.Avalonia.ViewModels;

public partial class AdministrationWorkspaceViewModel : ObservableObject
{
    private readonly OperationalConfigurationService _service = new();
    private SupportMonitoringSettings _loadedSettings = SupportMonitoringSettings.Default;
    private bool _emailPasswordStored;

    [ObservableProperty] private string _status = "Cargando configuración...";
    [ObservableProperty] private string _configurationRoot = "—";
    [ObservableProperty] private string _configurationSource = "—";
    [ObservableProperty] private string _baselineState = "—";
    [ObservableProperty] private string _baselinePath = "—";
    [ObservableProperty] private string _retentionState = "—";
    [ObservableProperty] private string _federationEditor = string.Empty;
    [ObservableProperty] private string _federationStatus = string.Empty;
    [ObservableProperty] private bool _emailEnabled;
    [ObservableProperty] private string _emailSmtpHost = string.Empty;
    [ObservableProperty] private int _emailSmtpPort = 587;
    [ObservableProperty] private bool _emailUseTls = true;
    [ObservableProperty] private string _emailUserName = string.Empty;
    [ObservableProperty] private string _emailPassword = string.Empty;
    [ObservableProperty] private string _emailFromAddress = string.Empty;
    [ObservableProperty] private string _emailRecipients = string.Empty;
    [ObservableProperty] private string _emailMinimumSeverity = "Error";
    [ObservableProperty] private bool _emailNotifyOpened = true;
    [ObservableProperty] private bool _emailNotifyEscalated = true;
    [ObservableProperty] private bool _emailNotifyRecovered = true;
    [ObservableProperty] private int _emailTimeoutSeconds = 15;
    [ObservableProperty] private string _emailPasswordState = "Sin credencial guardada";
    [ObservableProperty] private string _emailConfigurationPath = "—";
    [ObservableProperty] private string _emailStatus = "Correo no configurado";

    public IReadOnlyList<string> EmailSeverityOptions { get; } = ["Advertencia", "Error", "Crítico"];
    public SupportThresholds CurrentThresholds => _loadedSettings.Thresholds;

    [ObservableProperty] private double _cpuWarning = 70;
    [ObservableProperty] private double _cpuCritical = 85;
    [ObservableProperty] private double _memoryWarning = 80;
    [ObservableProperty] private double _memoryCritical = 90;
    [ObservableProperty] private int _sessionWarning = 80;
    [ObservableProperty] private int _sessionCritical = 120;
    [ObservableProperty] private int _serviceChangesWarning = 3;
    [ObservableProperty] private int _serviceChangesCritical = 6;
    [ObservableProperty] private double _tdmCpuWarning = 3;
    [ObservableProperty] private double _tdmCpuCritical = 7;
    [ObservableProperty] private double _tdmRamWarning = 5;
    [ObservableProperty] private double _tdmRamCritical = 10;
    [ObservableProperty] private int _tdmHandlesWarning = 2000;
    [ObservableProperty] private int _tdmHandlesCritical = 4000;
    [ObservableProperty] private int _tdmThreadsWarning = 80;
    [ObservableProperty] private int _tdmThreadsCritical = 150;
    [ObservableProperty] private int _incidentCooldownSeconds = 120;
    [ObservableProperty] private int _incidentRecoverySamples = 2;
    [ObservableProperty] private int _clockDriftSeconds = 90;
    [ObservableProperty] private int _nodeStaleSeconds = 150;
    [ObservableProperty] private int _nodeOfflineSeconds = 300;
    [ObservableProperty] private int _nodeReadTimeoutSeconds = 8;
    [ObservableProperty] private bool _enableIncidentAntiNoise = true;
    [ObservableProperty] private bool _enableSynchronizedCursor = true;
    [ObservableProperty] private bool _enableMultiServer = true;

    // P2-02: Flapping threshold
    [ObservableProperty] private int _causeStabilityFlappingThreshold = 2;
    // P2: TSplus log limits (diagnostic full)
    [ObservableProperty] private int _maxFilesPerDirectory = 400;
    [ObservableProperty] private int _maxBytesPerFile = 64 * 1024 * 1024;
    [ObservableProperty] private long _maxTotalBytes = 256L * 1024 * 1024;
    [ObservableProperty] private int _maxEvents = 5000;
    // P2: TSplus incremental log limits
    [ObservableProperty] private int _maxFilesPerDirectoryIncremental = 240;
    [ObservableProperty] private int _maxBytesPerFileIncremental = 256 * 1024;
    [ObservableProperty] private long _maxTotalBytesIncremental = 1024 * 1024;
    [ObservableProperty] private int _maxEventsIncremental = 300;

    // Counterfactual Engine - Remediation Simulator
    [ObservableProperty] private string _remediationTargetService = string.Empty;
    [ObservableProperty] private string _remediationAction = "RestartService";
    [ObservableProperty] private string _remediationResult = string.Empty;
    [ObservableProperty] private bool _remediationIsSafe = false;
    [ObservableProperty] private string _remediationSummary = string.Empty;
    [ObservableProperty] private string _remediationAffectedCount = string.Empty;
    [ObservableProperty] private string _remediationDetails = string.Empty;

    public IReadOnlyList<string> RemediationActions { get; } = ["RestartService", "StopService", "StartService", "KillProcess", "RestartProcess", "ClearCache", "ResetConnection", "RebootHost"];

    public Task InitializeAsync() => RefreshAsync();

    [RelayCommand]
    private async Task RefreshAsync()
    {
        try
        {
            var snapshot = await _service.LoadAsync();
            _loadedSettings = snapshot.Settings;
            ApplyThresholds(snapshot.Settings.Thresholds);
            EnableIncidentAntiNoise = snapshot.Settings.EnableIncidentAntiNoise;
            EnableSynchronizedCursor = snapshot.Settings.EnableSynchronizedCursor;
            EnableMultiServer = snapshot.Settings.EnableMultiServer;
            ConfigurationRoot = snapshot.RootPath;
            ConfigurationSource = snapshot.Source;
            BaselineState = snapshot.StoreStatus.BaselineExists
                ? $"Referencia guardada · {snapshot.StoreStatus.BaselineCapturedAt?.ToLocalTime():dd/MM/yyyy HH:mm:ss}"
                : "Aún no se ha generado una referencia";
            BaselinePath = snapshot.StoreStatus.BaselinePath;
            RetentionState = $"{snapshot.StoreStatus.RetentionDays} días · {snapshot.StoreStatus.HistoryFileCount} históricos · {snapshot.StoreStatus.TransitionFileCount} transiciones";
            FederationEditor = OperationalConfigurationService.FormatFederation(snapshot.Federation);
            FederationStatus = $"{snapshot.Federation.Nodes.Count} nodo(s) configurados · coordinador {snapshot.Federation.CoordinatorName}";
            ApplyEmailSettings(snapshot.EmailSettings);
            EmailPassword = string.Empty;
            _emailPasswordStored = snapshot.EmailPasswordStored;
            EmailPasswordState = snapshot.EmailPasswordStored ? "Credencial SMTP guardada y protegida" : "Sin credencial SMTP guardada";
            EmailConfigurationPath = snapshot.EmailSettingsPath;
            EmailStatus = snapshot.EmailSettings.Enabled
                ? $"Correo habilitado · {snapshot.EmailSettings.Recipients.Count} destinatario(s)"
                : "Correo deshabilitado";
            Status = "Configuración cargada";
        }
        catch (UnauthorizedAccessException)
        {
            Status = "Sin permisos para leer la configuración compartida";
        }
        catch (Exception ex)
        {
            Status = "No fue posible cargar configuración: " + ex.Message;
        }
    }

    [RelayCommand]
    private async Task SaveThresholdsAsync()
    {
        try
        {
            var thresholds = BuildThresholds();
            var errors = SupportThresholdsValidator.Validate(thresholds);
            if (errors.Count > 0)
            {
                Status = "Umbrales no válidos: " + string.Join(" | ", errors);
                return;
            }

            var settings = _loadedSettings with
            {
                Thresholds = thresholds,
                EnableIncidentAntiNoise = EnableIncidentAntiNoise,
                EnableSynchronizedCursor = EnableSynchronizedCursor,
                EnableMultiServer = EnableMultiServer
            };
            await _service.SaveSettingsAsync(settings);
            _loadedSettings = settings;
            Status = "Umbrales guardados correctamente";
        }
        catch (UnauthorizedAccessException)
        {
            Status = "Sin permisos para guardar umbrales en el store compartido";
        }
        catch (Exception ex)
        {
            Status = "No fue posible guardar umbrales: " + ex.Message;
        }
    }

    [RelayCommand]
    private async Task SaveEmailSettingsAsync()
    {
        try
        {
            var settings = BuildEmailSettings();
            var errors = EmailNotificationSettingsValidator.Validate(settings);
            if (errors.Count > 0)
            {
                EmailStatus = "Configuración de correo no válida: " + string.Join(" | ", errors);
                return;
            }

            var newPassword = string.IsNullOrEmpty(EmailPassword) ? null : EmailPassword;
            if (!string.IsNullOrWhiteSpace(settings.UserName) && newPassword is null && !_emailPasswordStored)
            {
                EmailStatus = "Indique la contraseña SMTP o deje el usuario vacío para un relay sin autenticación.";
                return;
            }
            await _service.SaveEmailSettingsAsync(settings, newPassword, clearStoredPassword: false);
            EmailPassword = string.Empty;
            if (!string.IsNullOrEmpty(newPassword)) _emailPasswordStored = true;
            EmailPasswordState = _emailPasswordStored
                ? "Credencial SMTP guardada y protegida"
                : "Sin credencial SMTP guardada";
            EmailStatus = settings.Enabled
                ? $"Correo guardado y habilitado · {settings.Recipients.Count} destinatario(s)"
                : "Configuración de correo guardada · envío deshabilitado";
        }
        catch (UnauthorizedAccessException)
        {
            EmailStatus = "Sin permisos para guardar correo en ProgramData";
        }
        catch (PlatformNotSupportedException ex)
        {
            EmailStatus = ex.Message;
        }
        catch (Exception ex)
        {
            EmailStatus = "No fue posible guardar la configuración de correo: " + ex.Message;
        }
    }

    [RelayCommand]
    private async Task SendTestEmailAsync()
    {
        try
        {
            var settings = BuildEmailSettings();
            var testSettings = settings with { Enabled = true };
            var errors = EmailNotificationSettingsValidator.Validate(testSettings);
            if (errors.Count > 0)
            {
                EmailStatus = "No se puede probar el correo: " + string.Join(" | ", errors);
                return;
            }

            // La prueba guarda primero el formulario actual para verificar exactamente
            // la configuración que consumirá TDM.Service, incluso si el envío automático queda deshabilitado.
            var newPassword = string.IsNullOrEmpty(EmailPassword) ? null : EmailPassword;
            if (!string.IsNullOrWhiteSpace(settings.UserName) && newPassword is null && !_emailPasswordStored)
            {
                EmailStatus = "No se puede probar: indique la contraseña SMTP o deje el usuario vacío para un relay sin autenticación.";
                return;
            }
            await _service.SaveEmailSettingsAsync(settings, newPassword, clearStoredPassword: false);
            var result = await _service.SendTestEmailAsync();
            EmailPassword = string.Empty;
            if (!string.IsNullOrEmpty(newPassword))
            {
                _emailPasswordStored = true;
                EmailPasswordState = "Credencial SMTP guardada y protegida";
            }
            EmailStatus = result.Success
                ? "Prueba SMTP correcta · configuración guardada · revise la bandeja de los destinatarios"
                : "Prueba SMTP fallida: " + result.Message;
        }
        catch (Exception ex)
        {
            EmailStatus = "Prueba SMTP fallida: " + ex.Message;
        }
    }

    [RelayCommand]
    private async Task ClearEmailCredentialAsync()
    {
        try
        {
            await _service.ClearEmailPasswordAsync();
            EmailPassword = string.Empty;
            _emailPasswordStored = false;
            EmailPasswordState = "Sin credencial SMTP guardada";
            EmailStatus = "Credencial SMTP eliminada; la configuración restante se conserva";
        }
        catch (Exception ex)
        {
            EmailStatus = "No fue posible eliminar la credencial SMTP: " + ex.Message;
        }
    }

    [RelayCommand]
    private void RestoreRecommended()
    {
        var defaults = SupportMonitoringSettings.Default;
        _loadedSettings = defaults;
        ApplyThresholds(defaults.Thresholds);
        EnableIncidentAntiNoise = defaults.EnableIncidentAntiNoise;
        EnableSynchronizedCursor = defaults.EnableSynchronizedCursor;
        EnableMultiServer = defaults.EnableMultiServer;
        Status = "Valores recomendados cargados en el formulario; pulse Guardar para aplicarlos";
    }

    [RelayCommand]
    private void AddLocalServer()
    {
        var line = OperationalConfigurationService.LocalNodeLine(ConfigurationRoot);
        var lines = FederationEditor.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();
        var idx = lines.FindIndex(x => x.Split('|', 4, StringSplitOptions.TrimEntries).FirstOrDefault()?.Equals(Environment.MachineName, StringComparison.OrdinalIgnoreCase) == true);
        if (idx >= 0) lines[idx] = line; else lines.Add(line);
        FederationEditor = string.Join(Environment.NewLine, lines);
        FederationStatus = "Servidor local agregado al editor; pulse Guardar servidores para aplicar";
    }

    [RelayCommand]
    private async Task ClearFederationAsync()
    {
        try
        {
            await _service.SaveFederationAsync(string.Empty);
            FederationEditor = string.Empty;
            FederationStatus = "Servidores eliminados · 0 nodo(s)";
        }
        catch (UnauthorizedAccessException)
        {
            FederationStatus = "Sin permisos para borrar la configuración de servidores";
        }
        catch (Exception ex)
        {
            FederationStatus = "No fue posible borrar servidores: " + ex.Message;
        }
    }

    [RelayCommand]
    private async Task SaveFederationAsync()
    {
        try
        {
            var parsed = OperationalConfigurationService.ParseNodes(FederationEditor);
            if (parsed.Count == 0 && !string.IsNullOrWhiteSpace(FederationEditor))
            {
                FederationStatus = "No se encontraron líneas válidas. Formato: Nombre | Grupo | Rol | Ruta TDM";
                return;
            }
            var config = await _service.SaveFederationAsync(FederationEditor);
            FederationEditor = OperationalConfigurationService.FormatFederation(config);
            FederationStatus = $"Servidores guardados · {config.Nodes.Count} nodo(s)";
        }
        catch (UnauthorizedAccessException)
        {
            FederationStatus = "Sin permisos para modificar la configuración de servidores";
        }
        catch (Exception ex)
        {
            FederationStatus = "No fue posible guardar servidores: " + ex.Message;
        }
    }

    [RelayCommand]
    private async Task SimulateRemediationAsync()
    {
        try
        {
            if (string.IsNullOrWhiteSpace(RemediationTargetService))
            {
                RemediationResult = "❌ Indique el nombre del servicio objetivo";
                return;
            }

            // Build dependency propagator from current monitoring data
            var propagator = BuildDependencyPropagator();
            if (propagator is null)
            {
                RemediationResult = "❌ No hay datos de dependencias disponibles (ejecute diagnóstico primero)";
                return;
            }

            var actionType = Enum.Parse<CounterfactualEngine.ActionType>(RemediationAction);
            var action = new CounterfactualEngine.Action(
                Guid.NewGuid().ToString("N")[..8],
                actionType,
                RemediationTargetService);

            var result = CounterfactualEngine.Simulate(action, propagator);

            RemediationResult = result.IsSafe ? "✅ SEGURO" : "⚠️ RIESGO";
            RemediationIsSafe = result.IsSafe;
            RemediationSummary = result.Summary;
            RemediationAffectedCount = $"{result.AffectedServices.Count} servicios afectados";
            RemediationDetails = FormatRemediationDetails(result.AffectedServices);
            Status = $"Simulación completada: {result.OverallImpact}";
        }
        catch (Exception ex)
        {
            RemediationResult = "❌ Error: " + ex.Message;
        }
        await Task.CompletedTask;
    }

    [RelayCommand]
    private async Task FindRemediationActionsAsync()
    {
        try
        {
            if (string.IsNullOrWhiteSpace(RemediationTargetService))
            {
                RemediationResult = "❌ Indique el nombre del servicio degradado";
                return;
            }

            var propagator = BuildDependencyPropagator();
            if (propagator is null)
            {
                RemediationResult = "❌ No hay datos de dependencias disponibles";
                return;
            }

            var actions = CounterfactualEngine.FindRemediationActions(RemediationTargetService, propagator);

            if (actions.Count == 0)
            {
                RemediationResult = "⚠️ No se encontraron acciones seguras";
                RemediationDetails = string.Empty;
                return;
            }

            var best = actions.First();
            RemediationAction = best.ActionType.ToString();
            RemediationTargetService = best.Target;
            RemediationResult = best.IsSafe ? "✅ SEGURO" : "⚠️ RIESGO";
            RemediationIsSafe = best.IsSafe;
            RemediationSummary = best.Summary;
            RemediationAffectedCount = $"{best.AffectedServices.Count} servicios afectados";
            RemediationDetails = FormatRemediationDetails(best.AffectedServices);
            Status = $"Mejor acción encontrada: {best.ActionType}";
        }
        catch (Exception ex)
        {
            RemediationResult = "❌ Error: " + ex.Message;
        }
        await Task.CompletedTask;
    }

    private DependencyHealthPropagator? BuildDependencyPropagator()
    {
        // This would typically read from the service dependency graph collector
        // For now, create a minimal propagator based on known TSplus/Windows dependencies
        var propagator = new DependencyHealthPropagator();

        // Add common TSplus services
        propagator.AddNode("TSplus Web Portal", ServiceHealth.Healthy);
        propagator.AddNode("TSplus Application Server", ServiceHealth.Healthy);
        propagator.AddNode("TSplus Gateway", ServiceHealth.Healthy);
        propagator.AddNode("TSplus Load Balancer", ServiceHealth.Healthy);

        // Add Windows dependencies
        propagator.AddNode("Spooler", ServiceHealth.Healthy);
        propagator.AddNode("W32Time", ServiceHealth.Healthy);
        propagator.AddNode("Netlogon", ServiceHealth.Healthy);
        propagator.AddNode("Dnscache", ServiceHealth.Healthy);
        propagator.AddNode("LanmanServer", ServiceHealth.Healthy);

        // Functional dependencies (TSplus -> Windows)
        propagator.AddDependency("TSplus Web Portal", "Spooler");
        propagator.AddDependency("TSplus Application Server", "Spooler");
        propagator.AddDependency("TSplus Gateway", "W32Time");
        propagator.AddDependency("TSplus Load Balancer", "Netlogon");

        return propagator;
    }

    private string FormatRemediationDetails(IReadOnlyList<CounterfactualEngine.ServiceImpact> impacts)
    {
        var lines = new List<string>();
        foreach (var impact in impacts.OrderBy(i => i.ServiceName))
        {
            var arrow = impact.SimulatedHealth == impact.CurrentHealth ? "→" : "↘";
            var icon = impact.Reason switch
            {
                CounterfactualEngine.ImpactReason.DirectAction => "🎯",
                CounterfactualEngine.ImpactReason.DependencyDownstream => "⬇",
                CounterfactualEngine.ImpactReason.DependencyUpstream => "⬆",
                _ => "•"
            };
            lines.Add($"{icon} {impact.ServiceName}: {impact.CurrentHealth} {arrow} {impact.SimulatedHealth} ({impact.EstimatedRecovery.TotalMinutes:F0} min)");
        }
        return string.Join(Environment.NewLine, lines);
    }

    private SupportThresholds BuildThresholds() => new()
    {
        CpuWarning = CpuWarning,
        CpuCritical = CpuCritical,
        MemoryUsedWarning = MemoryWarning,
        MemoryUsedCritical = MemoryCritical,
        SessionWarning = SessionWarning,
        SessionCritical = SessionCritical,
        ServiceChangesWarning = ServiceChangesWarning,
        ServiceChangesCritical = ServiceChangesCritical,
        TdmCpuWarning = TdmCpuWarning,
        TdmCpuCritical = TdmCpuCritical,
        TdmMemoryWarningPercent = TdmRamWarning,
        TdmMemoryCriticalPercent = TdmRamCritical,
        TdmHandlesWarning = TdmHandlesWarning,
        TdmHandlesCritical = TdmHandlesCritical,
        TdmThreadsWarning = TdmThreadsWarning,
        TdmThreadsCritical = TdmThreadsCritical,
        IncidentCooldownSeconds = IncidentCooldownSeconds,
        IncidentRecoveryConfirmSamples = IncidentRecoverySamples,
        ClockDriftWarningSeconds = ClockDriftSeconds,
        NodeStaleWarningSeconds = NodeStaleSeconds,
        NodeOfflineSeconds = NodeOfflineSeconds,
        NodeReadTimeoutSeconds = NodeReadTimeoutSeconds,
        CauseStabilityFlappingThreshold = CauseStabilityFlappingThreshold,
        MaxFilesPerDirectory = MaxFilesPerDirectory,
        MaxBytesPerFile = MaxBytesPerFile,
        MaxTotalBytes = MaxTotalBytes,
        MaxEvents = MaxEvents,
        MaxFilesPerDirectoryIncremental = MaxFilesPerDirectoryIncremental,
        MaxBytesPerFileIncremental = MaxBytesPerFileIncremental,
        MaxTotalBytesIncremental = MaxTotalBytesIncremental,
        MaxEventsIncremental = MaxEventsIncremental
    };

    private EmailNotificationSettings BuildEmailSettings() => new()
    {
        Enabled = EmailEnabled,
        SmtpHost = EmailSmtpHost,
        SmtpPort = EmailSmtpPort,
        UseTls = EmailUseTls,
        UserName = EmailUserName,
        FromAddress = EmailFromAddress,
        Recipients = EmailNotificationSettingsStore.ParseRecipients(EmailRecipients),
        MinimumSeverity = EmailMinimumSeverity,
        NotifyOpened = EmailNotifyOpened,
        NotifyEscalated = EmailNotifyEscalated,
        NotifyRecovered = EmailNotifyRecovered,
        TimeoutSeconds = EmailTimeoutSeconds
    };

    private void ApplyEmailSettings(EmailNotificationSettings settings)
    {
        EmailEnabled = settings.Enabled;
        EmailSmtpHost = settings.SmtpHost;
        EmailSmtpPort = settings.SmtpPort;
        EmailUseTls = settings.UseTls;
        EmailUserName = settings.UserName;
        EmailFromAddress = settings.FromAddress;
        EmailRecipients = string.Join("; ", settings.Recipients);
        EmailMinimumSeverity = settings.MinimumSeverity;
        EmailNotifyOpened = settings.NotifyOpened;
        EmailNotifyEscalated = settings.NotifyEscalated;
        EmailNotifyRecovered = settings.NotifyRecovered;
        EmailTimeoutSeconds = settings.TimeoutSeconds;
    }

    private void ApplyThresholds(SupportThresholds t)
    {
        CpuWarning = t.CpuWarning;
        CpuCritical = t.CpuCritical;
        MemoryWarning = t.MemoryUsedWarning;
        MemoryCritical = t.MemoryUsedCritical;
        SessionWarning = t.SessionWarning;
        SessionCritical = t.SessionCritical;
        ServiceChangesWarning = t.ServiceChangesWarning;
        ServiceChangesCritical = t.ServiceChangesCritical;
        TdmCpuWarning = t.TdmCpuWarning;
        TdmCpuCritical = t.TdmCpuCritical;
        TdmRamWarning = t.TdmMemoryWarningPercent;
        TdmRamCritical = t.TdmMemoryCriticalPercent;
        TdmHandlesWarning = t.TdmHandlesWarning;
        TdmHandlesCritical = t.TdmHandlesCritical;
        TdmThreadsWarning = t.TdmThreadsWarning;
        TdmThreadsCritical = t.TdmThreadsCritical;
        IncidentCooldownSeconds = t.IncidentCooldownSeconds;
        IncidentRecoverySamples = t.IncidentRecoveryConfirmSamples;
        ClockDriftSeconds = t.ClockDriftWarningSeconds;
        NodeStaleSeconds = t.NodeStaleWarningSeconds;
        NodeOfflineSeconds = t.NodeOfflineSeconds;
        NodeReadTimeoutSeconds = t.NodeReadTimeoutSeconds;
        CauseStabilityFlappingThreshold = t.CauseStabilityFlappingThreshold;
        MaxFilesPerDirectory = t.MaxFilesPerDirectory;
        MaxBytesPerFile = t.MaxBytesPerFile;
        MaxTotalBytes = t.MaxTotalBytes;
        MaxEvents = t.MaxEvents;
        MaxFilesPerDirectoryIncremental = t.MaxFilesPerDirectoryIncremental;
        MaxBytesPerFileIncremental = t.MaxBytesPerFileIncremental;
        MaxTotalBytesIncremental = t.MaxTotalBytesIncremental;
        MaxEventsIncremental = t.MaxEventsIncremental;
    }
}
