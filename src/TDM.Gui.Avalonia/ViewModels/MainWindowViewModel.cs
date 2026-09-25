using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using TDM.Gui.Avalonia.Services;
using TDM.Notifications;

namespace TDM.Gui.Avalonia.ViewModels;

public partial class MainWindowViewModel : ObservableObject, IDisposable
{
    private readonly TelemetryReadService _telemetry = new();
    private readonly IntegratedMonitoringService _monitor = new();
    private readonly LiveResourceReadService _liveResources = new();
    private readonly CancellationTokenSource _lifetime = new();
    private bool _refreshPending;

    public SupportDashboardViewModel Support { get; } = new();
    public DiagnosticWorkspaceViewModel Diagnostics { get; } = new();
    public MultiServerDashboardViewModel MultiServer { get; } = new();
    public GeneralDashboardViewModel General { get; } = new();
    public PerformanceDashboardViewModel Performance { get; } = new();
    public TsplusDashboardViewModel Tsplus { get; } = new();
    public ServicesDashboardViewModel Services { get; } = new();
    public SessionsDashboardViewModel Sessions { get; } = new();
    public IncidentsDashboardViewModel Incidents { get; } = new();
    public CausalityDashboardViewModel Causality { get; } = new();
    public PreventiveDashboardViewModel Preventive { get; } = new();
    public TdmHealthDashboardViewModel TdmHealth { get; } = new();
    public AdministrationWorkspaceViewModel Administration { get; } = new();
    public LogsViewModel Logs { get; }
    public IReadOnlyList<string> PeriodOptions => _telemetry.PeriodOptions;

    [ObservableProperty] private string _selectedPeriod = "Tiempo real";
    [ObservableProperty] private bool _isLoading;
    [ObservableProperty] private string _statusMessage = "Inicializando TDM";
    [ObservableProperty] private string _dataSource = "Esperando telemetría";
    [ObservableProperty] private string _lastUpdated = "—";
    [ObservableProperty] private bool _isAdministrationOpen;

    public event Action<IReadOnlyList<IncidentNotification>>? PortableNotificationsProduced;

    public MainWindowViewModel()
{
    var logService = App.LogService ?? new LogService();
    Logs = new LogsViewModel(logService);
    Diagnostics.DiagnosticCompleted += Diagnostics_DiagnosticCompleted;
    _monitor.PortableNotificationsProduced += Monitor_PortableNotificationsProduced;
    Diagnostics.SelectedLookback = SelectedPeriod;
}

    public string ConfigurationButtonText => IsAdministrationOpen ? "Volver al panel" : "Configuración";
    public bool IsDashboardOpen => !IsAdministrationOpen;

    partial void OnSelectedPeriodChanged(string value)
    {
        if (!string.Equals(Diagnostics.SelectedLookback, value, StringComparison.Ordinal))
        {
            Diagnostics.SelectedLookback = value;
        }

        _ = RefreshAllAsync();
    }

    partial void OnIsAdministrationOpenChanged(bool value)
    {
        OnPropertyChanged(nameof(ConfigurationButtonText));
        OnPropertyChanged(nameof(IsDashboardOpen));
    }

    public async Task InitializeAsync()
    {
        await _monitor.InitializeAsync(_lifetime.Token);
        await Administration.InitializeAsync();
        await RefreshAllAsync();
    }

    public Task RefreshAsync() => RefreshAllAsync();

    private void Diagnostics_DiagnosticCompleted(object? sender, EventArgs e)
        => _ = RefreshAllAsync();

    private void Monitor_PortableNotificationsProduced(IReadOnlyList<IncidentNotification> notifications)
        => PortableNotificationsProduced?.Invoke(notifications);

    [RelayCommand]
    private void ToggleAdministration()
        => IsAdministrationOpen = !IsAdministrationOpen;

    [RelayCommand]
    private async Task RefreshFromToolbarAsync()
    {
        Diagnostics.ResetExecutionTimer();
        await RefreshAllAsync();
    }

    private async Task RefreshAllAsync()
    {
        if (IsLoading)
        {
            _refreshPending = true;
            return;
        }

        IsLoading = true;
        try
        {
            // Las tarjetas de procesos/discos no dependen del diagnóstico ni del store de telemetría.
            // Se refrescan primero para mantener su ciclo de 5 s incluso si la lectura histórica falla.
            var liveResources = await _liveResources.ReadAsync(_lifetime.Token);
            Performance.ApplyLiveResources(liveResources);

            var result = await _telemetry.ReadAsync(SelectedPeriod, _lifetime.Token);
            Support.Apply(result.Samples);
            MultiServer.Apply(result.CoordinatorName, result.FederationStatuses);
            General.Apply(result.Samples);
            Performance.Apply(result.Samples, liveResources);
            Tsplus.Apply(result.Samples);
            Services.Apply(result.Samples);
            Sessions.Apply(result.Samples);
            Incidents.Apply(result.Samples);
            Causality.Apply(result.Samples);
            Preventive.Apply(result.Samples, Administration.CurrentThresholds);
            TdmHealth.Apply(result.Samples, Administration.CurrentThresholds);

            DataSource = result.DataSource;
            LastUpdated = result.LastTimestamp?.ToLocalTime().ToString("dd/MM/yyyy HH:mm:ss") ?? "—";
            StatusMessage = result.Samples.Count == 0
                ? $"No hay muestras disponibles · {DashboardRules.ShortPath(result.RootPath)}"
                : $"{result.Samples.Count} muestra(s) · {SelectedPeriod} · {DashboardRules.ShortPath(result.RootPath)}";
        }
        catch (OperationCanceledException)
        {
            StatusMessage = "Actualización cancelada";
        }
        catch (UnauthorizedAccessException)
        {
            StatusMessage = "Sin permisos para leer la telemetría de máquina";
            DataSource = "Cobertura no disponible";
        }
        catch (Exception ex)
        {
            StatusMessage = $"No fue posible actualizar: {ex.Message}";
        }
        finally
        {
            IsLoading = false;
            if (_refreshPending)
            {
                _refreshPending = false;
                _ = RefreshAllAsync();
            }
        }
    }

    public void Dispose()
    {
        Diagnostics.DiagnosticCompleted -= Diagnostics_DiagnosticCompleted;
        _monitor.PortableNotificationsProduced -= Monitor_PortableNotificationsProduced;
        Diagnostics.Dispose();
        _monitor.Dispose();
        _lifetime.Cancel();
        _lifetime.Dispose();
    }
}
