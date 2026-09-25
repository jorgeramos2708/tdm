using Avalonia.Media;
using Avalonia.Threading;
using System.Collections.ObjectModel;
using System.Text;
using System.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using TDM.Gui.Avalonia.Services;
using TDM.Models;
using TDM.Persistence;

namespace TDM.Gui.Avalonia.ViewModels;

public sealed record DiagnosticEventItem(
    string Time,
    string Severity,
    string Origin,
    string Component,
    string Type,
    string Message,
    IBrush Accent);

public partial class DiagnosticWorkspaceViewModel : ObservableObject, IDisposable
{
    private readonly DiagnosticExecutionService _service = new();
    private readonly List<DiagnosticEvent> _allEvents = [];
    private CancellationTokenSource? _runCts;
    private DiagnosticReport? _report;
    private readonly ResumableExecutionClock _executionClock = new();
    private CancellationTokenSource? _executionClockCts;
    private TimeSpan? _executionLimit;
    private bool _automaticStopRequested;
    private bool _manualStopRequested;
    private static readonly TimeSpan DiagnosticCycleInterval = TimeSpan.FromSeconds(5);

    public IReadOnlyList<string> LookbackOptions => _service.LookbackOptions;
    public IReadOnlyList<string> SeverityOptions { get; } = ["Todos", "Crítico", "Error", "Advertencia", "Informativo"];
    public IReadOnlyList<string> OriginOptions { get; } = ["Todos", "Windows", "Rdp", "Red", "Seguridad", "Tsplus", "Desconocida"];
    public ObservableCollection<DiagnosticEventItem> Events { get; } = [];

    public event EventHandler? DiagnosticCompleted;
    public Func<CancellationToken, Task<string?>>? SelectExportDirectoryAsync { get; set; }
    public Action<string>? RevealExportedFile { get; set; }

    public DiagnosticWorkspaceViewModel()
    {
        UpdateExecutionLimitText();
    }

    [ObservableProperty] private string _selectedLookback = "Tiempo real";
    [ObservableProperty] private string _selectedSeverity = "Todos";
    [ObservableProperty] private string _selectedOrigin = "Todos";
    [ObservableProperty] private bool _isRunning;
    [ObservableProperty] private string _executionTimerText = "00:00:00";
    [ObservableProperty] private string _executionTimerLimitText = string.Empty;
    [ObservableProperty] private bool _hasReport;
    [ObservableProperty] private string _status = "Listo para ejecutar diagnóstico completo";
    [ObservableProperty] private string _summaryText = "Ejecuta un diagnóstico para ver el resumen técnico.";
    [ObservableProperty] private string _rootCauseText = "Sin análisis causal todavía.";
    [ObservableProperty] private string _actionPlanText = "Sin plan de acción todavía.";
    [ObservableProperty] private string _coverageText = "Sin evaluación de cobertura todavía.";
    [ObservableProperty] private string _patternsText = "Sin patrones analizados todavía.";
    [ObservableProperty] private string _guidedResolutionText = "Sin resolución guiada todavía.";
    [ObservableProperty] private string _exportStatus = "";
    [ObservableProperty] private string _feedbackNote = "";
    [ObservableProperty] private string _baselineStatus = "";
    [ObservableProperty] private bool _isBaselineIndicatorVisible;
    [ObservableProperty] private string _baselineIndicator = "SIN DIAGNÓSTICO";
    [ObservableProperty] private string _baselineIndicatorDetail = "Ejecuta un diagnóstico para evaluar el estado.";
    [ObservableProperty] private IBrush _baselineIndicatorAccent = DashboardPalette.Muted;
    [ObservableProperty] private IBrush _baselineIndicatorBackground = new SolidColorBrush(Color.FromArgb(28, 143, 163, 184));
    [ObservableProperty] private int _findingCount;
    [ObservableProperty] private int _eventCount;
    [ObservableProperty] private int _criticalCount;
    [ObservableProperty] private int _errorCount;
    [ObservableProperty] private double _eventTimeWidth = 120;
    [ObservableProperty] private double _eventSeverityWidth = 110;
    [ObservableProperty] private double _eventOriginWidth = 110;
    [ObservableProperty] private double _eventComponentWidth = 220;
    [ObservableProperty] private double _eventTypeWidth = 210;
    [ObservableProperty] private double _eventMessageWidth = 640;


    public bool CanStartDiagnostic => !IsRunning;
    public bool CanStopDiagnostic => IsRunning;
    public bool HasExportStatus => !string.IsNullOrWhiteSpace(ExportStatus);

    partial void OnSelectedLookbackChanged(string value)
    {
        if (IsRunning) return;
        UpdateExecutionLimitText();
    }

    partial void OnExportStatusChanged(string value)
        => OnPropertyChanged(nameof(HasExportStatus));

    partial void OnIsRunningChanged(bool value)
    {
        OnPropertyChanged(nameof(CanStartDiagnostic));
        OnPropertyChanged(nameof(CanStopDiagnostic));
    }

    partial void OnSelectedSeverityChanged(string value) => ApplyFilters();
    partial void OnSelectedOriginChanged(string value) => ApplyFilters();

    [RelayCommand]
    private async Task RunDiagnosticAsync()
    {
        if (IsRunning) return;

        _executionLimit = DiagnosticExecutionService.ExecutionLimitForPeriod(SelectedLookback);
        var elapsedBeforeStart = _executionClock.Elapsed;
        if (_executionLimit.HasValue && elapsedBeforeStart >= _executionLimit.Value)
        {
            ExecutionTimerText = FormatElapsed(_executionLimit.Value);
            Status = $"El periodo {SelectedLookback} ya se completó. Pulsa actualizar para reiniciar el cronómetro.";
            return;
        }

        _runCts?.Dispose();
        var runCts = new CancellationTokenSource();
        _runCts = runCts;
        _automaticStopRequested = false;
        _manualStopRequested = false;
        if (_executionLimit.HasValue)
            runCts.CancelAfter(_executionLimit.Value - elapsedBeforeStart);
        _executionClockCts?.Cancel();
        _executionClockCts?.Dispose();
        _executionClockCts = new CancellationTokenSource();
        _executionClock.Start();
        UpdateExecutionTimerText();
        UpdateExecutionLimitText();
        IsRunning = true;
        _ = RunExecutionClockAsync(_executionClockCts.Token);
        Status = string.Empty;
        ExportStatus = string.Empty;
        BaselineStatus = string.Empty;
        IsBaselineIndicatorVisible = true;
        BaselineIndicator = "EVALUANDO";
        BaselineIndicatorDetail = "Analizando hallazgos, eventos y cobertura...";
        BaselineIndicatorAccent = DashboardPalette.Muted;
        BaselineIndicatorBackground = new SolidColorBrush(Color.FromArgb(28, 143, 163, 184));

        try
        {
            DiagnosticReport? lastCompletedReport = null;
            var cycle = 0;

            while (!runCts.IsCancellationRequested)
            {
                cycle++;
                Status = string.Empty;

                var report = await Task.Run(() => _service.RunAsync(SelectedLookback, runCts.Token), runCts.Token);
                lastCompletedReport = report;
                _report = report;
                HasReport = true;
                ApplyReport(report);
                ApplyBaselineIndicator(report);
                DiagnosticCompleted?.Invoke(this, EventArgs.Empty);

                if (_manualStopRequested)
                    break;

                if (_executionLimit.HasValue && _executionClock.Elapsed >= _executionLimit.Value - TimeSpan.FromMilliseconds(250))
                {
                    _automaticStopRequested = true;
                    break;
                }

                var wait = DiagnosticCycleInterval;
                if (_executionLimit.HasValue)
                {
                    var remaining = _executionLimit.Value - _executionClock.Elapsed;
                    if (remaining <= TimeSpan.Zero)
                    {
                        _automaticStopRequested = true;
                        break;
                    }

                    if (remaining < wait)
                        wait = remaining;
                }

                Status = string.Empty;
                await Task.Delay(wait, runCts.Token);
            }

            if (_automaticStopRequested)
            {
                Status = $"Diagnóstico detenido automáticamente al alcanzar {SelectedLookback}.";
            }
            else if (_manualStopRequested)
            {
                Status = lastCompletedReport is not null
                    ? $"Diagnóstico detenido por el usuario · último ciclo completado {lastCompletedReport.Fin.ToLocalTime():HH:mm:ss}."
                    : "Diagnóstico detenido";
            }
            else if (lastCompletedReport is not null)
            {
                Status = $"Diagnóstico completado · {lastCompletedReport.Fin.ToLocalTime():HH:mm:ss} · {lastCompletedReport.RendimientoDiagnostico?.DuracionTotalMs / 1000d:0.0} s";
            }
        }
        catch (OperationCanceledException)
        {
            var reachedSelectedPeriod = !_manualStopRequested && _executionLimit.HasValue &&
                                        (_automaticStopRequested || _executionClock.Elapsed >= _executionLimit.Value - TimeSpan.FromMilliseconds(250));
            if (reachedSelectedPeriod) _automaticStopRequested = true;

            Status = reachedSelectedPeriod
                ? $"Diagnóstico detenido automáticamente al alcanzar {SelectedLookback}."
                : "Diagnóstico detenido";

            if (_report is null)
            {
                SetBaselineIndicator("NO EVALUADO",
                    reachedSelectedPeriod
                        ? $"Se alcanzó el periodo de ejecución de {SelectedLookback} antes de completar la evaluación."
                        : "El diagnóstico fue detenido antes de completar la evaluación.",
                    DashboardPalette.Muted, Color.FromArgb(28, 143, 163, 184));
            }
        }
        catch (UnauthorizedAccessException ex)
        {
            Status = "Diagnóstico parcial: acceso denegado a una fuente requerida";
            SummaryText = ex.Message;
            SetBaselineIndicator("ADVERTENCIA", "Cobertura parcial por acceso denegado; el estado no puede declararse sano.", DashboardPalette.Warn,
                Color.FromArgb(34, 255, 209, 102));
        }
        catch (Exception ex)
        {
            Status = "No fue posible completar el diagnóstico";
            SummaryText = ex.ToString();
            SetBaselineIndicator("ERROR", "El diagnóstico no pudo completarse; revise el detalle técnico.", DashboardPalette.Error,
                Color.FromArgb(34, 255, 138, 61));
        }
        finally
        {
            _executionClockCts?.Cancel();
            _executionClockCts?.Dispose();
            _executionClockCts = null;
            _executionClock.Pause();
            UpdateExecutionTimerText();
            IsRunning = false;
        }
    }

    [RelayCommand]
    private void CancelDiagnostic()
    {
        _manualStopRequested = true;
        Status = "Deteniendo diagnóstico...";
        _runCts?.Cancel();
    }

    [RelayCommand]
    private async Task ExportReportAsync()
    {
        if (_report is null)
        {
            ExportStatus = "Ejecuta un diagnóstico antes de exportar.";
            return;
        }

        try
        {
            string? selectedDirectory = null;
            if (SelectExportDirectoryAsync is not null)
            {
                selectedDirectory = await SelectExportDirectoryAsync(CancellationToken.None);
                if (string.IsNullOrWhiteSpace(selectedDirectory))
                {
                    ExportStatus = "Exportación cancelada.";
                    return;
                }
            }

            var result = selectedDirectory is null
                ? await _service.ExportAsync(_report, CancellationToken.None)
                : await _service.ExportAsync(_report, selectedDirectory, CancellationToken.None);

            if (!File.Exists(result.HtmlPath) || new FileInfo(result.HtmlPath).Length == 0 ||
                !File.Exists(result.JsonPath) || new FileInfo(result.JsonPath).Length == 0)
                throw new IOException("Los archivos del reporte no se generaron correctamente.");

            ExportStatus = $"Reporte guardado: {result.HtmlPath}";
            try
            {
                RevealExportedFile?.Invoke(result.HtmlPath);
            }
            catch
            {
                // El reporte ya quedó guardado; un fallo al abrir Explorer no invalida la exportación.
            }
        }
        catch (Exception ex)
        {
            ExportStatus = "No fue posible exportar: " + ex.Message;
        }
    }

    // Productor del loop de aprendizaje: registra el veredicto del técnico sobre la
    // causa principal en la raíz de máquina (la misma que lee el servicio). Sin causa
    // principal o sin acceso, informa en Status sin tumbar nada.
    [RelayCommand]
    private async Task ConfirmPrimaryCauseAsync() => await RecordPrimaryVerdictAsync(FeedbackVerdict.Confirmada);

    [RelayCommand]
    private async Task DiscardPrimaryCauseAsync() => await RecordPrimaryVerdictAsync(FeedbackVerdict.Descartada);

    private async Task RecordPrimaryVerdictAsync(FeedbackVerdict verdict)
    {
        var primary = _report?.CausaRaizPrincipal;
        if (primary is null)
        {
            Status = "Sin causa principal en el reporte actual; ejecute un diagnóstico primero.";
            return;
        }
        try
        {
            var store = new DiagnosticFeedbackStore(TdmDataPaths.MachineRootPath);
            var recorded = await store.RecordAsync(
                primary.Id, primary.Componente, primary.Puntaje, primary.Confianza.ToString(), verdict,
                string.IsNullOrWhiteSpace(FeedbackNote) ? null : FeedbackNote.Trim(), Environment.UserName);
            Status = $"Veredicto registrado: {(verdict == FeedbackVerdict.Confirmada ? "Confirmada" : "Descartada")} para {primary.Id} ({recorded.Id}). Aplica al ranking desde la próxima muestra.";
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _ = ex;
            Status = "No se pudo registrar (sin acceso a la raíz de máquina; ejecute como administrador).";
        }
    }

    [RelayCommand]
    private async Task SaveHealthyBaselineAsync()
    {
        if (_report is null)
        {
            BaselineStatus = "Ejecuta un diagnóstico antes de establecer el baseline.";
            return;
        }

        try
        {
            var result = await _service.SaveBaselineAsync(_report, CancellationToken.None);
            BaselineStatus = result.Message;
        }
        catch (UnauthorizedAccessException)
        {
            BaselineStatus = "Sin permisos para modificar el baseline compartido.";
        }
        catch (Exception ex)
        {
            BaselineStatus = "No fue posible guardar el baseline: " + ex.Message;
        }
    }


    private async Task RunExecutionClockAsync(CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested)
            {
                await Dispatcher.UIThread.InvokeAsync(() =>
                {
                    UpdateExecutionTimerText();
                    if (!IsRunning || !_executionLimit.HasValue || _executionClock.Elapsed < _executionLimit.Value)
                        return;

                    _automaticStopRequested = true;
                    Status = $"Periodo cumplido · deteniendo diagnóstico ({SelectedLookback})...";
                    _runCts?.Cancel();
                });

                await Task.Delay(TimeSpan.FromSeconds(1), ct);
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
        }
    }

    private void UpdateExecutionTimerText()
    {
        var elapsed = _executionClock.Elapsed;
        if (_executionLimit.HasValue && elapsed > _executionLimit.Value)
            elapsed = _executionLimit.Value;
        ExecutionTimerText = FormatElapsed(elapsed);
    }

    public void ResetExecutionTimer()
    {
        _executionClock.Reset(IsRunning);
        _automaticStopRequested = false;
        if (IsRunning && _executionLimit.HasValue && _runCts is { IsCancellationRequested: false })
            _runCts.CancelAfter(_executionLimit.Value);
        UpdateExecutionTimerText();
    }

    private void UpdateExecutionLimitText()
    {
        var limit = IsRunning ? _executionLimit : DiagnosticExecutionService.ExecutionLimitForPeriod(SelectedLookback);
        ExecutionTimerLimitText = limit.HasValue
            ? $"Periodo: {FormatElapsed(limit.Value)}"
            : string.Empty;
    }

    private static string FormatElapsed(TimeSpan value)
    {
        if (value.TotalDays >= 1)
            return $"{(int)value.TotalDays}d {value.Hours:00}:{value.Minutes:00}:{value.Seconds:00}";
        return $"{(int)value.TotalHours:00}:{value.Minutes:00}:{value.Seconds:00}";
    }

    private void ApplyBaselineIndicator(DiagnosticReport report)
    {
        // El indicador usa los hallazgos curados del diagnóstico, no cada evento crudo del sistema,
        // para evitar colorear el estado por ruido de Event Viewer que no fue promovido como falla funcional.
        var critical = report.Hallazgos.Count(x => x.Severidad == DiagnosticSeverity.Critico);
        var errors = report.Hallazgos.Count(x => x.Severidad == DiagnosticSeverity.Error);
        var warnings = report.Hallazgos.Count(x => x.Severidad == DiagnosticSeverity.Advertencia);

        if (critical > 0)
        {
            SetBaselineIndicator("CRÍTICO", $"{critical} señal(es) crítica(s) detectada(s).", DashboardPalette.Danger,
                Color.FromArgb(34, 255, 77, 79));
            return;
        }

        if (errors > 0)
        {
            SetBaselineIndicator("ERROR", $"{errors} señal(es) de error detectada(s).", DashboardPalette.Error,
                Color.FromArgb(34, 255, 138, 61));
            return;
        }

        if (warnings > 0)
        {
            SetBaselineIndicator("ADVERTENCIA", $"{warnings} advertencia(s) requieren revisión.", DashboardPalette.Warn,
                Color.FromArgb(34, 255, 209, 102));
            return;
        }

        var assessment = _service.AssessBaseline(report);
        if (!assessment.Eligible)
        {
            SetBaselineIndicator("ADVERTENCIA", assessment.Reason, DashboardPalette.Warn,
                Color.FromArgb(34, 255, 209, 102));
            return;
        }

        SetBaselineIndicator("SANO", "Sin advertencias, errores ni críticos en la evaluación actual.", DashboardPalette.Good,
            Color.FromArgb(34, 103, 232, 165));
    }

    private void SetBaselineIndicator(string status, string detail, IBrush accent, Color background)
    {
        IsBaselineIndicatorVisible = true;
        BaselineIndicator = status;
        BaselineIndicatorDetail = detail;
        BaselineIndicatorAccent = accent;
        BaselineIndicatorBackground = new SolidColorBrush(background);
    }

    private void ApplyReport(DiagnosticReport report)
    {
        FindingCount = report.Hallazgos.Count;
        EventCount = report.Eventos.Count;
        CriticalCount = report.Hallazgos.Count(x => x.Severidad == DiagnosticSeverity.Critico) +
                        report.Eventos.Count(x => x.Severidad == DiagnosticSeverity.Critico);
        ErrorCount = report.Hallazgos.Count(x => x.Severidad == DiagnosticSeverity.Error) +
                     report.Eventos.Count(x => x.Severidad == DiagnosticSeverity.Error);

        SummaryText = BuildSummary(report);
        RootCauseText = BuildRootCause(report);
        ActionPlanText = BuildActionPlan(report);
        CoverageText = BuildCoverage(report);
        PatternsText = BuildPatterns(report);
        GuidedResolutionText = BuildGuidedResolution(report);

        _allEvents.Clear();
        _allEvents.AddRange(report.Eventos.OrderByDescending(x => x.Timestamp ?? DateTimeOffset.MinValue));
        ApplyFilters();
    }

    private void ApplyFilters()
    {
        Events.Clear();
        foreach (var item in _allEvents.Where(MatchesSeverity).Where(MatchesOrigin).Take(500))
        {
            Events.Add(new DiagnosticEventItem(
                item.Timestamp?.ToLocalTime().ToString("dd/MM HH:mm:ss") ?? "—",
                SeverityLabel(item.Severidad),
                item.Capa.ToString(),
                item.Componente,
                item.Tipo,
                item.Mensaje,
                SeverityBrush(item.Severidad)));
        }
    }

    private bool MatchesSeverity(DiagnosticEvent item)
    {
        if (SelectedSeverity == "Todos") return true;
        return SelectedSeverity switch
        {
            "Crítico" => item.Severidad == DiagnosticSeverity.Critico,
            "Error" => item.Severidad == DiagnosticSeverity.Error,
            "Advertencia" => item.Severidad == DiagnosticSeverity.Advertencia,
            "Informativo" => item.Severidad == DiagnosticSeverity.Informativo,
            _ => true
        };
    }

    private bool MatchesOrigin(DiagnosticEvent item)
        => SelectedOrigin == "Todos" || item.Capa.ToString().Equals(SelectedOrigin, StringComparison.OrdinalIgnoreCase);

    private static string SeverityLabel(DiagnosticSeverity value)
        => value == DiagnosticSeverity.Critico ? "Crítico" : value.ToString();

    private static IBrush SeverityBrush(DiagnosticSeverity value)
        => value switch
        {
            DiagnosticSeverity.Critico => DashboardPalette.Danger,
            DiagnosticSeverity.Error => DashboardPalette.Error,
            DiagnosticSeverity.Advertencia => DashboardPalette.Warn,
            DiagnosticSeverity.Informativo => DashboardPalette.Info,
            _ => DashboardPalette.Muted
        };

    private static string BuildSummary(DiagnosticReport report)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"Equipo: {report.Sistema.Equipo}");
        sb.AppendLine($"Sistema: {report.Sistema.SistemaOperativo} {report.Sistema.Version} | build: {report.Sistema.Build} | arquitectura: {report.Sistema.Arquitectura}");
        sb.AppendLine($"TSplus: {(report.Sistema.TsplusDetectado ? $"Detectado | versión: {report.Sistema.TsplusVersion ?? "N/D"}" : "No detectado")}");
        sb.AppendLine($"Ventana: {report.PeriodoAnalizadoInicio.ToLocalTime():dd/MM HH:mm} – {report.PeriodoAnalizadoFin.ToLocalTime():dd/MM HH:mm}");
        sb.AppendLine($"Hallazgos: {report.Hallazgos.Count} | Eventos: {report.Eventos.Count}");
        if (report.ImpactoFuncional is not null)
            sb.AppendLine($"Impacto funcional: {report.ImpactoFuncional.EstadoGeneral} | detalle: {report.ImpactoFuncional.Resumen}");
        if (report.PrecisionDiagnostica is not null)
            sb.AppendLine($"Precisión diagnóstica: {report.PrecisionDiagnostica.Score}/100 | nivel: {report.PrecisionDiagnostica.Nivel}");
        if (report.RendimientoDiagnostico is not null)
            sb.AppendLine($"Duración: {report.RendimientoDiagnostico.DuracionTotalMs / 1000d:0.0} s | collectors: {report.RendimientoDiagnostico.CollectorsEjecutados} | timeout: {report.RendimientoDiagnostico.CollectorsConTimeout} | error: {report.RendimientoDiagnostico.CollectorsConError}");

        var serious = report.Hallazgos
            .Where(x => x.Severidad is DiagnosticSeverity.Critico or DiagnosticSeverity.Error or DiagnosticSeverity.Advertencia)
            .OrderByDescending(x => x.Severidad)
            .Take(10)
            .ToList();
        if (serious.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine("Hallazgos destacados:");
            foreach (var finding in serious)
                sb.AppendLine($"Severidad: {SeverityLabel(finding.Severidad)} | Componente: {finding.Componente} | Resumen: {finding.Resumen}");
        }
        return sb.ToString().TrimEnd();
    }

    private static string BuildRootCause(DiagnosticReport report)
    {
        if (report.CausasRaiz.Count == 0)
            return "No existe evidencia suficiente para proponer una causa raíz con el criterio actual.";

        var sb = new StringBuilder();
        foreach (var cause in report.CausasRaiz.Take(8))
        {
            sb.AppendLine($"Posición: {cause.Posicion} | Componente: {cause.Componente} | Puntaje: {cause.Puntaje} | Confianza: {cause.Confianza} | Origen: {cause.OrigenClasificado}");
            sb.AppendLine($"Resumen: {cause.Resumen}");
            sb.AppendLine($"Explicación: {cause.Explicacion}");
            if (!string.IsNullOrWhiteSpace(cause.SolucionSugerida)) sb.AppendLine("Sugerencia: " + cause.SolucionSugerida);
            sb.AppendLine();
        }
        return sb.ToString().TrimEnd();
    }

    private static string BuildActionPlan(DiagnosticReport report)
    {
        var plan = report.PlanAccion;
        if (plan is null) return "No se generó plan de acción.";

        var sb = new StringBuilder();
        sb.AppendLine($"Resumen: {plan.Resumen}");
        sb.AppendLine();
        sb.AppendLine("Dónde empezar:");
        foreach (var item in plan.DondeEmpezar) sb.AppendLine($"Orden: {item.Orden} | Acción: {item.Accion} | Motivo: {item.Motivo}");
        if (plan.Verificaciones.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine("Verificaciones:");
            foreach (var item in plan.Verificaciones) sb.AppendLine($"Orden: {item.Orden} | Acción: {item.Accion} | Motivo: {item.Motivo}");
        }
        if (plan.NoTocarPrimero.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine("No tocar primero:");
            foreach (var item in plan.NoTocarPrimero) sb.AppendLine($"Orden: {item.Orden} | Acción: {item.Accion} | Motivo: {item.Motivo}");
        }
        return sb.ToString().TrimEnd();
    }

    private static string BuildPatterns(DiagnosticReport report)
    {
        if (report.PatronesFalla.Count == 0) return "No se detectaron patrones de falla recurrentes en la ventana.";
        var sb = new StringBuilder();
        foreach (var pattern in report.PatronesFalla.Take(20))
        {
            sb.AppendLine($"Componente: {pattern.Componente} | Incidentes: {pattern.Incidentes} | Estado: {pattern.EstadoInvestigacion}");
            sb.AppendLine($"Origen: {pattern.OrigenClasificado} | Primera detección: {pattern.PrimeraDeteccion.ToLocalTime():dd/MM HH:mm:ss} | Última detección: {pattern.UltimaDeteccion.ToLocalTime():dd/MM HH:mm:ss}");
            if (pattern.IntervaloPromedio.HasValue) sb.AppendLine($"Intervalo promedio: {pattern.IntervaloPromedio.Value}");
            sb.AppendLine();
        }
        return sb.ToString().TrimEnd();
    }

    private static string BuildGuidedResolution(DiagnosticReport report)
    {
        if (report.ResolucionesGuiadas.Count == 0) return "No hay resolución guiada aplicable para la evidencia actual.";
        var sb = new StringBuilder();
        foreach (var item in report.ResolucionesGuiadas.Take(12))
        {
            sb.AppendLine($"Producto: {item.Producto} | Componente: {item.Componente} | Estado: {item.Estado} | Confianza: {item.Confianza}");
            sb.AppendLine("Síntoma: " + item.Sintoma);
            sb.AppendLine("Causa probable: " + item.CausaProbable);
            sb.AppendLine("Impacto: " + item.Impacto);
            if (item.ComoCorregir.Count > 0)
            {
                sb.AppendLine("Cómo corregir:");
                foreach (var step in item.ComoCorregir) sb.AppendLine("• " + step);
            }
            if (item.ComoValidar.Count > 0)
            {
                sb.AppendLine("Cómo validar:");
                foreach (var step in item.ComoValidar) sb.AppendLine("• " + step);
            }
            if (item.NoHacerPrimero.Count > 0)
            {
                sb.AppendLine("No hacer primero:");
                foreach (var step in item.NoHacerPrimero) sb.AppendLine("• " + step);
            }
            sb.AppendLine();
        }
        return sb.ToString().TrimEnd();
    }

    private static string BuildCoverage(DiagnosticReport report)
    {
        var coverage = report.CoberturaDiagnostica;
        if (coverage is null) return "Sin evaluación de cobertura.";

        var sb = new StringBuilder();
        sb.AppendLine($"Cobertura: {coverage.Score}/100 | Nivel: {coverage.Nivel}");
        sb.AppendLine($"Resumen: {coverage.Resumen}");
        sb.AppendLine();
        foreach (var source in coverage.Fuentes)
            sb.AppendLine($"Fuente: {source.Fuente} | Estado: {source.Estado} | Detalle: {source.Detalle}");
        if (coverage.Limitaciones.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine("Limitaciones:");
            foreach (var limitation in coverage.Limitaciones) sb.AppendLine("• " + limitation);
        }
        return sb.ToString().TrimEnd();
    }

    public void Dispose()
    {
        _executionClockCts?.Cancel();
        _executionClockCts?.Dispose();
        _executionClock.Pause();
        _runCts?.Cancel();
        _runCts?.Dispose();
    }
}
