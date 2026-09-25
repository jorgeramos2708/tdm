using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.IO;
using System.Linq;
using System.Reactive.Concurrency;
using System.Reactive.Linq;
using System.Reactive.Disposables;
using System.Threading;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;
using Avalonia.Platform.Storage;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using TDM.Core;
using TDM.Gui.Avalonia.Services;

// Alias to avoid namespace collision with TDM.Application
using AvaloniaApplication = Avalonia.Application;
using AvaloniaLifetimes = Avalonia.Controls.ApplicationLifetimes;

namespace TDM.Gui.Avalonia.ViewModels;

/// <summary>
/// ViewModel para un entry de log individual con propiedades computadas para coloreo dual.
/// </summary>
public sealed partial class LogEntryViewModel : ObservableObject
{
    public LogEntry Model { get; }

    public DateTimeOffset Timestamp => Model.Timestamp;
    public LogLevel Level => Model.Level;
    public string Source => Model.Source;
    public string? Component => Model.Component;
    public string Message => Model.Message;
    public Exception? Exception => Model.Exception;

    // Sistema origen (clasificado automáticamente)
    public LogSourceSystem SourceSystem => Model.SourceSystem;

    // --- ROW ACCENT (Source System based) ---
    // Left border + source badge color
    public IBrush RowAccent => SourceSystem switch
    {
        LogSourceSystem.TSplus => DashboardPalette.Cyan,
        LogSourceSystem.Windows => DashboardPalette.Info,
        LogSourceSystem.Other => DashboardPalette.Violet,
        _ => DashboardPalette.Muted
    };

    // Subtle row background tint (source-based)
    public IBrush RowBackground => SourceSystem switch
    {
        LogSourceSystem.TSplus => new SolidColorBrush(Color.FromArgb(25, 57, 208, 255)),
        LogSourceSystem.Windows => new SolidColorBrush(Color.FromArgb(20, 245, 250, 255)),
        LogSourceSystem.Other => new SolidColorBrush(Color.FromArgb(25, 167, 139, 250)),
        _ => new SolidColorBrush(Color.FromArgb(15, 143, 163, 184))
    };

    // --- LEVEL BADGE (Severity based) ---
    public IBrush LevelBrush => Level switch
    {
        LogLevel.Critical => DashboardPalette.Danger,
        LogLevel.Error => DashboardPalette.Error,
        LogLevel.Warning => DashboardPalette.Warn,
        LogLevel.Information => DashboardPalette.Info,
        LogLevel.Debug => DashboardPalette.Muted,
        _ => DashboardPalette.Muted
    };

    public string LevelText => Model.LevelText;
    public string SourceSystemText => Model.SourceSystemText;
    public IBrush SourceSystemBrush => RowAccent;
    public string FullDetail => Model.FullDetail;

    public LogEntryViewModel(LogEntry model)
    {
        Model = model;
    }
}

/// <summary>
/// ViewModel para la pestaña de Logs con filtrado, búsqueda y coloreo dual.
/// </summary>
public sealed partial class LogsViewModel : ObservableObject, IDisposable
{
    private readonly LogService _logService;
    private readonly CancellationTokenSource _cts = new();
    private readonly IDisposable _subscription;
    private readonly ObservableCollection<LogEntryViewModel> _allLogs = [];
    private readonly ObservableCollection<LogEntryViewModel> _filteredLogs = [];

    [ObservableProperty] private LogLevel? _selectedLevelFilter;
    [ObservableProperty] private LogSourceSystem? _selectedSourceSystemFilter;
    [ObservableProperty] private string _searchText = string.Empty;
    [ObservableProperty] private bool _autoScroll = true;
    [ObservableProperty] private int _totalCount;
    [ObservableProperty] private int _filteredCount;
    [ObservableProperty] private bool _isLoading;

    public IReadOnlyList<LogLevel> LevelFilterOptions { get; } =
    [
        LogLevel.Critical, LogLevel.Error, LogLevel.Warning,
        LogLevel.Information, LogLevel.Debug
    ];

    public IReadOnlyList<LogSourceSystem> SourceSystemFilterOptions { get; } =
    [
        LogSourceSystem.TSplus, LogSourceSystem.Windows,
        LogSourceSystem.Other, LogSourceSystem.Unknown
    ];

    public IReadOnlyList<LogEntryViewModel> FilteredLogs => _filteredLogs;

    public LogsViewModel(LogService logService)
    {
        _logService = logService;

        // Cargar snapshot inicial
        var snapshot = _logService.GetSnapshot();
        foreach (var entry in snapshot)
        {
            _allLogs.Add(new LogEntryViewModel(entry));
        }
        UpdateFiltered();

        // Suscribir a nuevos logs en tiempo real
        _subscription = _logService.Entries
            .Subscribe(entry =>
            {
                Dispatcher.UIThread.Post(() =>
                {
                    var vm = new LogEntryViewModel(entry);
                    _allLogs.Insert(0, vm);
                    UpdateFiltered();
                });
            });

        // Observar cambios en filtros
        PropertyChanged += (_, e) =>
        {
            if (e.PropertyName is nameof(SelectedLevelFilter)
                or nameof(SelectedSourceSystemFilter)
                or nameof(SearchText))
            {
                UpdateFiltered();
            }
        };

        // Mantener tamaño del buffer
        _allLogs.CollectionChanged += (_, e) =>
        {
            if (e.Action == NotifyCollectionChangedAction.Add && _allLogs.Count > 10000)
            {
                _allLogs.RemoveAt(_allLogs.Count - 1);
            }
        };
    }

    private void UpdateFiltered()
    {
        var query = _allLogs.AsEnumerable();

        if (SelectedLevelFilter.HasValue)
            query = query.Where(l => l.Level == SelectedLevelFilter.Value);

        if (SelectedSourceSystemFilter.HasValue)
            query = query.Where(l => l.SourceSystem == SelectedSourceSystemFilter.Value);

        if (!string.IsNullOrWhiteSpace(SearchText))
        {
            var search = SearchText.ToLowerInvariant();
            query = query.Where(l =>
                l.Message.ToLowerInvariant().Contains(search) ||
                l.Source.ToLowerInvariant().Contains(search) ||
                (l.Component?.ToLowerInvariant().Contains(search) ?? false) ||
                l.SourceSystemText.ToLowerInvariant().Contains(search));
        }

        _filteredLogs.Clear();
        foreach (var item in query.Take(5000))
        {
            _filteredLogs.Add(item);
        }

        FilteredCount = _filteredLogs.Count;
        TotalCount = _allLogs.Count;
    }

    [RelayCommand]
    private void ClearLogs()
    {
        _allLogs.Clear();
        UpdateFiltered();
    }

    [RelayCommand]
    private void ClearFilters()
    {
        SelectedLevelFilter = null;
        SelectedSourceSystemFilter = null;
        SearchText = string.Empty;
    }

    [RelayCommand]
    private async Task ExportAsync()
    {
        try
        {
            var window = AvaloniaApplication.Current?.ApplicationLifetime is AvaloniaLifetimes.IClassicDesktopStyleApplicationLifetime desktop
                ? desktop.MainWindow
                : null;

            if (window?.StorageProvider is null) return;

            var file = await window.StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions
            {
                Title = "Exportar logs",
                SuggestedFileName = $"tdm-logs-{DateTime.Now:yyyyMMdd-HHmmss}",
                FileTypeChoices = new[]
                {
                    new FilePickerFileType("CSV") { Patterns = ["*.csv"] },
                    new FilePickerFileType("JSON") { Patterns = ["*.json"] },
                    new FilePickerFileType("Texto") { Patterns = ["*.txt"] }
                }
            });

            if (file is null) return;

            var lines = _filteredLogs.Select(l => FormatExportLine(l)).ToArray();
            await using var stream = await file.OpenWriteAsync();
            await using var writer = new StreamWriter(stream);
            foreach (var line in lines)
                await writer.WriteLineAsync(line);
        }
        catch
        {
            // Log error
        }
    }

    private string FormatExportLine(LogEntryViewModel l)
    {
        var parts = new[]
        {
            l.Timestamp.ToString("yyyy-MM-dd HH:mm:ss.fff"),
            l.LevelText,
            l.SourceSystemText,
            l.Source,
            l.Component ?? "",
            $"\"{l.Message.Replace("\"", "\"\"")}\""
        };
        return string.Join(";", parts);
    }

    public void Dispose()
    {
        _subscription?.Dispose();
        _cts.Cancel();
        _cts.Dispose();
    }
}