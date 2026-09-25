using System;
using System.Collections.Generic;

namespace TDM.Core;

/// <summary>
/// Nivel de severidad del log.
/// </summary>
public enum LogLevel
{
    Debug = 0,
    Information = 1,
    Warning = 2,
    Error = 3,
    Critical = 4
}

/// <summary>
/// Sistema de origen del log para coloreo por procedencia.
/// </summary>
public enum LogSourceSystem
{
    Unknown = 0,
    Windows = 1,
    TSplus = 2,
    Other = 3
}

/// <summary>
/// Entrada de log estructurada con clasificación automática de sistema origen.
/// </summary>
public sealed record LogEntry(
    DateTimeOffset Timestamp,
    LogLevel Level,
    string Source,
    string? Component,
    string Message,
    Exception? Exception = null,
    IReadOnlyDictionary<string, string>? Context = null,
    LogSourceSystem SourceSystem = LogSourceSystem.Unknown,
    string? RawOrigin = null)
{
    /// <summary>
    /// Crea una entrada con clasificación automática de sistema origen.
    /// </summary>
    public static LogEntry Create(
        LogLevel level,
        string source,
        string? component,
        string message,
        Exception? exception = null,
        IReadOnlyDictionary<string, string>? context = null,
        string? rawOrigin = null)
    {
        var sourceSystem = LogSourceClassifier.Classify(source, component);
        return new LogEntry(
            DateTimeOffset.Now,
            level,
            source,
            component,
            message,
            exception,
            context,
            sourceSystem,
            rawOrigin);
    }

    /// <summary>
    /// Texto formateado para el badge de nivel.
    /// </summary>
    public string LevelText => Level switch
    {
        LogLevel.Critical => "CRIT",
        LogLevel.Error => "ERR",
        LogLevel.Warning => "WARN",
        LogLevel.Information => "INFO",
        LogLevel.Debug => "DBG",
        _ => Level.ToString().ToUpperInvariant()
    };

    /// <summary>
    /// Texto abreviado del sistema origen.
    /// </summary>
    public string SourceSystemText => SourceSystem switch
    {
        LogSourceSystem.TSplus => "TSPLUS",
        LogSourceSystem.Windows => "WIN",
        LogSourceSystem.Other => "OTRO",
        _ => "?"
    };

    /// <summary>
    /// Detalle completo para tooltip.
    /// </summary>
    public string FullDetail
    {
        get
        {
            var parts = new List<string>
            {
                $"[{Timestamp:yyyy-MM-dd HH:mm:ss.fff}]",
                $"[{LevelText}]",
                $"[{SourceSystemText}]",
                $"Source: {Source}"
            };
            if (!string.IsNullOrWhiteSpace(Component))
                parts.Add($"Component: {Component}");
            parts.Add($"Message: {Message}");
            if (Exception != null)
                parts.Add($"Exception: {Exception}");
            return string.Join(" | ", parts);
        }
    }
}

/// <summary>
/// Clasificador automático de sistema origen basado en source/component.
/// Reutiliza la lógica existente de DashboardRules.IsTsplusRootService.
/// </summary>
internal static class LogSourceClassifier
{
    private static readonly string[] TsplusMarkers =
    [
        "TSPLUS", "REMOTEACCESS", "REMOTE ACCESS", "REMOTESUPPORT", "REMOTE SUPPORT",
        "SERVERMONITORING", "SERVER MONITORING", "ADVANCED SECURITY", "TSPLUS-SECURITY",
        "APPLICATION PUBLISHING", "APSC", "WEBPORTAL", "HTML5", "TWOFACTOR", "TWO FACTOR",
        "2FA", "UNIVERSALPRINTER", "VIRTUALPRINTER", "FARM/GATEWAY", "FARM / GATEWAY"
    ];

    private static readonly string[] WindowsMarkers =
    [
        "WINDOWS", "WIN32", "SYSTEM", "SECURITY", "APPLICATION", "SERVICE",
        "EVENTLOG", "WMI", "REGISTRY", "SERVICECONTROLLER", "TERMSERVICE",
        "UMRDPSERVICE", "SESSIONENV", "RDP", "REMOTEDESKTOP"
    ];

    public static LogSourceSystem Classify(string? source, string? component)
    {
        var text = $"{source ?? ""} {component ?? ""}".ToUpperInvariant();

        if (TsplusMarkers.Any(m => text.Contains(m)))
            return LogSourceSystem.TSplus;

        if (WindowsMarkers.Any(m => text.Contains(m)))
            return LogSourceSystem.Windows;

        return string.IsNullOrWhiteSpace(text)
            ? LogSourceSystem.Unknown
            : LogSourceSystem.Other;
    }
}