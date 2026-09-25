using System;
using System.Collections.Generic;
using System.Diagnostics.Tracing;
using System.Threading;
using System.Threading.Tasks;
using TDM.Core;
using TDM.Models;

namespace TDM.Collectors.Windows;

/// <summary>
/// P2-01: Optional ETW provider for sub-second RDP transition tracking.
/// Uses EventSource/EventListener for real-time RDP session monitoring.
/// Only activates when explicitly enabled via DiagnosticContext.Options.
/// </summary>
public sealed class RdpEtwCollector : IReadOnlyCollector
{
    public string Nombre => "RDP ETW Transitions (sub-segundo)";

    private readonly object _sync = new();
    private readonly List<DiagnosticEvent> _events = new();
    private readonly List<DiagnosticFinding> _findings = new();
    private EventListener? _listener;
    private CancellationTokenSource? _cts;

    public Task<CollectorResult> CollectAsync(DiagnosticContext context, CancellationToken cancellationToken = default)
    {
        var findings = new List<DiagnosticFinding>();
        var events = new List<DiagnosticEvent>();
        var coverage = new List<EvidenceItem>();

        // P2-ETW: Auto-enable when running as Admin, unless explicitly disabled
        var explicitEtw = context.Options?.EnableRdpEtw;
        var isAdmin = IsRunningAsAdmin();
        var enableEtw = explicitEtw ?? isAdmin; // auto-enable on admin, respect explicit false

        if (!enableEtw)
        {
            coverage.Add(new EvidenceItem("ETW RDP", "Deshabilitado (opcional)"));
            return Task.FromResult(new CollectorResult(findings, events));
        }

        // Check if running as admin (required for ETW)
        if (!isAdmin)
        {
            findings.Add(new DiagnosticFinding(
                "RDP-ETW-NO-ADMIN", "RDP ETW", DiagnosticSeverity.Advertencia,
                "ETW RDP requiere privilegios de administrador",
                "El collector ETW no se activó. Ejecute TDM como administrador para habilitar trazas sub-segundo.",
                [new EvidenceItem("Requerido", "Admin"), new EvidenceItem("Estado", "Deshabilitado")],
                ConfidenceLevel.Alta, Capa: DiagnosticLayer.Rdp));
            coverage.Add(new EvidenceItem("ETW RDP", "Deshabilitado (sin admin)"));
            return Task.FromResult(new CollectorResult(findings, events));
        }

        coverage.Add(new EvidenceItem("ETW RDP", explicitEtw == true ? "Activo (explícito)" : "Activo (auto-admin)"));

        try
        {
            _cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            _listener = new RdpEtwListener(_events, _findings, _sync);
            // Enable events for known RDP ETW providers
            foreach (var source in EventSource.GetSources())
            {
                var name = source.Name;
                if (name == "Microsoft-Windows-TerminalServices-LocalSessionManager" ||
                    name == "Microsoft-Windows-TerminalServices-RemoteConnectionManager" ||
                    name == "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS")
                {
                    _listener.EnableEvents(source, EventLevel.Verbose, EventKeywords.All);
                }
            }

            coverage.Add(new EvidenceItem("ETW RDP", "Activo (sub-segundo)"));
            coverage.Add(new EvidenceItem("Proveedor", "Microsoft-Windows-TerminalServices-LocalSessionManager"));
            coverage.Add(new EvidenceItem("Eventos capturados", "0 (en tiempo real)"));
        }
        catch (Exception ex)
        {
            findings.Add(new DiagnosticFinding(
                "RDP-ETW-FAILED", "RDP ETW", DiagnosticSeverity.Advertencia,
                "No se pudo inicializar el listener ETW para RDP",
                ex.Message,
                [new EvidenceItem("Error", ex.Message)],
                ConfidenceLevel.Media, Capa: DiagnosticLayer.Rdp));
            coverage.Add(new EvidenceItem("ETW RDP", "Error: " + ex.Message));
        }

        return Task.FromResult(new CollectorResult(findings, events));
    }

    public void Dispose()
    {
        try
        {
            _cts?.Cancel();
            _listener?.Dispose();
        }
        catch { }
    }

    private static bool IsRunningAsAdmin()
    {
        try
        {
            using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            var principal = new System.Security.Principal.WindowsPrincipal(identity);
            return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }
        catch { return false; }
    }

    private sealed class RdpEtwListener : EventListener
    {
        private readonly List<DiagnosticEvent> _events;
        private readonly List<DiagnosticFinding> _findings;
        private readonly object _sync;

        public RdpEtwListener(List<DiagnosticEvent> events, List<DiagnosticFinding> findings, object sync)
        {
            _events = events;
            _findings = findings;
            _sync = sync;
        }

        protected override void OnEventSourceCreated(EventSource eventSource)
        {
            if (eventSource.Name == "Microsoft-Windows-TerminalServices-LocalSessionManager" ||
                eventSource.Name == "Microsoft-Windows-TerminalServices-RemoteConnectionManager" ||
                eventSource.Name == "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS")
            {
                EnableEvents(eventSource, EventLevel.Verbose);
            }
        }

        protected override void OnEventWritten(EventWrittenEventArgs eventData)
        {
            try
            {
                if (eventData.EventId is 21 or 22 or 23 or 24 or 25 or 1149)
            {
                var timestamp = DateTimeOffset.Now;
                var layer = DiagnosticLayer.Rdp;
                var severity = DiagnosticSeverity.Informativo;

                var taskName = eventData.EventName ?? $"Event_{eventData.EventId}";
                var message = $"RDP Event: {taskName} (ID: {eventData.EventId})";

                // Extract payload if available
                if (eventData.Payload?.Count > 0)
                {
                    var payload = string.Join(", ", eventData.Payload);
                    message += $" | Payload: {payload}";
                }

                var evidence = new List<EvidenceItem>
                {
                    new("Canal", eventData.EventSource.Name),
                    new("EventID", eventData.EventId.ToString()),
                    new("Task", taskName),
                    new("Timestamp", timestamp.ToString("O"))
                };

                // Add payload as evidence
                if (eventData.Payload?.Count > 0)
                {
                    for (int i = 0; i < eventData.Payload.Count; i++)
                    {
                        var name = eventData.PayloadNames?.Count > i ? eventData.PayloadNames[i] : $"Arg{i}";
                        evidence.Add(new EvidenceItem(name, eventData.Payload[i]?.ToString() ?? "null"));
                    }
                }

                var evt = new DiagnosticEvent(
                    timestamp,
                    "ETW RDP",
                    "TerminalServices",
                    layer,
                    severity,
                    $"ETW_RDP_{eventData.EventId}",
                    message,
                    Codigo: eventData.EventId.ToString(),
                    Archivo: "ETW",
                    Evidencia: evidence);

                lock (_sync)
                {
                    _events.Add(evt);
                }

                // Map known event IDs to diagnostic types
                var (diagType, diagSeverity) = MapEventId(eventData.EventId);
                if (diagSeverity >= DiagnosticSeverity.Advertencia)
                {
lock (_sync)
                {
                    _findings.Add(new DiagnosticFinding(
                        $"ETW-RDP-{eventData.EventId}",
                        "TerminalServices",
                        diagSeverity,
                        $"Transición RDP detectada vía ETW: {taskName}",
                        message,
                        [new EvidenceItem("EventID", eventData.EventId.ToString()), new EvidenceItem("Task", taskName)],
                        ConfidenceLevel.Alta,
                        Capa: DiagnosticLayer.Rdp));
                }
            }
        }
        }
        catch (EventSourceException ex)
        {
            // Event source disappeared or became invalid during processing
            // Log and continue - don't crash the listener
            _events.Add(new DiagnosticEvent(
                DateTimeOffset.Now,
                "ETW RDP",
                "TerminalServices",
                DiagnosticLayer.Rdp,
                DiagnosticSeverity.Advertencia,
                "ETW_EVENT_SOURCE_ERROR",
                $"Event source error while processing RDP ETW event: {ex.Message}",
                Codigo: "EventSourceException",
                Archivo: "ETW",
                Evidencia: [new EvidenceItem("Error", ex.Message), new EvidenceItem("Tipo", ex.GetType().Name)]));
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Unexpected error in ETW processing - log and continue
            _events.Add(new DiagnosticEvent(
                DateTimeOffset.Now,
                "ETW RDP",
                "TerminalServices",
                DiagnosticLayer.Rdp,
                DiagnosticSeverity.Advertencia,
                "ETW_PROCESSING_ERROR",
                $"Unexpected error processing RDP ETW event: {ex.Message}",
                Codigo: ex.GetType().Name,
                Archivo: "ETW",
                Evidencia: [new EvidenceItem("Error", ex.Message), new EvidenceItem("Tipo", ex.GetType().Name)]));
        }
    }

        private static (string DiagType, DiagnosticSeverity Severity) MapEventId(int eventId)
        {
            return eventId switch
            {
                21 => ("RDP_SESSION_LOGON_STAGE", DiagnosticSeverity.Informativo),
                22 => ("RDP_SHELL_START_STAGE", DiagnosticSeverity.Informativo),
                23 => ("RDP_SESSION_LOGOFF_STAGE", DiagnosticSeverity.Informativo),
                24 => ("RDP_SESSION_DISCONNECT_STAGE", DiagnosticSeverity.Advertencia),
                25 => ("RDP_SESSION_RECONNECT_STAGE", DiagnosticSeverity.Informativo),
                1149 => ("RDP_AUTHENTICATION_STAGE", DiagnosticSeverity.Advertencia),
                _ => ("RDP_EVENT_INCREMENTAL", DiagnosticSeverity.Informativo)
            };
        }
    }
}