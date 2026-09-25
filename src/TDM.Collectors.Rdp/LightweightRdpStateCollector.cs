using TDM.Core;
using TDM.Models;

namespace TDM.Collectors.Rdp;

/// <summary>
/// Estado RDP/WTS para monitor continuo. No abre almacenes de certificados ni Event Log.
/// </summary>
public sealed class LightweightRdpStateCollector : IReadOnlyCollector
{
    public string Nombre => "RDP/WTS ligero";

    public Task<CollectorResult> CollectAsync(DiagnosticContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var snap = RdpStateReader.CaptureLightweight();
        var findings = new List<DiagnosticFinding>();
        var events = new List<DiagnosticEvent>();

        events.Add(new DiagnosticEvent(
            DateTimeOffset.Now,
            "RDP Snapshot ligero",
            "Remote Desktop Services",
            DiagnosticLayer.Rdp,
            !snap.CoreStateComplete
                ? DiagnosticSeverity.Advertencia
                : string.Equals(snap.TermServiceStatus, "Running", StringComparison.OrdinalIgnoreCase) && snap.PortListening
                    ? DiagnosticSeverity.Informativo
                    : DiagnosticSeverity.Error,
            DiagnosticEventTypes.RdpState,
            snap.CoreStateComplete
                ? $"TermService={snap.TermServiceStatus}; Puerto={snap.ConfiguredPort}; Listening={snap.PortListening}; Sesiones={snap.Sessions.Count}"
                : "Estado RDP ligero parcialmente no evaluado; TDM conserva la limitación de cobertura.",
            Evidencia:
            [
                new EvidenceItem("TermService", snap.TermServiceEvaluated ? snap.TermServiceStatus : "No evaluado"),
                new EvidenceItem("Puerto RDP configurado", snap.PortConfigurationEvaluated ? snap.ConfiguredPort.ToString() : "No evaluado"),
                new EvidenceItem("Puerto escuchando", snap.ListenerEvaluated ? (snap.PortListening ? "Sí" : "No") : "No evaluado"),
                new EvidenceItem("Sesiones WTS", snap.SessionsEvaluated ? snap.Sessions.Count.ToString() : "No evaluado"),
                new EvidenceItem("Cobertura", snap.CoreStateComplete ? "Completa" : "Parcial"),
                new EvidenceItem("Cobertura monitor", "SCM + Registro + IPGlobalProperties + WTS; sin Event Log/certificados"),
                new EvidenceItem("Limitaciones", snap.CoverageLimitations.Count == 0 ? "Ninguna" : string.Join(" | ", snap.CoverageLimitations))
            ]));

        var active = snap.Sessions.Count(x => x.State.Equals("Active", StringComparison.OrdinalIgnoreCase));
        var disconnected = snap.Sessions.Count(x => x.State.Equals("Disconnected", StringComparison.OrdinalIgnoreCase));
        events.Add(new DiagnosticEvent(
            DateTimeOffset.Now,
            "WTS",
            "Sesiones Windows",
            DiagnosticLayer.Rdp,
            snap.SessionsEvaluated ? DiagnosticSeverity.Informativo : DiagnosticSeverity.Advertencia,
            DiagnosticEventTypes.UserSessionInventory,
            snap.SessionsEvaluated ? $"Sesiones={snap.Sessions.Count}; activas={active}; desconectadas={disconnected}" : "Sesiones WTS no evaluadas en esta muestra.",
            Evidencia:
            [
                new EvidenceItem("Sesiones totales", snap.SessionsEvaluated ? snap.Sessions.Count.ToString() : "No evaluado"),
                new EvidenceItem("Sesiones activas", snap.SessionsEvaluated ? active.ToString() : "No evaluado"),
                new EvidenceItem("Sesiones desconectadas", snap.SessionsEvaluated ? disconnected.ToString() : "No evaluado"),
                new EvidenceItem("Identidades", "No recopiladas por monitor continuo")
            ]));

        if (context.Sistema.TsplusDetectado && snap.TermServiceEvaluated && !string.Equals(snap.TermServiceStatus, "Running", StringComparison.OrdinalIgnoreCase))
            findings.Add(new DiagnosticFinding(
                "MONITOR-RDP-TERMSERVICE",
                "Remote Desktop Services (TermService)",
                DiagnosticSeverity.Error,
                "El monitor detectó TermService fuera de estado Running.",
                "Se conserva como señal operativa. Ejecute un diagnóstico manual para obtener Event Log y causa raíz.",
                [new EvidenceItem("Estado", snap.TermServiceStatus)],
                ConfidenceLevel.Alta,
                Capa: DiagnosticLayer.Rdp));
        else if (context.Sistema.TsplusDetectado && snap.TermServiceEvaluated && snap.PortConfigurationEvaluated && snap.ListenerEvaluated && !snap.PortListening)
            findings.Add(new DiagnosticFinding(
                "MONITOR-RDP-LISTENER",
                "RDP Listener",
                DiagnosticSeverity.Error,
                "El monitor no detectó el listener RDP configurado.",
                "Se conserva como señal operativa. Ejecute un diagnóstico manual antes de atribuir causalidad.",
                [new EvidenceItem("Puerto", snap.ConfiguredPort.ToString())],
                ConfidenceLevel.Alta,
                Capa: DiagnosticLayer.Rdp));

        return Task.FromResult(new CollectorResult(findings, events));
    }
}
