using TDM.Core;
using TDM.Models;

namespace TDM.Collectors.Rdp;

public sealed class RdpHealthCollector : IReadOnlyCollector
{
    public string Nombre => "RDP Health";

    public Task<CollectorResult> CollectAsync(DiagnosticContext context, CancellationToken cancellationToken)
    {
        var snap = RdpStateReader.Capture();
        var findings = new List<DiagnosticFinding>();
        var events = new List<DiagnosticEvent>
        {
            new(
                DateTimeOffset.Now,
                "RDP Snapshot",
                "Remote Desktop Services",
                DiagnosticLayer.Rdp,
                snap.CoreStateComplete ? DiagnosticSeverity.Informativo : DiagnosticSeverity.Advertencia,
                DiagnosticEventTypes.RdpState,
                snap.CoreStateComplete
                    ? $"TermService={snap.TermServiceStatus}; Puerto={snap.ConfiguredPort}; Listening={snap.PortListening}; Sesiones={snap.Sessions.Count}"
                    : "El estado RDP quedó parcialmente no evaluado; las fuentes no legibles no se interpretan como falla ni como estado sano.",
                Evidencia:
                [
                    new EvidenceItem("TermService", snap.TermServiceEvaluated ? snap.TermServiceStatus : "No evaluado"),
                    new EvidenceItem("Puerto RDP configurado", snap.PortConfigurationEvaluated ? snap.ConfiguredPort.ToString() : "No evaluado"),
                    new EvidenceItem("Puerto escuchando", snap.ListenerEvaluated ? (snap.PortListening ? "Sí" : "No") : "No evaluado"),
                    new EvidenceItem("Sesiones WTS", snap.SessionsEvaluated ? snap.Sessions.Count.ToString() : "No evaluado"),
                    new EvidenceItem("Certificado RDP", DescribeCertificate(snap)),
                    new EvidenceItem("Cobertura", snap.CoreStateComplete ? "Completa" : "Parcial"),
                    new EvidenceItem("Limitaciones", snap.CoverageLimitations.Count == 0 ? "Ninguna" : string.Join(" | ", snap.CoverageLimitations))
                ])
        };

        // En una estación sin TSplus Remote Access, RDP deshabilitado puede ser totalmente intencional.
        if (!context.Sistema.TsplusDetectado)
            return Task.FromResult(new CollectorResult(findings, events));

        if (snap.TermServiceEvaluated && !string.Equals(snap.TermServiceStatus, "Running", StringComparison.OrdinalIgnoreCase))
        {
            findings.Add(new DiagnosticFinding(
                "RDP-TERMSERVICE-NOT-RUNNING",
                "Remote Desktop Services (TermService)",
                DiagnosticSeverity.Critico,
                "El servicio Remote Desktop Services no está en ejecución.",
                "TSplus Remote Access depende de la capacidad de Windows para crear y administrar sesiones remotas. Este hallazgo debe investigarse antes de atribuir la falla a TSplus.",
                [new EvidenceItem("Estado de TermService", snap.TermServiceStatus)],
                ConfidenceLevel.Alta,
                "Microsoft Learn",
                "https://learn.microsoft.com/troubleshoot/windows-server/remote/rdp-error-general-troubleshooting",
                "Revisar los eventos de Service Control Manager y Remote Desktop Services relacionados con TermService. TDM no inicia ni reinicia el servicio.",
                DiagnosticLayer.Rdp));
        }
        else if (snap.TermServiceEvaluated && snap.PortConfigurationEvaluated && snap.ListenerEvaluated && !snap.PortListening)
        {
            findings.Add(new DiagnosticFinding(
                "RDP-LISTENER-NOT-LISTENING",
                "RDP Listener",
                DiagnosticSeverity.Critico,
                $"TermService está en ejecución, pero no se detectó un listener TCP en el puerto RDP configurado ({snap.ConfiguredPort}).",
                "La discrepancia entre servicio activo y ausencia de listener apunta a la capa RDP/Windows y no demuestra una falla interna de TSplus.",
                [
                    new EvidenceItem("TermService", snap.TermServiceStatus),
                    new EvidenceItem("Puerto configurado", snap.ConfiguredPort.ToString()),
                    new EvidenceItem("Listener TCP", "No detectado")
                ],
                ConfidenceLevel.Alta,
                "Microsoft Learn",
                "https://learn.microsoft.com/troubleshoot/windows-server/remote/rdp-error-general-troubleshooting",
                "Validar los eventos de RDP, la configuración efectiva del listener y si otro cambio del sistema impidió que el puerto quede en escucha. TDM no modifica el Registro ni el firewall.",
                DiagnosticLayer.Rdp));
        }

        if (snap.CertificateConfigurationEvaluated && snap.CertificateStoreEvaluated && !string.IsNullOrWhiteSpace(snap.CertificateThumbprint) && !snap.CertificateFound)
        {
            findings.Add(new DiagnosticFinding(
                "RDP-CERTIFICATE-NOT-FOUND",
                "Certificado RDP",
                DiagnosticSeverity.Advertencia,
                "Existe una huella de certificado configurada para RDP, pero TDM no encontró el certificado correspondiente en los almacenes locales revisados.",
                "Esto puede afectar la negociación TLS del listener RDP. Debe correlacionarse con eventos Schannel/RDP antes de considerarlo causa raíz.",
                [new EvidenceItem("Thumbprint configurado", snap.CertificateThumbprint)],
                ConfidenceLevel.Media,
                "Microsoft Learn",
                "https://learn.microsoft.com/troubleshoot/windows-server/remote/rdp-error-general-troubleshooting",
                "Revisar el certificado asociado al listener y los eventos de TLS/Schannel. TDM no reemplaza ni vincula certificados.",
                DiagnosticLayer.Rdp));
        }
        else if (snap.CertificateNotAfter.HasValue)
        {
            var remaining = snap.CertificateNotAfter.Value - DateTimeOffset.Now;
            if (remaining <= TimeSpan.Zero)
            {
                findings.Add(new DiagnosticFinding(
                    "RDP-CERTIFICATE-EXPIRED",
                    "Certificado RDP",
                    DiagnosticSeverity.Critico,
                    "El certificado asociado al listener RDP está vencido.",
                    "Un certificado vencido puede provocar fallas TLS dependiendo de la configuración y del cliente.",
                    [
                        new EvidenceItem("Expiración", snap.CertificateNotAfter.Value.LocalDateTime.ToString("dd/MM/yyyy HH:mm:ss")),
                        new EvidenceItem("Sujeto", snap.CertificateSubject ?? "N/D")
                    ],
                    ConfidenceLevel.Alta,
                    "Microsoft Learn",
                    "https://learn.microsoft.com/troubleshoot/windows-server/remote/rdp-error-general-troubleshooting",
                    "Validar la configuración del certificado RDP y seguir el procedimiento oficial de Microsoft para corregir la asignación/certificado. TDM no modifica certificados.",
                    DiagnosticLayer.Rdp));
            }
            else if (remaining <= TimeSpan.FromDays(30))
            {
                var days = Math.Max(1, (int)Math.Ceiling(remaining.TotalDays));
                var severity = remaining <= TimeSpan.FromDays(7)
                    ? DiagnosticSeverity.Critico
                    : DiagnosticSeverity.Advertencia;
                var band = remaining <= TimeSpan.FromDays(7) ? "7" : remaining <= TimeSpan.FromDays(14) ? "14" : "30";
                findings.Add(new DiagnosticFinding(
                    $"RDP-CERTIFICATE-EXPIRING-{band}D",
                    "Certificado RDP",
                    severity,
                    $"El certificado asociado al listener RDP vencerá aproximadamente en {days} día(s).",
                    remaining <= TimeSpan.FromDays(7)
                        ? "La expiración es inminente. TDM eleva la señal como crítica preventiva para permitir renovación antes de afectar conexiones TLS."
                        : "TDM conserva esta señal preventiva para permitir renovación planificada antes del vencimiento.",
                    [
                        new EvidenceItem("Expiración", snap.CertificateNotAfter.Value.LocalDateTime.ToString("dd/MM/yyyy HH:mm:ss")),
                        new EvidenceItem("Días restantes", days.ToString()),
                        new EvidenceItem("Sujeto", snap.CertificateSubject ?? "N/D")
                    ],
                    ConfidenceLevel.Alta,
                    "Microsoft Learn",
                    "https://learn.microsoft.com/troubleshoot/windows-server/remote/rdp-error-general-troubleshooting",
                    "Programar la validación/renovación del certificado RDP antes de la fecha indicada. TDM no modifica certificados.",
                    DiagnosticLayer.Rdp));
            }
        }

        return Task.FromResult(new CollectorResult(findings, events));
    }
    private static string DescribeCertificate(RdpSnapshot snap)
    {
        if (!snap.CertificateConfigurationEvaluated) return "No evaluado: configuración del listener no legible";
        if (!snap.CertificateStoreEvaluated) return "No evaluado: almacén de certificados no legible";
        if (snap.CertificateFound) return "Encontrado";
        if (!string.IsNullOrWhiteSpace(snap.CertificateThumbprint)) return "Huella configurada; certificado no resuelto";
        return "No determinado (Windows puede administrar el certificado automáticamente)";
    }

}
