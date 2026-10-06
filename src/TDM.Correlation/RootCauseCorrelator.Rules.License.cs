using TDM.Core;
using TDM.Models;

namespace TDM.Correlation;

public static partial class RootCauseCorrelator
{
    /// <summary>
    /// C3 (auditoría de efectividad, Fase 30): los eventos LICENSE de los logs TSplus se
    /// filtraban del pool causal (`Tipo != "LICENSE"` en Analyze) y ninguna regla los
    /// consumía por su cuenta, así que expiración/problema de licencia jamás llegaba a
    /// `CausasRaíz`. La regla sólo acepta eventos fechados dentro de la ventana con
    /// severidad Error/Crítico —la temporalidad documentada por TSplus (docs de activación
    /// y rehosting)— y nunca supera Media: no baja el listón de evidencia primaria del
    /// resto del pipeline.
    /// </summary>
    private static void AddLicenseCandidates(DiagnosticReport report, List<CandidateDraft> drafts)
    {
        var licenseErrors = report.Eventos
            .Where(e => e.Tipo.Equals("LICENSE", StringComparison.OrdinalIgnoreCase))
            .Where(e => e.Timestamp.HasValue)
            .Where(e => e.Severidad is DiagnosticSeverity.Error or DiagnosticSeverity.Critico)
            .Where(e => DiagnosticTimeWindow.IsEventInside(report, e.Timestamp!.Value))
            .OrderByDescending(e => e.Timestamp)
            .ToList();
        if (licenseErrors.Count == 0) return;

        var latest = licenseErrors[0];
        drafts.Add(new CandidateDraft(
            "ROOT-TSPLUS-LICENSE",
            "Licencia TSplus",
            DiagnosticLayer.Tsplus,
            76,
            ConfidenceLevel.Media,
            "TSplus registró eventos de licencia con severidad Error/Crítico dentro de la ventana.",
            "TDM detectó eventos de licencia fechados dentro del periodo analizado con severidad Error/Crítico. La condición de licencia es un estado operativo documentado por TSplus (activación y rehosting), pero el log por sí sólo no demuestra que provocó el incidente: valide el estado de la licencia, el problema de activación y la fecha de rehost en la consola TSplus antes de modificar otras capas.",
            Merge(
                latest.Evidencia ?? [],
                new EvidenceItem("Eventos de licencia en la ventana", licenseErrors.Count.ToString()),
                new EvidenceItem("Severidad del evento", latest.Severidad.ToString()),
                new EvidenceItem("Hora del evento", latest.Timestamp!.Value.ToLocalTime().ToString("dd/MM/yyyy HH:mm:ss"))),
            "TSPLUS-LICENSE",
            latest.Timestamp,
            "TSPLUS",
            latest.Producto is TsplusProduct.Ninguno or TsplusProduct.Desconocido
                ? TsplusProduct.RemoteAccess
                : latest.Producto));
    }
}
