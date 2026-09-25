namespace TDM.Models;

public enum GuidedResolutionState
{
    Saludable,
    Informativo,
    Advertencia,
    Error,
    NoEvaluado,
    NoAplica
}

public sealed record GuidedResolutionCheck(
    string Nombre,
    string Estado,
    string Detalle,
    DiagnosticSeverity Severidad = DiagnosticSeverity.Informativo);

public sealed record GuidedResolutionResult(
    TsplusProduct Producto,
    string Componente,
    GuidedResolutionState Estado,
    DiagnosticSeverity Severidad,
    ConfidenceLevel Confianza,
    string Sintoma,
    string CausaProbable,
    string Impacto,
    IReadOnlyList<GuidedResolutionCheck> Comprobaciones,
    IReadOnlyList<EvidenceItem> Evidencia,
    IReadOnlyList<string> ComoCorregir,
    IReadOnlyList<string> ComoValidar,
    IReadOnlyList<string> NoHacerPrimero,
    string FuenteOficial,
    string UrlOficial,
    string Cobertura);
