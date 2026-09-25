namespace TDM.Models;

public enum DiagnosticSeverity
{
    Informativo = 0,
    Advertencia = 1,
    Error = 2,
    Critico = 3
}
public enum ConfidenceLevel { Confirmada, Alta, Media, Baja, EvidenciaInsuficiente }
public enum DiagnosticLayer { Windows, Rdp, Red, Seguridad, Tsplus, Desconocida }
public enum TsplusProduct { Ninguno, RemoteAccess, TwoFactorAuthentication, AdvancedSecurity, ServerMonitoring, RemoteSupport, Desconocido }
public enum ProductInstallationState { Instalado, NoInstalado, Indeterminado }
public enum LicenseActivationState { Activa, NoActivada, Expirada, ProblemaDetectado, Permanente, Suscripcion, Desconocida, NoAplica }
public enum ProductOperationalState { Operativo, NoOperativo, Parcial, Desconocido, NoAplica }
public enum ProductHealthState { Saludable, Advertencia, Falla, NoEvaluado }

public sealed record EvidenceItem(string Clave, string Valor);

/// <summary>
/// Perfil de release TSplus para parsing versionado de logs.
/// Definido aquí para evitar dependencia circular entre TDM.Models y TDM.Collectors.TSplus.
/// </summary>
public sealed record TsplusReleaseProfile(
    string Id,
    string Nombre,
    bool Soportado,
    string Motivo,
    IReadOnlyDictionary<string, string> ArchivosPrincipales);

public sealed record DiagnosticFinding(
    string Id,
    string Componente,
    DiagnosticSeverity Severidad,
    string Resumen,
    string Detalle,
    IReadOnlyList<EvidenceItem> Evidencia,
    ConfidenceLevel Confianza = ConfidenceLevel.EvidenciaInsuficiente,
    string? FuenteOficial = null,
    string? UrlOficial = null,
    string? SolucionSugerida = null,
    DiagnosticLayer Capa = DiagnosticLayer.Desconocida);

public sealed record DiagnosticEvent(
    DateTimeOffset? Timestamp,
    string Fuente,
    string Componente,
    DiagnosticLayer Capa,
    DiagnosticSeverity Severidad,
    string Tipo,
    string Mensaje,
    string? Codigo = null,
    string? Archivo = null,
    int? Linea = null,
    IReadOnlyList<EvidenceItem>? Evidencia = null,
    TsplusProduct Producto = TsplusProduct.Ninguno,
    DateTimeOffset? IngestedAt = null);

public sealed record RootCauseCandidate(
    int Posicion,
    string Id,
    string Componente,
    DiagnosticLayer Capa,
    int Puntaje,
    ConfidenceLevel Confianza,
    string Resumen,
    string Explicacion,
    IReadOnlyList<EvidenceItem> Evidencia,
    string? SolucionSugerida = null,
    string? FuenteOficial = null,
    string? UrlOficial = null,
    TsplusProduct Producto = TsplusProduct.Ninguno,
    DateTimeOffset? HoraIncidente = null,
    string OrigenClasificado = "INDETERMINADO",
    string RolCausal = "CAUSA_CANDIDATA");



public sealed record DiagnosticPrecisionAssessment(
    int Score,
    string Nivel,
    bool CoberturaCompleta,
    int FuentesBloqueadas,
    int SenalesCausales,
    int EventosContexto,
    int EvidenciaSinTimestamp,
    bool OrigenEnConflicto,
    bool EvidenciaPrimariaIndependiente,
    string Resumen,
    IReadOnlyList<EvidenceItem> Evidencia);

public sealed record DiagnosticIncidentCluster(
    string Id,
    string Dominio,
    string Estado,
    DiagnosticSeverity SeveridadMaxima,
    DateTimeOffset Inicio,
    DateTimeOffset Fin,
    int Senales,
    int IncidentesOperativos,
    string Resumen,
    IReadOnlyList<string> Componentes,
    IReadOnlyList<EvidenceItem> Evidencia);


public sealed record FailurePattern(
    string Id,
    TsplusProduct Producto,
    string Componente,
    string ComponenteSemantico,
    string TipoExcepcion,
    string OrigenClasificado,
    string EstadoInvestigacion,
    int Incidentes,
    DateTimeOffset PrimeraDeteccion,
    DateTimeOffset UltimaDeteccion,
    TimeSpan? IntervaloPromedio,
    IReadOnlyList<string> IdsIncidente,
    IReadOnlyList<EvidenceItem> Evidencia);


public enum FunctionalImpactState { SinImpactoObservado, Degradado, Interrumpido, Indeterminado }

public sealed record FunctionalImpactItem(
    string Funcion,
    string Modulo,
    FunctionalImpactState Estado,
    string Resumen,
    ConfidenceLevel Confianza,
    IReadOnlyList<EvidenceItem> Evidencia);

public sealed record FunctionalImpactAssessment(
    FunctionalImpactState EstadoGeneral,
    string Resumen,
    IReadOnlyList<FunctionalImpactItem> Impactos);

public sealed record SafeActionItem(
    int Orden,
    string Accion,
    string Motivo,
    string Categoria);

public sealed record SafeActionPlan(
    string Resumen,
    IReadOnlyList<SafeActionItem> DondeEmpezar,
    IReadOnlyList<SafeActionItem> NoTocarPrimero,
    IReadOnlyList<SafeActionItem> Verificaciones);

public sealed record DiagnosticPerformanceAssessment(
    double DuracionTotalMs,
    int CollectorsEjecutados,
    int CollectorsConError,
    int CollectorsConTimeout,
    string CollectorMasLento,
    double CollectorMasLentoMs,
    int EventosEntrada,
    int EventosNormalizados,
    int Hallazgos,
    long MemoriaAntesBytes,
    long MemoriaDespuesBytes,
    string Resumen)
{
    public bool PresupuestoAgotado { get; init; }
    public int CollectorsOmitidosPorPresupuesto { get; init; }
    public double PresupuestoTotalMs { get; init; }
}

public sealed record CoverageSourceAssessment(
    string Fuente,
    string Estado,
    string Detalle,
    bool Critica);

public sealed record DiagnosticCoverageAssessment(
    int Score,
    string Nivel,
    IReadOnlyList<CoverageSourceAssessment> Fuentes,
    IReadOnlyList<string> Limitaciones,
    string Resumen);

public enum TsplusDetectionState { ConfirmedPresent, ConfirmedAbsent, NotEvaluated }

public sealed record SystemSnapshot(
    string Equipo,
    string SistemaOperativo,
    string Version,
    string Build,
    string Arquitectura,
    TimeSpan Uptime,
    DateTimeOffset FechaCaptura,
    bool TsplusDetectado,
    string? TsplusRuta,
    string? TsplusVersion)
{
    public TsplusDetectionState TsplusEstadoDeteccion { get; init; } = TsplusDetectado ? TsplusDetectionState.ConfirmedPresent : TsplusDetectionState.ConfirmedAbsent;
}

public sealed record DiagnosticContext(
    SystemSnapshot Sistema,
    TimeSpan Lookback,
    DateTimeOffset? HoraIncidente = null,
    TsplusReleaseProfile? TsplusProfile = null,
    DiagnosticOptions? Options = null);

public sealed record DiagnosticOptions(
    int? MaxFilesPerDirectory = null,
    int? MaxBytesPerFile = null,
    long? MaxTotalBytes = null,
    int? MaxEvents = null,
    bool EnableRdpEtw = false,
    int? CauseStabilityFlappingThreshold = null,
    int? MaxFilesPerDirectoryIncremental = null,
    int? MaxBytesPerFileIncremental = null,
    long? MaxTotalBytesIncremental = null,
    int? MaxEventsIncremental = null);

public sealed record CollectorResult(
    IReadOnlyList<DiagnosticFinding> Hallazgos,
    IReadOnlyList<DiagnosticEvent> Eventos)
{
    public static CollectorResult Empty { get; } = new([], []);
}

public sealed record DiagnosticReport(
    SystemSnapshot Sistema,
    IReadOnlyList<DiagnosticFinding> Hallazgos,
    IReadOnlyList<DiagnosticEvent> Eventos,
    DateTimeOffset Inicio,
    DateTimeOffset Fin)
{
    public IReadOnlyList<RootCauseCandidate> CausasRaiz { get; init; } = [];
    /// <summary> Causa raíz única sólo cuando existe evidencia causal suficiente y margen de separación. </summary>
    public RootCauseCandidate? CausaRaizPrincipal { get; init; }
    public TimeSpan Lookback { get; init; }
    public DateTimeOffset PeriodoAnalizadoInicio { get; init; }
    public DateTimeOffset PeriodoAnalizadoFin { get; init; }
    public TimeSpan LookbackSolicitado { get; init; }
    public bool VentanaAutoAmpliada { get; init; }
    public string? MotivoAmpliacion { get; init; }
    // RC15 separa el dataset máximo recopilado (4 h en GUI) de la vista temporal seleccionada.
    public TimeSpan EvidenciaDisponibleLookback { get; init; }
    public DateTimeOffset PeriodoEvidenciaInicio { get; init; }
    public DateTimeOffset PeriodoEvidenciaFin { get; init; }
    public IReadOnlyList<FailurePattern> PatronesFalla { get; init; } = [];
    public IReadOnlyList<DiagnosticIncidentCluster> Incidentes { get; init; } = [];
    public DiagnosticPrecisionAssessment? PrecisionDiagnostica { get; init; }

    public FunctionalImpactAssessment? ImpactoFuncional { get; init; }
    public SafeActionPlan? PlanAccion { get; init; }
    public DiagnosticPerformanceAssessment? RendimientoDiagnostico { get; init; }
    public DiagnosticCoverageAssessment? CoberturaDiagnostica { get; init; }
    public bool DiagnosticoContinuo { get; init; }
    public DateTimeOffset? UltimaActualizacionContinua { get; init; }
    public int IntervaloContinuoSegundos { get; init; }
    public int MuestrasContinuas { get; init; }
    public IReadOnlyList<GuidedResolutionResult> ResolucionesGuiadas { get; init; } = [];
    /// <summary> Tensiones explícitas de coherencia interna ( auto-chequeo del reporte ). Vacío = sin tensiones. </summary>
    public IReadOnlyList<string> Tensiones { get; init; } = [];
}
