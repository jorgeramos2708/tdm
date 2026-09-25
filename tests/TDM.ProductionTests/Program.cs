using TDM.Application;
using TDM.Collectors.TSplus;
using TDM.Collectors.Windows;
using TDM.Core;
using TDM.Correlation;
using TDM.Models;
using TDM.Notifications;
using TDM.Persistence;
using TDM.Reporting;

var tests = new List<(string Name, Func<Task> Run)>
{
    ("UndatedFunctionalIncidentRejected", UndatedFunctionalIncidentRejected),
    ("TimestampedFunctionalIncidentAccepted", TimestampedFunctionalIncidentAccepted),
    ("StoppedTsplusServiceStateIsFunctionalIncident", StoppedTsplusServiceStateIsFunctionalIncident),
    ("StoppedWebPortalIsImpactNotCause", StoppedWebPortalIsImpactNotCause),
    ("RankingConflictEvidenceUsesFinalScores", RankingConflictEvidenceUsesFinalScores),
    ("TsplusUndatedLogKeepsEventTimeNull", TsplusUndatedLogKeepsEventTimeNull),
    ("TsplusIsoTimestampParses", TsplusIsoTimestampParses),
    ("AmbiguousTsplusDateUsesInvestigationWindow", AmbiguousTsplusDateUsesInvestigationWindow),
    ("TsplusStackTraceIsContinuation", TsplusStackTraceIsContinuation),
    ("AlertTitleRemovesTrendLabel", AlertTitleRemovesTrendLabel),
    ("DispatcherDoesNotEmitRecovered", DispatcherDoesNotEmitRecovered),
    ("EmailRecoveredNotificationsDisabled", EmailRecoveredNotificationsDisabled),
    ("CollectorCursorStoreRoundTrip", CollectorCursorStoreRoundTrip),
    ("DiagnosticFeedbackRoundTrip", DiagnosticFeedbackRoundTrip),
    ("IncidentLedgerSerializesConcurrentWriters", IncidentLedgerSerializesConcurrentWriters),
    ("DiagnosticEngineKeepsUndatedAsNonCausalContext", DiagnosticEngineKeepsUndatedAsNonCausalContext),
    ("IdentitySubstringDoesNotCorrelate", IdentitySubstringDoesNotCorrelate),
    ("StaleApplicationConfigDoesNotBecomeHighCause", StaleApplicationConfigDoesNotBecomeHighCause),
    ("SchannelWithoutSharedIdentityDoesNotCorrelate", SchannelWithoutSharedIdentityDoesNotCorrelate),
    ("CrashIgnoresUnrelatedWindowsDistractors", CrashIgnoresUnrelatedWindowsDistractors),
    ("CursorCorruptionIsNotTreatedAsMissing", CursorCorruptionIsNotTreatedAsMissing),
    ("FindingIntervalOverlapsDiagnosticWindow", FindingIntervalOverlapsDiagnosticWindow),
    ("AssignedUsersAreSanitized", AssignedUsersAreSanitized),
    ("WmiDoesNotRaiseCausalSignal", WmiDoesNotRaiseCausalSignal),
    ("ServiceStateDoesNotRaiseCausalSignal", ServiceStateDoesNotRaiseCausalSignal),
    ("ConcurrentIncidentsAreClusteredSeparately", ConcurrentIncidentsAreClusteredSeparately),
    ("ObservabilityClusterIsNotFunctionalCause", ObservabilityClusterIsNotFunctionalCause),
    ("WmiIsNotPersistedAsOperationalIncident", WmiIsNotPersistedAsOperationalIncident),
    ("EventLogCollectorsHandleEventLogException", EventLogCollectorsHandleEventLogException),
    ("VerifiedHistoryBoostsConfirmedCandidate", VerifiedHistoryBoostsConfirmedCandidate),
    ("VerifiedHistoryDemotesDiscardedCandidate", VerifiedHistoryDemotesDiscardedCandidate),
    ("VerifiedHistoryVetoProtectsIndependentEvidence", VerifiedHistoryVetoProtectsIndependentEvidence),
    ("VerifiedHistoryCannotOvertakeIndependentEvidence", VerifiedHistoryCannotOvertakeIndependentEvidence),
    ("VerifiedHistorySingleSampleMovesLittle", VerifiedHistorySingleSampleMovesLittle),
    ("VerifiedHistoryClampsToValidRange", VerifiedHistoryClampsToValidRange),
    ("VerifiedHistoryAbsentLeavesRankingUntouched", VerifiedHistoryAbsentLeavesRankingUntouched),
    ("ReportExportIncludesDiffAndAnchors", ReportExportIncludesDiffAndAnchors),
    ("LogonSurgeNeedsVolumeAndRate", LogonSurgeNeedsVolumeAndRate),
    ("LogonLockoutsNeedThree", LogonLockoutsNeedThree),
    ("UnknownFormatFlagsSingleFile", UnknownFormatFlagsSingleFile),
    ("IniSemanticDiffDetectsKeyChanges", IniSemanticDiffDetectsKeyChanges),
    ("RegistryFingerprintStableAndSecretFree", RegistryFingerprintStableAndSecretFree),
    ("ProcessModulePolicyFlags", ProcessModulePolicyFlags),
    ("ChannelCoverageFormatsRange", ChannelCoverageFormatsRange),
    ("CauseStabilityCalmWhenStable", CauseStabilityCalmWhenStable),
    ("CauseStabilityFlagsFlapping", CauseStabilityFlagsFlapping),
    ("CauseStabilityIgnoresEmpty", CauseStabilityIgnoresEmpty)
};

var failed = 0;
foreach (var test in tests)
{
    try
    {
        await test.Run();
        Console.WriteLine($"PASS {test.Name}");
    }
    catch (Exception ex)
    {
        failed++;
        Console.Error.WriteLine($"FAIL {test.Name}: {ex.Message}");
    }
}
Console.WriteLine($"ProductionTests: {tests.Count - failed}/{tests.Count} PASS");
return failed == 0 ? 0 : 1;

static Task WmiDoesNotRaiseCausalSignal()
{
    var e = new DiagnosticEvent(DateTimeOffset.Now, "WMI", "WMI", DiagnosticLayer.Windows, DiagnosticSeverity.Critico, "WMI_EVENT_INCREMENTAL", "0x80041032");
    False(DiagnosticPrecisionAnalyzer.IsCausalSignal(e), "WMI fue contabilizado como señal causal.");
    return Task.CompletedTask;
}

static Task ServiceStateDoesNotRaiseCausalSignal()
{
    var e = new DiagnosticEvent(DateTimeOffset.Now, "Service Control Manager", "Web Portal Service", DiagnosticLayer.Tsplus, DiagnosticSeverity.Critico, "SERVICE_STATE", "Stopped", Evidencia: [new EvidenceItem("Estado", "Stopped")], Producto: TsplusProduct.RemoteAccess);
    False(DiagnosticPrecisionAnalyzer.IsCausalSignal(e), "SERVICE_STATE fue elevado a señal causal en vez de tratarse como impacto/estado.");
    return Task.CompletedTask;
}

static Task ConcurrentIncidentsAreClusteredSeparately()
{
    var now = DateTimeOffset.Now;
    var web = new DiagnosticEvent(now, "SCM", "Web Portal Service", DiagnosticLayer.Tsplus, DiagnosticSeverity.Critico, "SERVICE_STATE", "Stopped", Evidencia: [new EvidenceItem("Servicio", "WebPortalService"), new EvidenceItem("Estado", "Stopped")], Producto: TsplusProduct.RemoteAccess);
    var ad = new DiagnosticEvent(now.AddSeconds(15), "Netlogon", "Active Directory", DiagnosticLayer.Windows, DiagnosticSeverity.Error, "WINDOWS_AD_DOMAIN_CONNECTIVITY_FAILURE", "Secure channel failed");
    var report = Report([web, ad], now);
    var clusters = IncidentClusterAnalyzer.Analyze(report);
    True(clusters.Count == 2, "Web/HTML5 y AD fueron mezclados en un solo incidente.");
    return Task.CompletedTask;
}

static Task ObservabilityClusterIsNotFunctionalCause()
{
    var now = DateTimeOffset.Now;
    var wmi = new DiagnosticEvent(now, "WMI", "WMI", DiagnosticLayer.Windows, DiagnosticSeverity.Critico, "WMI_EVENT_INCREMENTAL", "0x80041032");
    var report = Report([wmi], now);
    var clusters = IncidentClusterAnalyzer.Analyze(report);
    NotNull(clusters.SingleOrDefault(x => x.Dominio == "OBSERVABILIDAD"), "WMI no fue identificado como observabilidad.");
    True(!report.CausasRaiz.Any(c => c.Id.Contains("WMI", StringComparison.OrdinalIgnoreCase)), "WMI apareció como causa raíz.");
    return Task.CompletedTask;
}

static Task WmiIsNotPersistedAsOperationalIncident()
{
    var incident = new ObservabilityIncident(DateTimeOffset.Now, "WMI_EVENT_INCREMENTAL", "WMI", "Error", "0x80041032", "WMI", "x", null, "TDM incremental", nameof(TsplusProduct.Ninguno), "Funcional");
    False(ObservabilityIncidentPolicy.IsOperationalIncident(incident), "WMI fue aceptado como incidente operativo persistible.");
    return Task.CompletedTask;
}

static Task UndatedFunctionalIncidentRejected()
{
    var e = new DiagnosticEvent(null, "TSplus Log", "Remote Access", DiagnosticLayer.Tsplus,
        DiagnosticSeverity.Error, "APPLICATION_CRASH", "old error without timestamp", IngestedAt: DateTimeOffset.Now);
    False(DiagnosticEventCatalog.IsFunctionalIncident(e), "IngestedAt convirtió evidencia sin fecha en incidente.");
    return Task.CompletedTask;
}

static Task TimestampedFunctionalIncidentAccepted()
{
    var e = new DiagnosticEvent(DateTimeOffset.Now, "Application Error", "TSplus", DiagnosticLayer.Tsplus,
        DiagnosticSeverity.Error, "APPLICATION_CRASH", "crash");
    True(DiagnosticEventCatalog.IsFunctionalIncident(e), "Un crash fechado y funcional no fue aceptado.");
    return Task.CompletedTask;
}

static Task StoppedTsplusServiceStateIsFunctionalIncident()
{
    var e = new DiagnosticEvent(DateTimeOffset.Now, "TDM", "Web Portal Service", DiagnosticLayer.Tsplus,
        DiagnosticSeverity.Critico, "SERVICE_STATE", "Estado actual: Stopped",
        Evidencia: [
            new EvidenceItem("Servicio", "WebPortalService"),
            new EvidenceItem("Nombre visible", "Web Portal Service"),
            new EvidenceItem("Estado", "Stopped"),
            new EvidenceItem("Proveedor", "TSplus"),
            new EvidenceItem("Rol", "Web / HTML5 / Web Portal"),
            new EvidenceItem("Requerida ahora", "Sí")
        ], Producto: TsplusProduct.RemoteAccess);
    True(DiagnosticEventCatalog.IsFunctionalIncident(e), "Un Web Portal detenido no fue elevado como incidente funcional.");
    return Task.CompletedTask;
}

static Task StoppedWebPortalIsImpactNotCause()
{
    var now = DateTimeOffset.Now;
    var stopped = new DiagnosticEvent(now.AddMinutes(-1), "TDM", "Web Portal Service", DiagnosticLayer.Tsplus,
        DiagnosticSeverity.Critico, "SERVICE_STATE", "Estado actual: Stopped",
        Evidencia: [
            new EvidenceItem("Servicio", "WebPortalService"),
            new EvidenceItem("Nombre visible", "Web Portal Service"),
            new EvidenceItem("Estado", "Stopped"),
            new EvidenceItem("Proveedor", "TSplus"),
            new EvidenceItem("Rol", "Web / HTML5 / Web Portal"),
            new EvidenceItem("Requerida ahora", "Sí")
        ], Producto: TsplusProduct.RemoteAccess);
    var malformed = new DiagnosticEvent(now.AddSeconds(-30), "TSplus", "manifest.json", DiagnosticLayer.Tsplus,
        DiagnosticSeverity.Error, "LOG_ERROR", "manifest.json invalid JSON", Archivo: "C:\\Program Files (x86)\\TSplus\\Clients\\webportal\\wwwroot\\manifest.json", Producto: TsplusProduct.RemoteAccess);
    var report = Report([stopped, malformed], now);
    var analyzed = DiagnosticWorkflow.Analyze(report);
    var direct = analyzed.CausasRaiz.FirstOrDefault(c => c.RolCausal.Equals("IMPACTO_DIRECTO_SIN_CAUSA_DEL_PARO", StringComparison.OrdinalIgnoreCase));
    NotNull(direct, "No se conservó el estado operativo como impacto directo.");
    True(analyzed.ImpactoFuncional?.Impactos.Any(i => i.Modulo.Contains("Web / HTML5 / Web Portal", StringComparison.OrdinalIgnoreCase) && i.Estado == FunctionalImpactState.Interrumpido) == true,
        "Web/HTML5 no reflejó el paro directo del Web Portal.");
    if (analyzed.CausaRaizPrincipal is not null)
        False(analyzed.CausaRaizPrincipal.Id.Contains("manifest", StringComparison.OrdinalIgnoreCase), "manifest.json fue elevado a causa principal sin margen causal suficiente.");
    return Task.CompletedTask;
}

static Task RankingConflictEvidenceUsesFinalScores()
{
    var now = DateTimeOffset.Now;
    var windows = new RootCauseCandidate(1, "WIN-A", "Active Directory", DiagnosticLayer.Windows, 79, ConfidenceLevel.Alta, "AD", "AD signal", [], Producto: TsplusProduct.Ninguno, HoraIncidente: now.AddMinutes(-2), OrigenClasificado: "WINDOWS");
    var tsplus = new RootCauseCandidate(2, "TS-A", "manifest.json", DiagnosticLayer.Tsplus, 78, ConfidenceLevel.Alta, "manifest", "config", [], Producto: TsplusProduct.RemoteAccess, HoraIncidente: now.AddMinutes(-1), OrigenClasificado: "TSPLUS");
    var calibrated = DiagnosticPrecisionAnalyzer.Calibrate(Report([], now), [windows, tsplus]);
    var top = calibrated.OrderByDescending(c => c.Puntaje).First();
    var evidence = top.Evidencia.FirstOrDefault(e => e.Clave == "Conflicto entre orígenes fuertes")?.Valor;
    var ranking = top.Evidencia.FirstOrDefault(e => e.Clave == "Estado de ranking")?.Valor;
    True(string.Equals(evidence, "No", StringComparison.OrdinalIgnoreCase), "El reporte conserva 'conflicto fuerte' según el estado previo al calibrado.");
    True(ranking?.Contains("EMPATE_TECNICO", StringComparison.OrdinalIgnoreCase) == true, "El ranking no marca empate técnico cuando la brecha es menor a 5 puntos.");
    return Task.CompletedTask;
}

static Task TsplusUndatedLogKeepsEventTimeNull()
{
    var parsed = TsplusLogParser.ParseLine("Remote Access", "x.log", "ERROR failed to start application", 1,
        Context(TimeSpan.FromHours(1)));
    NotNull(parsed, "La línea ERROR no fue parseada.");
    True(parsed!.Timestamp is null, "El parser inventó EventTime para una línea sin fecha.");
    True(parsed.IngestedAt.HasValue, "Falta metadato IngestedAt.");
    return Task.CompletedTask;
}

static Task TsplusIsoTimestampParses()
{
    var ts = TsplusLogParser.TryParseTimestamp("2026-09-06 18:10:11 ERROR failed");
    True(ts.HasValue && ts.Value.Year == 2026 && ts.Value.Month == 9 && ts.Value.Day == 6, "Timestamp ISO no reconocido.");
    return Task.CompletedTask;
}


static Task AmbiguousTsplusDateUsesInvestigationWindow()
{
    var local = new DateTime(2026, 4, 3, 12, 30, 0, DateTimeKind.Unspecified);
    var end = new DateTimeOffset(local, TimeZoneInfo.Local.GetUtcOffset(local));
    var context = new DiagnosticContext(Snapshot(), TimeSpan.FromHours(1), end);
    var parsed = TsplusLogParser.ParseLine("Remote Access", "x.log", "03/04/2026 12:00:00 ERROR failed to start application", 1, context);
    NotNull(parsed, "La fecha ambigua no se resolvió con la ventana de investigación.");
    True(parsed!.Timestamp.HasValue && parsed.Timestamp.Value.Month == 4 && parsed.Timestamp.Value.Day == 3,
        "La fecha dd/MM no fue seleccionada de forma inequívoca por la ventana de investigación.");
    return Task.CompletedTask;
}

static Task TsplusStackTraceIsContinuation()
{
    True(TsplusLogParser.IsContinuationLine("   at Module.Type.Method()"), "Stack trace no reconocido como continuación.");
    return Task.CompletedTask;
}

static Task AlertTitleRemovesTrendLabel()
{
    var finding = new DiagnosticFinding("RESOURCE-TREND-MEMORY-DOWN", "Memoria / tendencia", DiagnosticSeverity.Advertencia,
        "La memoria libre muestra una caída sostenida.", "", [], ConfidenceLevel.Alta, Capa: DiagnosticLayer.Windows);
    var title = AlertTitleFormatter.ForFinding(finding);
    True(title.Contains("memoria libre en descenso", StringComparison.OrdinalIgnoreCase), "Título de memoria no es explícito.");
    False(title.Contains("/ tendencia", StringComparison.OrdinalIgnoreCase), "El título conserva '/ tendencia'.");
    return Task.CompletedTask;
}

static async Task DispatcherDoesNotEmitRecovered()
{
    var root = TempDir();
    try
    {
        var sink = new MemorySink();
        var dispatcher = new NotificationDispatcher([sink], root);
        var signal = new AlertSignal("mem", DateTimeOffset.Now, "Advertencia", "TDM · Alerta de memoria", "Detalle", "test");
        var opened = await dispatcher.DispatchAsync([signal], DateTimeOffset.Now);
        Equal(1, opened.Count, "No se emitió apertura.");
        var recovered = await dispatcher.DispatchAsync([], DateTimeOffset.Now.AddMinutes(1));
        Equal(0, recovered.Count, "Se emitió una alerta Recovered.");
        False(sink.Items.Any(x => x.Transition == NotificationTransition.Recovered), "Un sink recibió Recovered.");
    }
    finally { TryDelete(root); }
}

static Task EmailRecoveredNotificationsDisabled()
{
    False(EmailNotificationSettings.Default.NotifyRecovered, "NotifyRecovered sigue habilitado por defecto.");
    return Task.CompletedTask;
}

static Task CollectorCursorStoreRoundTrip()
{
    var root = TempDir();
    var prior = Environment.GetEnvironmentVariable("TDM_STATE_ROOT");
    try
    {
        Environment.SetEnvironmentVariable("TDM_STATE_ROOT", root);
        var state = new CursorFixture(new Dictionary<string, long> { ["System"] = 123 }, DateTimeOffset.Now);
        True(CollectorCursorStore.TrySave("production-test", state, out var saveError), "No se guardó cursor: " + saveError);
        True(CollectorCursorStore.TryLoad<CursorFixture>("production-test", out var loaded, out var loadError), "No se leyó cursor: " + loadError);
        Equal(123L, loaded!.Values["System"], "Cursor persistido incorrecto.");
    }
    finally
    {
        Environment.SetEnvironmentVariable("TDM_STATE_ROOT", prior);
        TryDelete(root);
    }
    return Task.CompletedTask;
}

static async Task IncidentLedgerSerializesConcurrentWriters()
{
    var root = TempDir();
    try
    {
        var at = DateTimeOffset.Now;
        var incident = new ObservabilityIncident(at, "APPLICATION_CRASH", "TSplus", "Error", "crash");
        var a = new IncidentLedger(root);
        var b = new IncidentLedger(root);
        await Task.WhenAll(
            a.ReconcileAsync([incident], at, SupportMonitoringSettings.Default),
            b.ReconcileAsync([incident], at, SupportMonitoringSettings.Default));
        var items = await a.ReadAsync();
        Equal(1, items.Count, "Carrera del ledger creó registros duplicados/corruptos.");
        True(items[0].Occurrences >= 2, "La segunda escritura concurrente no observó la primera.");
    }
    finally { TryDelete(root); }
}

static async Task DiagnosticEngineKeepsUndatedAsNonCausalContext()
{
    var undated = new DiagnosticEvent(null, "TSplus Log", "Remote Access", DiagnosticLayer.Tsplus,
        DiagnosticSeverity.Error, "APPLICATION_CRASH", "undated", IngestedAt: DateTimeOffset.Now);
    var engine = new DiagnosticEngine([new FixedCollector(undated)], TimeSpan.FromSeconds(2), 1000);
    var report = await engine.RunAsync(Context(TimeSpan.FromHours(1)));
    True(report.Eventos.Any(x => x.Mensaje == "undated" && x.Timestamp is null), "Se perdió evidencia no temporal.");
    False(report.Eventos.Where(x => x.Mensaje == "undated").Any(DiagnosticEventCatalog.IsFunctionalIncident), "Evidencia no temporal se volvió causal.");
}

static Task IdentitySubstringDoesNotCorrelate()
{
    var now = DateTimeOffset.Now;
    var failure = new DiagnosticEvent(now.AddMinutes(-2), "Security", "Windows NLA", DiagnosticLayer.Seguridad,
        DiagnosticSeverity.Advertencia, "USER_NLA_PASSWORD_FAILURE", "credential failure",
        Evidencia: [new EvidenceItem("Usuario", "ann")]);
    var symptom = new DiagnosticEvent(now.AddMinutes(-1), "TSplus Log", "Remote Access", DiagnosticLayer.Tsplus,
        DiagnosticSeverity.Error, "SESSION", "session failed",
        Evidencia: [new EvidenceItem("Usuario", "joann")], Producto: TsplusProduct.RemoteAccess);
    var report = Report([failure, symptom], now);
    var causes = RootCauseCorrelator.Analyze(report);
    False(causes.Any(x => x.Id.StartsWith("ROOT-WINDOWS-NLA-CREDENTIALS-", StringComparison.OrdinalIgnoreCase)), "ann coincidió incorrectamente con joann.");
    return Task.CompletedTask;
}

static Task StaleApplicationConfigDoesNotBecomeHighCause()
{
    var now = DateTimeOffset.Now;
    var issue = new DiagnosticFinding("TSPLUS-PUBLISHED-APP-TEST", "Accounting.exe", DiagnosticSeverity.Error,
        "Ruta inválida", "", [new EvidenceItem("Aplicación", "Accounting.exe")], ConfidenceLevel.Alta, Capa: DiagnosticLayer.Tsplus);
    var stale = new DiagnosticEvent(now.AddHours(-1), "TSplus Log", "Remote Access", DiagnosticLayer.Tsplus,
        DiagnosticSeverity.Error, "APPLICATION_PUBLISHING", "Accounting.exe failed", Producto: TsplusProduct.RemoteAccess);
    var report = Report([stale], now, [issue]);
    var cause = RootCauseCorrelator.Analyze(report).FirstOrDefault(x => x.Id == "ROOT-TSPLUS-APPLICATION-CONFIG");
    NotNull(cause, "No se conservó la anomalía como hipótesis.");
    True(cause!.Confianza is ConfidenceLevel.Media or ConfidenceLevel.Baja or ConfidenceLevel.EvidenciaInsuficiente || cause.Puntaje < 90, "Un error histórico distante elevó configuración a causa alta.");
    return Task.CompletedTask;
}

static Task SchannelWithoutSharedIdentityDoesNotCorrelate()
{
    var now = DateTimeOffset.Now;
    var schannel = new DiagnosticEvent(now.AddMinutes(-2), "Schannel", "TLS", DiagnosticLayer.Rdp,
        DiagnosticSeverity.Error, "SCHANNEL_EVENT", "TLS handshake failed for unrelated endpoint");
    var web = new DiagnosticEvent(now.AddMinutes(-1), "TSplus Log", "HTML5", DiagnosticLayer.Tsplus,
        DiagnosticSeverity.Error, "WEB", "HTTPS connection failed", Producto: TsplusProduct.RemoteAccess);
    var causes = RootCauseCorrelator.Analyze(Report([schannel, web], now));
    False(causes.Any(x => x.Id == "ROOT-TLS-SCHANNEL"), "Schannel se correlacionó sólo por proximidad temporal.");
    return Task.CompletedTask;
}


static Task CrashIgnoresUnrelatedWindowsDistractors()
{
    var now = DateTimeOffset.Now;
    var crash = new DiagnosticEvent(now, "Application Error", "TSplus.Application.exe", DiagnosticLayer.Tsplus,
        DiagnosticSeverity.Error, "APPLICATION_CRASH", "TSplus.Application.exe crashed",
        Evidencia: [new EvidenceItem("Aplicación", "TSplus.Application.exe")], Producto: TsplusProduct.RemoteAccess);
    var schannel = new DiagnosticEvent(now.AddMinutes(-2), "Schannel", "TLS", DiagnosticLayer.Rdp,
        DiagnosticSeverity.Error, "SCHANNEL_EVENT", "Handshake failed for unrelated.example:443");
    var disk = new DiagnosticEvent(now.AddMinutes(-3), "Disk", "Disk 9", DiagnosticLayer.Windows,
        DiagnosticSeverity.Error, "WINDOWS_EVENT", "I/O error on unrelated volume Z:");
    var security = new DiagnosticEvent(now.AddMinutes(-4), "Third-party security", "EDR", DiagnosticLayer.Seguridad,
        DiagnosticSeverity.Advertencia, "THIRD_PARTY_SECURITY_INTERFERENCE_SIGNAL", "EDR activity on unrelated.exe");

var cause = RootCauseCorrelator.Analyze(Report([security, disk, schannel, crash], now))
          .FirstOrDefault(x => x.Id == "ROOT-PROCESS-CRASH");
    NotNull(cause, "No se generó candidato del crash confirmado.");
    var strong = cause!.Evidencia.FirstOrDefault(x => x.Clave == "Antecedentes Windows fuertes")?.Valor;
    Equal("0", strong ?? "", "Se promovió evidencia Windows no relacionada como antecedente fuerte del crash.");
    return Task.CompletedTask;
}

static Task AssignedUsersAreSanitized()
{
    var now = DateTimeOffset.Now;
    var finding = new DiagnosticFinding("TEST", "App", DiagnosticSeverity.Advertencia, "test", "test",
        [new EvidenceItem("Usuarios asignados", "DOMAIN\\jorge"), new EvidenceItem("Grupos asignados", "DOMAIN\\Admins")]);
    var sanitized = SupportBundleSanitizer.Sanitize(Report([], now, [finding]));
    var values = sanitized.Hallazgos[0].Evidencia.Select(x => x.Valor).ToList();
    False(values.Any(x => x.Contains("jorge", StringComparison.OrdinalIgnoreCase) || x.Contains("Admins", StringComparison.OrdinalIgnoreCase)), "Identidades asignadas no fueron pseudonimizadas.");
    return Task.CompletedTask;
}

static DiagnosticContext Context(TimeSpan lookback)
    => new(Snapshot(), lookback);

static SystemSnapshot Snapshot()
    => new("TEST", "Windows Server", "2025", "test", "x64", TimeSpan.FromHours(1), DateTimeOffset.Now, true, @"C:\\Program Files (x86)\\TSplus", "19");

static DiagnosticReport Report(IReadOnlyList<DiagnosticEvent> events, DateTimeOffset end, IReadOnlyList<DiagnosticFinding>? findings = null)
    => new(Snapshot(), findings ?? [], events, end.AddMinutes(-1), end)
    {
        Lookback = TimeSpan.FromHours(4),
        LookbackSolicitado = TimeSpan.FromHours(4),
        PeriodoAnalizadoInicio = end.AddHours(-4),
        PeriodoAnalizadoFin = end,
        EvidenciaDisponibleLookback = TimeSpan.FromHours(4),
        PeriodoEvidenciaInicio = end.AddHours(-4),
        PeriodoEvidenciaFin = end
    };

static string TempDir()
{
    var path = Path.Combine(Path.GetTempPath(), "TDM-ProductionTests-" + Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(path);
    return path;
}

static void TryDelete(string path)
{
    try { if (Directory.Exists(path)) Directory.Delete(path, true); } catch { }
}

static void True(bool value, string message) { if (!value) throw new InvalidOperationException(message); }
static void False(bool value, string message) => True(!value, message);
static void NotNull(object? value, string message) => True(value is not null, message);
static void Equal<T>(T expected, T actual, string message) where T : notnull
{
    if (!EqualityComparer<T>.Default.Equals(expected, actual))
        throw new InvalidOperationException($"{message} Esperado={expected}; actual={actual}");
}

static Task CursorCorruptionIsNotTreatedAsMissing()
{
    var root = TempDir();
    var prior = Environment.GetEnvironmentVariable("TDM_STATE_ROOT");
    try
    {
        Environment.SetEnvironmentVariable("TDM_STATE_ROOT", root);
        File.WriteAllText(Path.Combine(root, "corrupt.json"), "{ not-json");
        False(CollectorCursorStore.TryLoad<CursorFixture>("corrupt", out _, out var error), "Un cursor corrupto fue aceptado.");
        True(!string.IsNullOrWhiteSpace(error), "La corrupción del cursor no quedó señalada.");
    }
    finally { Environment.SetEnvironmentVariable("TDM_STATE_ROOT", prior); TryDelete(root); }
    return Task.CompletedTask;
}

static async Task DiagnosticFeedbackRoundTrip()
{
    var root = TempDir();
    try
    {
        var store = new DiagnosticFeedbackStore(root);
        var confirmed = await store.RecordAsync("ROOT-TEST-A", "Servicio X", 90, "Alta", FeedbackVerdict.Confirmada, "validado", "tec");
        await store.RecordAsync("ROOT-TEST-A", "Servicio X", 88, "Alta", FeedbackVerdict.Descartada, null, null);
        await store.RecordAsync("ROOT-TEST-B", "Servicio Y", 70, "Media", FeedbackVerdict.Confirmada, null, null);
        var items = await store.ReadAsync();
        Equal(3, items.Count, "Feedback no persistido/legible.");
        True(items.Any(x => x.Id == confirmed.Id && x.Verdicto == FeedbackVerdict.Confirmada), "Registro confirmado no recuperado.");
        var rates = DiagnosticFeedbackStore.HitRateByCandidate(items);
        Equal(0.5, rates["ROOT-TEST-A"].Tasa, "Tasa de acierto mal calculada.");
        Equal(1.0, rates["ROOT-TEST-B"].Tasa, "Tasa de acierto mal calculada.");
        var empty = await new DiagnosticFeedbackStore(Path.Combine(root, "vacio")).ReadAsync();
        Equal(0, empty.Count, "Store inexistente debería leer vacío.");
    }
    finally { TryDelete(root); }
}

static RootCauseCandidate VerifiedCandidate(string id, int puntaje, bool independent)
    => new(0, id, "Comp-" + id, DiagnosticLayer.Tsplus, puntaje, ConfidenceLevel.Alta,
        "resumen", "explicacion",
        [new EvidenceItem("Evidencia primaria independiente", independent ? "Sí" : "No")],
        Producto: TsplusProduct.RemoteAccess, OrigenClasificado: "TSPLUS");

static Dictionary<string, (int Confirmadas, int Descartadas, double Tasa)> Rates(params (string Id, int Confirmadas, int Descartadas)[] entries)
{
    var dict = new Dictionary<string, (int, int, double)>(StringComparer.OrdinalIgnoreCase);
    foreach (var (id, c, d) in entries)
    {
        var total = c + d;
        dict[id] = (c, d, total == 0 ? 0d : (double)c / total);
    }
    return dict;
}

static Task VerifiedHistoryBoostsConfirmedCandidate()
{
    var a = VerifiedCandidate("ROOT-A", 70, independent: false);
    var b = VerifiedCandidate("ROOT-B", 72, independent: false);
    var result = VerifiedHistoryCalibrator.ApplyVerifiedHistory([a, b], Rates(("ROOT-A", 5, 0)));
    Equal("ROOT-A", result[0].Id, "La causa confirmada 5 veces no subió al primer lugar.");
    Equal(85, result[0].Puntaje, "Ajuste esperado +15 con muestra completa.");
    Equal(1, result[0].Posicion, "Posición no reasignada tras reordenar.");
    Equal(2, result[1].Posicion, "Posición no reasignada tras reordenar.");
    True(result[0].Evidencia.Any(e => e.Clave == "Historial verificado por técnico"), "El ajuste no quedó registrado como evidencia.");
    return Task.CompletedTask;
}

static Task VerifiedHistoryDemotesDiscardedCandidate()
{
    var a = VerifiedCandidate("ROOT-A", 80, independent: false);
    var b = VerifiedCandidate("ROOT-B", 72, independent: false);
    var result = VerifiedHistoryCalibrator.ApplyVerifiedHistory([a, b], Rates(("ROOT-A", 0, 4)));
    Equal("ROOT-B", result[0].Id, "La causa descartada 4 veces no bajó del primer lugar.");
    Equal(68, result[1].Puntaje, "Ajuste esperado -12 (4/5 de peso).");
    return Task.CompletedTask;
}

static Task VerifiedHistoryVetoProtectsIndependentEvidence()
{
    // Pin anti-inversión: el historial de descartes no resta a evidencia primaria independiente.
    var a = VerifiedCandidate("ROOT-A", 80, independent: true);
    var b = VerifiedCandidate("ROOT-B", 72, independent: false);
    var result = VerifiedHistoryCalibrator.ApplyVerifiedHistory([a, b], Rates(("ROOT-A", 0, 5)));
    Equal("ROOT-A", result[0].Id, "El feedback invirtió una causa con evidencia primaria independiente.");
    Equal(80, result[0].Puntaje, "El veto no protegió el puntaje de evidencia dura.");
    True(result[0].Evidencia.Any(e => e.Clave == "Historial verificado por técnico" && e.Valor.Contains("no aplicado", StringComparison.OrdinalIgnoreCase)),
        "El veto no quedó declarado en la evidencia.");
    return Task.CompletedTask;
}

static Task VerifiedHistoryCannotOvertakeIndependentEvidence()
{
    // Pin anti-adelantamiento: +15 por historial no supera a quien venía arriba con evidencia dura.
    var a = VerifiedCandidate("ROOT-A", 80, independent: true);
    var b = VerifiedCandidate("ROOT-B", 72, independent: false);
    var result = VerifiedHistoryCalibrator.ApplyVerifiedHistory([a, b], Rates(("ROOT-B", 5, 0)));
    Equal("ROOT-A", result[0].Id, "El feedback adelantó a un candidato con evidencia primaria independiente.");
    Equal(80, result[1].Puntaje, "El recorte por veto no dejó el empate en 80.");
    return Task.CompletedTask;
}

static Task VerifiedHistorySingleSampleMovesLittle()
{
    // Una sola anécdota mueve ±3 como máximo: no decide primarias.
    var a = VerifiedCandidate("ROOT-A", 70, independent: false);
    var result = VerifiedHistoryCalibrator.ApplyVerifiedHistory([a], Rates(("ROOT-A", 1, 0)));
    Equal(73, result[0].Puntaje, "Una sola confirmación debería mover +3, no más.");
    return Task.CompletedTask;
}

static Task VerifiedHistoryClampsToValidRange()
{
    var c = VerifiedCandidate("ROOT-C", 95, independent: false);
    var d = VerifiedCandidate("ROOT-D", 5, independent: false);
    var result = VerifiedHistoryCalibrator.ApplyVerifiedHistory([c, d], Rates(("ROOT-C", 5, 0), ("ROOT-D", 0, 5)));
    Equal(100, result[0].Puntaje, "El ajuste positivo debe clampear a 100.");
    Equal(0, result[1].Puntaje, "El ajuste negativo debe clampear a 0.");
    return Task.CompletedTask;
}

static Task VerifiedHistoryAbsentLeavesRankingUntouched()
{
    var a = VerifiedCandidate("ROOT-A", 70, independent: false);
    var b = VerifiedCandidate("ROOT-B", 72, independent: false);
    var list = new List<RootCauseCandidate> { a, b };
    True(ReferenceEquals(list, VerifiedHistoryCalibrator.ApplyVerifiedHistory(list, null)), "Null debería devolver la lista intacta.");
    True(ReferenceEquals(list, VerifiedHistoryCalibrator.ApplyVerifiedHistory(list, new Dictionary<string, (int, int, double)>())),
        "Diccionario vacío debería devolver la lista intacta.");
    return Task.CompletedTask;
}

static async Task ReportExportIncludesDiffAndAnchors()
{
    var dir = TempDir();
    try
    {
        var now = DateTimeOffset.Now;
        var prev = Report([], now.AddHours(-4),
        [
            new DiagnosticFinding("F-OLD", "Comp-Old", DiagnosticSeverity.Error, "hallazgo viejo", "", [], ConfidenceLevel.Alta, Capa: DiagnosticLayer.Tsplus)
        ]);
        var current = Report([], now,
        [
            new DiagnosticFinding("F-NEW", "Comp-New", DiagnosticSeverity.Error, "hallazgo nuevo", "", [], ConfidenceLevel.Alta, Capa: DiagnosticLayer.Tsplus),
            new DiagnosticFinding("F-REL", "Comp-ROOT-A", DiagnosticSeverity.Advertencia, "hallazgo relacionado", "", [], ConfidenceLevel.Media, Capa: DiagnosticLayer.Tsplus)
        ]);
        current = current with
        {
            CausasRaiz = [VerifiedCandidate("ROOT-A", 80, independent: false) with { Posicion = 2, Componente = "Comp-ROOT-A" }]
        };
        var result = await ReportExporter.ExportAsync(current, dir, CancellationToken.None, prev);
        var html = await File.ReadAllTextAsync(result.HtmlPath);
        True(html.Contains("Cambios desde el reporte anterior", StringComparison.Ordinal), "El diff no se inyecto al HTML.");
        True(html.Contains("F-OLD", StringComparison.Ordinal) && html.Contains("F-NEW", StringComparison.Ordinal), "El diff no lista el alta y la baja.");
        True(html.Contains("id='fnd-1'", StringComparison.Ordinal), "Falta ancla en las filas de hallazgos.");
        True(html.Contains("id='cau-2'", StringComparison.Ordinal), "Falta ancla en las causas.");
        True(html.Contains("Hallazgos relacionados en este reporte", StringComparison.Ordinal), "Falta el bloque causa-hallazgo.");
        var solo = await ReportExporter.ExportAsync(current, dir);
        var htmlSolo = await File.ReadAllTextAsync(solo.HtmlPath);
        False(htmlSolo.Contains("Cambios desde el reporte anterior", StringComparison.Ordinal), "Sin reporte previo no debe haber tarjeta diff.");
    }
    finally { TryDelete(dir); }
}

static Task LogonSurgeNeedsVolumeAndRate()
{
    var now = DateTimeOffset.Now;
    True(WindowsLogonHealthCollector.EvaluateCounts(5, 5, 0, now).Count == 0, "5 fallos sin volumen elevaron hallazgo.");
    True(WindowsLogonHealthCollector.EvaluateCounts(80, 10, 0, now).Count == 0, "Tasa 11% elevó hallazgo.");
    var surge = WindowsLogonHealthCollector.EvaluateCounts(80, 30, 0, now);
    Equal(1, surge.Count, "Oleada 27% no elevada.");
    Equal(DiagnosticSeverity.Advertencia, surge[0].Severidad, "Oleada media debería ser Advertencia.");
    var big = WindowsLogonHealthCollector.EvaluateCounts(10, 50, 0, now);
    Equal(DiagnosticSeverity.Error, big[0].Severidad, "50+ fallos deberían ser Error.");
    return Task.CompletedTask;
}

static Task LogonLockoutsNeedThree()
{
    var now = DateTimeOffset.Now;
    True(WindowsLogonHealthCollector.EvaluateCounts(100, 0, 2, now).Count == 0, "2 bloqueos elevaron hallazgo.");
    var found = WindowsLogonHealthCollector.EvaluateCounts(100, 0, 3, now);
    Equal(1, found.Count, "3 bloqueos no elevados.");
    Equal("WINDOWS-ACCOUNT-LOCKOUTS", found[0].Id, "Id de bloqueo inesperado.");
    return Task.CompletedTask;
}

static Task UnknownFormatFlagsSingleFile()
{
    var flagged = TsplusLogFormatDetector.Evaluate(new Dictionary<string, (long, long)> { ["a.log"] = (1000, 900) });
    Equal(1, flagged.Count, "Archivo 90% no parseado no señalado.");
    Equal("TSPLUS-LOG-UNKNOWN-FORMAT", flagged[0].Id, "Id de formato desconocido inesperado.");
    True(TsplusLogFormatDetector.Evaluate(new Dictionary<string, (long, long)> { ["b.log"] = (1000, 100) }).Count == 0, "Archivo sano señalado.");
    True(TsplusLogFormatDetector.Evaluate(new Dictionary<string, (long, long)> { ["c.log"] = (100, 95) }).Count == 0, "Volumen bajo señalado.");
    True(TsplusLogFormatDetector.Evaluate(new Dictionary<string, (long, long)>()).Count == 0, "Vacío señaló.");
    return Task.CompletedTask;
}

static Task IniSemanticDiffDetectsKeyChanges()
{
    var parsed = TsplusConfigSemanticDiff.ParseIniKeys("[App1]\npath=c:\\x\nusers=a\n;comentario\n[App1]\npath=duplicado\n\n[Seguridad]\nalwaydesktop=1\n");
    True(parsed["App1"].Count == 2 && parsed["App1"].Contains("path") && parsed["App1"].Contains("users"), "Parseo INI incorrecto (secciones/claves/duplicados).");
    True(parsed["Seguridad"].Contains("alwaydesktop"), "Segunda sección no parseada.");
    var prev = new Dictionary<string, Dictionary<string, List<string>>>(StringComparer.OrdinalIgnoreCase)
    {
        ["app.ini"] = new(StringComparer.OrdinalIgnoreCase) { ["App1"] = ["path", "users"] }
    };
    var cur = new Dictionary<string, Dictionary<string, List<string>>>(StringComparer.OrdinalIgnoreCase)
    {
        ["app.ini"] = new(StringComparer.OrdinalIgnoreCase) { ["App1"] = ["path", "groups"], ["App2"] = ["x"] }
    };
    var changes = TsplusConfigSemanticDiff.DiffIni(prev, cur);
    Equal(3, changes.Count, "Debería haber +seccion App2, +clave groups, -clave users.");
    True(TsplusConfigSemanticDiff.DiffIni(prev, prev).Count == 0, "Idénticos generaron cambios.");
    True(TsplusConfigSemanticDiff.Summarize(changes).Contains("App2", StringComparison.Ordinal), "El resumen no menciona la sección agregada.");
    return Task.CompletedTask;
}

static Task RegistryFingerprintStableAndSecretFree()
{
    var a = TsplusConfigSemanticDiff.FingerprintValue("String", "Password123");
    Equal(a, TsplusConfigSemanticDiff.FingerprintValue("String", "Password123"), "Huella inestable.");
    False(a.Contains("Password123", StringComparison.Ordinal), "La huella expone el secreto.");
    False(TsplusConfigSemanticDiff.FingerprintValue("String", "Password123").Equals(TsplusConfigSemanticDiff.FingerprintValue("String", "otra"), StringComparison.Ordinal), "Huella insensible al contenido.");
    return Task.CompletedTask;
}

static Task ProcessModulePolicyFlags()
{
    True(TsplusProcessModulePolicy.IsUnderRoot("C:\\TSplus\\svc.exe", "C:\\TSplus"), "Binario propio no reconocido.");
    False(TsplusProcessModulePolicy.IsUnderRoot("C:\\Windows\\System32\\a.dll", "C:\\TSplus"), "Sistema marcado como propio.");
    False(TsplusProcessModulePolicy.IsUnderRoot(null, "C:\\TSplus"), "Null aceptado.");
    True(TsplusProcessModulePolicy.IsSuspiciousLocation("C:\\Users\\x\\AppData\\Local\\Temp\\evil.dll"), "Temp no marcado.");
    False(TsplusProcessModulePolicy.IsSuspiciousLocation("C:\\Windows\\System32\\a.dll"), "System32 marcado.");
    return Task.CompletedTask;
}

static Task ChannelCoverageFormatsRange()
{
    Equal("Disponible; registros leídos=10; rango=100..109",
        IncrementalWindowsEventCollector.FormatChannelCoverage(false, 10, 100, 109), "Formato de cobertura incorrecto.");
    True(IncrementalWindowsEventCollector.FormatChannelCoverage(true, 250, 1, 300).StartsWith("Parcial; backlog pendiente; registros procesados=250; rango=1..300", StringComparison.Ordinal), "Backlog mal formateado.");
    Equal("Disponible; registros leídos=0; rango=N/D",
        IncrementalWindowsEventCollector.FormatChannelCoverage(false, 0, null, null), "Vacío mal formateado.");
    return Task.CompletedTask;
}

static Task CauseStabilityCalmWhenStable()
{
    True(CauseStabilityAnalyzer.Analyze(["A", "A", "A", "A", "A", "A"]) is null, "Historial estable marcado inestable.");
    True(CauseStabilityAnalyzer.Analyze(["A"]) is null, "Historial corto marcado inestable.");
    True(CauseStabilityAnalyzer.Analyze([]) is null, "Vacío marcado inestable.");
    True(CauseStabilityAnalyzer.Analyze(["A", "B", "A", "B", "A", "B"]) is null, "Alternancia entre 2 marcada inestable.");
    return Task.CompletedTask;
}

static Task CauseStabilityFlagsFlapping()
{
    var finding = CauseStabilityAnalyzer.Analyze(["A", "B", "A", "C", "B", "C"]);
    NotNull(finding, "Rotación A/B/C no detectada.");
    Equal("TDM-CAUSE-UNSTABLE", finding!.Id, "Id de inestabilidad inesperado.");
    True(finding.Evidencia.Any(e => e.Clave == "Secuencia"), "Falta la secuencia en evidencia.");
    return Task.CompletedTask;
}

static Task CauseStabilityIgnoresEmpty()
{
    True(CauseStabilityAnalyzer.Analyze(["A", "", "A", "", "A", "A"]) is null, "Vacíos contados como causas.");
    return Task.CompletedTask;
}

static Task FindingIntervalOverlapsDiagnosticWindow()
{
    var now = DateTimeOffset.Now;
    var finding = new DiagnosticFinding("INTERVAL", "TSplus", DiagnosticSeverity.Error, "intervalo", "",
        [new EvidenceItem("Primer evento", now.AddHours(-2).ToString("O")), new EvidenceItem("Último evento", now.AddMinutes(-5).ToString("O"))],
        ConfidenceLevel.Media, Capa: DiagnosticLayer.Tsplus);
    True(DiagnosticTimeWindow.IsFindingInside(finding, now.AddMinutes(-30), now), "Un hallazgo cuyo intervalo se solapa con la ventana fue descartado.");
    return Task.CompletedTask;
}

static Task EventLogCollectorsHandleEventLogException()
{
    // Gate anti-Y1: todo collector que abra un EventLogQuery debe capturar EventLogException
    // (forma directa o filtro `when`), o una lectura corrupta a mitad de canal tumba el collector
    // entero como COLLECTOR-ERROR perdiendo hasta la cobertura. Regla a nivel archivo.
    var root = FindRepoRoot();
    NotNull(root, "No se localizó TDM.sln caminando desde el ensamblado de pruebas; gate anti-Y1 no ejecutable.");
    var offenders = new List<string>();
    foreach (var file in Directory.EnumerateFiles(Path.Combine(root!, "src"), "*.cs", SearchOption.AllDirectories))
    {
        if (file.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.OrdinalIgnoreCase)
            || file.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}", StringComparison.OrdinalIgnoreCase))
            continue;
        var text = File.ReadAllText(file);
        if (!text.Contains("new EventLogQuery", StringComparison.Ordinal)) continue;
        if (text.Contains("catch (EventLogException", StringComparison.Ordinal)) continue;
        if (text.Contains("when (ex is EventLogException", StringComparison.Ordinal)) continue;
        offenders.Add(Path.GetRelativePath(root!, file));
    }
    True(offenders.Count == 0, "Collectors con EventLogQuery sin catch EventLogException: " + string.Join(", ", offenders));
    return Task.CompletedTask;
}

static string? FindRepoRoot()
{
    var directory = new DirectoryInfo(AppContext.BaseDirectory);
    while (directory is not null)
    {
        if (File.Exists(Path.Combine(directory.FullName, "TDM.sln"))) return directory.FullName;
        directory = directory.Parent;
    }
    return null;
}

sealed record CursorFixture(Dictionary<string, long> Values, DateTimeOffset SavedAt);

sealed class MemorySink : INotificationSink
{
    public List<IncidentNotification> Items { get; } = [];
    public Task SendAsync(IncidentNotification notification, CancellationToken ct = default)
    {
        Items.Add(notification);
        return Task.CompletedTask;
    }
}

sealed class FixedCollector(DiagnosticEvent value) : IReadOnlyCollector
{
    public string Nombre => "ProductionTestCollector";
    public Task<CollectorResult> CollectAsync(DiagnosticContext context, CancellationToken cancellationToken = default)
        => Task.FromResult(new CollectorResult([], [value]));
}
