using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;
using TDM.Application;
using TDM.Collectors.TSplus;
using TDM.Collectors.Windows;
using TDM.Core;
using TDM.Correlation;
using TDM.Gui.Avalonia.ViewModels;
using TDM.Models;
using TDM.Notifications;
using TDM.Persistence;
using TDM.Reporting;

CultureInfo.DefaultThreadCurrentCulture = CultureInfo.InvariantCulture;
CultureInfo.DefaultThreadCurrentUICulture = CultureInfo.InvariantCulture;
Thread.CurrentThread.CurrentCulture = CultureInfo.InvariantCulture;
Thread.CurrentThread.CurrentUICulture = CultureInfo.InvariantCulture;

var tests = new List<(string Name, Func<Task> Run)>
{
    ("UndatedFunctionalIncidentRejected", UndatedFunctionalIncidentRejected),
    ("TimestampedFunctionalIncidentAccepted", TimestampedFunctionalIncidentAccepted),
    ("StoppedTsplusServiceStateIsFunctionalIncident", StoppedTsplusServiceStateIsFunctionalIncident),
    ("StoppedWebPortalIsImpactNotCause", StoppedWebPortalIsImpactNotCause),
    ("RankingConflictEvidenceUsesFinalScores", RankingConflictEvidenceUsesFinalScores),
    ("DuplicateCandidateIdsRankIndependently", DuplicateCandidateIdsRankIndependently),
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
    ("LedgerKeepsIdentityClassifiedIncidents", LedgerKeepsIdentityClassifiedIncidents),
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
    ("SpanishUserEvidenceSplitsIdentityClusters", SpanishUserEvidenceSplitsIdentityClusters),
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
    ("CauseStabilityIgnoresEmpty", CauseStabilityIgnoresEmpty),
    ("CauseDrivenImpactUsesWordBoundaries", CauseDrivenImpactUsesWordBoundaries),
    ("FlappingThresholdHonorsConfiguredOptions", FlappingThresholdHonorsConfiguredOptions),
    ("EwmaAnomaliesSurfaceAsReportFindings", EwmaAnomaliesSurfaceAsReportFindings),
    ("WindowsEventCollectorHonorsMaxEventsOption", WindowsEventCollectorHonorsMaxEventsOption),
    ("SecurityLogTargetsAuditEventIdsAndAlignsDedupKeys", SecurityLogTargetsAuditEventIdsAndAlignsDedupKeys),
    ("LightweightTsplusStoppedSeverityHonorsStartMode", LightweightTsplusStoppedSeverityHonorsStartMode),
    ("StaticWindowsConfigCandidatesNeedRemoteSessionSymptom", StaticWindowsConfigCandidatesNeedRemoteSessionSymptom),
    ("WindowsPushSubscriptionIsSharedAcrossInstances", WindowsPushSubscriptionIsSharedAcrossInstances),
    ("GuiPrerecordsStateAndReadsFeedbackFromBothRoots", GuiPrerecordsStateAndReadsFeedbackFromBothRoots),
    ("FeedbackReadMergesRootsAndDeduplicates", FeedbackReadMergesRootsAndDeduplicates),
    ("TestsRunUnderPinnedInvariantCulture", TestsRunUnderPinnedInvariantCulture),
    ("ContinuousMergerKeepsWindowStateAndAnchoredEvents", ContinuousMergerKeepsWindowStateAndAnchoredEvents),
    ("ContinuousRunReplansSeedWhenWindowGrows", ContinuousRunReplansSeedWhenWindowGrows),
    ("ContinuousCatalogSwapsHeavySourcesForIncremental", ContinuousCatalogSwapsHeavySourcesForIncremental),
    ("TsplusCoverageAcceptsIncrementalSource", TsplusCoverageAcceptsIncrementalSource),
    ("GuiRealtimeWiresIncrementalContinuousDiagnostics", GuiRealtimeWiresIncrementalContinuousDiagnostics),
    ("ExportRootCauseMarkersAndFooters", ExportRootCauseMarkersAndFooters),
    ("ExportGuidedResolutionOrderAndDetails", ExportGuidedResolutionOrderAndDetails),
    ("ExportPatternsShowSingletonsAndFullColumns", ExportPatternsShowSingletonsAndFullColumns),
    ("ExportCoverageCountsAndCriticalFirst", ExportCoverageCountsAndCriticalFirst),
    ("ExportJsonUsesStringEnumsAndRoundTrips", ExportJsonUsesStringEnumsAndRoundTrips),
    ("SanitizerIdempotentAvoidsSpuriousDiff", SanitizerIdempotentAvoidsSpuriousDiff),
    ("NarrativeUsesLocalTimeForWindows", NarrativeUsesLocalTimeForWindows),
    ("EvidenceDetailsFallBackToIngestedAt", EvidenceDetailsFallBackToIngestedAt),
    ("SanitizeCoversPreviouslyRawSections", SanitizeCoversPreviouslyRawSections),
    ("ExportJsonMasksPrimaryCauseAndClusterIdentity", ExportJsonMasksPrimaryCauseAndClusterIdentity),
    ("ExportSanitizesIdentityBearingIdsAndComponents", ExportSanitizesIdentityBearingIdsAndComponents),
    ("EvidenceKeysOutsideTablesArePseudonymized", EvidenceKeysOutsideTablesArePseudonymized),
    ("SourcePseudonymizesIdentityIdsAndComponents", SourcePseudonymizesIdentityIdsAndComponents),
    ("SecurityLogMissingStatusIsNotAvailable", SecurityLogMissingStatusIsNotAvailable),
    ("WindowsEventRecoveryLookbackRestoresPersistedGap", WindowsEventRecoveryLookbackRestoresPersistedGap),
    ("WindowsEventRecoveryLookbackDisarmsAfterFirstCollect", WindowsEventRecoveryLookbackDisarmsAfterFirstCollect),
    ("TsplusCursorKeepsOffsetAfterAppend", TsplusCursorKeepsOffsetAfterAppend),
    ("TsplusBacklogSurvivesRestartWithoutCursorLoss", TsplusBacklogSurvivesRestartWithoutCursorLoss),
    ("WindowsEventNewChannelStartsWithRecentWindow", WindowsEventNewChannelStartsWithRecentWindow),
    ("WindowsEventGapRecoveryIsWiredInWorker", WindowsEventGapRecoveryIsWiredInWorker),
    ("WindowsEventBaseCoverageCountsMissingChannelAsPartial", WindowsEventBaseCoverageCountsMissingChannelAsPartial),
    ("ExportRendersBaseWindowsEventCoverage", ExportRendersBaseWindowsEventCoverage),
    ("DiagnosticSampleKindUnifiesProducers", DiagnosticSampleKindUnifiesProducers),
    ("ResourceMetricReadersUseStableKeys", ResourceMetricReadersUseStableKeys),
    ("NotEvaluatedTsplusDetectionIsCommunicated", NotEvaluatedTsplusDetectionIsCommunicated),
    ("TsplusLogCoverageNotEvaluatedWithoutDetection", TsplusLogCoverageNotEvaluatedWithoutDetection),
    ("IncrementalCoverageCountsMissingExpectedSources", IncrementalCoverageCountsMissingExpectedSources),
    ("ServiceRecentTransitionsWiredBeforeCorrelation", ServiceRecentTransitionsWiredBeforeCorrelation),
    ("RecordAndEnrichDeduplicatesPreRecordedTransitions", RecordAndEnrichDeduplicatesPreRecordedTransitions),
    ("CarryForwardKeepsDroppedObservationLinked", CarryForwardKeepsDroppedObservationLinked),
    ("ConfigDriftUnreadableFileKeepsBaseline", ConfigDriftUnreadableFileKeepsBaseline),
    ("ConfigDriftTracksWebArtifactsAndSeedsExisting", ConfigDriftTracksWebArtifactsAndSeedsExisting),
    ("ExportRendersTensionesSection", ExportRendersTensionesSection),
    ("ExportExecutiveCardsAndCountsAreCoherent", ExportExecutiveCardsAndCountsAreCoherent),
    ("NarrativeCountsTsplusFindingsAsInternalAnomalies", NarrativeCountsTsplusFindingsAsInternalAnomalies),
    ("SettingsLoadRepairsInvalidThresholdsPerGroup", SettingsLoadRepairsInvalidThresholdsPerGroup),
    ("UnknownTsplusVersionStillReportsMissingSettingsJs", UnknownTsplusVersionStillReportsMissingSettingsJs),
    ("UnifiedServiceRequiredNowPolicyMatchesSeverity", UnifiedServiceRequiredNowPolicyMatchesSeverity),
    ("StateTransitionDedupKeepsDistinctEpisodes", StateTransitionDedupKeepsDistinctEpisodes),
    ("IncidentClustersClipToAnalyzedWindow", IncidentClustersClipToAnalyzedWindow),
    ("StaleRemoteSymptomDoesNotConfirmCandidates", StaleRemoteSymptomDoesNotConfirmCandidates),
    ("AnalysisWindowClipIsWiredAcrossRcaFeeds", AnalysisWindowClipIsWiredAcrossRcaFeeds),
    ("ExportDependencyRowsShowOriginServiceAndWarnOnNotEvaluated", ExportDependencyRowsShowOriginServiceAndWarnOnNotEvaluated),
    ("ExportFooterReportsHiddenDependencyRows", ExportFooterReportsHiddenDependencyRows),
    ("ScmDriftBaselineSkipsFailedReads", ScmDriftBaselineSkipsFailedReads),
    ("TsplusSpanishLogLinesClassify", TsplusSpanishLogLinesClassify),
    ("CorruptSnapshotIsTelemetered", CorruptSnapshotIsTelemetered),
    ("ConfigurationHistoryDiffWorksAcrossGenerations", ConfigurationHistoryDiffWorksAcrossGenerations),
    ("DiagnosticAvaloniaTransitionsReadAcrossChannels", DiagnosticAvaloniaTransitionsReadAcrossChannels),
    ("ExportRendersServiceStateAndProcessSections", ExportRendersServiceStateAndProcessSections),
    ("ClusterIdsAreContentDerivedAndStable", ClusterIdsAreContentDerivedAndStable),
    ("BurstCollapseReportsRealSpanAndSubjects", BurstCollapseReportsRealSpanAndSubjects),
    ("IncidentWindowDeclaresSourceTruncation", IncidentWindowDeclaresSourceTruncation),
    ("LedgerKindChangeCreatesNewIncident", LedgerKindChangeCreatesNewIncident),
    ("TimestampParsingHasNoCulturalFallback", TimestampParsingHasNoCulturalFallback),
    ("IncrementalReadsUtf16WithoutBom", IncrementalReadsUtf16WithoutBom),
    ("ReportDifferHandlesDuplicateFindingIdsAndUndatedReports", ReportDifferHandlesDuplicateFindingIdsAndUndatedReports),
    ("ExportKeepsDiffCardWithDuplicateFindingIds", ExportKeepsDiffCardWithDuplicateFindingIds),
    ("EmergencySamplePersistsJournalTransitionsAndLongitudinal", EmergencySamplePersistsJournalTransitionsAndLongitudinal),
    ("LongitudinalPhaseBudgetGateRejectsFixed45Seconds", LongitudinalPhaseBudgetGateRejectsFixed45Seconds),
    ("ServiceDependencyGraphIsolatesServiceFailures", ServiceDependencyGraphIsolatesServiceFailures),
    ("NlaPasswordChangeNeedsWindowedConflict", NlaPasswordChangeNeedsWindowedConflict),
    ("UncorrelatedConfigCandidatesDoNotConflict", UncorrelatedConfigCandidatesDoNotConflict),
    ("RdpSuccessStagesAreNotOperationalIncidents", RdpSuccessStagesAreNotOperationalIncidents),
    ("PrincipalWithoutIndependentEvidenceRaisesTension", PrincipalWithoutIndependentEvidenceRaisesTension),
    ("FailurePatternsUseFullCandidateList", FailurePatternsUseFullCandidateList),
    ("RemoteLogonFailuresCoverEachCorrelatedUser", RemoteLogonFailuresCoverEachCorrelatedUser),
    ("PeriodEndFallbackIsUnifiedAcrossNarrativeAndExport", PeriodEndFallbackIsUnifiedAcrossNarrativeAndExport),
    ("ServiceDiscoveryFallbackDeclaresCoverage", ServiceDiscoveryFallbackDeclaresCoverage),
    ("LogIntegrityBudgetIsPerChannelAndDeclared", LogIntegrityBudgetIsPerChannelAndDeclared),
    ("RegistryBaselineInitializationIsDeclared", RegistryBaselineInitializationIsDeclared),
    ("ForensicMissingChannelIsNotPermanentPartial", ForensicMissingChannelIsNotPermanentPartial),
    ("LogParserHonorsBracketedDeclaredLevel", LogParserHonorsBracketedDeclaredLevel),
    ("UndatedLogEventsExpireWithTheWindow", UndatedLogEventsExpireWithTheWindow),
    ("TransitionCarriesObservationInterval", TransitionCarriesObservationInterval),
    ("LongitudinalPrecedenceUsesIntervalLowerBound", LongitudinalPrecedenceUsesIntervalLowerBound),
    ("RecentTransitionReadFailureIsDeclared", RecentTransitionReadFailureIsDeclared),
    ("WindowsEventCollectorPinsSecurityAuditIdsEndToEnd", WindowsEventCollectorPinsSecurityAuditIdsEndToEnd),
    ("ForensicCollectorEndToEndDeclaresEveryChannelState", ForensicCollectorEndToEndDeclaresEveryChannelState),
    ("MergerPreservesRequestedLookbackAndDeclaresExpansion", MergerPreservesRequestedLookbackAndDeclaresExpansion),
    ("DependencyNotEvaluatedGuardChecksDependentsToo", DependencyNotEvaluatedGuardChecksDependentsToo),
    ("RecentTransitionReadSkipsFilesOutsideWindow", RecentTransitionReadSkipsFilesOutsideWindow),
    ("LocalHistoryUnavailableIsDeclaredInCoverage", LocalHistoryUnavailableIsDeclaredInCoverage),
    ("DashboardDeclaresDependencyDataFreshness", DashboardDeclaresDependencyDataFreshness),
    ("SafeWmiAppliesBoundedOptionsInBothBranches", SafeWmiAppliesBoundedOptionsInBothBranches),
    ("SingleFlightCaptureReusesPendingFlightUntilAbandonAge", SingleFlightCaptureReusesPendingFlightUntilAbandonAge),
    ("SingleFlightCaptureTakesCompletedAndRestartsAfterFault", SingleFlightCaptureTakesCompletedAndRestartsAfterFault),
    ("IncidentLedgerGateSurvivesInterprocessLockFailure", IncidentLedgerGateSurvivesInterprocessLockFailure),
    ("HistoricalReadFailurePreservesRetentionHistory", HistoricalReadFailurePreservesRetentionHistory),
    ("ResourceWindowReadFailureSkipsCompaction", ResourceWindowReadFailureSkipsCompaction),
    ("LatestReportSaveKeepsPreviousOnFailedWrite", LatestReportSaveKeepsPreviousOnFailedWrite),
    ("TimeWindowParsesExactFormatsWithoutCulture", TimeWindowParsesExactFormatsWithoutCulture),
    ("TdmSourcedEventsAreNotCausalSignals", TdmSourcedEventsAreNotCausalSignals),
    ("SaturatedDirectImpactStillElectsCausalPrimary", SaturatedDirectImpactStillElectsCausalPrimary),
    ("CrashAndDependencyCandidateIdsAreUnique", CrashAndDependencyCandidateIdsAreUnique),
    ("EachFailingDependencyGetsItsOwnCandidate", EachFailingDependencyGetsItsOwnCandidate),
    ("PendingAndManualStopsDoNotClaimDirectImpact", PendingAndManualStopsDoNotClaimDirectImpact),
    ("InterleavedBurstKeepsSharedIncidentTogether", InterleavedBurstKeepsSharedIncidentTogether)
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
    var report = Report([web, ad], now.AddSeconds(30));
    var clusters = IncidentClusterAnalyzer.Analyze(report);
    True(clusters.Count == 2, "Web/HTML5 y AD fueron mezclados en un solo incidente.");
    return Task.CompletedTask;
}

static Task SpanishUserEvidenceSplitsIdentityClusters()
{
    var now = DateTimeOffset.Now;
    var alice = new DiagnosticEvent(now, "Netlogon", "Active Directory", DiagnosticLayer.Windows, DiagnosticSeverity.Error,
        "WINDOWS_AD_DOMAIN_CONNECTIVITY_FAILURE", "Secure channel failed", Evidencia: [new EvidenceItem("Usuario", "alice")]);
    var bob = new DiagnosticEvent(now.AddSeconds(20), "Netlogon", "Active Directory", DiagnosticLayer.Windows, DiagnosticSeverity.Error,
        "WINDOWS_AD_DOMAIN_CONNECTIVITY_FAILURE", "Secure channel failed", Evidencia: [new EvidenceItem("Usuario", "bob")]);
    var report = Report([alice, bob], now.AddSeconds(30));
    var clusters = IncidentClusterAnalyzer.Analyze(report);
    True(clusters.Count == 2, "Dos identidades con evidencia 'Usuario' distinta se agruparon en un solo clúster.");
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

static Task DuplicateCandidateIdsRankIndependently()
{
    var now = DateTimeOffset.Now;
    var strong = new RootCauseCandidate(1, "ROOT-PROCESS-CRASH", "tsplus.exe", DiagnosticLayer.Tsplus, 90, ConfidenceLevel.Alta, "Crash A", "explicación", [], Producto: TsplusProduct.RemoteAccess, HoraIncidente: now.AddMinutes(-5), OrigenClasificado: "TSPLUS");
    var weak = new RootCauseCandidate(2, "ROOT-PROCESS-CRASH", "webportal", DiagnosticLayer.Tsplus, 70, ConfidenceLevel.Media, "Crash B", "explicación", [], Producto: TsplusProduct.RemoteAccess, HoraIncidente: now.AddMinutes(-4), OrigenClasificado: "TSPLUS");
    var calibrated = DiagnosticPrecisionAnalyzer.Calibrate(Report([], now), [strong, weak]);
    Equal(2, calibrated.Count, "El calibrador descartó candidatos duplicados.");
    string Evidence(RootCauseCandidate c, string key) => c.Evidencia.FirstOrDefault(e => e.Clave == key)?.Valor ?? "N/D";
    var top = calibrated.First(c => c.Posicion == 1);
    var second = calibrated.First(c => c.Posicion == 2);
    Equal("0 puntos", Evidence(top, "Diferencia contra mejor candidato causal"), "El candidato top no reporta brecha cero.");
    True(top.Puntaje > second.Puntaje, "El orden esperado del ranking se invirtió.");
    Equal($"{top.Puntaje - second.Puntaje} puntos", Evidence(second, "Diferencia contra mejor candidato causal"), "Dos candidatos con el mismo Id compartieron la brecha del ranking.");
    Equal("CANDIDATO_PRINCIPAL", Evidence(top, "Estado de ranking"), "El candidato top perdió su estado de principal.");
    Equal("CANDIDATO_SECUNDARIO", Evidence(second, "Estado de ranking"), "El segundo candidato con el mismo Id heredó el estado de principal.");
    True(calibrated.Count(c => Evidence(c, "Estado de ranking") == "CANDIDATO_PRINCIPAL") == 1, "Más de un candidato se declaró principal.");
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

static async Task LedgerKeepsIdentityClassifiedIncidents()
{
    var root = TempDir();
    try
    {
        var at = DateTimeOffset.Now;
        var ledger = new IncidentLedger(root);
        var identity = new ObservabilityIncident(at, "ACCOUNT_LOCKOUT", "RDP/Auth", "Error",
            "Bloqueo de cuenta correlacionado con sesión", Product: nameof(TsplusProduct.Ninguno),
            Classification: "IdentityCorrelated");
        var written = await ledger.ReconcileAsync([identity], at, SupportMonitoringSettings.Default);
        Equal(1, written.Count, "El incidente de identidad clasificado no entró al ledger.");
        True(written[0].Classification == "IdentityCorrelated", "El ledger no conservó la clasificación de identidad.");

        await ledger.AddNoteAsync(written[0].Id, "revisar cuentas");
        var afterNote = await ledger.ReadAsync();
        Equal(1, afterNote.Count, "AddNoteAsync borró el incidente de identidad del archivo.");
        True(afterNote[0].TechnicianNote == "revisar cuentas", "La nota técnica no se persistió.");
        True(afterNote[0].Classification == "IdentityCorrelated", "La clasificación de identidad se perdió al reescribir.");

        await ledger.CloseAsync(afterNote[0].Id);
        var afterClose = await ledger.ReadAsync();
        Equal(1, afterClose.Count, "CloseAsync borró el incidente de identidad del archivo.");
        True(afterClose[0].State == ManagedIncidentState.Closed, "El incidente de identidad no se cerró.");
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
          .FirstOrDefault(x => x.Id.StartsWith("ROOT-PROCESS-CRASH", StringComparison.OrdinalIgnoreCase));
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

static Task ClusterIdsAreContentDerivedAndStable()
{
    var now = DateTimeOffset.Now;
    static DiagnosticEvent Web(DateTimeOffset at) => new(at, "SCM", "Web Portal Service", DiagnosticLayer.Tsplus,
        DiagnosticSeverity.Critico, "SERVICE_STATE", "Stopped",
        Evidencia: [new EvidenceItem("Servicio", "WebPortalService"), new EvidenceItem("Estado", "Stopped")],
        Producto: TsplusProduct.RemoteAccess);
    static DiagnosticEvent Ad(DateTimeOffset at) => new(at, "Netlogon", "Active Directory", DiagnosticLayer.Windows,
        DiagnosticSeverity.Error, "WINDOWS_AD_DOMAIN_CONNECTIVITY_FAILURE", "Secure channel failed");

    var t0 = now.AddMinutes(-30);
    var baseReport = Report([Web(t0), Ad(t0.AddSeconds(15))], now);
    var run1 = IncidentClusterAnalyzer.Analyze(baseReport);
    var run2 = IncidentClusterAnalyzer.Analyze(baseReport);
    Equal(2, run1.Count, "Web/HTML5 y AD no formaron clústeres separados.");
    for (var i = 0; i < run1.Count; i++)
        Equal(run1[i].Id, run2[i].Id, $"El ID del clúster {i} no es determinista entre ejecuciones.");

    var early = Web(now.AddMinutes(-50));
    var shifted = IncidentClusterAnalyzer.Analyze(Report([early, Web(t0), Ad(t0.AddSeconds(15))], now));
    Equal(3, shifted.Count, "El clúster temprano no generó un tercer grupo.");
    Equal(run1[0].Id, shifted[1].Id, "El ID de un clúster cambió de posición al aparecer un clúster previo.");
    Equal(run1[1].Id, shifted[2].Id, "El ID del segundo clúster cambió de posición al aparecer un clúster previo.");
    True(!run1[0].Id.Equals(shifted[0].Id, StringComparison.Ordinal),
        "Dos clústeres con el mismo dominio/identidad pero distinto primer evento compartieron ID.");
    foreach (var cluster in run1.Concat(shifted))
    {
        True(cluster.Id.StartsWith("INC-GRP-", StringComparison.Ordinal), "El ID del clúster no usa el prefijo INC-GRP-.");
        Equal(16, cluster.Id.Length, "El ID del clúster no tiene la longitud content-derived esperada (8+8).");
        True(cluster.Id[8..].All(Uri.IsHexDigit), $"El ID del clúster no termina en 8 dígitos hexadecimales: {cluster.Id}");
    }
    return Task.CompletedTask;
}

static async Task BurstCollapseReportsRealSpanAndSubjects()
{
    var root = TempDir();
    try
    {
        var store = new ObservabilityStore(root);
        var t0 = DateTimeOffset.Now.AddMinutes(-10);
        var users = new[] { "alice", "bob", "alice", "carol" };
        var events = new List<DiagnosticEvent>();
        for (var i = 0; i < 4; i++)
        {
            events.Add(new DiagnosticEvent(t0.AddSeconds(i * 50), "TSplus Log", "Remote Access", DiagnosticLayer.Tsplus,
                DiagnosticSeverity.Error, "APPLICATION_CRASH", $"crash {i}",
                Evidencia: [new EvidenceItem("RecordId", $"R{i}"), new EvidenceItem("Usuario", users[i])],
                Producto: TsplusProduct.RemoteAccess));
        }
        var sample = await store.RecordAsync(Report(events, DateTimeOffset.Now), "monitor", new ObservabilityRuntimeState());

        NotNull(sample.Incidents, "La muestra no conserva la colección de incidentes.");
        Equal(1, sample.Incidents!.Count, "La ráfaga no colapsó en un solo incidente.");
        Equal(0, sample.IncidentsDropped, "Una ráfaga colapsada declaró truncamiento falso en origen.");
        var incident = sample.Incidents[0];
        True(incident.Summary.Contains("ráfaga ×4", StringComparison.Ordinal),
            $"El resumen no declara el conteo real de la ráfaga: {incident.Summary}");
        True(incident.Summary.Contains(" en 2.5 min", StringComparison.Ordinal),
            $"El resumen no declara el span real de la ráfaga (esperado ' en 2.5 min'): {incident.Summary}");
        False(incident.Summary.Contains("/60s", StringComparison.Ordinal),
            $"El resumen volvió al rótulo '/60s' que mentía sobre el span: {incident.Summary}");
        Equal(t0.AddSeconds(150), incident.Timestamp, "La ráfaga colapsada no conservó el evento más reciente.");
        Equal("R3", incident.EvidenceId ?? "", "La ráfaga no conservó el EvidenceId del evento más reciente.");
        var subjects = (incident.Subject ?? string.Empty).Split(',', StringSplitOptions.TrimEntries);
        Equal(3, subjects.Length, $"El Subject de la ráfaga no unió los distintos usuarios sin duplicados: '{incident.Subject}'");
        True(subjects.Contains("alice") && subjects.Contains("bob") && subjects.Contains("carol"),
            $"El Subject de la ráfaga perdió identidades previas (hereda sólo la del último): '{incident.Subject}'");
    }
    finally { TryDelete(root); }
}

static async Task IncidentWindowDeclaresSourceTruncation()
{
    var root = TempDir();
    try
    {
        var store = new ObservabilityStore(root);
        var now = DateTimeOffset.Now;
        var events = new List<DiagnosticEvent>();
        for (var i = 0; i < 130; i++)
        {
            events.Add(new DiagnosticEvent(now.AddSeconds(-(130 - i) * 90), "TSplus Log", "Remote Access", DiagnosticLayer.Tsplus,
                DiagnosticSeverity.Error, "APPLICATION_CRASH", $"crash {i}",
                Evidencia: [new EvidenceItem("RecordId", $"R{i}")],
                Producto: TsplusProduct.RemoteAccess));
        }
        var sample = await store.RecordAsync(Report(events, now), "monitor", new ObservabilityRuntimeState());
        NotNull(sample.Incidents, "La muestra no conserva la colección de incidentes.");
        Equal(120, sample.Incidents!.Count, "El tope de 120 por muestra no se aplicó.");
        Equal(10, sample.IncidentsDropped, "La muestra no declaró los incidentes descartados en el origen.");
        Equal(0, new ObservabilitySample().IncidentsDropped,
            "Muestras legadas sin el campo declararon truncamiento falso.");
    }
    finally { TryDelete(root); }
}

static async Task LedgerKindChangeCreatesNewIncident()
{
    var root = TempDir();
    try
    {
        var at = DateTimeOffset.Now;
        var ledger = new IncidentLedger(root);
        var crash = new ObservabilityIncident(at, "APPLICATION_CRASH", "Remote Access", "Error", "crash 1");
        var first = await ledger.ReconcileAsync([crash], at, SupportMonitoringSettings.Default);
        Equal(1, first.Count, "El incidente inicial no entró al ledger.");
        var crashId = first[0].Id;

        var wer = new ObservabilityIncident(at.AddSeconds(5), "WER_REPORT", "Remote Access", "Error", "wer 1");
        var second = await ledger.ReconcileAsync([wer], at.AddSeconds(5), SupportMonitoringSettings.Default);
        Equal(2, second.Count, "El cambio de Kind no creó un incidente nuevo en el ledger.");
        var werItem = second.Single(x => x.Kind.Equals("WER_REPORT", StringComparison.OrdinalIgnoreCase));
        True(!werItem.Id.Equals(crashId, StringComparison.OrdinalIgnoreCase),
            "El incidente con Kind distinto reutilizó el Id del incidente previo (contaminaría VerifiedHistory).");

        var crashAgain = crash with { Timestamp = at.AddSeconds(10) };
        var third = await ledger.ReconcileAsync([crashAgain], at.AddSeconds(10), SupportMonitoringSettings.Default);
        var crashItem = third.Single(x => x.Kind.Equals("APPLICATION_CRASH", StringComparison.OrdinalIgnoreCase));
        Equal(crashId, crashItem.Id, "El mismo Kind dentro del cooldown no reutilizó su incidente.");
        Equal(2, crashItem.Occurrences, "El mismo Kind dentro del cooldown no incrementó su conteo.");
        Equal(ManagedIncidentState.Persistent, crashItem.State, "El mismo Kind dentro del cooldown no elevó su estado a persistente.");
    }
    finally { TryDelete(root); }
}

static Task TimestampParsingHasNoCulturalFallback()
{
    var isoT = TsplusLogParser.TryParseTimestamp("2026-09-06T18:10:11 ERROR failed");
    True(isoT.HasValue && isoT.Value.Year == 2026 && isoT.Value.Month == 9 && isoT.Value.Day == 6,
        "El timestamp ISO con separador T dejó de reconocerse sin fallback cultural.");

    var utc = TsplusLogParser.TryParseTimestamp("2026-09-06 18:10:11Z ERROR failed");
    True(utc.HasValue && utc.Value.Offset == TimeSpan.Zero, "El sufijo Z no se conservó como UTC.");

    var offset = TsplusLogParser.TryParseTimestamp("13/02/2026 10:00:00+01:00 ERROR failed");
    True(offset.HasValue && offset.Value.Offset == TimeSpan.FromHours(1) && offset.Value.Month == 2 && offset.Value.Day == 13,
        "La fecha con sufijo de zona +01:00 no se resolvió de forma inequívoca.");

    False(TsplusLogParser.TryParseTimestamp("12/11/2026T10:00:00 ERROR failed").HasValue,
        "Una fecha ambigua sin contexto de ventana se resolvió por una cultura de fallback.");

    var local = new DateTime(2026, 4, 3, 12, 30, 0, DateTimeKind.Unspecified);
    var end = new DateTimeOffset(local, TimeZoneInfo.Local.GetUtcOffset(local));
    var context = new DiagnosticContext(Snapshot(), TimeSpan.FromHours(1), end);
    var withT = TsplusLogParser.ParseLine("Remote Access", "x.log", "03/04/2026T12:00:00 ERROR failed to start application", 1, context);
    NotNull(withT, "La fecha ambigua con separador T no se resolvió con la ventana de investigación.");
    True(withT!.Timestamp is { Month: 4, Day: 3 },
        "La fecha ambigua T no se resolvió como dd/MM dentro de la ventana de investigación.");

    var withFraction = TsplusLogParser.ParseLine("Remote Access", "x.log", "03/04/2026 12:00:00,500 ERROR failed to start application", 1, context);
    NotNull(withFraction, "La fecha con fracción con coma no se resolvió dentro de la ventana de investigación.");
    True(withFraction!.Timestamp is { Month: 4, Day: 3 },
        "La fecha con fracción con coma se resolvió con la interpretación equivocada.");

    var root = FindRepoRoot();
    NotNull(root, "No se localizó TDM.sln; gate del parser no ejecutable.");
    var parser = File.ReadAllText(Path.Combine(root!, "src", "TDM.Collectors.TSplus", "TsplusLogParser.cs"));
    False(parser.Contains("\"es-MX\"", StringComparison.Ordinal), "El parser conservó el fallback cultural es-MX.");
    False(parser.Contains("GetCultureInfo", StringComparison.Ordinal), "El parser siguió consultando una cultura de fallback.");
    return Task.CompletedTask;
}

static async Task IncrementalReadsUtf16WithoutBom()
{
    var dir = TempDir();
    var stateRoot = TempDir();
    var prior = Environment.GetEnvironmentVariable("TDM_STATE_ROOT");
    try
    {
        Environment.SetEnvironmentVariable("TDM_STATE_ROOT", stateRoot);
        var install = Path.Combine(dir, "TSplus");
        var logDir = Path.Combine(install, "Clients", "www", "cgi-bin");
        Directory.CreateDirectory(logDir);
        var logPath = Path.Combine(logDir, "hb.log");
        // La primera línea inicia con una grafía no-ASCII (“): con la detección previa de
        // 4 bytes el byte alto rompía la comprobación de paridad y el archivo se leía como UTF-8.
        var content = "“ERROR connection refused utf16-event\nERROR access denied utf16-second\n";
        await File.WriteAllTextAsync(logPath, content, new System.Text.UnicodeEncoding(false, false));
        var head = new byte[2];
        await using (var fs = File.OpenRead(logPath))
        {
            await fs.ReadAsync(head.AsMemory(0, 2));
        }
        False(head[0] == 0xFF && head[1] == 0xFE, "El archivo de prueba no quedó sin BOM UTF-16.");

        var creation = new FileInfo(logPath).CreationTimeUtc.Ticks;
        var emptyHash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(Array.Empty<byte>())).ToLowerInvariant();
        var cursor = new TsplusCursorFixture(new Dictionary<string, TsplusFileCursorFixture>
        {
            [logPath] = new TsplusFileCursorFixture(0, creation, string.Empty, emptyHash)
        }, DateTimeOffset.Now);
        True(CollectorCursorStore.TrySave("tsplus-log-cursors", cursor, out var saveError), "No se guardó el cursor TSplus: " + saveError);

        var collector = new IncrementalTsplusLogCollector();
        collector.Prime(install);
        var result = await collector.CollectAsync(new DiagnosticContext(Snapshot() with { TsplusRuta = install }, TimeSpan.FromHours(1)));

        var fromLog = result.Eventos.Where(e => e.Archivo == logPath).ToList();
        True(fromLog.Any(e => e.Mensaje.Contains("utf16-event", StringComparison.Ordinal)),
            "UTF-16 sin BOM no fue detectado: la línea inicial con grafía no-ASCII se perdió.");
        True(fromLog.Any(e => e.Mensaje.Contains("utf16-second", StringComparison.Ordinal)),
            "UTF-16 sin BOM no fue detectado: la segunda línea se perdió.");
    }
    finally
    {
        Environment.SetEnvironmentVariable("TDM_STATE_ROOT", prior);
        TryDelete(dir);
        TryDelete(stateRoot);
    }
}

static Task ReportDifferHandlesDuplicateFindingIdsAndUndatedReports()
{
    var now = DateTimeOffset.Now;
    static DiagnosticFinding Finding(string id, DiagnosticSeverity severity)
        => new(id, "App", severity, "resumen " + id, "causa " + id, [new EvidenceItem("Evidencia", id)]);

    // IDs duplicados en ambos reportes: ToDictionary lanzaba ArgumentException y el
    // exportador tragaba el error, borrando la tarjeta de diff sin rastro.
    var previous = Report([], now.AddMinutes(-10), [Finding("DUP-1", DiagnosticSeverity.Advertencia), Finding("DUP-1", DiagnosticSeverity.Critico)]);
    var current = Report([], now, [Finding("DUP-1", DiagnosticSeverity.Informativo), Finding("DUP-1", DiagnosticSeverity.Advertencia)]);
    var diff = ReportDiffer.Compute(previous, current);
    NotNull(diff, "El diff con IDs de hallazgo duplicados no debió descartarse.");
    True(diff!.Changes.Any(c => c.Category == "Hallazgo" && c.Key == "DUP-1" && c.Kind == ReportDiffer.DiffKind.Changed),
        "El hallazgo duplicado no produjo el cambio de severidad con last-wins.");

    // Reportes sin ventana analizada: la tarjeta nunca debe mostrar 01/01/0001.
    var undatedPrevious = previous with { PeriodoAnalizadoFin = default };
    var undatedCurrent = current with { PeriodoAnalizadoFin = default };
    var undated = ReportDiffer.Compute(undatedPrevious, undatedCurrent);
    NotNull(undated, "El diff de reportes sin ventana analizada no debió descartarse.");
    True(undated!.PreviousTimestamp != default && undated.CurrentTimestamp != default,
        "El diff conservó timestamps sin fecha para un reporte sin ventana analizada.");
    Equal(previous.Fin, undated.PreviousTimestamp, "El fallback de fecha anterior no usó Fin del reporte.");
    Equal(current.Fin, undated.CurrentTimestamp, "El fallback de fecha actual no usó Fin del reporte.");
    var card = ReportDiffer.ToHtmlCard(undated);
    True(card.Contains("Cambios desde el reporte anterior", StringComparison.Ordinal), "La tarjeta de diff no se generó.");
    True(!card.Contains("01/01/0001", StringComparison.Ordinal), "La tarjeta de diff mostró la fecha por defecto 01/01/0001.");
    return Task.CompletedTask;
}

static async Task ExportKeepsDiffCardWithDuplicateFindingIds()
{
    var now = DateTimeOffset.Now;
    static DiagnosticFinding Finding(string id, DiagnosticSeverity severity)
        => new(id, "App", severity, "resumen " + id, "causa " + id, [new EvidenceItem("Evidencia", id)]);

    var previous = Report([], now.AddMinutes(-20), [Finding("DUP-1", DiagnosticSeverity.Advertencia), Finding("DUP-1", DiagnosticSeverity.Critico)])
        with { PeriodoAnalizadoFin = default };
    var current = Report([], now, [Finding("DUP-1", DiagnosticSeverity.Advertencia), Finding("ALT-1", DiagnosticSeverity.Error)]);
    var dir = TempDir();
    try
    {
        var result = await ReportExporter.ExportAsync(current, dir, default, previous);
        var html = await File.ReadAllTextAsync(result.HtmlPath);
        True(html.Contains("Cambios desde el reporte anterior", StringComparison.Ordinal),
            "La tarjeta de diff desapareció del HTML con IDs duplicados en el reporte previo.");
        True(!html.Contains("01/01/0001", StringComparison.Ordinal),
            "El HTML del reporte de diff mostró la fecha por defecto 01/01/0001.");
    }
    finally { TryDelete(dir); }
}

static Task EmergencySamplePersistsJournalTransitionsAndLongitudinal()
{
    var root = FindRepoRoot();
    NotNull(root, "No se localizó TDM.sln; gate de la muestra de emergencia no ejecutable.");
    var worker = File.ReadAllText(Path.Combine(root!, "src", "TDM.Service", "TdmWorker.cs"));
    var start = worker.IndexOf("private async Task RunEmergencySampleAsync", StringComparison.Ordinal);
    var end = worker.IndexOf("private IReadOnlyList<AlertSignal> BuildSignals", StringComparison.Ordinal);
    True(start > 0 && end > start, "No se localizó el cuerpo de RunEmergencySampleAsync en TdmWorker.");
    var body = worker[start..end];
    True(body.Contains("StateSnapshotBuilder.Build(report, TdmProductInfo.Version)", StringComparison.Ordinal),
        "La muestra de emergencia no pre-registra el estado en el journal service-monitor.");
    True(body.Contains("AddTransitionsFromRecordResult", StringComparison.Ordinal),
        "La muestra de emergencia no incorpora las transiciones del pre-registro al reporte.");
    True(body.Contains("AddRecentMonitorTransitionsAsync", StringComparison.Ordinal),
        "La muestra de emergencia no añade las transiciones recientes de los canales.");
    True(body.Contains("RecordAndEnrichAsync", StringComparison.Ordinal),
        "La muestra de emergencia no enriquece ni persiste el reporte enriquecido.");
    True(body.Contains("CaptureLongitudinalStateIfDueAsync", StringComparison.Ordinal),
        "La muestra de emergencia no despacha la auditoría longitudinal cuando los timers vencen.");
    True(body.Contains("cycleStarted", StringComparison.Ordinal),
        "La muestra de emergencia no recibe el inicio del ciclo para el gate de presupuesto longitudinal.");
    return Task.CompletedTask;
}

static Task LongitudinalPhaseBudgetGateRejectsFixed45Seconds()
{
    var policy = DiagnosticExecutionPolicy.ProductionDefault;
    // 50 s: el gate previo (fijo de 45 s) omitía la auditoría aunque el ciclo aún tuviera
    // casi todo su presupuesto de 180 s.
    True(policy.HasBudgetForLongitudinal(TimeSpan.FromSeconds(50), TimeSpan.FromSeconds(23)),
        "Con 50 s consumidos aún debe haber presupuesto para la fase longitudinal.");
    True(policy.HasBudgetForLongitudinal(TimeSpan.FromSeconds(157), TimeSpan.FromSeconds(23)),
        "157 s + 23 s = 180 s caben exactamente en el presupuesto del ciclo.");
    False(policy.HasBudgetForLongitudinal(TimeSpan.FromSeconds(158), TimeSpan.FromSeconds(23)),
        "158 s + 23 s exceden los 180 s: la fase longitudinal debe omitirse.");
    False(policy.HasBudgetForLongitudinal(TimeSpan.FromMinutes(5), TimeSpan.FromSeconds(23)),
        "Un ciclo ya fuera de presupuesto no debe estirarse con la auditoría longitudinal.");

    var root = FindRepoRoot();
    NotNull(root, "No se localizó TDM.sln; gate del presupuesto longitudinal no ejecutable.");
    var worker = File.ReadAllText(Path.Combine(root!, "src", "TDM.Service", "TdmWorker.cs"));
    True(worker.Contains("HasBudgetForLongitudinal(now - cycleStarted, LongitudinalAllowance)", StringComparison.Ordinal),
        "El worker no evalúa el presupuesto restante del ciclo para la auditoría longitudinal.");
    False(worker.Contains("(now - cycleStarted > TimeSpan.FromSeconds(45))", StringComparison.Ordinal),
        "El gate fijo de 45 s sigue en el worker.");
    return Task.CompletedTask;
}

static Task ServiceDependencyGraphIsolatesServiceFailures()
{
    var root = FindRepoRoot();
    NotNull(root, "No se localizó TDM.sln; gate del grafo SCM no ejecutable.");
    var graph = File.ReadAllText(Path.Combine(root!, "src", "TDM.Collectors.Windows", "ServiceDependencyGraphCollector.cs"));
    var isolationSites = graph.Split("when (ex is not OperationCanceledException)", StringSplitOptions.None).Length - 1;
    True(isolationSites >= 4,
        $"El grafo SCM sólo aísla {isolationSites} lecturas; se esperaban las 4 (inventario SCM, por servicio, profundidad y nombres).");
    True(graph.Contains("foreach (var service in all) service.Dispose()", StringComparison.Ordinal),
        "El inventario de ServiceController del ciclo no se libera.");
    True(graph.Contains("finally { foreach (var value in values) value.Dispose(); }", StringComparison.Ordinal),
        "Las lecturas de nombres de ServiceController no se liberan.");
    True(graph.Contains("using var sc = new ServiceController(serviceName)", StringComparison.Ordinal),
        "El ServiceController por servicio no se libera con using.");
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

static Task CauseDrivenImpactUsesWordBoundaries()
{
    var now = DateTimeOffset.Now;
    RootCauseCandidate Cause(string resumen, string explicacion) =>
        new(1, "ROOT-TEST", "svc", DiagnosticLayer.Tsplus, 85, ConfidenceLevel.Alta, resumen, explicacion, [],
            Producto: TsplusProduct.Ninguno, HoraIncidente: now, OrigenClasificado: "TSPLUS");

    var port8080 = FunctionalImpactAnalyzer.Analyze(
        Report([], now) with { CausaRaizPrincipal = Cause("Servicio escuchando en el puerto 8080", "El socket 8080 permanece abierto") });
    False(port8080.Impactos.Any(i => i.Funcion == "Acceso Web / HTML5"),
        "El puerto 8080 activó el impacto Web/HTML5 por coincidencia de subcadena.");

    var powershell = FunctionalImpactAnalyzer.Analyze(
        Report([], now) with { CausaRaizPrincipal = Cause("Fallo en PowerShell del sistema", "PowerShell no inicia sesión") });
    False(powershell.Impactos.Any(i => i.Funcion == "Inicio de escritorio/shell"),
        "PowerShell activó el impacto de shell de escritorio por subcadena.");

    var port80 = FunctionalImpactAnalyzer.Analyze(
        Report([], now) with { CausaRaizPrincipal = Cause("Servicio escuchando en el puerto 80", "El puerto 80 dejó de aceptar") });
    True(port80.Impactos.Any(i => i.Funcion == "Acceso Web / HTML5"),
        "El puerto 80 dejó de activar el impacto Web/HTML5 con límites de palabra.");

    var shell = FunctionalImpactAnalyzer.Analyze(
        Report([], now) with { CausaRaizPrincipal = Cause("Fallo de shell en el inicio de sesión", "El shell de escritorio no carga") });
    True(shell.Impactos.Any(i => i.Funcion == "Inicio de escritorio/shell"),
        "Un shell literal dejó de activar el impacto de escritorio.");
    return Task.CompletedTask;
}

static Task FlappingThresholdHonorsConfiguredOptions()
{
    var root = FindRepoRoot();
    NotNull(root, "No se localizó TDM.sln; gate del umbral de flapping no ejecutable.");
    var text = File.ReadAllText(Path.Combine(root!, "src", "TDM.Service", "TdmWorker.cs"));
    True(text.Contains("options?.CauseStabilityFlappingThreshold ?? 2", StringComparison.Ordinal),
        "El análisis de estabilidad de causa no lee el umbral configurado.");
    True(!text.Contains("policy.CauseStabilityFlappingThreshold", StringComparison.Ordinal),
        "El análisis de estabilidad sigue usando el valor fijo de la política.");
    return Task.CompletedTask;
}

static Task EwmaAnomaliesSurfaceAsReportFindings()
{
    var root = FindRepoRoot();
    NotNull(root, "No se localizó TDM.sln; gate de anomalías EWMA no ejecutable.");
    var text = File.ReadAllText(Path.Combine(root!, "src", "TDM.Gui.Avalonia", "Services", "IntegratedMonitoringService.cs"));
    True(!text.Contains("new AnomalyDetectionService()", StringComparison.Ordinal),
        "El monitor sigue instanciando AnomalyDetectionService sin usarla.");
    True(!text.Contains("Debug.WriteLine", StringComparison.Ordinal),
        "Las anomalías EWMA siguen yendo a Debug.WriteLine en vez del reporte.");
    True(text.Contains("report with { Hallazgos", StringComparison.Ordinal),
        "Las anomalías EWMA no se agregan a los hallazgos del reporte.");
    True(text.Contains("EWMA-", StringComparison.Ordinal),
        "Falta el identificador EWMA en los hallazgos de anomalía.");
    return Task.CompletedTask;
}

static Task WindowsEventCollectorHonorsMaxEventsOption()
{
    Equal(250, WindowsEventCollector.ResolveRelevantLimit(TimeSpan.FromHours(2), null),
        "Sin MaxEvents el límite por ventana cambió.");
    Equal(100, WindowsEventCollector.ResolveRelevantLimit(TimeSpan.FromHours(2), 100),
        "MaxEvents no acotó el límite por ventana.");
    Equal(300, WindowsEventCollector.ResolveRelevantLimit(TimeSpan.FromHours(8), 300),
        "MaxEvents no prevaleció sobre el límite por ventana.");
    Equal(2_500, WindowsEventCollector.ResolveRelevantLimit(TimeSpan.FromHours(48), null),
        "Ventana de 48 h perdió el límite máximo.");
    var root = FindRepoRoot();
    NotNull(root, "No se localizó TDM.sln; gate de MaxEvents no ejecutable.");
    var text = File.ReadAllText(Path.Combine(root!, "src", "TDM.Collectors.Windows", "WindowsEventCollector.cs"));
    True(text.Contains("context.Options?.MaxEvents", StringComparison.Ordinal),
        "El collector de eventos Windows ignora DiagnosticOptions.MaxEvents.");
    return Task.CompletedTask;
}

static Task SecurityLogTargetsAuditEventIdsAndAlignsDedupKeys()
{
    var time = "TimeCreated[@SystemTime >= '2026-01-01T00:00:00Z']";
    var security = WindowsEventCollector.ResolveEventQuery("Security", time);
    True(security.Contains("EventID=4625", StringComparison.Ordinal), "La consulta Security dejó de leer 4625.");
    True(security.Contains("EventID=4740", StringComparison.Ordinal), "La consulta Security dejó de leer 4740.");
    True(security.Contains("EventID=4771", StringComparison.Ordinal), "La consulta Security dejó de leer 4771.");
    True(security.Contains("EventID=4776", StringComparison.Ordinal), "La consulta Security dejó de leer 4776.");
    True(security.Contains(time, StringComparison.Ordinal), "La consulta Security perdió la ventana temporal.");
    False(security.Contains("Level=1", StringComparison.OrdinalIgnoreCase),
        "La consulta Security sigue filtrando por nivel y omite los eventos de auditoría Level=0.");
    var system = WindowsEventCollector.ResolveEventQuery("System", time);
    True(system.Contains("Level=1 or Level=2", StringComparison.Ordinal) && system.Contains(time, StringComparison.Ordinal),
        "La consulta System dejó de filtrar errores/críticos dentro de la ventana.");
    var application = WindowsEventCollector.ResolveEventQuery("Application", time);
    True(application.Contains("Level=1 or Level=2", StringComparison.Ordinal) && application.Contains(time, StringComparison.Ordinal),
        "La consulta Application dejó de filtrar errores/críticos dentro de la ventana.");

    var now = DateTimeOffset.Now;
    var baseEvent = new DiagnosticEvent(now, "Microsoft-Windows-Security-Auditing",
        "Microsoft-Windows-Security-Auditing", DiagnosticLayer.Windows, DiagnosticSeverity.Informativo,
        "WINDOWS_EVENT", "registro 4740", "4740",
        Evidencia:
        [
            new EvidenceItem("Log", "Security"),
            new EvidenceItem("EventId", "4740"),
            new EvidenceItem("RecordId", "12345")
        ]);
    var profileEvent = new DiagnosticEvent(now, "Microsoft-Windows-Security-Auditing",
        "Cuenta de usuario bloqueada", DiagnosticLayer.Seguridad, DiagnosticSeverity.Advertencia,
        "ACCOUNT_LOCKOUT", "registro 4740", "4740",
        Evidencia:
        [
            new EvidenceItem("Log", "Security"),
            new EvidenceItem("Usuario", "alice"),
            new EvidenceItem("RecordId", "12345")
        ]);
    Equal(DiagnosticEventIdentity.Resolve(baseEvent) ?? string.Empty, DiagnosticEventIdentity.Resolve(profileEvent) ?? string.Empty,
        "Las emisiones base y de perfil del mismo registro 4740 no comparten clave de deduplicación.");
    True(DiagnosticEventIdentity.Resolve(baseEvent)?.StartsWith("EVT|Security|", StringComparison.Ordinal) == true,
        "La clave del evento Security no queda anclada al canal Security.");

    var root = FindRepoRoot();
    NotNull(root, "No se localizó TDM.sln; gate de Security no ejecutable.");
    var text = File.ReadAllText(Path.Combine(root!, "src", "TDM.Collectors.Rdp", "UserSessionProfileCollector.cs"));
    var logEvidenceCount = text.Split("new EvidenceItem(\"Log\", \"Security\")", StringSplitOptions.None).Length - 1;
    True(logEvidenceCount >= 5,
        $"Los eventos Security de UserSessionProfileCollector no declaran la evidencia Log=Security ({logEvidenceCount}/5).");
    return Task.CompletedTask;
}

static Task LightweightTsplusStoppedSeverityHonorsStartMode()
{
    Equal(DiagnosticSeverity.Critico,
        LightweightTsplusStateCollector.StoppedServiceSeverity("Automático", false),
        "Un servicio TSplus con arranque automático detenido dejó de ser Crítico.");
    Equal(DiagnosticSeverity.Critico,
        LightweightTsplusStateCollector.StoppedServiceSeverity("Boot", false),
        "Un servicio en arranque Boot detenido dejó de ser Crítico.");
    Equal(DiagnosticSeverity.Critico,
        LightweightTsplusStateCollector.StoppedServiceSeverity("Manual", true),
        "Un servicio requerido por catálogo TSplus dejó de ser Crítico.");
    Equal(DiagnosticSeverity.Advertencia,
        LightweightTsplusStateCollector.StoppedServiceSeverity("Manual", false),
        "Un servicio Manual detenido sigue escalando más allá de Advertencia.");
    Equal(DiagnosticSeverity.Informativo,
        LightweightTsplusStateCollector.StoppedServiceSeverity("Deshabilitado", false),
        "Un servicio Deshabilitado detenido se contó como incidencia.");
    Equal(DiagnosticSeverity.Informativo,
        LightweightTsplusStateCollector.StoppedServiceSeverity("N/D", false),
        "Sin modo de inicio conocido el evento dejó de ser Informativo.");
    True(LightweightTsplusStateCollector.IsAutoStart("Automático"), "Automático dejó de contarse como arranque automático.");
    False(LightweightTsplusStateCollector.IsAutoStart("Manual"), "Manual se contó como arranque automático.");

    var root = FindRepoRoot();
    NotNull(root, "No se localizó TDM.sln; gate del TSplus ligero no ejecutable.");
    var text = File.ReadAllText(Path.Combine(root!, "src", "TDM.Collectors.TSplus", "LightweightTsplusStateCollector.cs"));
    False(text.Contains("isRunning ? DiagnosticSeverity.Informativo : DiagnosticSeverity.Critico", StringComparison.Ordinal),
        "El TSplus ligero vuelve a declarar Critico sin consultar el modo de inicio.");
    True(text.Contains("StoppedServiceSeverity(startMode, requiredWhenTsplus)", StringComparison.Ordinal),
        "El TSplus ligero no decide la severidad detenida con el modo de inicio.");
    True(text.Contains("new EvidenceItem(\"Inicio\", startMode)", StringComparison.Ordinal),
        "El evento SERVICE_STATE del TSplus ligero no expone el modo de inicio.");
    return Task.CompletedTask;
}

static Task StaticWindowsConfigCandidatesNeedRemoteSessionSymptom()
{
    string Evidence(RootCauseCandidate c, string key) => c.Evidencia.FirstOrDefault(e => e.Clave == key)?.Valor ?? "N/D";
    var now = DateTimeOffset.Now;
    var policy = new DiagnosticFinding("WINDOWS-RDP-DISABLED-POLICY", "Windows Remote Desktop", DiagnosticSeverity.Advertencia,
        "RDP deshabilitado por directiva.", "fDenyTSConnections activo impide nuevas conexiones.",
        [new EvidenceItem("fDenyTSConnections", "1")], ConfidenceLevel.Alta, Capa: DiagnosticLayer.Windows);
    var rds = new DiagnosticFinding("WINDOWS-RDS-ROLE-CONFLICT", "Windows Server RDS", DiagnosticSeverity.Advertencia,
        "Roles RDS incompatibles.", "Roles RDS no deben coexistir con TSplus.",
        [new EvidenceItem("Roles", "RDS Session Host")], ConfidenceLevel.Alta, Capa: DiagnosticLayer.Windows);

    var quiet = RootCauseCorrelator.Analyze(Report([], now, [policy, rds]));
    var quietRdp = quiet.FirstOrDefault(x => x.Id == "ROOT-WINDOWS-RDP-DISABLED-POLICY");
    var quietRds = quiet.FirstOrDefault(x => x.Id == "ROOT-WINDOWS-RDS-ROLE-CONFLICT");
    NotNull(quietRdp, "El candidato de política RDP desapareció sin síntoma de sesión remota.");
    NotNull(quietRds, "El candidato de roles RDS desapareció sin síntoma de sesión remota.");
    Equal(ConfidenceLevel.Media, quietRdp!.Confianza, "La política RDP se declaró Alta sin síntoma de sesión remota.");
    Equal(84, quietRdp.Puntaje, "La política RDP mantuvo el puntaje dominante sin síntoma.");
    Equal(ConfidenceLevel.Media, quietRds!.Confianza, "Los roles RDS se declararon Alta sin síntoma de sesión remota.");
    Equal(84, quietRds.Puntaje, "Los roles RDS mantuvieron el puntaje dominante sin síntoma.");
    Equal("No observado", Evidence(quietRdp, "Síntoma de sesión remota en la ventana"),
        "La ausencia de síntoma no quedó registrada en la evidencia.");
    True(quietRdp.HoraIncidente is null, "Sin síntoma el candidato de política RDP recibió hora de incidente.");

    var symptom = new DiagnosticEvent(now.AddMinutes(-4), "TermService", "Remote Desktop Services",
        DiagnosticLayer.Rdp, DiagnosticSeverity.Error, "RDP_SESSION_FAILURE", "La sesión RDP falló.");
    var symptomatic = RootCauseCorrelator.Analyze(Report([symptom], now, [policy, rds]));
    var fullRdp = symptomatic.FirstOrDefault(x => x.Id == "ROOT-WINDOWS-RDP-DISABLED-POLICY");
    var fullRds = symptomatic.FirstOrDefault(x => x.Id == "ROOT-WINDOWS-RDS-ROLE-CONFLICT");
    NotNull(fullRdp, "El candidato de política RDP desapareció con síntoma presente.");
    NotNull(fullRds, "El candidato de roles RDS desapareció con síntoma presente.");
    Equal(ConfidenceLevel.Alta, fullRdp!.Confianza, "Con síntoma la política RDP dejó de ser Alta.");
    Equal(96, fullRdp.Puntaje, "Con síntoma el puntaje de la política RDP cambió.");
    Equal(ConfidenceLevel.Alta, fullRds!.Confianza, "Con síntoma los roles RDS dejaron de ser Alta.");
    Equal(97, fullRds.Puntaje, "Con síntoma el puntaje de los roles RDS cambió.");
    True(fullRdp.HoraIncidente == symptom.Timestamp, "El síntoma no ancló la hora de incidente del candidato.");
    Equal("RDP_SESSION_FAILURE", Evidence(fullRdp, "Síntoma de sesión remota en la ventana"),
        "El síntoma observado no quedó registrado en la evidencia.");
    return Task.CompletedTask;
}

static async Task WindowsPushSubscriptionIsSharedAcrossInstances()
{
    try
    {
        WindowsPushEventCollector.StopWatchers();
        var first = await new WindowsPushEventCollector().CollectAsync(Context(TimeSpan.FromHours(1)));
        var second = await new WindowsPushEventCollector().CollectAsync(Context(TimeSpan.FromHours(1)));
        var coverage1 = first.Eventos.FirstOrDefault(e => e.Tipo == "WINDOWS_PUSH_EVENT_COVERAGE");
        var coverage2 = second.Eventos.FirstOrDefault(e => e.Tipo == "WINDOWS_PUSH_EVENT_COVERAGE");
        NotNull(coverage1, "La primera llamada push no emitió cobertura.");
        NotNull(coverage2, "La segunda llamada push no emitió cobertura.");
        var head1 = coverage1!.Mensaje.Split('.')[0];
        var head2 = coverage2!.Mensaje.Split('.')[0];
        True(head1.StartsWith("Canales suscritos: ", StringComparison.Ordinal),
            "El mensaje de cobertura push cambió de formato.");
        Equal(head1, head2, "La suscripción push no es estable entre instancias del collector.");

        WindowsPushEventCollector.StopWatchers();
        var third = await new WindowsPushEventCollector().CollectAsync(Context(TimeSpan.FromHours(1)));
        var coverage3 = third.Eventos.FirstOrDefault(e => e.Tipo == "WINDOWS_PUSH_EVENT_COVERAGE");
        NotNull(coverage3, "Tras detener watchers la suscripción no volvió a establecerse.");
        Equal(head1, coverage3!.Mensaje.Split('.')[0],
            "La re-suscripción tras StopWatchers cambió el número de canales suscritos.");
    }
    finally
    {
        WindowsPushEventCollector.StopWatchers();
    }

    var root = FindRepoRoot();
    NotNull(root, "No se localizó TDM.sln; gate del push collector no ejecutable.");
    var text = File.ReadAllText(Path.Combine(root!, "src", "TDM.Collectors.Windows", "WindowsPushEventCollector.cs"));
    False(text.Contains("cancellationToken.Register", StringComparison.Ordinal),
        "El push collector sigue amarrando la suscripción al token de cada llamada.");
    True(text.Contains("EnsureSubscribed()", StringComparison.Ordinal),
        "El push collector no idempotencia la suscripción a canales.");
    True(text.Contains("private static bool _subscribed", StringComparison.Ordinal),
        "El push collector no mantiene el estado de suscripción compartido por proceso.");
}

static Task GuiPrerecordsStateAndReadsFeedbackFromBothRoots()
{
    var root = FindRepoRoot();
    NotNull(root, "No se localizó TDM.sln; gate de paridad GUI no ejecutable.");
    var gui = File.ReadAllText(Path.Combine(root!, "src", "TDM.Gui.Avalonia", "Services", "DiagnosticExecutionService.cs"));
    True(gui.Contains("preRecordedResult", StringComparison.Ordinal),
        "El diagnóstico GUI no pre-graba el estado antes de correlacionar causas.");
    True(gui.Contains("AddTransitionsFromRecordResult(", StringComparison.Ordinal),
        "El diagnóstico GUI no integra las transiciones del pre-record antes de Analyze.");
    True(gui.Contains("- TimeSpan.FromMinutes(15)", StringComparison.Ordinal),
        "El diagnóstico GUI no replica el margen de 15 min del servicio para transiciones.");
    True(gui.Contains("preRecordedResult: preRecordedResult", StringComparison.Ordinal),
        "RecordAndEnrichAsync de la GUI no reutiliza el pre-registro del ciclo.");
    True(gui.Contains("ReadFromRootsAsync(", StringComparison.Ordinal),
        "El diagnóstico GUI lee feedback de una sola raíz de estado.");
    var preIndex = gui.IndexOf("preRecordedResult", StringComparison.Ordinal);
    var analyzeIndex = gui.IndexOf("DiagnosticWorkflow.Analyze(", StringComparison.Ordinal);
    True(preIndex >= 0 && analyzeIndex > preIndex,
        "El pre-record de estado ocurre después de DiagnosticWorkflow.Analyze en la GUI.");
    var worker = File.ReadAllText(Path.Combine(root!, "src", "TDM.Service", "TdmWorker.cs"));
    True(worker.Contains("ReadFromRootsAsync(", StringComparison.Ordinal),
        "El servicio lee feedback de una sola raíz de estado.");
    return Task.CompletedTask;
}

static async Task FeedbackReadMergesRootsAndDeduplicates()
{
    var rootA = TempDir();
    var rootB = TempDir();
    try
    {
        var storeA = new DiagnosticFeedbackStore(rootA);
        var onlyA = await storeA.RecordAsync("ROOT-MERGE-A", "Comp A", 90, "Alta", FeedbackVerdict.Confirmada);
        var storeB = new DiagnosticFeedbackStore(rootB);
        Directory.CreateDirectory(Path.Combine(rootB, "state"));
        File.Copy(storeA.Path, Path.Combine(rootB, "state", "diagnostic-feedback.jsonl"), overwrite: true);
        var onlyB = await storeB.RecordAsync("ROOT-MERGE-B", "Comp B", 70, "Media", FeedbackVerdict.Descartada);

        var merged = await DiagnosticFeedbackStore.ReadFromRootsAsync([rootA, rootB, rootA]);
        Equal(2, merged.Count, "La lectura multi-raíz duplicó o perdió registros.");
        True(merged.Any(x => x.Id == onlyA.Id), "El registro de la raíz A no llegó a la fusión.");
        True(merged.Any(x => x.Id == onlyB.Id), "El registro de la raíz B no llegó a la fusión.");

        var rates = DiagnosticFeedbackStore.HitRateByCandidate(merged);
        Equal(1.0, rates["ROOT-MERGE-A"].Tasa, "La tasa de A se contaminó con la copia duplicada.");
        Equal(0.0, rates["ROOT-MERGE-B"].Tasa, "La tasa de B cambió al fusionar raíces.");

        var future = await DiagnosticFeedbackStore.ReadFromRootsAsync(
            [rootA, rootB], from: DateTimeOffset.Now + TimeSpan.FromMinutes(1));
        Equal(0, future.Count, "El filtro from no se aplicó en la lectura multi-raíz.");

        var empty = await DiagnosticFeedbackStore.ReadFromRootsAsync([]);
        Equal(0, empty.Count, "Una lista de raíces vacía debería devolver vacío.");
    }
    finally { TryDelete(rootA); TryDelete(rootB); }
}

static Task TestsRunUnderPinnedInvariantCulture()
{
    True(ReferenceEquals(CultureInfo.DefaultThreadCurrentCulture, CultureInfo.InvariantCulture),
        "La cultura por defecto de los hilos no quedó fijada a InvariantCulture.");
    True(ReferenceEquals(Thread.CurrentThread.CurrentCulture, CultureInfo.InvariantCulture),
        "El hilo principal no corre con InvariantCulture.");
    return Task.CompletedTask;
}

static Task ContinuousMergerKeepsWindowStateAndAnchoredEvents()
{
    var now = DateTimeOffset.Now;
    var staleEvent = new DiagnosticEvent(now.AddMinutes(-30), "Service Control Manager", "svcA", DiagnosticLayer.Windows,
        DiagnosticSeverity.Error, "SERVICE_START_FAILURE", "fallo de arranque", "7000",
        Evidencia: [new EvidenceItem("Log", "System"), new EvidenceItem("RecordId", "111")]);
    var keptEvent = new DiagnosticEvent(now.AddMinutes(-5), "Service Control Manager", "svcA", DiagnosticLayer.Windows,
        DiagnosticSeverity.Error, "SERVICE_START_FAILURE", "fallo de arranque", "7000",
        Evidencia: [new EvidenceItem("Log", "System"), new EvidenceItem("RecordId", "222")]);
    var stateDown = new DiagnosticEvent(now.AddMinutes(-4), "Service Control Manager", "TermService", DiagnosticLayer.Windows,
        DiagnosticSeverity.Critico, "SERVICE_STATE", "Stopped", "stopped",
        Evidencia: [new EvidenceItem("Servicio", "TermService"), new EvidenceItem("Estado", "Stopped")]);
    var carriedFinding = new DiagnosticFinding("EVT-System-222", "Service Control Manager", DiagnosticSeverity.Error,
        "Evento relevante detectado: ID 7034", "fallo de arranque",
        [new EvidenceItem("Fecha", now.AddMinutes(-5).ToString("O"))], ConfidenceLevel.Media, Capa: DiagnosticLayer.Windows);
    var accessFinding = new DiagnosticFinding("EVT-System-ACCESS", "Event Log", DiagnosticSeverity.Advertencia,
        "No fue posible leer el registro System.", "sin acceso",
        [new EvidenceItem("Log", "System"), new EvidenceItem("Fecha", now.AddMinutes(-5).ToString("O"))],
        ConfidenceLevel.Alta, Capa: DiagnosticLayer.Windows);
    var stateFinding = new DiagnosticFinding("SVC-TERMSERVICE-DOWN", "TermService", DiagnosticSeverity.Critico,
        "Servicio detenido", "estado", [], ConfidenceLevel.Alta, Capa: DiagnosticLayer.Windows);
    var tslogFinding = new DiagnosticFinding("TSLOG-APPSVC-ERROR", "AppSvc", DiagnosticSeverity.Error,
        "Errores en log", "detalle",
        [new EvidenceItem("Último registro", now.AddMinutes(-3).ToString("O"))], ConfidenceLevel.Media, Capa: DiagnosticLayer.Tsplus);

    var baseline = new DiagnosticReport(Snapshot(), [carriedFinding, accessFinding, stateFinding, tslogFinding],
        [staleEvent, keptEvent, stateDown], now.AddMinutes(-10), now.AddMinutes(-1))
    {
        PeriodoAnalizadoInicio = now.AddMinutes(-16),
        PeriodoAnalizadoFin = now.AddMinutes(-1)
    };

    var incomingSameRecord = new DiagnosticEvent(now.AddMinutes(-5), "Service Control Manager", "svcA", DiagnosticLayer.Windows,
        DiagnosticSeverity.Error, "WINDOWS_EVENT", "fallo de arranque", "7000",
        Evidencia: [new EvidenceItem("Log", "System"), new EvidenceItem("RecordId", "222")]);
    var newEvent = new DiagnosticEvent(now.AddMinutes(-1), "Service Control Manager", "svcB", DiagnosticLayer.Windows,
        DiagnosticSeverity.Error, "SERVICE_START_FAILURE", "fallo de arranque", "7000",
        Evidencia: [new EvidenceItem("Log", "System"), new EvidenceItem("RecordId", "333")]);
    var stateUp = new DiagnosticEvent(now, "Service Control Manager", "TermService", DiagnosticLayer.Windows,
        DiagnosticSeverity.Informativo, "SERVICE_STATE", "Running", "running",
        Evidencia: [new EvidenceItem("Servicio", "TermService"), new EvidenceItem("Estado", "Running")]);
    var liveFinding = new DiagnosticFinding("LIVE-EVT-System-999", "Service Control Manager", DiagnosticSeverity.Error,
        "Nueva evidencia durante el diagnóstico continuo", "detalle",
        [new EvidenceItem("Fecha", now.ToString("O"))], ConfidenceLevel.Media, Capa: DiagnosticLayer.Windows);

    var incremental = new DiagnosticReport(Snapshot(), [liveFinding], [incomingSameRecord, newEvent, stateUp],
        now.AddMinutes(-1), now)
    {
        PeriodoAnalizadoInicio = now.AddMinutes(-15),
        PeriodoAnalizadoFin = now
    };

    var merged = ContinuousDiagnosticMerger.Merge(baseline, incremental, TimeSpan.FromMinutes(15));

    Equal(now.AddMinutes(-15), merged.PeriodoAnalizadoInicio,
        "La ventana móvil no se ancló al final de la muestra incremental.");
    Equal(1, merged.Eventos.Count(e => EvidenceReader.Value(e, "RecordId") == "222"),
        "El evento repetido por RecordId entre muestra completa e incremental no colapsó a uno solo.");
    True(merged.Eventos.Any(e => e.Tipo == "WINDOWS_EVENT" && EvidenceReader.Value(e, "RecordId") == "222"),
        "La muestra incremental no prevaleció sobre la lectura completa del mismo registro.");
    False(merged.Eventos.Any(e => EvidenceReader.Value(e, "RecordId") == "111"),
        "Un evento fuera de la ventana móvil sobrevivió a la fusión.");
    True(merged.Eventos.Any(e => EvidenceReader.Value(e, "RecordId") == "333"),
        "El evento nuevo de la muestra incremental se perdió.");
    var states = merged.Eventos.Where(e => e.Tipo == "SERVICE_STATE" && e.Componente == "TermService").ToList();
    True(states.Count == 1 && states[0].Mensaje == "Running",
        "El estado recuperado no reemplazó al estado detenido anterior.");
    True(merged.Hallazgos.Any(f => f.Id == "EVT-System-222"),
        "El hallazgo anclado a la ventana dejó de arrastrarse.");
    True(merged.Hallazgos.Any(f => f.Id == "TSLOG-APPSVC-ERROR"),
        "El hallazgo de logs TSplus del catálogo completo dejó de arrastrarse.");
    True(merged.Hallazgos.Any(f => f.Id == "LIVE-EVT-System-999"),
        "El hallazgo nuevo de la muestra incremental se perdió.");
    False(merged.Hallazgos.Any(f => f.Id == "EVT-System-ACCESS"),
        "El hallazgo de acceso al canal se arrastró aunque la fuente ya no corre en modo continuo.");
    False(merged.Hallazgos.Any(f => f.Id == "SVC-TERMSERVICE-DOWN"),
        "Un hallazgo de estado sobrevivió a la recuperación del servicio.");
    return Task.CompletedTask;
}

static Task ContinuousRunReplansSeedWhenWindowGrows()
{
    var now = DateTimeOffset.Now;
    False(ContinuousDiagnosticMerger.ShouldContinue(null, TimeSpan.FromMinutes(15), now),
        "Sin línea base el ciclo debe re-sembrar con el catálogo completo.");
    var baseline = new DiagnosticReport(Snapshot(), [], [], now.AddMinutes(-10), now.AddMinutes(-1))
    {
        PeriodoAnalizadoInicio = now.AddMinutes(-16)
    };
    True(ContinuousDiagnosticMerger.ShouldContinue(baseline, TimeSpan.FromMinutes(15), now),
        "Con la misma ventana el ciclo debe continuar en modo incremental.");
    True(ContinuousDiagnosticMerger.ShouldContinue(baseline, TimeSpan.FromMinutes(5), now),
        "Reducir la ventana no debe obligar a re-sembrar.");
    False(ContinuousDiagnosticMerger.ShouldContinue(baseline, TimeSpan.FromHours(4), now),
        "Ampliar la ventana debe re-sembrar el catálogo completo.");
    var noWindow = new DiagnosticReport(Snapshot(), [], [], now.AddMinutes(-10), now.AddMinutes(-1));
    False(ContinuousDiagnosticMerger.ShouldContinue(noWindow, TimeSpan.FromMinutes(15), now),
        "Un reporte sin ventana analizada no puede continuar en modo continuo.");
    return Task.CompletedTask;
}

static Task ContinuousCatalogSwapsHeavySourcesForIncremental()
{
    var full = CollectorCatalog.CreateFull();
    var windows = new IncrementalWindowsEventCollector();
    var tsplus = new IncrementalTsplusLogCollector();
    var continuous = CollectorCatalog.CreateContinuous(windows, tsplus);
    Equal(full.Count, continuous.Count, "El catálogo continuo debe mantener la misma cantidad de fuentes.");
    True(continuous.Any(c => ReferenceEquals(c, windows)), "El collector incremental de Event Viewer no entró al catálogo.");
    True(continuous.Any(c => ReferenceEquals(c, tsplus)), "El collector incremental de logs TSplus no entró al catálogo.");
    False(continuous.Any(c => c is WindowsEventCollector), "El collector completo de Event Viewer sigue presente en modo continuo.");
    False(continuous.Any(c => c is TsplusLogCollector), "El collector completo de logs TSplus sigue presente en modo continuo.");
    True(continuous.Any(c => c is WindowsServiceCollector), "El estado de servicios desapareció del catálogo continuo.");
    True(full.Any(c => c is WindowsEventCollector), "El catálogo puntual perdió el collector completo de Event Viewer.");
    True(full.Any(c => c is TsplusLogCollector), "El catálogo puntual perdió el collector completo de logs TSplus.");
    return Task.CompletedTask;
}

static Task TsplusCoverageAcceptsIncrementalSource()
{
    var now = DateTimeOffset.Now;
    var fullCoverage = new DiagnosticEvent(now, "TDM", "Cobertura TSplus", DiagnosticLayer.Tsplus,
        DiagnosticSeverity.Informativo, "TSPLUS_LOG_COVERAGE", "Cobertura de logs actualizada",
        Evidencia:
        [
            new EvidenceItem("Cobertura", "Disponible"),
            new EvidenceItem("Fuentes Remote Access disponibles", "3"),
            new EvidenceItem("Fuentes Remote Access conocidas/detectadas", "3")
        ]);
    var assessmentFull = DiagnosticCoverageAnalyzer.Analyze(Report([fullCoverage], now));
    Equal("Disponible", assessmentFull.Fuentes.Single(x => x.Fuente == "Logs TSplus Remote Access").Estado,
        "La cobertura completa de logs dejó de alimentar la fuente base.");

    var incrementalCoverage = new DiagnosticEvent(now.AddSeconds(1), "TDM", "Cobertura TSplus", DiagnosticLayer.Tsplus,
        DiagnosticSeverity.Informativo, "TSPLUS_INCREMENTAL_LOG_COVERAGE", "Cobertura incremental actualizada",
        Evidencia:
        [
            new EvidenceItem("Cobertura", "Disponible"),
            new EvidenceItem("Fuentes candidatas", "5"),
            new EvidenceItem("Fuentes no evaluadas", "0")
        ]);
    var assessmentIncremental = DiagnosticCoverageAnalyzer.Analyze(Report([incrementalCoverage], now));
    Equal("Disponible", assessmentIncremental.Fuentes.Single(x => x.Fuente == "Logs TSplus Remote Access").Estado,
        "La cobertura incremental no alimenta la fuente base de logs TSplus.");

    var partialCoverage = incrementalCoverage with
    {
        Evidencia =
        [
            new EvidenceItem("Cobertura", "Disponible"),
            new EvidenceItem("Fuentes candidatas", "5"),
            new EvidenceItem("Fuentes no evaluadas", "2")
        ]
    };
    var assessmentPartial = DiagnosticCoverageAnalyzer.Analyze(Report([partialCoverage], now));
    Equal("Parcial", assessmentPartial.Fuentes.Single(x => x.Fuente == "Logs TSplus Remote Access").Estado,
        "Dos fuentes candidatas sin evaluar no dejaron la cobertura parcial.");

    var assessmentNone = DiagnosticCoverageAnalyzer.Analyze(Report([], now));
    Equal("No disponible", assessmentNone.Fuentes.Single(x => x.Fuente == "Logs TSplus Remote Access").Estado,
        "Sin ningún estado de cobertura la fuente base debe seguir marcada No disponible.");
    return Task.CompletedTask;
}

static Task SecurityLogMissingStatusIsNotAvailable()
{
    var now = DateTimeOffset.Now;
    DiagnosticEvent Coverage(string raw) => new(now, "TDM", "Auditoría de autenticación", DiagnosticLayer.Seguridad,
        DiagnosticSeverity.Informativo, "USER_AUTH_AUDIT_COVERAGE", "Cobertura de auditoría de autenticación",
        Evidencia: [new EvidenceItem("Security log", raw)]);

    var missing = DiagnosticCoverageAnalyzer.Analyze(Report([Coverage("No disponible")], now));
    Equal("No disponible", missing.Fuentes.Single(x => x.Fuente == "Security Log / autenticación").Estado,
        "'No disponible' en el Security Log no quedó como fuente no disponible.");
    True(missing.Limitaciones.Any(l => l.StartsWith("Cobertura de autenticación/NLA/Kerberos limitada", StringComparison.Ordinal)),
        "La ausencia de Security Log no dejó la limitación de autenticación.");

    var available = DiagnosticCoverageAnalyzer.Analyze(Report([Coverage("Disponible")], now));
    Equal("Disponible", available.Fuentes.Single(x => x.Fuente == "Security Log / autenticación").Estado,
        "'Disponible' dejó de reconocerse como cobertura completa.");
    False(available.Limitaciones.Any(l => l.StartsWith("Cobertura de autenticación/NLA/Kerberos limitada", StringComparison.Ordinal)),
        "Una fuente Disponible no debe declarar limitación de autenticación.");

    var partial = DiagnosticCoverageAnalyzer.Analyze(Report([Coverage("Parcial: límite adaptativo de eventos aplicado")], now));
    Equal("Parcial", partial.Fuentes.Single(x => x.Fuente == "Security Log / autenticación").Estado,
        "Un estado parcial del Security Log no quedó como Parcial.");

    var blocked = DiagnosticCoverageAnalyzer.Analyze(Report([Coverage("Sin permisos de lectura")], now));
    Equal("Bloqueada", blocked.Fuentes.Single(x => x.Fuente == "Security Log / autenticación").Estado,
        "Sin permisos de lectura no quedó como fuente bloqueada.");

    True(missing.Score < available.Score, "Perder el Security Log no penalizó el puntaje de cobertura.");
    return Task.CompletedTask;
}

static Task WindowsEventRecoveryLookbackRestoresPersistedGap()
{
    var root = TempDir();
    var prior = Environment.GetEnvironmentVariable("TDM_STATE_ROOT");
    try
    {
        Environment.SetEnvironmentVariable("TDM_STATE_ROOT", root);

        var fresh = new IncrementalWindowsEventCollector();
        fresh.Prime();
        False(fresh.RecoveryLookback(DateTimeOffset.Now).HasValue, "Sin estado persistido no debe haber lookback de recuperación.");

        var probe = DateTimeOffset.Now;
        var justNow = probe.AddSeconds(-30);
        var recent = new WindowsCursorFixture(new Dictionary<string, long> { ["Security"] = 1 }, justNow, new Dictionary<string, string>(), justNow);
        True(CollectorCursorStore.TrySave("windows-event-cursors", recent, out var saveError), "No se guardó el cursor de Event Viewer: " + saveError);
        var recentCollector = new IncrementalWindowsEventCollector();
        recentCollector.Prime();
        False(recentCollector.RecoveryLookback(probe).HasValue, "Un hueco mínimo no debe ampliar la ventana de recuperación.");

        var fiveMinAgo = probe.AddMinutes(-5);
        var five = new WindowsCursorFixture(new Dictionary<string, long> { ["Security"] = 1 }, fiveMinAgo, new Dictionary<string, string>(), fiveMinAgo);
        True(CollectorCursorStore.TrySave("windows-event-cursors", five, out saveError), "No se guardó el cursor de Event Viewer: " + saveError);
        var fiveCollector = new IncrementalWindowsEventCollector();
        fiveCollector.Prime();
        Equal(TimeSpan.FromMinutes(5), fiveCollector.RecoveryLookback(fiveMinAgo.AddMinutes(5)) ?? TimeSpan.Zero,
            "Tras reiniciar no se restauró la última muestra con cobertura completa.");

        var twoHoursAgo = probe.AddHours(-2);
        var old = new WindowsCursorFixture(new Dictionary<string, long> { ["Security"] = 1 }, twoHoursAgo, new Dictionary<string, string>(), twoHoursAgo);
        True(CollectorCursorStore.TrySave("windows-event-cursors", old, out saveError), "No se guardó el cursor de Event Viewer: " + saveError);
        var oldCollector = new IncrementalWindowsEventCollector();
        oldCollector.Prime();
        Equal(TimeSpan.FromMinutes(15), oldCollector.RecoveryLookback(twoHoursAgo.AddHours(2)) ?? TimeSpan.Zero,
            "Un hueco prolongado no se acotó a 15 min.");

        File.WriteAllText(Path.Combine(root, "windows-event-cursors.json"),
            "{\"cursors\":{\"Security\":1},\"savedAt\":\"" + fiveMinAgo.ToString("O", CultureInfo.InvariantCulture) + "\",\"lastKnownGoodState\":{}}");
        var legacyCollector = new IncrementalWindowsEventCollector();
        legacyCollector.Prime();
        Equal(TimeSpan.FromMinutes(5), legacyCollector.RecoveryLookback(fiveMinAgo.AddMinutes(5)) ?? TimeSpan.Zero,
            "Un estado legado sin lastSuccessUtc no cayó a savedAt.");
    }
    finally
    {
        Environment.SetEnvironmentVariable("TDM_STATE_ROOT", prior);
        TryDelete(root);
    }
    return Task.CompletedTask;
}

static async Task WindowsEventRecoveryLookbackDisarmsAfterFirstCollect()
{
    var root = TempDir();
    var prior = Environment.GetEnvironmentVariable("TDM_STATE_ROOT");
    try
    {
        Environment.SetEnvironmentVariable("TDM_STATE_ROOT", root);
        var last = DateTimeOffset.Now.AddMinutes(-5);
        var state = new WindowsCursorFixture(new Dictionary<string, long> { ["Security"] = 1 }, last, new Dictionary<string, string>(), last);
        True(CollectorCursorStore.TrySave("windows-event-cursors", state, out var saveError), "No se guardó el cursor de Event Viewer: " + saveError);
        var collector = new IncrementalWindowsEventCollector();
        collector.Prime();
        NotNull(collector.RecoveryLookback(DateTimeOffset.Now), "El estado persistido no armó el lookback de recuperación.");
        try
        {
            await collector.CollectAsync(Context(TimeSpan.FromHours(1)), new CancellationToken(true));
            throw new InvalidOperationException("La primera recolección cancelada no interrumpió el ciclo.");
        }
        catch (OperationCanceledException) { }
        False(collector.RecoveryLookback(DateTimeOffset.Now).HasValue,
            "Tras la primera recolección el lookback de recuperación debía desarmarse.");
    }
    finally
    {
        Environment.SetEnvironmentVariable("TDM_STATE_ROOT", prior);
        TryDelete(root);
    }
}

static async Task TsplusCursorKeepsOffsetAfterAppend()
{
    var dir = TempDir();
    var stateRoot = TempDir();
    var prior = Environment.GetEnvironmentVariable("TDM_STATE_ROOT");
    try
    {
        Environment.SetEnvironmentVariable("TDM_STATE_ROOT", stateRoot);
        var install = Path.Combine(dir, "TSplus");
        var logDir = Path.Combine(install, "Clients", "www", "cgi-bin");
        Directory.CreateDirectory(logDir);
        var logPath = Path.Combine(logDir, "hb.log");
        var oldContent = "ERROR connection refused old-event-1\nERROR connection refused old-event-2\n";
        await File.WriteAllTextAsync(logPath, oldContent);
        var creation = new FileInfo(logPath).CreationTimeUtc.Ticks;
        var oldBytes = System.Text.Encoding.UTF8.GetBytes(oldContent);
        var hash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(oldBytes)).ToLowerInvariant();
        var cursor = new TsplusCursorFixture(new Dictionary<string, TsplusFileCursorFixture>
        {
            [logPath] = new TsplusFileCursorFixture(oldBytes.LongLength, creation, string.Empty, hash)
        }, DateTimeOffset.Now);
        True(CollectorCursorStore.TrySave("tsplus-log-cursors", cursor, out var saveError), "No se guardó el cursor TSplus: " + saveError);

        await File.AppendAllTextAsync(logPath, "ERROR connection refused new-event-1\n");

        var collector = new IncrementalTsplusLogCollector();
        collector.Prime(install);
        var result = await collector.CollectAsync(new DiagnosticContext(Snapshot() with { TsplusRuta = install }, TimeSpan.FromHours(1)));

        var fromLog = result.Eventos.Where(e => e.Archivo == logPath).ToList();
        True(fromLog.Any(e => e.Mensaje.Contains("new-event-1", StringComparison.Ordinal)),
            "El cursor no leyó la línea agregada tras reiniciar.");
        False(fromLog.Any(e => e.Mensaje.Contains("old-event", StringComparison.Ordinal)),
            "El cursor releyó historial ya consumido.");
    }
    finally
    {
        Environment.SetEnvironmentVariable("TDM_STATE_ROOT", prior);
        TryDelete(dir);
        TryDelete(stateRoot);
    }
}

static async Task TsplusBacklogSurvivesRestartWithoutCursorLoss()
{
    var dir = TempDir();
    var stateRoot = TempDir();
    var prior = Environment.GetEnvironmentVariable("TDM_STATE_ROOT");
    try
    {
        Environment.SetEnvironmentVariable("TDM_STATE_ROOT", stateRoot);
        var install = Path.Combine(dir, "TSplus");
        var logDir = Path.Combine(install, "Clients", "www", "cgi-bin");
        Directory.CreateDirectory(logDir);
        var logPath = Path.Combine(logDir, "hb.log");
        // Tormenta de errores más grande que la entrega de un ciclo (tope por defecto 299):
        // el remanente queda como backlog y el cursor debe seguir al inicio del chunk.
        var lines = Enumerable.Range(0, 400).Select(i => $"ERROR connection refused storm-{i}").ToList();
        lines.Add("ERROR disk full TSPLUS-C6-MARKER");
        await File.WriteAllTextAsync(logPath, string.Join('\n', lines) + "\n");

        var creation = new FileInfo(logPath).CreationTimeUtc.Ticks;
        var emptyHash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(Array.Empty<byte>())).ToLowerInvariant();
        var cursor = new TsplusCursorFixture(new Dictionary<string, TsplusFileCursorFixture>
        {
            [logPath] = new TsplusFileCursorFixture(0, creation, string.Empty, emptyHash)
        }, DateTimeOffset.Now);
        True(CollectorCursorStore.TrySave("tsplus-log-cursors", cursor, out var saveError), "No se guardó el cursor TSplus: " + saveError);

        // Sesión 1: entrega acotada; el marcador queda pendiente y NO debe darse por leído.
        var session1 = new IncrementalTsplusLogCollector();
        session1.Prime(install);
        var first = await session1.CollectAsync(new DiagnosticContext(Snapshot() with { TsplusRuta = install }, TimeSpan.FromHours(1)));
        True(first.Eventos.Any(e => e.Mensaje.Contains("storm-", StringComparison.Ordinal)),
            "La tormenta inicial no se entregó parcialmente: el tope de drenaje dejó de funcionar.");
        False(first.Eventos.Any(e => e.Mensaje.Contains("TSPLUS-C6-MARKER", StringComparison.Ordinal)),
            "El marcador debía quedar como backlog en la primera muestra.");
        True(first.Eventos.Any(e => e.Tipo == "TSPLUS_INCREMENTAL_LOG_COVERAGE"
                && e.Evidencia?.Any(i => i.Clave == "Cobertura" && i.Valor == "Parcial") == true),
            "El backlog de la tormenta no se declaró como cobertura Parcial.");

        // Reinicio: el cursor persistido debe seguir al INICIO del chunk (commit sólo al
        // drenar). Con el commit prematuro previo avanzaba al fin del archivo y el remanente
        // de la tormenta se perdía para siempre.
        var session2 = new IncrementalTsplusLogCollector();
        session2.Prime(install);
        var secondA = await session2.CollectAsync(new DiagnosticContext(Snapshot() with { TsplusRuta = install }, TimeSpan.FromHours(1)));
        var secondB = await session2.CollectAsync(new DiagnosticContext(Snapshot() with { TsplusRuta = install }, TimeSpan.FromHours(1)));

        True(secondA.Eventos.Any(e => e.Mensaje.Contains("storm-", StringComparison.Ordinal)),
            "C6: tras reiniciar el cursor avanzó sobre eventos aún en cola y la tormenta no se releyó.");
        True(secondA.Eventos.Concat(secondB.Eventos).Any(e => e.Mensaje.Contains("TSPLUS-C6-MARKER", StringComparison.Ordinal)),
            "C6: el remanente del backlog se perdió tras el reinicio (cursor avanzó sobre lo no entregado).");
    }
    finally
    {
        Environment.SetEnvironmentVariable("TDM_STATE_ROOT", prior);
        TryDelete(dir);
        TryDelete(stateRoot);
    }
}

static Task WindowsEventNewChannelStartsWithRecentWindow()
{
    var filter = "*[System[(EventID=7000 or EventID=7001)]]";
    var window = TimeSpan.FromMinutes(15);

    var withCursor = IncrementalWindowsEventCollector.ComposeCycleFilter(filter, 42, window);
    True(withCursor.Contains("EventRecordID > 42", StringComparison.Ordinal),
        "Con cursor el XPath dejó de usar el bookmark oficial EventRecordID > cursor.");
    False(withCursor.Contains("timediff", StringComparison.Ordinal),
        "Con cursor persistido no debe aplicarse ventana temporal.");

    var newChannel = IncrementalWindowsEventCollector.ComposeCycleFilter(filter, 0, window);
    True(newChannel.Contains("TimeCreated[timediff(@SystemTime) <= 900000]", StringComparison.Ordinal),
        "Un canal sin cursor no arrancó con la ventana temporal oficial de 15 min.");
    True(newChannel.Contains("EventID=7000", StringComparison.Ordinal),
        "La ventana inicial descartó el filtro propio del canal.");
    False(newChannel.Contains("EventRecordID", StringComparison.Ordinal),
        "Un canal sin cursor no debe fabricar un EventRecordID inexistente.");

    var root = FindRepoRoot();
    NotNull(root, "No se localizó TDM.sln; gate del cableado H6 no ejecutable.");
    var source = File.ReadAllText(Path.Combine(root!, "src", "TDM.Collectors.Windows", "IncrementalWindowsEventCollector.cs"));
    True(source.Contains("ComposeCycleFilter(channel.Filter, cursor, InitialChannelWindow)", StringComparison.Ordinal),
        "El ciclo continuo no compone el XPath con la ventana inicial de canal sin cursor.");
    False(source.Contains("replayAfterReset ? AppendRecentWindow", StringComparison.Ordinal),
        "Se conservó el ensamblaje de XPath condicional previo al fix H6.");
    return Task.CompletedTask;
}

static Task WindowsEventGapRecoveryIsWiredInWorker()
{
    var root = FindRepoRoot();
    NotNull(root, "No se localizó TDM.sln; gate del cableado de recuperación no ejecutable.");
    var worker = File.ReadAllText(Path.Combine(root!, "src", "TDM.Service", "TdmWorker.cs"));
    True(worker.Contains("recoveryLookback ?? NormalInterval", StringComparison.Ordinal),
        "El ciclo continuo no aplica el lookback de recuperación tras reinicio.");
    True(worker.Contains("recoveryLookback ?? EmergencyPolicy.Lookback", StringComparison.Ordinal),
        "El ciclo de emergencia no aplica el lookback de recuperación tras reinicio.");
    var collector = File.ReadAllText(Path.Combine(root!, "src", "TDM.Collectors.Windows", "IncrementalWindowsEventCollector.cs"));
    True(collector.Contains("_gapDeclared", StringComparison.Ordinal),
        "El collector no persiste el estado de hueco declarado entre muestras.");
    True(collector.Contains("LastSuccessUtc", StringComparison.Ordinal),
        "El collector no persiste la última muestra con cobertura completa.");
    return Task.CompletedTask;
}

static Task WindowsEventBaseCoverageCountsMissingChannelAsPartial()
{
    True(WindowsEventCollector.IsPartialCoverage([new EvidenceItem("Security", "Canal no disponible")]),
        "Un canal no disponible no dejó la cobertura base parcial.");
    True(WindowsEventCollector.IsPartialCoverage([new EvidenceItem("System", "Parcial; relevantes=1; examinados=2")]),
        "Una cobertura parcial dejó de detectarse.");
    True(WindowsEventCollector.IsPartialCoverage([new EvidenceItem("System", "Sin permisos de lectura")]),
        "Un canal sin permisos no dejó la cobertura base parcial.");
    True(WindowsEventCollector.IsPartialCoverage([new EvidenceItem("System", "No legible: error")]),
        "Un canal no legible no dejó la cobertura base parcial.");
    False(WindowsEventCollector.IsPartialCoverage([new EvidenceItem("System", "Disponible; relevantes=0; examinados=0")]),
        "Una cobertura disponible se marcó parcial.");
    var root = FindRepoRoot();
    NotNull(root, "No se localizó TDM.sln; gate de cobertura base no ejecutable.");
    var text = File.ReadAllText(Path.Combine(root!, "src", "TDM.Collectors.Windows", "WindowsEventCollector.cs"));
    True(text.Contains("IsPartialCoverage(coverage.Skip(1))", StringComparison.Ordinal),
        "El evento de cobertura base ya no se calcula con IsPartialCoverage.");
    return Task.CompletedTask;
}

static async Task ExportRendersBaseWindowsEventCoverage()
{
    var dir = TempDir();
    try
    {
        var now = DateTimeOffset.Now;
        var coverage = new DiagnosticEvent(now, "TDM", "Cobertura de eventos Windows", DiagnosticLayer.Windows,
            DiagnosticSeverity.Advertencia, "WINDOWS_EVENT_COVERAGE",
            "La lectura base de eventos Windows quedó parcial; las ausencias no se interpretan como estado sano.",
            Evidencia:
            [
                new EvidenceItem("Ventana solicitada", $"{now.AddHours(-4):O} → {now:O}"),
                new EvidenceItem("System", "Disponible; relevantes=1; examinados=1"),
                new EvidenceItem("Security", "Canal no disponible")
            ]);
        var result = await ReportExporter.ExportAsync(Report([coverage], now), dir, CancellationToken.None);
        var html = await File.ReadAllTextAsync(result.HtmlPath);
        True(html.Contains("Cobertura base de eventos Windows", StringComparison.Ordinal),
            "El HTML no renderiza la cobertura base de Event Log.");
        True(html.Contains("Canal no disponible", StringComparison.Ordinal),
            "El HTML no muestra el canal no disponible de la cobertura base.");
    }
    finally { TryDelete(dir); }
}

static Task DiagnosticSampleKindUnifiesProducers()
{
    True(new ObservabilitySample { SampleKind = "diagnostic" }.IsDiagnosticSample,
        "El tipo legado 'diagnostic' dejó de reconocerse como diagnóstico.");
    True(new ObservabilitySample { SampleKind = "diagnostic-avalonia" }.IsDiagnosticSample,
        "Las ejecuciones de diagnóstico de la GUI dejaron de contar como diagnóstico.");
    True(new ObservabilitySample { SampleKind = "service-monitor" }.IsDiagnosticSample,
        "Los ciclos de diagnóstico del servicio dejaron de contar como diagnóstico.");
    False(new ObservabilitySample { SampleKind = "monitor" }.IsDiagnosticSample,
        "Un muestreo simple se contó como diagnóstico.");
    False(new ObservabilitySample { SampleKind = "monitor-summary" }.IsDiagnosticSample,
        "El resumen de monitoreo se contó como diagnóstico.");
    False(new ObservabilitySample { SampleKind = "avalonia-monitor" }.IsDiagnosticSample,
        "El monitoreo en vivo de la GUI se contó como diagnóstico.");
    var root = FindRepoRoot();
    NotNull(root, "No se localizó TDM.sln; gate de SampleKind no ejecutable.");
    var causality = File.ReadAllText(Path.Combine(root!, "src", "TDM.Gui.Avalonia", "ViewModels", "CausalityDashboardViewModel.cs"));
    True(causality.Contains("IsDiagnosticSample", StringComparison.Ordinal),
        "El panel de causalidad volvió a filtrar por un SampleKind que ningún productor escribe.");
    var preventive = File.ReadAllText(Path.Combine(root!, "src", "TDM.Gui.Avalonia", "ViewModels", "PreventiveDashboardViewModel.cs"));
    True(preventive.Contains("IsDiagnosticSample", StringComparison.Ordinal),
        "El panel preventivo volvió a filtrar por un SampleKind que ningún productor escribe.");
    return Task.CompletedTask;
}

static Task ResourceMetricReadersUseStableKeys()
{
    var now = DateTimeOffset.Now;
    var stable = new DiagnosticEvent(now, "TDM", "Recursos", DiagnosticLayer.Windows,
        DiagnosticSeverity.Informativo, "SYSTEM_RESOURCE_STATE", "Recursos", Evidencia:
        [
            new EvidenceItem(ResourceMetricKeys.CpuPercent, "42.5"),
            new EvidenceItem(ResourceMetricKeys.MemoryFreePercent, "63.25")
        ]);
    Equal(42.5, ObservabilityStore.ParseCpu(stable) ?? -1, "El lector de CPU ignora la clave estable Metric.Cpu.Percent.");
    Equal(63.25, ObservabilityStore.ParseMemory(stable) ?? -1, "El lector de memoria ignora la clave estable Metric.Memory.FreePercent.");

    var legacy = new DiagnosticEvent(now, "TDM", "Recursos", DiagnosticLayer.Windows,
        DiagnosticSeverity.Informativo, "SYSTEM_RESOURCE_STATE", "Recursos", Evidencia:
        [
            new EvidenceItem("CPU", "87 %"),
            new EvidenceItem("Memoria física", "Memoria disponible (50% libre)")
        ]);
    Equal(87d, ObservabilityStore.ParseCpu(legacy) ?? -1, "El lector de CPU perdió el respaldo legado.");
    Equal(50d, ObservabilityStore.ParseMemory(legacy) ?? -1, "El lector de memoria perdió el respaldo legado.");

    True(ObservabilityStore.ParseCpu(new DiagnosticEvent(now, "TDM", "Recursos", DiagnosticLayer.Windows,
        DiagnosticSeverity.Informativo, "SYSTEM_RESOURCE_STATE", "Recursos")) is null,
        "Sin métricas el lector de CPU devolvió un valor fabricado.");

    var root = FindRepoRoot();
    NotNull(root, "No se localizó TDM.sln; gate de métricas no ejecutable.");
    var text = File.ReadAllText(Path.Combine(root!, "src", "TDM.Gui.Avalonia", "Services", "IntegratedMonitoringService.cs"));
    True(text.Contains("ObservabilityStore.ParseCpu(", StringComparison.Ordinal),
        "El monitor GUI sigue leyendo claves de métricas locales en vez del lector estable.");
    True(!text.Contains("e.Clave.Equals(\"CpuPercent\"", StringComparison.Ordinal),
        "El monitor GUI sigue buscando la clave legada 'CpuPercent'.");
    True(!text.Contains("e.Clave.Equals(\"MemoryFreePercent\"", StringComparison.Ordinal),
        "El monitor GUI sigue buscando la clave legada 'MemoryFreePercent'.");
    return Task.CompletedTask;
}

static async Task NotEvaluatedTsplusDetectionIsCommunicated()
{
    var now = DateTimeOffset.Now;
    var inconcluso = Report([], now) with
    {
        Sistema = Snapshot() with { TsplusDetectado = false, TsplusEstadoDeteccion = TsplusDetectionState.NotEvaluated }
    };
    var narrative = DiagnosticNarrativeBuilder.Build(inconcluso);
    True(narrative.Contains("No evaluado", StringComparison.Ordinal),
        "La detección no evaluada no se comunica en la narrativa.");
    False(narrative.Contains("no está detectado", StringComparison.OrdinalIgnoreCase),
        "La narrativa afirma ausencia de TSplus cuando sólo hubo un permiso denegado.");

    var ausente = Report([], now) with
    {
        Sistema = Snapshot() with { TsplusDetectado = false, TsplusEstadoDeteccion = TsplusDetectionState.ConfirmedAbsent }
    };
    True(DiagnosticNarrativeBuilder.Build(ausente).Contains("no está detectado", StringComparison.Ordinal),
        "Con ausencia confirmada la narrativa dejó de declararlo.");

    Equal("No evaluado", (Snapshot() with { TsplusDetectado = false, TsplusEstadoDeteccion = TsplusDetectionState.NotEvaluated }).EstadoDeteccionTexto(),
        "El estado NotEvaluated no se tradujo a 'No evaluado'.");
    Equal("No detectado", (Snapshot() with { TsplusDetectado = false, TsplusEstadoDeteccion = TsplusDetectionState.ConfirmedAbsent }).EstadoDeteccionTexto(),
        "La ausencia confirmada cambió su texto estable.");
    Equal("Detectado", Snapshot().EstadoDeteccionTexto(),
        "La detección confirmada cambió su texto estable.");

    var dir = TempDir();
    try
    {
        var result = await ReportExporter.ExportAsync(inconcluso, dir, CancellationToken.None);
        var html = await File.ReadAllTextAsync(result.HtmlPath);
        True(html.Contains("No evaluado", StringComparison.Ordinal),
            "El HTML no comunica la detección no evaluada.");
        False(html.Contains("no está detectado", StringComparison.OrdinalIgnoreCase),
            "El HTML afirma ausencia de TSplus ante una detección inconclusa.");
    }
    finally { TryDelete(dir); }
}

static Task TsplusLogCoverageNotEvaluatedWithoutDetection()
{
    var now = DateTimeOffset.Now;
    var sinTsplus = Report([], now) with
    {
        Sistema = Snapshot() with { TsplusDetectado = false, TsplusEstadoDeteccion = TsplusDetectionState.ConfirmedAbsent }
    };
    var assessment = DiagnosticCoverageAnalyzer.Analyze(sinTsplus);
    var fuente = assessment.Fuentes.Single(x => x.Fuente == "Logs TSplus Remote Access");
    Equal("No aplica", fuente.Estado,
        "Sin TSplus detectado la cobertura de logs se evaluó como fuente crítica.");
    False(assessment.Limitaciones.Any(l => l.StartsWith("Sin cobertura de logs TSplus", StringComparison.Ordinal)),
        "Sin TSplus detectado se agregó una limitación de cobertura de logs.");

    var conTsplus = Report([], now);
    var assessmentCon = DiagnosticCoverageAnalyzer.Analyze(conTsplus);
    Equal("No disponible", assessmentCon.Fuentes.Single(x => x.Fuente == "Logs TSplus Remote Access").Estado,
        "Con TSplus detectado y sin cobertura la fuente debe seguir No disponible.");
    True(assessment.Score > assessmentCon.Score,
        "La ausencia de TSplus sigue penalizando el puntaje de cobertura.");

    var inconcluso = Report([], now) with
    {
        Sistema = Snapshot() with { TsplusDetectado = false, TsplusEstadoDeteccion = TsplusDetectionState.NotEvaluated }
    };
    var assessmentInconcluso = DiagnosticCoverageAnalyzer.Analyze(inconcluso);
    Equal("No consultado", assessmentInconcluso.Fuentes.Single(x => x.Fuente == "Logs TSplus Remote Access").Estado,
        "Con detección inconclusa la cobertura de logs debe quedar NO EVALUADA.");
    True(assessmentInconcluso.Limitaciones.Any(l => l.Contains("logs TSplus no fue evaluada", StringComparison.Ordinal)),
        "La detección inconclusa no dejó la limitación de cobertura de logs.");
    return Task.CompletedTask;
}

static async Task IncrementalCoverageCountsMissingExpectedSources()
{
    var dir = TempDir();
    var stateRoot = TempDir();
    var prior = Environment.GetEnvironmentVariable("TDM_STATE_ROOT");
    try
    {
        Environment.SetEnvironmentVariable("TDM_STATE_ROOT", stateRoot);
        var install = Path.Combine(dir, "TSplus");
        var cgi = Path.Combine(install, "Clients", "www", "cgi-bin");
        Directory.CreateDirectory(cgi);
        await File.WriteAllTextAsync(Path.Combine(cgi, "hb.log"), "ERROR portal down 1\n");

        var collector = new IncrementalTsplusLogCollector();
        collector.Prime(install);
        var result = await collector.CollectAsync(new DiagnosticContext(Snapshot() with { TsplusRuta = install }, TimeSpan.FromHours(1)));

        var coverage = result.Eventos.LastOrDefault(e => e.Tipo == "TSPLUS_INCREMENTAL_LOG_COVERAGE");
        NotNull(coverage, "El collector incremental no emitió su evento de cobertura.");
        static string Value(DiagnosticEvent e, string key)
            => e.Evidencia?.FirstOrDefault(x => x.Clave.Equals(key, StringComparison.OrdinalIgnoreCase))?.Valor ?? "";
        Equal("2", Value(coverage!, "Fuentes esperadas"),
            "El denominador de la cobertura incremental no cuenta las fuentes base esperadas.");
        Equal("1", Value(coverage!, "Fuentes esperadas disponibles"),
            "La cobertura incremental no contabilizó la fuente base presente.");

        var assessment = DiagnosticCoverageAnalyzer.Analyze(Report([coverage!], DateTimeOffset.Now));
        var fuente = assessment.Fuentes.Single(x => x.Fuente == "Logs TSplus Remote Access");
        Equal("Parcial", fuente.Estado,
            "La ausencia de APSC.log dejó la cobertura incremental como Disponible.");
        True(fuente.Detalle.Contains("esperadas ausentes=1", StringComparison.Ordinal),
            "El detalle de cobertura no informa las fuentes esperadas ausentes.");

        var root = FindRepoRoot();
        NotNull(root, "No se localizó TDM.sln; gate de discovery no ejecutable.");
        var discovery = File.ReadAllText(Path.Combine(root!, "src", "TDM.Collectors.TSplus", "TsplusLogDiscovery.cs"));
        True(discovery.Split("optional: false", StringSplitOptions.None).Length - 1 >= 2,
            "Los logs base hb.log/APSC.log dejaron de declararse no opcionales.");
    }
    finally
    {
        Environment.SetEnvironmentVariable("TDM_STATE_ROOT", prior);
        TryDelete(dir);
        TryDelete(stateRoot);
    }
}

static Task GuiRealtimeWiresIncrementalContinuousDiagnostics()
{
    var root = FindRepoRoot();
    NotNull(root, "No se localizó TDM.sln; gate del cableado continuo no ejecutable.");
    var text = File.ReadAllText(Path.Combine(root!, "src", "TDM.Gui.Avalonia", "Services", "DiagnosticExecutionService.cs"));
    True(text.Contains("CollectorCatalog.CreateContinuous(", StringComparison.Ordinal),
        "El diagnóstico en tiempo real no sustituye las fuentes pesadas por collectors incrementales.");
    True(text.Contains("ContinuousDiagnosticMerger.Merge(", StringComparison.Ordinal),
        "El diagnóstico en tiempo real no fusiona la línea base con la muestra incremental.");
    True(text.Contains("_windowsIncremental.Prime()", StringComparison.Ordinal),
        "El cursor de Event Viewer no se posiciona al inicio de la siembra.");
    True(text.Contains("_tsplusIncremental.Prime(", StringComparison.Ordinal),
        "El cursor de logs TSplus no se posiciona al inicio de la siembra.");
    True(text.Contains("DiagnosticoContinuo", StringComparison.Ordinal),
        "El reporte no declara el modo continuo para exportación y cobertura.");
    return Task.CompletedTask;
}

static async Task ExportRootCauseMarkersAndFooters()
{
    var dir = TempDir();
    try
    {
        var now = DateTimeOffset.Now;
        var manyEvidence = Enumerable.Range(1, 25).Select(i => new EvidenceItem($"Evidencia {i}", $"valor {i}")).ToList();
        var causes = Enumerable.Range(1, 9)
            .Select(i => new RootCauseCandidate(i, $"ROOT-{i}", $"Comp-{i}", DiagnosticLayer.Tsplus, 90 - i,
                ConfidenceLevel.Alta, $"resumen {i}", $"explica {i}", i == 1 ? manyEvidence : [new EvidenceItem("k", "v")],
                Producto: TsplusProduct.RemoteAccess, OrigenClasificado: "TSPLUS"))
            .ToList();
        var principal = Report([], now) with { CausasRaiz = causes, CausaRaizPrincipal = causes[0] };
        var result = await ReportExporter.ExportAsync(principal, dir, CancellationToken.None);
        var html = await File.ReadAllTextAsync(result.HtmlPath);
        True(html.Contains("[PRINCIPAL] #1", StringComparison.Ordinal), "El candidato principal no quedó marcado con [PRINCIPAL].");
        True(html.Contains("id='cau-1'", StringComparison.Ordinal), "Se perdió el ancla de la causa principal.");
        True(html.Contains("evidencia(s) más (colección completa en JSON)", StringComparison.Ordinal),
            "La lista de evidencia truncada no indica el resto conservado en JSON.");
        True(html.Contains("… y 1 candidato(s) más sin mostrar.", StringComparison.Ordinal),
            "El listado de causas no anuncia el resto sin mostrar.");

        var sinPrincipal = Report([], now) with { CausasRaiz = causes };
        var second = await ReportExporter.ExportAsync(sinPrincipal, dir, CancellationToken.None);
        var secondHtml = await File.ReadAllTextAsync(second.HtmlPath);
        True(secondHtml.Contains("Sin causa principal declarada", StringComparison.Ordinal),
            "Sin CausaRaizPrincipal el export no explica la ausencia de causa declarada.");
        False(secondHtml.Contains("[PRINCIPAL]", StringComparison.Ordinal),
            "Con CausaRaizPrincipal nula no debe aparecer ningún marcador [PRINCIPAL].");
    }
    finally { TryDelete(dir); }
}

static async Task ExportGuidedResolutionOrderAndDetails()
{
    var dir = TempDir();
    try
    {
        static GuidedResolutionResult Guided(string comp, GuidedResolutionState estado, DiagnosticSeverity sev)
            => new(TsplusProduct.RemoteAccess, comp, estado, sev, ConfidenceLevel.Alta, "sintoma " + comp,
                "causa " + comp, "impacto " + comp, [new GuidedResolutionCheck("check " + comp, "OK", "detalle")],
                [], ["corregir " + comp], ["validar " + comp], [], "fuente", "https://example.test", "cobertura " + comp);

        var guided = new List<GuidedResolutionResult>
        {
            Guided("ACC-CRIT", GuidedResolutionState.Error, DiagnosticSeverity.Critico),
            Guided("ACC-ERR", GuidedResolutionState.Error, DiagnosticSeverity.Error),
            Guided("ACC-WARN", GuidedResolutionState.Saludable, DiagnosticSeverity.Advertencia)
        };
        guided.AddRange(Enumerable.Range(1, 11).Select(i => Guided($"N{i:D2}", GuidedResolutionState.Saludable, DiagnosticSeverity.Informativo)));

        var report = Report([], DateTimeOffset.Now) with { ResolucionesGuiadas = guided };
        var result = await ReportExporter.ExportAsync(report, dir, CancellationToken.None);
        var html = await File.ReadAllTextAsync(result.HtmlPath);

        True(html.Contains("Resoluciones: 14 | Requieren acción: 3 | Mostrando: 12", StringComparison.Ordinal),
            "La línea de conteos de resolución guiada no refleja totales/mostrados.");
        True(html.Contains("<h3>Requiere acción (3):</h3>", StringComparison.Ordinal), "Falta el encabezado del grupo accionable.");
        True(html.Contains("<h3>Sin acción requerida:</h3>", StringComparison.Ordinal), "Falta el encabezado del grupo no accionable.");
        True(html.IndexOf("<h3>Requiere acción (3):</h3>", StringComparison.Ordinal) < html.IndexOf("<h3>Sin acción requerida:</h3>", StringComparison.Ordinal),
            "El grupo accionable debe listarse primero.");
        var decodedHtml = System.Net.WebUtility.HtmlDecode(html);
        True(decodedHtml.Contains("[CRÍTICO] ", StringComparison.Ordinal), "Falta el marcador [CRÍTICO] en la tarjeta guiada.");
        True(decodedHtml.Contains("[ERROR] ", StringComparison.Ordinal), "Falta el marcador [ERROR] en la tarjeta guiada.");
        True(decodedHtml.Contains("[ADVERTENCIA] ", StringComparison.Ordinal), "Falta el marcador [ADVERTENCIA] en la tarjeta guiada.");
        True(html.Contains("ACC-CRIT · Error · Critico · Alta</h4>", StringComparison.Ordinal),
            "La tarjeta guiada no incluye producto/componente/estado/severidad/confianza en el h4.");
        True(html.Contains("<strong>Síntoma:</strong>", StringComparison.Ordinal), "La tarjeta guiada no muestra el síntoma.");
        True(html.Contains("<strong>Comprobaciones:</strong>", StringComparison.Ordinal), "La tarjeta guiada no muestra las comprobaciones.");
        True(html.Contains("… y 2 resolución(es) más sin mostrar.", StringComparison.Ordinal),
            "El listado guiado no anuncia el resto sin mostrar.");
    }
    finally { TryDelete(dir); }
}

static async Task ExportPatternsShowSingletonsAndFullColumns()
{
    var dir = TempDir();
    try
    {
        var now = DateTimeOffset.Now;
        FailurePattern Pattern(string id, int incidentes)
            => new(id, TsplusProduct.RemoteAccess, "Comp" + id, "sem-" + id, "ExcepcionX", "TSPLUS", "Nuevo",
                incidentes, now.AddDays(-1), now, null, [id], []);
        var patterns = Enumerable.Range(1, 25).Select(i => Pattern($"PAT-{i:D2}", i == 1 ? 1 : 2)).ToList();
        var report = Report([], now) with { PatronesFalla = patterns };
        var result = await ReportExporter.ExportAsync(report, dir, CancellationToken.None);
        var html = await File.ReadAllTextAsync(result.HtmlPath);
        True(html.Contains("<h2>Patrones de falla</h2>", StringComparison.Ordinal), "La tarjeta dejó de llamarse Patrones de falla.");
        False(html.Contains("Patrones recurrentes", StringComparison.Ordinal), "Quedó el título viejo Patrones recurrentes.");
        True(html.Contains("CompPAT-01", StringComparison.Ordinal), "Un patrón singleton (Incidentes=1) dejó de mostrarse.");
        True(html.Contains("<th>Origen</th>", StringComparison.Ordinal), "Falta la columna Origen en patrones.");
        True(html.Contains("<th>Intervalo promedio</th>", StringComparison.Ordinal), "Falta la columna Intervalo promedio en patrones.");
        True(html.Contains("<th>Incidentes relacionados</th>", StringComparison.Ordinal), "Falta la columna Incidentes relacionados en patrones.");
        True(html.Contains("… y 5 patrón(es) más sin mostrar.", StringComparison.Ordinal),
            "El listado de patrones no anuncia el resto sin mostrar.");

        var vacio = await ReportExporter.ExportAsync(Report([], now), dir, CancellationToken.None);
        var vacioHtml = await File.ReadAllTextAsync(vacio.HtmlPath);
        True(vacioHtml.Contains("No se detectaron patrones de falla en la vista temporal actual.", StringComparison.Ordinal),
            "El estado vacío de patrones ya no coincide con la GUI.");
    }
    finally { TryDelete(dir); }
}

static async Task ExportCoverageCountsAndCriticalFirst()
{
    var dir = TempDir();
    try
    {
        var now = DateTimeOffset.Now;
        var coverage = new DiagnosticCoverageAssessment(70, "Parcial",
            [
                new CoverageSourceAssessment("SRC-CRIT-A", "No disponible", "detalle", true),
                new CoverageSourceAssessment("SRC-CRIT-B", "Disponible", "detalle", true),
                new CoverageSourceAssessment("SRC-LOW-A", "Parcial", "detalle", false),
                new CoverageSourceAssessment("SRC-LOW-B", "No consultado", "detalle", false)
            ], [], "resumen");
        var report = Report([], now) with { CoberturaDiagnostica = coverage };
        var result = await ReportExporter.ExportAsync(report, dir, CancellationToken.None);
        var html = await File.ReadAllTextAsync(result.HtmlPath);
        True(html.Contains("Fuentes: 4 | Críticas: 2 | Críticas bloqueadas: 1 | Parciales: 2", StringComparison.Ordinal),
            "La línea de conteos de cobertura no cuenta Parciales por estado (incluye críticas).");
        True(html.IndexOf("SRC-CRIT-A", StringComparison.Ordinal) < html.IndexOf("SRC-LOW-A", StringComparison.Ordinal),
            "La tabla de cobertura ya no ordena primero las fuentes críticas.");
    }
    finally { TryDelete(dir); }
}

static async Task ExportJsonUsesStringEnumsAndRoundTrips()
{
    var dir = TempDir();
    try
    {
        var now = DateTimeOffset.Now;
        var evt = new DiagnosticEvent(now, "Test", "Test", DiagnosticLayer.Windows, DiagnosticSeverity.Critico, "TEST_EVENT", "mensaje");
        var report = Report([evt], now);
        var result = await ReportExporter.ExportAsync(report, dir, CancellationToken.None);
        var json = await File.ReadAllTextAsync(result.JsonPath);
        True(json.Contains("\"severidad\": \"Critico\"", StringComparison.Ordinal), "La severidad no se serializó como texto en JSON.");
        True(json.Contains("\"capa\": \"Windows\"", StringComparison.Ordinal), "La capa no se serializó como texto en JSON.");
        True(json.Contains("\"producto\": \"Ninguno\"", StringComparison.Ordinal), "El producto no se serializó como texto en JSON.");
        var round = JsonSerializer.Deserialize<DiagnosticReport>(json, new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true,
            Converters = { new JsonStringEnumConverter() }
        });
        NotNull(round, "El JSON exportado no volvió a leerse como reporte.");
        Equal(DiagnosticSeverity.Critico, round!.Eventos[0].Severidad, "El ciclo de escritura/lectura de enums perdió severidad.");
        Equal(DiagnosticLayer.Windows, round.Eventos[0].Capa, "El ciclo de escritura/lectura de enums perdió capa.");
    }
    finally { TryDelete(dir); }
}

static async Task SanitizerIdempotentAvoidsSpuriousDiff()
{
    var now = DateTimeOffset.Now;
    var evt = new DiagnosticEvent(now, "Security", "Accounts", DiagnosticLayer.Windows, DiagnosticSeverity.Error,
        "USER_ACCOUNT_STATE", "cuenta observada",
        Evidencia: [new EvidenceItem("Usuario", "alice"), new EvidenceItem("Contraseña", "hunter2")]);
    var raw = Report([evt], now);
    var once = SupportBundleSanitizer.Sanitize(raw);
    var twice = SupportBundleSanitizer.Sanitize(once);
    Equal(JsonSerializer.Serialize(once), JsonSerializer.Serialize(twice),
        "Sanitize no es idempotente: la pseudonimización cambió entre pasadas.");

    var dir = TempDir();
    try
    {
        var result = await ReportExporter.ExportAsync(once, dir, CancellationToken.None, once);
        var html = await File.ReadAllTextAsync(result.HtmlPath);
        False(html.Contains("Cambios desde el reporte anterior", StringComparison.Ordinal),
            "Un reporte previo ya sanitizado generó una tarjeta diff espuria por pseudónimos no idempotentes.");
    }
    finally { TryDelete(dir); }
}

static Task NarrativeUsesLocalTimeForWindows()
{
    var report = Report([], DateTimeOffset.Now);
    var text = DiagnosticNarrativeBuilder.Build(report);
    True(text.Contains($"Periodo visible: {report.PeriodoAnalizadoInicio.ToLocalTime():dd/MM/yyyy HH:mm:ss}", StringComparison.Ordinal),
        "La ventana del narrativo no se imprime en hora local.");
    True(text.Contains($"Ejecución TDM: {report.Inicio.ToLocalTime():dd/MM/yyyy HH:mm:ss}", StringComparison.Ordinal),
        "La ejecución TDM del narrativo no se imprime en hora local.");
    return Task.CompletedTask;
}

static async Task EvidenceDetailsFallBackToIngestedAt()
{
    var dir = TempDir();
    try
    {
        var now = DateTimeOffset.Now;
        var evt = new DiagnosticEvent(null, "Test", "Test", DiagnosticLayer.Windows, DiagnosticSeverity.Informativo,
            "TEST_EVENT", "sin timestamp", IngestedAt: now);
        var report = Report([evt], now);
        var result = await ReportExporter.ExportAsync(report, dir, CancellationToken.None);
        var html = await File.ReadAllTextAsync(result.HtmlPath);
        True(html.Contains($"{now.ToLocalTime():dd/MM/yyyy HH:mm:ss} [Informativo] [Fuente:", StringComparison.Ordinal),
            "La evidencia sin Timestamp no cae a IngestedAt en los detalles del export.");
    }
    finally { TryDelete(dir); }
}

static Task SanitizeCoversPreviouslyRawSections()
{
    var now = DateTimeOffset.Now;
    var identity = new DiagnosticEvent(now, "Netlogon", "Active Directory", DiagnosticLayer.Windows, DiagnosticSeverity.Error,
        "WINDOWS_AD_DOMAIN_CONNECTIVITY_FAILURE", "Secure channel failed",
        Evidencia: [new EvidenceItem("Usuario", "alice"), new EvidenceItem("Host", "win-pc")]);
    var baseReport = Report([identity], now);
    var clusters = IncidentClusterAnalyzer.Analyze(baseReport);
    True(clusters.Count == 1, "precondición: la señal de identidad debe formar un clúster.");
    True(clusters[0].Evidencia.Any(x => x.Valor.Contains("ALICE", StringComparison.Ordinal)),
        "precondición: la identidad cruda debe estar en la evidencia del clúster.");
    var primary = new RootCauseCandidate(1, "ROOT-IDENTITY", "Netlogon", DiagnosticLayer.Windows, 88, ConfidenceLevel.Alta,
        "Canal seguro fallido de alice@corp.example", "Fallo del dominio CORP\\alice",
        [new EvidenceItem("Usuario", "alice")], HoraIncidente: now, OrigenClasificado: "WINDOWS");
    var raw = baseReport with
    {
        CausasRaiz = [primary],
        CausaRaizPrincipal = primary,
        Incidentes = clusters,
        PrecisionDiagnostica = new DiagnosticPrecisionAssessment(72, "Alta", true, 0, 3, 12, 1, false, true,
            "Identidad observada alice@corp.example", [new EvidenceItem("Usuario", "alice")]),
        Tensiones = ["Evidencia de alice@corp.example sin contraste en otra fuente"],
        MotivoAmpliacion = "Ventana ampliada para alice@corp.example"
    };

    var once = SupportBundleSanitizer.Sanitize(raw);
    var twice = SupportBundleSanitizer.Sanitize(once);
    Equal(JsonSerializer.Serialize(once), JsonSerializer.Serialize(twice),
        "Las secciones nuevas de Sanitize no son idempotentes.");

    True(raw.CausaRaizPrincipal!.Resumen.Contains("alice", StringComparison.OrdinalIgnoreCase),
        "Sanitize mutó el reporte original.");
    True(once.CausaRaizPrincipal is not null, "CausaRaizPrincipal desapareció al sanitizar.");
    False(once.CausaRaizPrincipal!.Resumen.Contains("alice", StringComparison.OrdinalIgnoreCase),
        "CausaRaizPrincipal no se sanitizó.");
    True(once.CausaRaizPrincipal!.Evidencia.Any(x => x.Valor.StartsWith("USR-", StringComparison.Ordinal)),
        "La evidencia de identidad de CausaRaizPrincipal no se pseudonimizó.");

    True(once.Incidentes.Count == 1, "Los clústeres desaparecieron al sanitizar.");
    var identityGroup = once.Incidentes[0].Evidencia.FirstOrDefault(x => x.Clave == "Identidad del grupo")?.Valor ?? "";
    True(identityGroup.StartsWith("USR-", StringComparison.Ordinal),
        "La identidad del grupo del clúster no se pseudonimizó.");
    False(identityGroup.Contains("ALICE", StringComparison.Ordinal),
        "La identidad del grupo del clúster conservó el usuario en claro.");
    var domainValue = once.Incidentes[0].Evidencia.FirstOrDefault(x => x.Clave == "Dominio")?.Valor ?? "";
    Equal("AD_AUTENTICACION", domainValue,
        "El dominio funcional del clúster fue tratado como dominio AD y pseudonimizado.");

    NotNull(once.PrecisionDiagnostica, "PrecisionDiagnostica desapareció al sanitizar.");
    False(once.PrecisionDiagnostica!.Resumen.Contains("alice", StringComparison.OrdinalIgnoreCase),
        "El resumen de precisión diagnóstica conservó identidad cruda.");
    True(once.Tensiones.All(t => !t.Contains("alice", StringComparison.OrdinalIgnoreCase)),
        "Las tensiones de coherencia conservaron identidad cruda.");
    False((once.MotivoAmpliacion ?? "").Contains("alice", StringComparison.OrdinalIgnoreCase),
        "El motivo de ampliación conservó identidad cruda.");
    return Task.CompletedTask;
}

static async Task ExportJsonMasksPrimaryCauseAndClusterIdentity()
{
    var now = DateTimeOffset.Now;
    var identity = new DiagnosticEvent(now, "Netlogon", "Active Directory", DiagnosticLayer.Windows, DiagnosticSeverity.Error,
        "WINDOWS_AD_DOMAIN_CONNECTIVITY_FAILURE", "Secure channel failed",
        Evidencia: [new EvidenceItem("Usuario", "alice"), new EvidenceItem("Host", "win-pc")]);
    var primary = new RootCauseCandidate(1, "ROOT-IDENTITY", "Netlogon", DiagnosticLayer.Windows, 88, ConfidenceLevel.Alta,
        "Canal seguro fallido de alice@corp.example", "El dominio CORP\\alice perdió el canal seguro.",
        [new EvidenceItem("Usuario", "alice")], HoraIncidente: now, OrigenClasificado: "WINDOWS");
    var baseReport = Report([identity], now);
    var report = baseReport with
    {
        CausasRaiz = [primary],
        CausaRaizPrincipal = primary,
        Incidentes = IncidentClusterAnalyzer.Analyze(baseReport),
        PrecisionDiagnostica = new DiagnosticPrecisionAssessment(72, "Alta", true, 0, 3, 12, 1, false, true,
            "Cobertura aceptable; identidad observada alice@corp.example", [new EvidenceItem("Usuario", "alice")]),
        Tensiones = ["Evidencia de alice@corp.example sin contraste en otra fuente"],
        MotivoAmpliacion = "Ventana ampliada para alice@corp.example"
    };
    var dir = TempDir();
    try
    {
        var result = await ReportExporter.ExportAsync(report, dir, CancellationToken.None);
        var json = await File.ReadAllTextAsync(result.JsonPath);
        var html = System.Net.WebUtility.HtmlDecode(await File.ReadAllTextAsync(result.HtmlPath));
        False(json.Contains("alice", StringComparison.OrdinalIgnoreCase),
            "El JSON export conservó identidad cruda en secciones sin sanitizar.");
        False(html.Contains("alice", StringComparison.OrdinalIgnoreCase),
            "El HTML export conservó identidad cruda (causa principal / narrativo).");

        var round = JsonSerializer.Deserialize<DiagnosticReport>(json, new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true,
            Converters = { new JsonStringEnumConverter() }
        });
        NotNull(round, "El JSON export no volvió a leerse como reporte.");
        True(round!.Incidentes.Count == 1, "El clúster de incidentes no llegó al JSON export.");
        var identityGroup = round.Incidentes[0].Evidencia.FirstOrDefault(x => x.Clave == "Identidad del grupo")?.Valor ?? "";
        True(identityGroup.StartsWith("USR-", StringComparison.Ordinal),
            "La identidad del grupo no se pseudonimizó en el JSON export.");
        NotNull(round.CausaRaizPrincipal, "La causa principal no llegó al JSON export.");
        True(round.CausaRaizPrincipal!.Evidencia.Any(x => x.Valor.StartsWith("USR-", StringComparison.Ordinal)),
            "La evidencia de la causa principal no se pseudonimizó en el JSON export.");
        NotNull(round.PrecisionDiagnostica, "La precisión diagnóstica no llegó al JSON export.");
        False(round.PrecisionDiagnostica!.Resumen.Contains("alice", StringComparison.OrdinalIgnoreCase),
            "El resumen de precisión conservó identidad cruda en el JSON export.");
        True(round.Tensiones.All(t => !t.Contains("alice", StringComparison.OrdinalIgnoreCase)),
            "Las tensiones conservaron identidad cruda en el JSON export.");
        False((round.MotivoAmpliacion ?? "").Contains("alice", StringComparison.OrdinalIgnoreCase),
            "El motivo de ampliación conservó identidad cruda en el JSON export.");
    }
    finally { TryDelete(dir); }
}

static Task ExportSanitizesIdentityBearingIdsAndComponents()
{
    var now = DateTimeOffset.Now;
    var jsmith = TdmPseudonym.Create("USR", "jsmith");
    var alice = TdmPseudonym.Create("USR", "alice");
    var legacyCause = new RootCauseCandidate(1, "ROOT-WINDOWS-NLA-CREDENTIALS-jsmith",
        "Windows NLA / credenciales / jsmith", DiagnosticLayer.Seguridad, 96, ConfidenceLevel.Alta,
        "Windows rechazó credenciales NLA del mismo usuario antes del síntoma RDP/TSplus.",
        "La evidencia de Security identifica un rechazo previo a la creación de sesión.",
        [new EvidenceItem("Usuario", "jsmith")], HoraIncidente: now, OrigenClasificado: "WINDOWS");
    var profileFinding = new DiagnosticFinding(
        "USER-PROFILE-BAK-S-1-5-21-111122223333-1001-1001-500",
        "Windows User Profile", DiagnosticSeverity.Advertencia,
        "Se detectó una entrada .bak de perfil de usuario en ProfileList.",
        "Una entrada .bak puede ser evidencia de un problema previo de carga del perfil.",
        [new EvidenceItem("SID", "S-1-5-21-111122223333-1001-1001-500")],
        ConfidenceLevel.Media, Capa: DiagnosticLayer.Windows);
    var logonFinding = new DiagnosticFinding(
        "USER-REMOTE-LOGON-FAILURE-JSMITH", "Windows RemoteInteractive Logon", DiagnosticSeverity.Advertencia,
        $"Se detectaron 3 fallos de inicio de sesión RemoteInteractive para '{jsmith}' en la ventana.",
        "La autenticación Windows falló antes de completar la sesión.",
        [new EvidenceItem("Usuario", "JSMITH")], ConfidenceLevel.Media, Capa: DiagnosticLayer.Windows);
    var currentCauseId = $"ROOT-WINDOWS-REMOTE-LOGON-{alice}";
    var currentCause = new RootCauseCandidate(2, currentCauseId,
        $"Autenticación Windows / {alice}", DiagnosticLayer.Windows, 95, ConfidenceLevel.Alta,
        "Windows rechazó el inicio de sesión RemoteInteractive del mismo usuario antes del síntoma RDP/TSplus.",
        "El evento Security 4625 precede al síntoma correlacionado y corresponde al mismo usuario.",
        [new EvidenceItem("Usuario", "alice")], HoraIncidente: now, OrigenClasificado: "WINDOWS");
    var report = Report([], now, [profileFinding, logonFinding]) with
    {
        CausasRaiz = [legacyCause, currentCause],
        CausaRaizPrincipal = legacyCause
    };

    var once = SupportBundleSanitizer.Sanitize(report);
    var twice = SupportBundleSanitizer.Sanitize(once);
    Equal(JsonSerializer.Serialize(once), JsonSerializer.Serialize(twice),
        "La sanearización de Ids/Componentes no es idempotente.");
    var json = JsonSerializer.Serialize(once);
    False(json.Contains("jsmith", StringComparison.OrdinalIgnoreCase),
        "El Id/Componente de causa con usuario en claro sobrevivió al sanitizador.");
    False(json.Contains("S-1-5-21-111122223333", StringComparison.Ordinal),
        "El SID crudo sobrevivió dentro del Id del hallazgo de perfil.");
    False(json.Contains("JSMITH", StringComparison.Ordinal),
        "El Id del hallazgo de logon conservó el usuario en claro.");
    True(once.CausasRaiz[0].Id.StartsWith("ROOT-WINDOWS-NLA-CREDENTIALS-USR-", StringComparison.Ordinal),
        "El Id de causa legado no se pseudonimizó con prefijo USR.");
    Equal($"Windows NLA / credenciales / {jsmith}", once.CausasRaiz[0].Componente,
        "El componente de causa con identidad suelta no se pseudonimizó.");
    True(once.Hallazgos[0].Id.StartsWith("USER-PROFILE-BAK-SID-", StringComparison.Ordinal),
        "El SID dentro del Id del hallazgo de perfil no se pseudonimizó.");
    True(once.Hallazgos[1].Id.StartsWith("USER-REMOTE-LOGON-FAILURE-USR-", StringComparison.Ordinal),
        "El usuario dentro del Id del hallazgo de logon no se pseudonimizó.");
    True(once.Hallazgos[1].Resumen.Contains(jsmith, StringComparison.Ordinal),
        "El pseudónimo del usuario en el Resumen se alteró al sanitizar.");
    Equal(currentCauseId, once.CausasRaiz[1].Id, "Un Id ya pseudonimizado cambió al sanitizar.");
    return Task.CompletedTask;
}

static Task EvidenceKeysOutsideTablesArePseudonymized()
{
    var now = DateTimeOffset.Now;
    var leaks = new DiagnosticFinding("H8-KEYS-TEST", "Configuración", DiagnosticSeverity.Advertencia,
        "Asignaciones con evidencia de identidad sin clave tabulada.", "Detalle de prueba.",
        [
            new EvidenceItem("Equipo originador", "PC-JSMITH"),
            new EvidenceItem("Estación", "JSMITH-WS01"),
            new EvidenceItem("Dominio detectado", "CONTOSO"),
            new EvidenceItem("Asignación", "jsmith"),
            new EvidenceItem("Equipo actual", "SRV-CORP"),
            new EvidenceItem("Nombres internos Reverse Proxy", "GW01 | GW02"),
            new EvidenceItem("Originador observado", "10.20.30.40")
        ], ConfidenceLevel.Media, Capa: DiagnosticLayer.Tsplus);
    var sentinel = new DiagnosticFinding("H8-SENTINEL-TEST", "Configuración", DiagnosticSeverity.Advertencia,
        "Sentinelas de cobertura.", "Detalle de prueba.",
        [
            new EvidenceItem("Nombres internos Reverse Proxy", "Ninguno derivado"),
            new EvidenceItem("Nombres internos Reverse Proxy", "NO EVALUADO")
        ], ConfidenceLevel.Media, Capa: DiagnosticLayer.Tsplus);
    var report = Report([], now, [leaks, sentinel]);

    var once = SupportBundleSanitizer.Sanitize(report);
    var evidence = once.Hallazgos[0].Evidencia;
    var originador = evidence.First(x => x.Clave == "Equipo originador").Valor;
    True(originador.StartsWith("HOST-", StringComparison.Ordinal) && !originador.Contains("JSMITH", StringComparison.Ordinal),
        "Equipo originador no se pseudonimizó como host.");
    var estacion = evidence.First(x => x.Clave == "Estación").Valor;
    True(estacion.StartsWith("HOST-", StringComparison.Ordinal) && !estacion.Contains("JSMITH", StringComparison.Ordinal),
        "Estación no se pseudonimizó como host.");
    var dominio = evidence.First(x => x.Clave == "Dominio detectado").Valor;
    True(dominio.StartsWith("DOM-", StringComparison.Ordinal) && !dominio.Contains("CONTOSO", StringComparison.Ordinal),
        "Dominio detectado no se pseudonimizó como dominio.");
    var asignacion = evidence.First(x => x.Clave == "Asignación").Valor;
    True(asignacion.StartsWith("USR-", StringComparison.Ordinal) && !asignacion.Contains("jsmith", StringComparison.OrdinalIgnoreCase),
        "Asignación no se pseudonimizó como cuenta.");
    var equipoActual = evidence.First(x => x.Clave == "Equipo actual").Valor;
    True(equipoActual.StartsWith("HOST-", StringComparison.Ordinal) && !equipoActual.Contains("SRV-CORP", StringComparison.Ordinal),
        "Equipo actual no se pseudonimizó como host.");
    var originadorObservado = evidence.First(x => x.Clave == "Originador observado").Valor;
    False(originadorObservado.Contains("10.20.30.40", StringComparison.Ordinal),
        "Originador observado conservó la IP en claro.");
    var hostList = evidence.First(x => x.Clave == "Nombres internos Reverse Proxy").Valor;
    True(hostList.Split(" | ").Length == 2 && hostList.Split(" | ").All(t => t.StartsWith("HOST-", StringComparison.Ordinal)),
        "La lista de hosts internos del Reverse Proxy no se pseudonimizó por token.");
    False(hostList.Contains("GW01", StringComparison.Ordinal) || hostList.Contains("GW02", StringComparison.Ordinal),
        "La lista de hosts internos del Reverse Proxy conservó hosts en claro.");
    Equal("Ninguno derivado", once.Hallazgos[1].Evidencia[0].Valor,
        "La sentinela 'Ninguno derivado' se convirtió en pseudónimo.");
    Equal("NO EVALUADO", once.Hallazgos[1].Evidencia[1].Valor,
        "La sentinela 'NO EVALUADO' se convirtió en pseudónimo.");
    Equal(JsonSerializer.Serialize(once), JsonSerializer.Serialize(SupportBundleSanitizer.Sanitize(once)),
        "La sanearización de claves de evidencia no es idempotente.");
    return Task.CompletedTask;
}

static Task SourcePseudonymizesIdentityIdsAndComponents()
{
    var root = FindRepoRoot();
    NotNull(root, "No se localizó TDM.sln; gate de sanearización de identidad en origen no ejecutable.");
    var correlator = File.ReadAllText(Path.Combine(root!, "src", "TDM.Correlation", "RootCauseCorrelator.Rules.IdentitySecurity.cs"));
    False(correlator.Contains("ROOT-WINDOWS-REMOTE-LOGON-{user}", StringComparison.Ordinal),
        "El correlador sigue incrustando el usuario en claro dentro del Id de causa.");
    True(correlator.Contains("TdmPseudonym.Create(\"USR\", user)", StringComparison.Ordinal),
        "El correlador no pseudonimiza el usuario con TdmPseudonym.");
    True(correlator.Contains("Windows NLA / credenciales / {userId}", StringComparison.Ordinal),
        "El componente de causa NLA no usa el usuario pseudonimizado.");
    var profiles = File.ReadAllText(Path.Combine(root!, "src", "TDM.Collectors.Rdp", "UserSessionProfileCollector.cs"));
    False(profiles.Contains("private static string Sanitize(string value)", StringComparison.Ordinal),
        "El collector de perfiles conserva el sanitizador local que dejaba SIDs/nombres legibles en los Ids.");
    True(profiles.Contains("TdmPseudonym.Create(\"SID\", profile.Sid)", StringComparison.Ordinal),
        "Los Ids USER-PROFILE-* no pseudonimizan el SID con TdmPseudonym.");
    True(profiles.Contains("TdmPseudonym.Create(\"USR\", user)", StringComparison.Ordinal),
        "El hallazgo USER-REMOTE-LOGON-FAILURE no pseudonimiza el usuario.");
    var tsplus = File.ReadAllText(Path.Combine(root!, "src", "TDM.Collectors.TSplus", "TsplusInternalConfigurationCollector.cs"));
    True(tsplus.Contains("TSPLUS-PUBLISHED-APP-USER-{Sanitize(section.Name)}-{TdmPseudonym.Create(\"USR\", assignment)}", StringComparison.Ordinal),
        "La asignación de AppControl.ini sigue incrustándose en claro dentro del Id.");
    var sanitizer = File.ReadAllText(Path.Combine(root!, "src", "TDM.Reporting", "SupportBundleSanitizer.cs"));
    True(sanitizer.Contains("Id = SanitizeId(f.Id)", StringComparison.Ordinal),
        "SanitizeFinding no sanitiza el Id.");
    True(sanitizer.Contains("Id = SanitizeId(c.Id)", StringComparison.Ordinal),
        "SanitizeCause no sanitiza el Id.");
    True(sanitizer.Contains("LooseComponentIdentityRegex", StringComparison.Ordinal),
        "SanitizeText no detecta identidad suelta tras los formatos de componente conocidos.");

    var alice = TdmPseudonym.Create("USR", "alice");
    Equal(12, alice.Length, "El pseudónimo debe ser PREFIJO + 8 hex (12 caracteres).");
    True(alice.StartsWith("USR-", StringComparison.Ordinal) && !alice.Contains("alice", StringComparison.OrdinalIgnoreCase),
        "El pseudónimo conserva el usuario en claro.");
    Equal(alice, TdmPseudonym.Create("USR", " alice "), "El pseudónimo no es estable ante espacios.");
    Equal(alice, TdmPseudonym.Create("USR", alice), "El pseudónimo no es idempotente.");
    Equal("N/D", TdmPseudonym.Create("USR", "N/D"), "La sentinela N/D debe conservarse.");
    True(!alice.Equals(TdmPseudonym.Create("USR", "bob"), StringComparison.Ordinal),
        "Usuarios distintos colisionaron en el mismo pseudónimo.");
    return Task.CompletedTask;
}

static Task ServiceRecentTransitionsWiredBeforeCorrelation()
{
    var root = FindRepoRoot();
    NotNull(root, "No se localizó TDM.sln; gate de transiciones del servicio no ejecutable.");
    var worker = File.ReadAllText(Path.Combine(root!, "src", "TDM.Service", "TdmWorker.cs"));
    var readIndex = worker.IndexOf("AddRecentMonitorTransitionsAsync", StringComparison.Ordinal);
    True(readIndex >= 0, "El servicio no lee el journal reciente de transiciones (forensic/integrity/monitor).");
    var analyzeIndex = worker.IndexOf("DiagnosticWorkflow.Analyze(", StringComparison.Ordinal);
    True(analyzeIndex > readIndex, "La lectura del journal reciente no ocurre antes de DiagnosticWorkflow.Analyze en el ciclo del servicio.");
    return Task.CompletedTask;
}

static async Task RecordAndEnrichDeduplicatesPreRecordedTransitions()
{
    var root = TempDir();
    try
    {
        var now = DateTimeOffset.Now;
        var store = new LocalStateStore(root);
        await store.RecordAsync(StateSnapshotBuilder.Build(
            Report([ServiceStateEvent(now, "Running")], now), "1.0.0"), "service-monitor");
        var resultB = await store.RecordAsync(StateSnapshotBuilder.Build(
            Report([ServiceStateEvent(now.AddSeconds(5), "Stopped")], now.AddSeconds(5)), "1.0.0"), "service-monitor");
        Equal(1, resultB.Transitions.Count, "precondición: Running→Stopped debe producir una transición.");

        var report = Report([ServiceStateEvent(now.AddSeconds(5), "Stopped")], now.AddSeconds(5));
        report = StateReportIntegrator.AddTransitionsFromRecordResult(report, resultB, "service-monitor");
        Equal(1, report.Eventos.Count(e => e.Tipo == "TDM_MONITOR_STATE_TRANSITION"),
            "precondición: el pre-record debe aportar el evento de transición.");

        report = await StateReportIntegrator.RecordAndEnrichAsync(report, "1.0.0", CancellationToken.None,
            channel: "service-monitor", rootPath: root, preRecordedResult: resultB);

        var duplicated = report.Eventos.Count(e => e.Tipo == "TDM_STATE_TRANSITION"
            && e.Componente.Equals("Spooler", StringComparison.OrdinalIgnoreCase));
        Equal(0, duplicated, "RecordAndEnrich duplicó la transición ya emitida por el pre-record del ciclo.");
        var totalTransitions = report.Eventos.Count(e => e.Tipo is "TDM_MONITOR_STATE_TRANSITION" or "TDM_STATE_TRANSITION");
        Equal(1, totalTransitions, "El mismo cambio físico debe existir una sola vez en el reporte.");
    }
    finally { TryDelete(root); }
}

static async Task CarryForwardKeepsDroppedObservationLinked()
{
    var root = TempDir();
    try
    {
        var store = new LocalStateStore(root);
        var now = DateTimeOffset.Now;
        var full = await store.RecordAsync(StateSnapshotBuilder.Build(
            Report([LongitudinalConfigEvent(now, "Disponible", "Running")], now), "1.0.0"), "diagnostic");
        Equal(1, full.Snapshot.Observations.Count, "precondición: la observación longitudinal debe persistirse.");

        var degraded = await store.RecordAsync(StateSnapshotBuilder.Build(
            Report([LongitudinalConfigEvent(now.AddMinutes(1), "Sin permisos de lectura", "Stopped")], now.AddMinutes(1)), "1.0.0"), "diagnostic");
        Equal(0, degraded.Transitions.Count, "precondición: una cobertura degradada no debe producir transición.");
        var latest = await File.ReadAllTextAsync(store.GetLatestSnapshotPath("diagnostic"));
        True(latest.Contains("Running", StringComparison.Ordinal),
            "latest.json perdió la observación cuando la cobertura quedó degradada.");

        var recovered = await store.RecordAsync(StateSnapshotBuilder.Build(
            Report([LongitudinalConfigEvent(now.AddMinutes(2), "Disponible", "Stopped")], now.AddMinutes(2)), "1.0.0"), "diagnostic");
        Equal(1, recovered.Transitions.Count,
            "La observación reaparecida no vinculó contra el último estado conocido (carry-forward ausente).");
        True(recovered.Transitions[0].PreviousValue.Contains("Running", StringComparison.Ordinal),
            "La transición detectada no parte del último estado conocido conservado.");
        True(recovered.Transitions[0].CurrentValue.Contains("Stopped", StringComparison.Ordinal),
            "La transición detectada no llega al estado actual.");
    }
    finally { TryDelete(root); }
}

static async Task ConfigDriftUnreadableFileKeepsBaseline()
{
    var stateRoot = TempDir();
    var install = TempDir();
    var prior = Environment.GetEnvironmentVariable("TDM_STATE_ROOT");
    try
    {
        Environment.SetEnvironmentVariable("TDM_STATE_ROOT", stateRoot);
        SeedMinimalInstall(install, out var iniPath, out var original);

        var collector = new TsplusConfigurationDriftCollector();
        var ctx = InstallContext(install);
        var first = await collector.CollectAsync(ctx);
        True(first.Eventos.Any(e => e.Tipo == "TSPLUS_CONFIG_BASELINE_INITIALIZED"),
            "precondición: la primera ejecución debe inicializar la línea base.");
        True(File.Exists(Path.Combine(stateRoot, "tsplus-config-baseline.json")),
            "precondición: la línea base no se persistió en el state root aislado.");

        File.WriteAllText(iniPath, original + Environment.NewLine + new string('x', 1100 * 1024));
        var oversized = await collector.CollectAsync(ctx);
        False(oversized.Hallazgos.Any(f => f.Id == "TSPLUS-CONFIG-DRIFT"),
            "Un archivo presente-pero-ilegible por tamaño se reportó como eliminado (drift falso).");
        True(oversized.Eventos.Any(e => e.Tipo == "TSPLUS_CONFIG_STABLE"),
            "Un archivo ilegible por tamaño dejó de emitir el estado estable de configuración.");

        File.WriteAllText(iniPath, original);
        var restored = await collector.CollectAsync(ctx);
        False(restored.Hallazgos.Any(f => f.Id == "TSPLUS-CONFIG-DRIFT"),
            "La línea base se reescribió sin el archivo ilegible: al volver apareció un drift falso.");

        File.WriteAllText(iniPath, original + Environment.NewLine + "Port=8443");
        var changed = await collector.CollectAsync(ctx);
        True(changed.Hallazgos.Any(f => f.Id == "TSPLUS-CONFIG-DRIFT"
                && f.Evidencia.Any(x => x.Clave == "Archivos modificados" && x.Valor.Contains("AppControl.ini", StringComparison.Ordinal))),
            "Un cambio real en un archivo rastreado dejó de detectarse.");

        File.Delete(Path.Combine(install, "Clients", "www", "software", "html5", "settings.js"));
        var removed = await collector.CollectAsync(ctx);
        True(removed.Hallazgos.Any(f => f.Id == "TSPLUS-CONFIG-DRIFT"
                && f.Evidencia.Any(x => x.Clave == "Archivos eliminados" && x.Valor.Contains("settings.js", StringComparison.Ordinal))),
            "La eliminación real de un archivo rastreado dejó de detectarse.");
    }
    finally
    {
        Environment.SetEnvironmentVariable("TDM_STATE_ROOT", prior);
        TryDelete(stateRoot);
        TryDelete(install);
    }
}

static async Task ConfigDriftTracksWebArtifactsAndSeedsExisting()
{
    var stateRoot = TempDir();
    var install = TempDir();
    var prior = Environment.GetEnvironmentVariable("TDM_STATE_ROOT");
    try
    {
        Environment.SetEnvironmentVariable("TDM_STATE_ROOT", stateRoot);
        SeedMinimalInstall(install, out _, out _);

        var descriptor = TsplusConfigurationArtifactCatalog.Find("web.config");
        NotNull(descriptor, "web.config no está en el catálogo de artefactos de configuración TSplus.");
        Equal("Web / HTML5", descriptor!.Component, "web.config se clasificó fuera del componente Web / HTML5.");

        var collector = new TsplusConfigurationDriftCollector();
        var ctx = InstallContext(install);
        var first = await collector.CollectAsync(ctx);
        True(first.Eventos.Any(e => e.Tipo == "TSPLUS_CONFIG_BASELINE_INITIALIZED"),
            "precondición: la primera ejecución debe inicializar la línea base.");

        var wsDir = Path.Combine(install, "Clients", "webserver");
        Directory.CreateDirectory(wsDir);
        var webConfig = Path.Combine(wsDir, "web.config");
        var balance = Path.Combine(wsDir, "balance.bin");
        var settingsBin = Path.Combine(wsDir, "settings.bin");
        File.WriteAllText(webConfig, "<configuration></configuration>");
        File.WriteAllText(balance, "routes-v1");
        File.WriteAllText(settingsBin, "meta-v1");
        var past = DateTime.UtcNow.AddDays(-3);
        File.SetCreationTimeUtc(webConfig, past);
        File.SetCreationTimeUtc(balance, past);
        File.SetCreationTimeUtc(settingsBin, past);

        var seeded = await collector.CollectAsync(ctx);
        False(seeded.Hallazgos.Any(f => f.Id == "TSPLUS-CONFIG-DRIFT"),
            "Artefactos previos a la línea base se reportaron como archivos agregados (falso drift de upgrade).");
        True(seeded.Eventos.Any(e => e.Tipo == "TSPLUS_CONFIG_STABLE"
                && e.Evidencia?.Any(x => x.Clave == "Incorporados al seguimiento" && x.Valor.Contains("web.config", StringComparison.Ordinal)) == true),
            "El seguimiento de artefactos incorporados no quedó declarado en la evidencia.");

        File.WriteAllText(webConfig, "<configuration><system.webServer></system.webServer></configuration>");
        var modified = await collector.CollectAsync(ctx);
        True(modified.Hallazgos.Any(f => f.Id == "TSPLUS-CONFIG-DRIFT"
                && f.Evidencia.Any(x => x.Clave == "Archivos modificados" && x.Valor.Contains("web.config", StringComparison.Ordinal))),
            "La modificación de web.config no quedó rastreada como drift de configuración.");
    }
    finally
    {
        Environment.SetEnvironmentVariable("TDM_STATE_ROOT", prior);
        TryDelete(stateRoot);
        TryDelete(install);
    }
}

static async Task ExportRendersTensionesSection()
{
    var dir = TempDir();
    var cleanDir = TempDir();
    try
    {
        var now = DateTimeOffset.Now;
        var tension = "Hallazgo de severidad alta sin causa causal que lo explique en la ventana visible.";
        var withTension = Report([], now) with { Tensiones = [tension] };
        var result = await ReportExporter.ExportAsync(withTension, dir, CancellationToken.None);
        var html = await File.ReadAllTextAsync(result.HtmlPath);
        True(html.Contains("<h2>Tensiones de coherencia</h2>", StringComparison.Ordinal),
            "El HTML dejó de renderizar la sección de tensiones de coherencia.");
        True(html.Contains(tension, StringComparison.Ordinal),
            "El texto de la tensión no llegó al HTML exportado.");

        var clean = await ReportExporter.ExportAsync(Report([], now), cleanDir, CancellationToken.None);
        var cleanHtml = await File.ReadAllTextAsync(clean.HtmlPath);
        False(cleanHtml.Contains("Tensiones de coherencia", StringComparison.Ordinal),
            "Un reporte sin tensiones mostró la sección vacía.");
    }
    finally { TryDelete(dir); TryDelete(cleanDir); }
}

static async Task ExportExecutiveCardsAndCountsAreCoherent()
{
    var dir = TempDir();
    try
    {
        var now = DateTimeOffset.Now;
        var coverage = new DiagnosticCoverageAssessment(55, "BAJA",
            [
                new CoverageSourceAssessment("SRC-CRIT-PARTIAL", "Parcial", "detalle", true),
                new CoverageSourceAssessment("SRC-CRIT-BLOCKED", "No disponible", "detalle", true),
                new CoverageSourceAssessment("SRC-LOW-OK", "Disponible", "detalle", false)
            ], [], "resumen");
        var precision = new DiagnosticPrecisionAssessment(60, "LIMITADA", false, 2, 4, 9, 0, false, false, "resumen", []);
        var report = Report([], now) with
        {
            CoberturaDiagnostica = coverage,
            PrecisionDiagnostica = precision,
            ImpactoFuncional = new FunctionalImpactAssessment(FunctionalImpactState.SinImpactoObservado, "Sin impacto funcional confirmado.", [])
        };
        var result = await ReportExporter.ExportAsync(report, dir, CancellationToken.None);
        var html = await File.ReadAllTextAsync(result.HtmlPath);
        True(html.Contains("<div class='quick-label'>ESTADO</div><div class='quick-value state-muted'>NO EVALUADO</div>", StringComparison.Ordinal),
            "Con cobertura crítica incompleta y sin causa, el estado ejecutivo no quedó en NO EVALUADO.");
        False(html.Contains("<div class='quick-label'>IMPACTO</div><div class='quick-value state-ok'>SALUDABLE</div>", StringComparison.Ordinal),
            "La tarjeta IMPACTO contradice ESTADO: declara SALUDABLE con cobertura crítica incompleta.");
        True(html.Contains("Incompleta &#183; 1 fuente(s) bloqueada(s) &#183; 2 sin cobertura completa", StringComparison.Ordinal),
            "El detalle técnico no separa bloqueos duros de fuentes críticas sin cobertura completa.");
        True(html.Contains("Fuentes: 3 | Críticas: 2 | Críticas bloqueadas: 1 | Parciales: 1", StringComparison.Ordinal),
            "Los conteos de la tarjeta de cobertura no coinciden con el bloqueo duro del detalle técnico.");
    }
    finally { TryDelete(dir); }
}

static Task NarrativeCountsTsplusFindingsAsInternalAnomalies()
{
    var now = DateTimeOffset.Now;
    var finding = new DiagnosticFinding("TSPLUS-CONFIG-DRIFT", "Configuración TSplus", DiagnosticSeverity.Advertencia,
        "Cambios detectados en archivos de configuración", "detalle de prueba", [], Capa: DiagnosticLayer.Tsplus);
    var narrative = DiagnosticNarrativeBuilder.Build(Report([], now, [finding]));
    False(narrative.Contains("Anomalías internas detectadas: 0", StringComparison.Ordinal),
        "La narrativa declaró 0 anomalías internas pese a hallazgos TSPLUS en el reporte.");
    True(narrative.Contains("Cambios detectados en archivos de configuración", StringComparison.Ordinal),
        "El hallazgo TSPLUS no aparece en la sección de anomalías internas de la narrativa.");
    return Task.CompletedTask;
}

static async Task SettingsLoadRepairsInvalidThresholdsPerGroup()
{
    var root = TempDir();
    try
    {
        var store = new SupportMonitoringSettingsStore(root);
        Directory.CreateDirectory(Path.GetDirectoryName(store.Path)!);
        File.WriteAllText(store.Path,
            "{\"thresholds\":{\"cpuWarning\":55,\"cpuCritical\":95,\"sessionWarning\":200,\"sessionCritical\":100,\"tdmHandlesWarning\":3500,\"tdmHandlesCritical\":4500},\"enableIncidentAntiNoise\":false,\"enableSynchronizedCursor\":true,\"enableMultiServer\":true}");
        var loaded = await store.LoadAsync();
        Equal(55d, loaded.Thresholds.CpuWarning, "Un umbral válido se revirtió a defaults junto con el grupo inválido.");
        Equal(80, loaded.Thresholds.SessionWarning, "El par de sesiones inválido no se reparó a defaults.");
        Equal(120, loaded.Thresholds.SessionCritical, "El par de sesiones inválido no se reparó a defaults.");
        Equal(3500, loaded.Thresholds.TdmHandlesWarning, "Un umbral de handles válido no se conservó.");
        False(loaded.EnableIncidentAntiNoise, "Un flag de configuración se perdió al sanear umbrales.");
        True(SupportThresholdsValidator.IsValid(loaded.Thresholds), "LoadAsync devolvió umbrales aún inválidos.");

        var healed = JsonSerializer.Deserialize<SupportMonitoringSettings>(
            await File.ReadAllTextAsync(store.Path),
            new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase });
        NotNull(healed, "El archivo reparado no volvió a leerse.");
        Equal(80, healed!.Thresholds.SessionWarning, "El archivo no se sanearon/selló tras la reparación en carga.");
        Equal(55d, healed.Thresholds.CpuWarning, "La reparación en carga perdió el valor personalizado en disco.");
    }
    finally { TryDelete(root); }
}

static async Task UnknownTsplusVersionStillReportsMissingSettingsJs()
{
    var install = TempDir();
    try
    {
        SeedMinimalInstall(install, out _, out _);
        File.Delete(Path.Combine(install, "Clients", "www", "software", "html5", "settings.js"));

        var collector = new TsplusInternalConfigurationCollector();
        var baseCtx = InstallContext(install);

        var unknownCtx = baseCtx with { Sistema = baseCtx.Sistema with { TsplusVersion = null } };
        var unknown = await collector.CollectAsync(unknownCtx);
        var silenced = unknown.Hallazgos.FirstOrDefault(f => f.Id == "TSPLUS-WEB-SETTINGSJS-MISSING");
        NotNull(silenced, "Con versión TSplus desconocida la ausencia de settings.js quedó silenciada (H10).");
        Equal(DiagnosticSeverity.Advertencia, silenced!.Severidad,
            "Sin perfil de versión soportado la ausencia debe reportarse como Advertencia, no silenciarse.");
        True(silenced.Evidencia.Any(x => x.Clave == "Perfil de versión"),
            "El hallazgo no declara el perfil de versión que condiciona su severidad.");

        var supportedCtx = baseCtx with { Sistema = baseCtx.Sistema with { TsplusVersion = "19.30" } };
        var supported = await collector.CollectAsync(supportedCtx);
        var supportedMissing = supported.Hallazgos.FirstOrDefault(f => f.Id == "TSPLUS-WEB-SETTINGSJS-MISSING");
        NotNull(supportedMissing, "Con versión soportada dejó de reportarse la ausencia de settings.js.");
        Equal(DiagnosticSeverity.Error, supportedMissing!.Severidad,
            "Con perfil soportado la ausencia de settings.js debe seguir siendo Error.");

        File.WriteAllText(Path.Combine(install, "Clients", "www", "software", "html5", "settings.js"), "// settings");
        var present = await collector.CollectAsync(unknownCtx);
        False(present.Hallazgos.Any(f => f.Id == "TSPLUS-WEB-SETTINGSJS-MISSING"),
            "settings.js presente se reportó como ausente.");
    }
    finally { TryDelete(install); }
}

static Task UnifiedServiceRequiredNowPolicyMatchesSeverity()
{
    True(WindowsServiceCatalog.RequiredNow(true, true, false, false, false),
        "El servicio requerido por catálogo con TSplus detectado dejó de estar requerido ahora.");
    False(WindowsServiceCatalog.RequiredNow(true, false, false, false, false),
        "Sin TSplus detectado un servicio de catálogo se declaró requerido ahora.");
    True(WindowsServiceCatalog.RequiredNow(false, true, true, false, true),
        "Un servicio TSplus relacionado Automático no complementario dejó de estar requerido ahora.");
    False(WindowsServiceCatalog.RequiredNow(false, true, true, false, false),
        "Un servicio TSplus relacionado Manual se declaró requerido ahora.");
    False(WindowsServiceCatalog.RequiredNow(false, true, true, true, true),
        "Un servicio TSplus complementario se declaró requerido ahora.");
    Equal(DiagnosticSeverity.Critico, WindowsServiceCatalog.StoppedSeverity(true, true),
        "Requerido por catálogo y requerido ahora dejó de ser Crítico.");
    Equal(DiagnosticSeverity.Advertencia, WindowsServiceCatalog.StoppedSeverity(false, true),
        "Sin requisito de catálogo el estado detenido escaló más allá de Advertencia.");
    Equal(DiagnosticSeverity.Advertencia, WindowsServiceCatalog.StoppedSeverity(true, false),
        "Requerido por catálogo pero no requerido ahora escaló a Crítico.");

    var root = FindRepoRoot();
    NotNull(root, "No se localizó TDM.sln; gate de requiredNow no ejecutable.");
    var collector = File.ReadAllText(Path.Combine(root!, "src", "TDM.Collectors.Windows", "WindowsServiceCollector.cs"));
    True(collector.Contains("WindowsServiceCatalog.RequiredNow(", StringComparison.Ordinal),
        "El collector de servicios no usa la regla compartida RequiredNow.");
    True(collector.Contains("WindowsServiceCatalog.StoppedSeverity(", StringComparison.Ordinal),
        "El collector de servicios no usa la regla compartida de severidad detenida.");
    var graph = File.ReadAllText(Path.Combine(root!, "src", "TDM.Collectors.Windows", "ServiceDependencyGraphCollector.cs"));
    True(graph.Contains("WindowsServiceCatalog.RequiredNow(", StringComparison.Ordinal),
        "El grafo de dependencias no comparte la regla RequiredNow con el collector de servicios.");
    True(graph.Contains("WindowsServiceCatalog.StoppedSeverity(", StringComparison.Ordinal),
        "El grafo de dependencias no comparte la regla de severidad detenida.");
    True(graph.Contains("ShouldWarnWhenStopped(state.Value, depStartMode, depRequiredNow)", StringComparison.Ordinal),
        "La dependencia a profundidad no aplica el modo de inicio ni el requerido ahora de la dependencia.");
    return Task.CompletedTask;
}

static Task StateTransitionDedupKeepsDistinctEpisodes()
{
    var now = DateTimeOffset.Now;
    static DiagnosticEvent Transition(DateTimeOffset at, string component, string from, string to)
        => new(at, "TDM Monitor Journal", component, DiagnosticLayer.Windows, DiagnosticSeverity.Informativo,
            "TDM_MONITOR_STATE_TRANSITION", $"Cambio de estado observado por TDM: {from} → {to}",
            Evidencia: [new EvidenceItem("Estado anterior", from), new EvidenceItem("Estado actual", to)]);

    var stopped = Transition(now, "Web Portal Service", "Running", "Stopped");
    var report = Report([stopped], now.AddMinutes(20));
    var snapshot = new PersistentStateSnapshot(1, "test", now, "TEST", "Windows", "11", "22631", "x64", true, null, []);
    var duplicate = new StateTransition(now.AddSeconds(60), "svc", "SERVICE_STATE", "Web Portal Service",
        "Tsplus", "RemoteAccess", "Running", "Stopped", "Informativo", "Advertencia");
    var result = new RecordResult(snapshot, [duplicate], [], "root", "history", "transitions", "latest", null);

    var deduped = StateReportIntegrator.AddTransitionsFromRecordResult(report, result, "monitor");
    Equal(1, deduped.Eventos.Count(e => e.Tipo == "TDM_MONITOR_STATE_TRANSITION"),
        "El mismo cambio físico a 60 s se duplicó sin una transición opuesta intermedia.");

    var recovered = Transition(now.AddSeconds(20), "Web Portal Service", "Stopped", "Running");
    var episodic = Report([stopped, recovered], now.AddMinutes(20));
    var kept = StateReportIntegrator.AddTransitionsFromRecordResult(episodic, result, "monitor");
    Equal(3, kept.Eventos.Count(e => e.Tipo == "TDM_MONITOR_STATE_TRANSITION"),
        "Una inversión intermedia marcó un episodio nuevo y el tercer cambio físico se colapsó igual.");
    return Task.CompletedTask;
}

static Task IncidentClustersClipToAnalyzedWindow()
{
    var now = DateTimeOffset.Now;
    static DiagnosticEvent Service(DateTimeOffset at) => new(at, "SCM", "Web Portal Service", DiagnosticLayer.Tsplus,
        DiagnosticSeverity.Critico, "SERVICE_STATE", "Estado actual: Stopped",
        Evidencia: [new EvidenceItem("Servicio", "WebPortalService"), new EvidenceItem("Estado", "Stopped")],
        Producto: TsplusProduct.RemoteAccess);

    var staleOnly = IncidentClusterAnalyzer.Analyze(Report([Service(now.AddDays(-2))], now));
    Equal(0, staleOnly.Count, "Un estado fuera del periodo analizado formó un incidente agrupado.");

    var fresh = Service(now.AddMinutes(-3));
    var mixed = IncidentClusterAnalyzer.Analyze(Report([Service(now.AddDays(-2)), fresh], now));
    Equal(1, mixed.Count, "La señal dentro del periodo no formó su incidente.");
    Equal(fresh.Timestamp!.Value, mixed[0].Inicio,
        "El clúster conservó la señal fechada antes del periodo analizado.");
    Equal(fresh.Timestamp!.Value, mixed[0].Fin,
        "El clúster arrastró evidencia fuera de la ventana a su ventana temporal.");
    return Task.CompletedTask;
}

static Task StaleRemoteSymptomDoesNotConfirmCandidates()
{
    var now = DateTimeOffset.Now;
    var policy = new DiagnosticFinding("WINDOWS-RDP-DISABLED-POLICY", "Windows Remote Desktop", DiagnosticSeverity.Advertencia,
        "RDP deshabilitado por directiva.", "fDenyTSConnections activo impide nuevas conexiones.",
        [new EvidenceItem("fDenyTSConnections", "1")], ConfidenceLevel.Alta, Capa: DiagnosticLayer.Windows);

    static DiagnosticEvent Symptom(DateTimeOffset at)
        => new(at, "TermService", "Remote Desktop Services", DiagnosticLayer.Rdp, DiagnosticSeverity.Error,
            "RDP_SESSION_FAILURE", "La sesión RDP falló.");

    var stale = RootCauseCorrelator.Analyze(Report([Symptom(now.AddDays(-3))], now, [policy]))
        .FirstOrDefault(x => x.Id == "ROOT-WINDOWS-RDP-DISABLED-POLICY");
    NotNull(stale, "El candidato de política RDP desapareció con síntoma fuera de la ventana.");
    Equal(ConfidenceLevel.Media, stale!.Confianza,
        "Un síntoma anterior al periodo analizado confirmó el candidato RDP.");
    Equal(84, stale.Puntaje, "Un síntoma fuera de la ventana elevó el puntaje del candidato RDP.");

    var fresh = RootCauseCorrelator.Analyze(Report([Symptom(now.AddMinutes(-4))], now, [policy]))
        .FirstOrDefault(x => x.Id == "ROOT-WINDOWS-RDP-DISABLED-POLICY");
    NotNull(fresh, "El candidato de política RDP desapareció con síntoma dentro de la ventana.");
    Equal(ConfidenceLevel.Alta, fresh!.Confianza,
        "El síntoma dentro de la ventana dejó de confirmar el candidato RDP.");
    Equal(96, fresh.Puntaje, "El síntoma en ventana dejó de elevar el puntaje del candidato RDP.");
    return Task.CompletedTask;
}

static Task AnalysisWindowClipIsWiredAcrossRcaFeeds()
{
    var root = FindRepoRoot();
    NotNull(root, "No se localizó TDM.sln; gate de recorte a PeriodoAnalizado no ejecutable.");
    var correlator = File.ReadAllText(Path.Combine(root!, "src", "TDM.Correlation", "RootCauseCorrelator.cs"));
    True(correlator.Split("DiagnosticTimeWindow.IsEventInside").Length - 1 >= 2,
        "Los síntomas RCA (feeds de correlación y estados directos) no se recortan al periodo analizado.");
    var farm = File.ReadAllText(Path.Combine(root!, "src", "TDM.Correlation", "RootCauseCorrelator.Rules.WindowsFarm.cs"));
    True(farm.Contains("DiagnosticTimeWindow.IsEventInside", StringComparison.Ordinal),
        "El síntoma de sesión remota no se recorta al periodo analizado.");
    var clusters = File.ReadAllText(Path.Combine(root!, "src", "TDM.Correlation", "IncidentClusterAnalyzer.cs"));
    True(clusters.Contains("DiagnosticTimeWindow.IsEventInside", StringComparison.Ordinal),
        "El agrupador de incidentes no recorta las señales al periodo analizado.");
    var window = File.ReadAllText(Path.Combine(root!, "src", "TDM.Core", "DiagnosticTimeWindow.cs"));
    True(window.Contains("public static bool IsEventInside(DiagnosticReport report, DateTimeOffset timestamp)", StringComparison.Ordinal),
        "No existe la regla única de recorte de eventos al periodo analizado.");
    return Task.CompletedTask;
}

static async Task ExportDependencyRowsShowOriginServiceAndWarnOnNotEvaluated()
{
    var dir = TempDir();
    try
    {
        var now = DateTimeOffset.Now;
        var health = new DiagnosticEvent(now, "TSplus", "Remote Access", DiagnosticLayer.Tsplus,
            DiagnosticSeverity.Advertencia, "TSPLUS_DEPENDENCY_HEALTH", "Salud de dependencias TSplus",
            Evidencia: [new EvidenceItem("Web Portal", "No evaluado")]);
        var depthOne = new DiagnosticEvent(now, "Service Control Manager", "TermService → WebPortalService",
            DiagnosticLayer.Windows, DiagnosticSeverity.Advertencia, "SERVICE_DEPENDENCY_STATE",
            "Dependencia SCM nivel 1: WebPortalService = Stopped.",
            Evidencia:
            [
                new EvidenceItem("Servicio origen", "TermService"),
                new EvidenceItem("Estado servicio", "Running"),
                new EvidenceItem("Dependencia", "WebPortalService"),
                new EvidenceItem("Profundidad", "1"),
                new EvidenceItem("Estado", "Stopped")
            ], Producto: TsplusProduct.RemoteAccess);

        var result = await ReportExporter.ExportAsync(Report([health, depthOne], now), dir, CancellationToken.None);
        var html = await File.ReadAllTextAsync(result.HtmlPath);
        True(html.Contains("<td>TermService</td><td>depende de</td><td>WebPortalService</td>", StringComparison.Ordinal),
            "La fila de dependencia a profundidad mostró N/D en lugar del servicio origen.");
        False(html.Contains("<td>N/D</td><td>depende de</td>", StringComparison.Ordinal),
            "El export mantuvo N/D en la columna Servicio de una relación real.");
        True(html.Contains("<div class='dep warn'><strong>Web Portal</strong>", StringComparison.Ordinal),
            "Un 'No evaluado' del mapa de dependencias se pintó como warn.");
        False(html.Contains("<div class='dep ok'><strong>Web Portal</strong>", StringComparison.Ordinal),
            "Un 'No evaluado' del mapa de dependencias quedó en verde.");
    }
    finally { TryDelete(dir); }
}

static async Task ExportFooterReportsHiddenDependencyRows()
{
    var dir = TempDir();
    var quietDir = TempDir();
    try
    {
        var now = DateTimeOffset.Now;
        var many = new List<DiagnosticEvent>();
        for (var i = 0; i < 125; i++)
            many.Add(new DiagnosticEvent(now, "Service Control Manager", $"svc{i} → dep{i}",
                DiagnosticLayer.Windows, DiagnosticSeverity.Informativo, "SERVICE_DEPENDENCY_STATE",
                $"svc{i} depende de dep{i}; estado observado: Running.",
                Evidencia:
                [
                    new EvidenceItem("Servicio", $"svc{i}"),
                    new EvidenceItem("Dependencia", $"dep{i}"),
                    new EvidenceItem("Estado dependencia", "Running")
                ], Producto: TsplusProduct.RemoteAccess));
        var result = await ReportExporter.ExportAsync(Report(many, now), dir, CancellationToken.None);
        var html = await File.ReadAllTextAsync(result.HtmlPath);
        True(html.Contains("hasta 120 dependencias y 60 dependientes; 5 relación(es) adicional(es) no visibles", StringComparison.Ordinal),
            "Con 125 filas relevantes el pie no informó las 5 ocultas realmente no mostradas.");

        var quiet = new List<DiagnosticEvent>();
        for (var i = 0; i < 200; i++)
            quiet.Add(new DiagnosticEvent(now, "Service Control Manager", $"otro{i}",
                DiagnosticLayer.Windows, DiagnosticSeverity.Informativo, "SERVICE_DEPENDENCY_STATE",
                $"otro{i} declara una relación interna.",
                Evidencia:
                [
                    new EvidenceItem("Servicio", $"interno-{i}"),
                    new EvidenceItem("Dependencia", "interna-x"),
                    new EvidenceItem("Estado dependencia", "Running")
                ]));
        var quietResult = await ReportExporter.ExportAsync(Report(quiet, now), quietDir, CancellationToken.None);
        var quietHtml = await File.ReadAllTextAsync(quietResult.HtmlPath);
        False(quietHtml.Contains("hasta 120 dependencias y 60 dependientes", StringComparison.Ordinal),
            "Con 200 filas irrelevantes (0 mostradas) el pie afirmó que había relaciones ocultas.");
    }
    finally { TryDelete(dir); TryDelete(quietDir); }
}

static Task ScmDriftBaselineSkipsFailedReads()
{
    var root = FindRepoRoot();
    NotNull(root, "No se localizó TDM.sln; gate de baseline SCM no ejecutable.");
    var text = File.ReadAllText(Path.Combine(root!, "src", "TDM.Collectors.Windows", "ServiceDependencyDriftCollector.cs"));
    True(text.Contains("if (!dependencyRead.Available || !dependentRead.Available) readsFailed = true;", StringComparison.Ordinal),
        "La deriva SCM no marca las lecturas fallidas de dependencias/dependientes.");
    True(text.Contains("SCM_GRAPH_BASELINE_STALE", StringComparison.Ordinal),
        "La deriva SCM no declara cuándo la línea base quedó sin actualizar por lectura fallida.");
    True(text.IndexOf("if (readsFailed)", StringComparison.Ordinal) <
          text.IndexOf("CollectorCursorStore.TrySave(BaselineKey", StringComparison.Ordinal),
        "La línea base del grafo SCM se guarda sin pasar por la guarda de lectura fallida.");
    return Task.CompletedTask;
}

static Task TsplusSpanishLogLinesClassify()
{
    var context = Context(TimeSpan.FromHours(1));
    var denied = TsplusLogParser.ParseLine("Remote Access", "x.log",
        "No se pudo iniciar la aplicación: acceso denegado", 1, context);
    NotNull(denied, "Una línea de error en español no generó evento.");
    Equal(DiagnosticSeverity.Error, denied!.Severidad, "La línea de error en español no se clasificó como Error.");
    Equal("ACCESS_DENIED", denied.Tipo, "La denegación en español no se clasificó como ACCESS_DENIED.");

    var warning = TsplusLogParser.ParseLine("Remote Access", "x.log",
        "ADVERTENCIA: tiempo agotado al conectar con el portal", 1, context);
    NotNull(warning, "Una advertencia en español no generó evento.");
    Equal(DiagnosticSeverity.Advertencia, warning!.Severidad, "El prefijo ADVERTENCIA no se interpretó como Advertencia.");

    var critical = TsplusLogParser.ParseLine("Remote Access", "x.log",
        "CRÍTICO: fallo del servicio de publicación", 1, context);
    NotNull(critical, "Una línea crítica en español no generó evento.");
    Equal(DiagnosticSeverity.Critico, critical!.Severidad, "El prefijo CRÍTICO no se interpretó como Crítico.");

    var healthy = TsplusLogParser.ParseLine("Remote Access", "x.log",
        "Sin errores en la última hora", 1, context);
    True(healthy is null, "Un resumen sano en español se clasificó como falla.");
    return Task.CompletedTask;
}

static async Task CorruptSnapshotIsTelemetered()
{
    var root = TempDir();
    try
    {
        var store = new LocalStateStore(root);
        await store.SaveBaselineAsync(StateSnapshotBuilder.Build(
            Report([], DateTimeOffset.Now), "1.0.0"), replace: true);
        File.WriteAllText(store.BaselinePath, "{\"schemaVersion\": ");
        var before = LocalStateStore.CorruptSnapshotReadCount;
        var loaded = await store.LoadBaselineAsync();
        True(loaded is null, "Un snapshot de línea base corrupto no devolvió null.");
        True(LocalStateStore.CorruptSnapshotReadCount > before,
            "La lectura de snapshot corrupto no se telemetrizó con el contador.");
        True(store.BaselinePath == LocalStateStore.LastCorruptSnapshotPath,
            "El telemetro de snapshot corrupto no conserva la ruta leída.");
        var status = await store.GetStatusAsync();
        True(status.CorruptSnapshotReads > before,
            "El estado local no expone la lectura de snapshot corrupto.");
    }
    finally { TryDelete(root); }
}

static Task ConfigurationHistoryDiffWorksAcrossGenerations()
{
    var stateRoot = TempDir();
    var prior = Environment.GetEnvironmentVariable("TDM_STATE_ROOT");
    try
    {
        Environment.SetEnvironmentVariable("TDM_STATE_ROOT", stateRoot);
        var store = ConfigurationHistoryStore.Instance;
        var genA = new ConfigBaselineState(
            new Dictionary<string, string> { ["a.ini"] = "hash-a" },
            DateTimeOffset.UtcNow.AddDays(-2),
            new Dictionary<string, Dictionary<string, List<string>>>
            {
                ["a.ini"] = new() { ["appsettings"] = ["Port=443"] }
            });
        var genB = new ConfigBaselineState(
            new Dictionary<string, string> { ["a.ini"] = "hash-a", ["b.ini"] = "hash-b" },
            DateTimeOffset.UtcNow.AddDays(-1),
            new Dictionary<string, Dictionary<string, List<string>>>
            {
                ["a.ini"] = new() { ["appsettings"] = ["Port=443"] },
                ["b.ini"] = new() { ["appsettings"] = ["Mode=web"] }
            });
        var genC = new ConfigBaselineState(
            new Dictionary<string, string> { ["a.ini"] = "hash-a2", ["b.ini"] = "hash-b" },
            DateTimeOffset.UtcNow,
            new Dictionary<string, Dictionary<string, List<string>>>
            {
                ["a.ini"] = new() { ["appsettings"] = ["Port=8443"] },
                ["b.ini"] = new() { ["appsettings"] = ["Mode=web"] }
            });
        store.SaveAsync(genA);
        store.SaveAsync(genB);
        store.SaveAsync(genC);

        var latest = store.GetLatestAsync();
        NotNull(latest, "La última generación no se persistió.");
        Equal(genC.SavedAt, latest!.SavedAt, "La línea base latest no corresponde a la última generación guardada.");
        var previous = store.GetGenerationAsync(1);
        NotNull(previous, "La generación anterior no se recuperó del historial.");
        Equal(genB.SavedAt, previous!.SavedAt, "La generación anterior no es la inmediatamente previa a la última.");
        var twoBack = store.GetGenerationAsync(2);
        NotNull(twoBack, "La segunda generación anterior no se recuperó del historial.");
        Equal(genA.SavedAt, twoBack!.SavedAt, "La segunda generación anterior no corresponde a la primera generación guardada.");

        var diff = store.DiffAgainstGenerationAsync(genC, 1);
        True(diff.Count > 0, "El diff contra la generación anterior quedó vacío pese a cambios reales.");
        var summary = store.GetMultiGenDiffSummaryAsync(genC, 5);
        True(summary.Contains("Gen -1", StringComparison.Ordinal),
            "El resumen multi-generación no detalla la generación inmediatamente previa.");
        True(summary.Contains("Gen -2", StringComparison.Ordinal),
            "El resumen multi-generación no detalla la segunda generación previa.");

        store.SaveAsync(new ConfigBaselineState(
            new Dictionary<string, string> { ["z.ini"] = "hash-z" }, DateTimeOffset.UtcNow.AddDays(-45)));
        True(store.GetHistoryAsync().All(x => x.SavedAt >= DateTimeOffset.UtcNow.AddDays(-30)),
            "Una generación fuera de la retención de 30 días sobrevivió al podado.");
        return Task.CompletedTask;
    }
    finally
    {
        Environment.SetEnvironmentVariable("TDM_STATE_ROOT", prior);
        TryDelete(stateRoot);
    }
}

static async Task DiagnosticAvaloniaTransitionsReadAcrossChannels()
{
    var root = TempDir();
    try
    {
        var now = DateTimeOffset.Now;
        var store = new LocalStateStore(root);
        await store.RecordAsync(StateSnapshotBuilder.Build(
            Report([ServiceStateEvent(now, "Running")], now), "1.0.0"), "diagnostic-avalonia");
        var second = await store.RecordAsync(StateSnapshotBuilder.Build(
            Report([ServiceStateEvent(now.AddSeconds(5), "Stopped")], now.AddSeconds(5)), "1.0.0"), "diagnostic-avalonia");
        Equal(1, second.Transitions.Count, "precondición: el canal diagnostic-avalonia debe producir la transición Running→Stopped.");

        var report = await StateReportIntegrator.AddRecentMonitorTransitionsAsync(
            Report([], now.AddSeconds(5)), now.AddSeconds(-1), now.AddSeconds(10), rootPath: root);
        var readBack = report.Eventos.Count(e => e.Tipo == "TDM_MONITOR_STATE_TRANSITION"
            && e.Componente.Equals("Spooler", StringComparison.OrdinalIgnoreCase));
        Equal(1, readBack, "La lectura cruzada ignoró las transiciones pre-grabadas por la GUI en diagnostic-avalonia.");
    }
    finally { TryDelete(root); }
}

static async Task ExportRendersServiceStateAndProcessSections()
{
    var dir = TempDir();
    var quietDir = TempDir();
    try
    {
        var now = DateTimeOffset.Now;
        var crash = new DiagnosticEvent(now.AddMinutes(-5), "Windows Error Reporting", "sql.exe",
            DiagnosticLayer.Windows, DiagnosticSeverity.Error, "APPLICATION_CRASH",
            "La aplicación sql.exe terminó inesperadamente.");
        var result = await ReportExporter.ExportAsync(
            Report([ServiceStateEvent(now, "Stopped"), crash], now), dir, CancellationToken.None);
        var html = await File.ReadAllTextAsync(result.HtmlPath);
        True(html.Contains("Estado de servicios Windows/TSplus", StringComparison.Ordinal),
            "El HTML no incluye la sección de estado de servicios.");
        True(html.Contains("<td>Spooler</td>", StringComparison.Ordinal),
            "La sección de estado de servicios no muestra el servicio observado.");
        True(html.Contains("Procesos afectados", StringComparison.Ordinal),
            "El HTML no incluye la sección de procesos afectados.");
        True(html.Contains("<td>sql.exe</td>", StringComparison.Ordinal),
            "La sección de procesos afectados no muestra el proceso caído.");

        var quiet = await ReportExporter.ExportAsync(Report([], now), quietDir, CancellationToken.None);
        var quietHtml = await File.ReadAllTextAsync(quiet.HtmlPath);
        False(quietHtml.Contains("Estado de servicios Windows/TSplus", StringComparison.Ordinal),
            "Un informe sin eventos de servicio aun así renderizó la sección de servicios.");
        False(quietHtml.Contains("Procesos afectados", StringComparison.Ordinal),
            "Un informe sin caídas aun así renderizó la sección de procesos afectados.");
    }
    finally { TryDelete(dir); TryDelete(quietDir); }
}

static DiagnosticEvent ServiceStateEvent(DateTimeOffset at, string state)
    => new(at, "Service Control Manager", "Spooler", DiagnosticLayer.Windows,
        state == "Stopped" ? DiagnosticSeverity.Error : DiagnosticSeverity.Informativo,
        "SERVICE_STATE", $"Servicio Spooler {state}",
        Evidencia: [new EvidenceItem("Servicio", "Spooler"), new EvidenceItem("Estado", state)]);

static DiagnosticEvent LongitudinalConfigEvent(DateTimeOffset at, string coverage, string estado)
    => new(at, "TSplus Filesystem", "Web / HTML5", DiagnosticLayer.Tsplus, DiagnosticSeverity.Informativo,
        "TSPLUS_LONGITUDINAL_CONFIG_STATE", "Estado longitudinal de configuración TSplus: web.config.",
        Archivo: @"C:\\TSplus\\Clients\\webserver\\web.config",
        Evidencia:
        [
            new EvidenceItem("Archivo", @"C:\\TSplus\\Clients\\webserver\\web.config"),
            new EvidenceItem("Cobertura", coverage),
            new EvidenceItem("Estado", estado)
        ]);

static DiagnosticContext InstallContext(string install)
    => new(new SystemSnapshot("TEST", "Windows Server", "2025", "test", "x64", TimeSpan.FromHours(1),
        DateTimeOffset.Now, true, install, "19"), TimeSpan.FromHours(4));

static void SeedMinimalInstall(string install, out string iniPath, out string original)
{
    var iniDir = Path.Combine(install, "UserDesktop", "files");
    Directory.CreateDirectory(iniDir);
    iniPath = Path.Combine(iniDir, "AppControl.ini");
    original = "[appsettings]" + Environment.NewLine + "Port=443";
    File.WriteAllText(iniPath, original);
    var webDir = Path.Combine(install, "Clients", "www", "software", "html5");
    Directory.CreateDirectory(webDir);
    File.WriteAllText(Path.Combine(webDir, "settings.js"), "// settings");
    var wsDir = Path.Combine(install, "Clients", "webserver");
    Directory.CreateDirectory(wsDir);
    File.WriteAllText(Path.Combine(wsDir, "runwebserver.bat"), "@echo off");
}

// Fase 13 (P5): §6+§7 — B#14-20, B#23.
static Task NlaPasswordChangeNeedsWindowedConflict()
{
    var now = DateTimeOffset.Now;
    var nla2019 = new DiagnosticFinding(
        "WINDOWS-2019-NLA-PASSWORD-CHANGE-COMPATIBILITY",
        "Windows NLA / contraseña",
        DiagnosticSeverity.Advertencia,
        "Windows Server 2019 exige contraseña vigente con NLA habilitado.",
        "El cambio de contraseña obligatorio rompe la autenticación previa a la sesión.",
        [new EvidenceItem("Sistema", "Windows Server 2019")],
        ConfidenceLevel.Alta,
        Capa: DiagnosticLayer.Windows);
    string Evidence(RootCauseCandidate c, string key) => c.Evidencia.FirstOrDefault(e => e.Clave == key)?.Valor ?? "N/D";

    var quiet = RootCauseCorrelator.Analyze(Report([], now, [nla2019]));
    var quietNla = quiet.FirstOrDefault(x => x.Id == "ROOT-WINDOWS-NLA-PASSWORD-CHANGE");
    NotNull(quietNla, "La hipótesis NLA desapareció sin conflicto en ventana.");
    Equal(84, quietNla!.Puntaje, "NLA se elevó a 98 sin conflicto dentro de la ventana.");
    Equal(ConfidenceLevel.Media, quietNla.Confianza, "NLA se declaró Alta sin conflicto en ventana.");
    True(quietNla.HoraIncidente is null, "Sin conflicto en ventana NLA recibió hora de incidente.");
    Equal("No observado", Evidence(quietNla, "Conflicto NLA en la ventana"),
        "El gating de ventana NLA no quedó declarado en la evidencia.");

    var stale = new DiagnosticEvent(now.AddHours(-5), "Windows Security / RDP", "NLA / contraseña",
        DiagnosticLayer.Windows, DiagnosticSeverity.Error, "WINDOWS_NLA_PASSWORD_CHANGE_CONFLICT", "contraseña expirada");
    var staleRun = RootCauseCorrelator.Analyze(Report([stale], now, [nla2019]));
    var staleNla = staleRun.FirstOrDefault(x => x.Id == "ROOT-WINDOWS-NLA-PASSWORD-CHANGE");
    NotNull(staleNla, "La hipótesis NLA desapareció con conflicto fuera de la ventana.");
    Equal(84, staleNla!.Puntaje, "Un conflicto NLA fuera de la ventana analizada elevó el puntaje a 98.");

    var fresh = new DiagnosticEvent(now.AddMinutes(-10), "Windows Security / RDP", "NLA / contraseña",
        DiagnosticLayer.Windows, DiagnosticSeverity.Error, "WINDOWS_NLA_PASSWORD_CHANGE_CONFLICT", "contraseña expirada");
    var freshRun = RootCauseCorrelator.Analyze(Report([fresh], now, [nla2019]));
    var freshNla = freshRun.FirstOrDefault(x => x.Id == "ROOT-WINDOWS-NLA-PASSWORD-CHANGE");
    NotNull(freshNla, "El candidato NLA desapareció con conflicto en ventana.");
    Equal(98, freshNla!.Puntaje, "El conflicto NLA dentro de la ventana no elevó el puntaje a 98.");
    Equal(ConfidenceLevel.Alta, freshNla.Confianza, "El conflicto NLA dentro de la ventana no elevó la confianza a Alta.");
    True(freshNla.HoraIncidente == fresh.Timestamp, "El conflicto NLA dentro de la ventana no ancló la hora del incidente.");
    Equal("WINDOWS_NLA_PASSWORD_CHANGE_CONFLICT", Evidence(freshNla, "Conflicto NLA en la ventana"),
        "El evento NLA anclado no quedó declarado en la evidencia.");
    return Task.CompletedTask;
}

static Task UncorrelatedConfigCandidatesDoNotConflict()
{
    var now = DateTimeOffset.Now;
    string Evidence(RootCauseCandidate c, string key) => c.Evidencia.FirstOrDefault(e => e.Clave == key)?.Valor ?? "N/D";
    var windows = new RootCauseCandidate(1, "WIN-CFG", "Política RDP", DiagnosticLayer.Windows, 84, ConfidenceLevel.Media,
        "Política RDP estática", "hipótesis de configuración sin ventana", [], Producto: TsplusProduct.RemoteAccess,
        HoraIncidente: null, OrigenClasificado: "WINDOWS");
    var tsplus = new RootCauseCandidate(2, "TS-CFG", "Granja TSplus", DiagnosticLayer.Tsplus, 79, ConfidenceLevel.Media,
        "Granja estática", "hipótesis de configuración sin ventana", [], Producto: TsplusProduct.RemoteAccess,
        HoraIncidente: null, OrigenClasificado: "TSPLUS");

    var calm = DiagnosticPrecisionAnalyzer.Calibrate(Report([], now), [windows, tsplus]);
    Equal(84, calm[0].Puntaje, "Dos configuraciones estáticas sin HoraIncidente fueron penalizadas como conflicto de origen.");
    Equal(79, calm[1].Puntaje, "El segundo candidato estático perdió puntos por conflicto de origen.");
    False(Evidence(calm[0], "Calibración de precisión RC18.14.3").Contains("orígenes distintos", StringComparison.Ordinal),
        "La calibración aplicó penalización de conflicto a candidatos sin correlación temporal.");
    Equal("No", Evidence(calm[0], "Conflicto entre orígenes fuertes"),
        "Dos hipótesis sin hora de incidente se declararon en conflicto de origen.");

    var correlatedWindows = windows with { Puntaje = 90, HoraIncidente = now.AddMinutes(-2) };
    var correlatedTsplus = tsplus with { Puntaje = 88, HoraIncidente = now.AddMinutes(-1) };
    var tense = DiagnosticPrecisionAnalyzer.Calibrate(Report([], now), [correlatedWindows, correlatedTsplus]);
    Equal(82, tense[0].Puntaje, "El conflicto correlacionado no aplicó la penalización de 8 puntos al primer candidato.");
    Equal(80, tense[1].Puntaje, "El conflicto correlacionado no aplicó la penalización de 8 puntos al segundo candidato.");
    Equal("Sí", Evidence(tense[0], "Conflicto entre orígenes fuertes"),
        "Dos candidatos fuertes correlacionados de orígenes distintos no marcaron conflicto.");
    True(Evidence(tense[0], "Calibración de precisión RC18.14.3").Contains("orígenes distintos", StringComparison.Ordinal),
        "La penalización de conflicto no quedó explicada en la evidencia del candidato.");
    return Task.CompletedTask;
}

static Task RdpSuccessStagesAreNotOperationalIncidents()
{
    var now = DateTimeOffset.Now;
    var logon = new DiagnosticEvent(now, "Lsm", "Terminal Services", DiagnosticLayer.Rdp,
        DiagnosticSeverity.Informativo, "RDP_SESSION_LOGON_STAGE", "Logon succeeded");
    var auth = new DiagnosticEvent(now, "RDP", "RemoteConnectionManager", DiagnosticLayer.Rdp,
        DiagnosticSeverity.Advertencia, "RDP_AUTHENTICATION_STAGE", "authentication ok");
    var shell = new DiagnosticEvent(now, "Lsm", "Terminal Services", DiagnosticLayer.Rdp,
        DiagnosticSeverity.Informativo, "RDP_SHELL_START_STAGE", "shell started");
    False(DiagnosticPrecisionAnalyzer.IsCausalSignal(logon), "Un logon RDP exitoso contó como señal causal.");
    False(DiagnosticPrecisionAnalyzer.IsCausalSignal(auth), "Una autenticación RDP exitosa contó como señal causal.");
    False(DiagnosticPrecisionAnalyzer.IsCausalSignal(shell), "Un shell start exitoso contó como señal causal.");
    var gap = new DiagnosticEvent(now, "Lsm", "Terminal Services", DiagnosticLayer.Rdp,
        DiagnosticSeverity.Advertencia, "RDP_SHELL_START_GAP", "gap en el pipeline de shell");
    True(DiagnosticPrecisionAnalyzer.IsCausalSignal(gap), "RDP_SHELL_START_GAP dejó de contar como señal causal.");

    var stageClusters = IncidentClusterAnalyzer.Analyze(Report([logon, auth], now));
    Equal(1, stageClusters.Count, "Los stages RDP no formaron un solo clúster de evidencia.");
    Equal("EVIDENCIA_CORRELACIONABLE", stageClusters[0].Estado,
        "Un clúster sólo con stages de éxito se declaró INCIDENTE_OPERATIVO.");

    DiagnosticEvent Service(DiagnosticSeverity severidad) => new(now.AddMinutes(-1), "TDM", "Web Portal Service",
        DiagnosticLayer.Tsplus, severidad, "SERVICE_STATE", "Estado actual: Stopped",
        Evidencia: [new EvidenceItem("Servicio", "WebPortalService"), new EvidenceItem("Estado", "Stopped")],
        Producto: TsplusProduct.RemoteAccess);

    var warnClusters = IncidentClusterAnalyzer.Analyze(Report([Service(DiagnosticSeverity.Advertencia)], now));
    Equal(1, warnClusters.Count, "El SERVICE_STATE Advertencia no formó clúster.");
    Equal("EVIDENCIA_CORRELACIONABLE", warnClusters[0].Estado,
        "Un SERVICE_STATE Advertencia se declaró INCIDENTE_OPERATIVO fuera del contrato Error/Crítico.");

    var criticalClusters = IncidentClusterAnalyzer.Analyze(Report([Service(DiagnosticSeverity.Critico)], now));
    Equal(1, criticalClusters.Count, "El SERVICE_STATE Crítico no formó clúster.");
    Equal("INCIDENTE_OPERATIVO", criticalClusters[0].Estado,
        "Un servicio TSplus detenido Crítico dejó de declararse incidente operativo.");
    return Task.CompletedTask;
}

static Task PrincipalWithoutIndependentEvidenceRaisesTension()
{
    var now = DateTimeOffset.Now;
    var principal = new RootCauseCandidate(1, "ROOT-WINDOWS-RDP-DISABLED-POLICY", "Windows / política RDP",
        DiagnosticLayer.Windows, 96, ConfidenceLevel.Alta, "RDP deshabilitado por directiva.",
        "fDenyTSConnections activo impide nuevas conexiones.",
        [new EvidenceItem("Evidencia primaria independiente", "No")],
        Producto: TsplusProduct.RemoteAccess, HoraIncidente: now.AddMinutes(-2), OrigenClasificado: "WINDOWS");

    var report = Report([], now) with { CausaRaizPrincipal = principal };
    var tensions = ReportConsistencyAnalyzer.Analyze(report);
    True(tensions.Any(t => t.Contains("[PRINCIPAL]", StringComparison.Ordinal)
                        && t.Contains("evidencia primaria independiente", StringComparison.OrdinalIgnoreCase)),
        "La causa principal sin evidencia primaria independiente no generó tensión de coherencia.");

    var supported = principal with { Evidencia = [new EvidenceItem("Evidencia primaria independiente", "Sí")] };
    var clean = ReportConsistencyAnalyzer.Analyze(Report([], now) with { CausaRaizPrincipal = supported });
    False(clean.Any(t => t.Contains("[PRINCIPAL]", StringComparison.Ordinal)),
        "Una causa principal con evidencia independiente generó tensión espuria.");
    return Task.CompletedTask;
}

static Task FailurePatternsUseFullCandidateList()
{
    var now = DateTimeOffset.Now;
    var events = new List<DiagnosticEvent>();
    for (var i = 1; i <= 10; i++)
    {
        events.Add(new DiagnosticEvent(
            now.AddMinutes(-i * 3),
            "Application Error",
            $"app{i:D2}.exe",
            DiagnosticLayer.Tsplus,
            DiagnosticSeverity.Error,
            "APPLICATION_CRASH",
            $"Faulting application app{i:D2}.exe",
            Codigo: "1000",
            Evidencia: [
                new EvidenceItem("Aplicación", $"app{i:D2}.exe"),
                new EvidenceItem("Ruta del módulo", $@"C:\Program Files (x86)\TSplus\mod{i}.dll")
            ],
            Producto: TsplusProduct.RemoteAccess));
    }

    var report = DiagnosticWorkflow.Analyze(Report(events, now));
    Equal(8, report.CausasRaiz.Count, "El recorte de presentación dejó de limitar las causas visibles a 8.");
    Equal(10, report.PatronesFalla.Count,
        "Los patrones de falla se calcularon sobre el recorte de 8 candidatos en vez de la lista completa.");
    True(report.PatronesFalla.Any(p => p.Componente == "app01.exe"),
        "Un candidato de crash fuera del top 8 no alimentó los patrones de falla.");
    return Task.CompletedTask;
}

static Task RemoteLogonFailuresCoverEachCorrelatedUser()
{
    var now = DateTimeOffset.Now;
    DiagnosticEvent Failure(DateTimeOffset ts, string user) => new(ts, "Security",
        "Microsoft-Windows-Security-Auditing", DiagnosticLayer.Seguridad, DiagnosticSeverity.Error,
        "USER_LOGON_FAILURE", "4625",
        Evidencia: [new EvidenceItem("Usuario", user), new EvidenceItem("Status", "0xC000006D")]);
    DiagnosticEvent Symptom(DateTimeOffset ts, string user) => new(ts, "TermService",
        "Remote Desktop Services", DiagnosticLayer.Rdp, DiagnosticSeverity.Error,
        "RDP_SESSION_FAILURE", "La sesión RDP falló.",
        Evidencia: [new EvidenceItem("Usuario", user)]);

    var t0 = now.AddMinutes(-40);
    var events = new List<DiagnosticEvent>
    {
        Failure(t0, "alice"),
        Symptom(t0.AddMinutes(1), "alice"),
        Failure(t0.AddMinutes(5), "alice"),
        Symptom(t0.AddMinutes(6), "alice"),
        Failure(t0.AddMinutes(10), "bob"),
        Symptom(t0.AddMinutes(11), "bob"),
        Failure(t0.AddMinutes(15), "carol"),
        Symptom(t0.AddMinutes(16), "carol"),
        Failure(t0.AddMinutes(20), "dave")
    };

    var candidates = RootCauseCorrelator.Analyze(Report(events, now));
    var alice = TdmPseudonym.Create("USR", "alice");
    var bob = TdmPseudonym.Create("USR", "bob");
    var carol = TdmPseudonym.Create("USR", "carol");
    var dave = TdmPseudonym.Create("USR", "dave");
    True(candidates.Any(c => c.Id == $"ROOT-WINDOWS-REMOTE-LOGON-{alice}"),
        "El primer usuario correlacionado no generó candidato.");
    True(candidates.Any(c => c.Id == $"ROOT-WINDOWS-REMOTE-LOGON-{bob}"),
        "El segundo usuario correlacionado no generó candidato (el ciclo se detuvo en el primero).");
    True(candidates.Any(c => c.Id == $"ROOT-WINDOWS-REMOTE-LOGON-{carol}"),
        "El tercer usuario correlacionado no generó candidato (el ciclo se detuvo en el primero).");
    False(candidates.Any(c => c.Id == $"ROOT-WINDOWS-REMOTE-LOGON-{dave}"),
        "Un failure sin síntoma correlacionado generó candidato de ruido.");
    Equal(1, candidates.Count(c => c.Id == $"ROOT-WINDOWS-REMOTE-LOGON-{alice}"),
        "El mismo usuario generó candidatos duplicados.");
    False(candidates.Any(c => c.Id.Contains("alice", StringComparison.OrdinalIgnoreCase)),
        "El Id de causa conservó el usuario en claro (C7).");
    True(candidates.Any(c => c.Componente == $"Autenticación Windows / {alice}"),
        "El componente de causa no pseudonimizó el usuario (C7).");
    return Task.CompletedTask;
}

static async Task PeriodEndFallbackIsUnifiedAcrossNarrativeAndExport()
{
    var now = DateTimeOffset.Now;
    var withoutPeriod = Report([], now) with { PeriodoAnalizadoFin = default };
    Equal(now, DiagnosticReportWindow.EffectivePeriodEnd(withoutPeriod),
        "Sin PeriodoAnalizadoFin el cierre no cayó al fin de captura.");
    var declared = now.AddMinutes(-5);
    var withPeriod = Report([], now) with { PeriodoAnalizadoFin = declared };
    Equal(declared, DiagnosticReportWindow.EffectivePeriodEnd(withPeriod),
        "El PeriodoAnalizadoFin declarado no prevaleció sobre el fin de captura.");

    var narrative = DiagnosticNarrativeBuilder.Build(withoutPeriod);
    True(narrative.Contains($"Periodo visible: {withoutPeriod.PeriodoAnalizadoInicio.ToLocalTime():dd/MM/yyyy HH:mm:ss} - {withoutPeriod.Fin.ToLocalTime():dd/MM/yyyy HH:mm:ss}", StringComparison.Ordinal),
        "Sin PeriodoAnalizadoFin la narrativa no cerró la ventana con el fin de captura.");

    var dir = TempDir();
    try
    {
        var result = await ReportExporter.ExportAsync(withoutPeriod, dir, CancellationToken.None);
        var html = await File.ReadAllTextAsync(result.HtmlPath);
        True(html.Contains($"{withoutPeriod.PeriodoAnalizadoInicio.ToLocalTime():dd/MM/yyyy HH:mm}–{withoutPeriod.Fin.ToLocalTime():HH:mm}", StringComparison.Ordinal),
            "El periodo rápido del export no cerró con el fin de captura.");
    }
    finally { TryDelete(dir); }
}

// Fase 14 (P6): §1 C#7-8, C#9,11 · §2 CapturedAt + catch vacío · §3 C#12.
static Task ServiceDiscoveryFallbackDeclaresCoverage()
{
    var root = FindRepoRoot();
    NotNull(root, "No se localizó TDM.sln; gate del descubrimiento de servicios no ejecutable.");
    var collector = File.ReadAllText(Path.Combine(root!, "src", "TDM.Collectors.Windows", "WindowsServiceCollector.cs"));
    True(collector.Contains("SVC-DISCOVERY-COVERAGE", StringComparison.Ordinal),
        "El fallback al catálogo fijo no emite el hallazgo de cobertura SVC-DISCOVERY-COVERAGE.");
    True(collector.Contains("\"Cobertura\", \"No evaluado\"", StringComparison.Ordinal),
        "El fallback del descubrimiento no declara la fuente como No evaluado.");
    True(collector.Contains("CatalogFallback", StringComparison.Ordinal),
        "El descubrimiento no distingue el catálogo fijo del inventario dinámico.");
    return Task.CompletedTask;
}

static Task LogIntegrityBudgetIsPerChannelAndDeclared()
{
    var root = FindRepoRoot();
    NotNull(root, "No se localizó TDM.sln; gate de integridad de logs no ejecutable.");
    var collector = File.ReadAllText(Path.Combine(root!, "src", "TDM.Collectors.Windows", "WindowsLogIntegrityCollector.cs"));
    False(collector.Contains("findings.Count < MaxFindings", StringComparison.Ordinal),
        "El presupuesto de hallazgos de integridad sigue compartido entre canales.");
    True(collector.Contains("MaxFindingsPerChannel", StringComparison.Ordinal),
        "El presupuesto de hallazgos no es por canal.");
    True(collector.Contains("channelFindings >= MaxFindingsPerChannel", StringComparison.Ordinal),
        "El corte por presupuesto no se detecta dentro de la lectura del canal.");
    True(collector.Contains("Parcial; límite de", StringComparison.Ordinal),
        "El corte por presupuesto no se declara en la cobertura del canal.");
    return Task.CompletedTask;
}

static async Task RegistryBaselineInitializationIsDeclared()
{
    var stateRoot = TempDir();
    var install = TempDir();
    var prior = Environment.GetEnvironmentVariable("TDM_STATE_ROOT");
    try
    {
        Environment.SetEnvironmentVariable("TDM_STATE_ROOT", stateRoot);
        SeedMinimalInstall(install, out _, out _);

        var collector = new TsplusConfigurationDriftCollector();
        var ctx = InstallContext(install);
        var first = await collector.CollectAsync(ctx);
        True(first.Eventos.Any(e => e.Tipo == "TSPLUS_CONFIG_BASELINE_INITIALIZED"),
            "precondición: la primera ejecución debe inicializar la línea base.");
        True(CollectorCursorStore.TryLoad<ConfigBaselineState>("tsplus-config-baseline", out var baseline, out _) && baseline is not null,
            "precondición: la línea base no es reescribible en el state root aislado.");

        // Simula una línea base anterior a la Fase 14: existe pero sin campo Registry.
        ConfigurationHistoryStore.Instance.SaveAsync(baseline! with { Registry = null });

        var second = await collector.CollectAsync(ctx);
        True(second.Eventos.Any(e => e.Tipo == "TSPLUS_CONFIG_REGISTRY_BASELINE_INITIALIZED"),
            "El salto de la comparación de registro (baseline sin Registry) no se declaró.");
        False(second.Hallazgos.Any(f => f.Id == "TSPLUS-CONFIG-DRIFT-REGISTRY"),
            "Con baseline sin Registry no debe emitirse deriva de registro.");
        True(second.Eventos.Any(e => e.Tipo == "TSPLUS_CONFIG_STABLE"),
            "La corrida con baseline de registro ausente dejó de emitir el estado estable de archivos.");
    }
    finally
    {
        Environment.SetEnvironmentVariable("TDM_STATE_ROOT", prior);
        TryDelete(stateRoot);
        TryDelete(install);
    }
}

static Task ForensicMissingChannelIsNotPermanentPartial()
{
    var now = DateTimeOffset.Now;
    DiagnosticEvent Coverage(params EvidenceItem[] items) => new(now, "TDM", "Cobertura forense Windows",
        DiagnosticLayer.Windows, DiagnosticSeverity.Informativo, "WINDOWS_FORENSIC_COVERAGE",
        "Cobertura de registros Windows consultados por TDM.", Evidencia: items);

    var notApplicable = DiagnosticCoverageAnalyzer.Analyze(Report(
        [Coverage(new EvidenceItem("AppLocker EXE and DLL", "No existe en este SO"),
                  new EvidenceItem("Firewall de Windows", "Disponible; eventos relevantes=3"))], now));
    var source = notApplicable.Fuentes.Single(x => x.Fuente == "Windows Event Log forense");
    Equal("Disponible", source.Estado,
        "Un canal inexistente en este SKU hundió la fuente forense crítica a Parcial.");
    True(source.Detalle.Contains("no aplicables=1", StringComparison.Ordinal),
        "El desglose de cobertura no declara los canales no aplicables.");

    var legacyUnavailable = DiagnosticCoverageAnalyzer.Analyze(Report(
        [Coverage(new EvidenceItem("AppLocker EXE and DLL", "Canal no disponible"))], now));
    Equal("Parcial", legacyUnavailable.Fuentes.Single(x => x.Fuente == "Windows Event Log forense").Estado,
        "Un canal realmente no disponible dejó de marcar la fuente como Parcial.");

    var root = FindRepoRoot();
    NotNull(root, "No se localizó TDM.sln; gate del collector forense no ejecutable.");
    var collector = File.ReadAllText(Path.Combine(root!, "src", "TDM.Collectors.Windows", "WindowsForensicEventCollector.cs"));
    True(collector.Contains("\"No existe en este SO\"", StringComparison.Ordinal),
        "El collector forense no distingue el canal inexistente del no disponible.");
    return Task.CompletedTask;
}

static Task LogParserHonorsBracketedDeclaredLevel()
{
    var context = Context(TimeSpan.FromHours(1));
    var stamp = DateTimeOffset.Now.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);

    var declaredError = TsplusLogParser.ParseLine("Remote Access", "x.log", $"[{stamp}] [ERROR] cache warmed", 1, context);
    NotNull(declaredError, "[fecha] [ERROR] sin términos de error no pasó el atajo de nivel declarado.");
    Equal(DiagnosticSeverity.Error, declaredError!.Severidad, "El [ERROR] declarado no manda sobre el barrido de tokens.");

    var declaredDebug = TsplusLogParser.ParseLine("Remote Access", "x.log", $"[{stamp}] [DEBUG] timeout while loading", 2, context);
    True(declaredDebug is null, "[fecha] [DEBUG] con 'timeout' en el texto se clasificó por tokens en vez del nivel declarado.");

    var declaredWarn = TsplusLogParser.ParseLine("Remote Access", "x.log", $"[{stamp}] [WARN] application error detected", 3, context);
    NotNull(declaredWarn, "[fecha] [WARN] no pasó el atajo de nivel declarado.");
    Equal(DiagnosticSeverity.Advertencia, declaredWarn!.Severidad, "El [WARN] declarado perdió ante el token 'error'.");

    var declaredFatal = TsplusLogParser.ParseLine("Remote Access", "x.log", $"[{stamp}] [FATAL] routine stop", 4, context);
    NotNull(declaredFatal, "[fecha] [FATAL] no pasó el atajo de nivel declarado.");
    Equal(DiagnosticSeverity.Critico, declaredFatal!.Severidad, "El [FATAL] declarado no clasificó como Crítico.");

    var bare = TsplusLogParser.ParseLine("Remote Access", "x.log", "ERROR plain failure", 5, context);
    NotNull(bare, "El formato sin corchetes dejó de clasificarse.");
    Equal(DiagnosticSeverity.Error, bare!.Severidad, "ERROR sin corchetes cambió de severidad.");
    return Task.CompletedTask;
}

static Task UndatedLogEventsExpireWithTheWindow()
{
    var now = DateTimeOffset.Now;
    DiagnosticEvent Undated(string id, DateTimeOffset? ingested) => new(null, "TSplus Log", $"App {id}",
        DiagnosticLayer.Tsplus, DiagnosticSeverity.Error, "LOG_ERROR", $"fallo {id}", IngestedAt: ingested);
    var recentUndated = Undated("recent", now.AddHours(-1));
    var staleUndated = Undated("stale", now.AddHours(-8));
    var legacyUndated = Undated("legacy", null);
    var inWindow = new DiagnosticEvent(now.AddMinutes(-30), "Service Control Manager", "svcA", DiagnosticLayer.Windows,
        DiagnosticSeverity.Error, "SERVICE_START_FAILURE", "fallo", "7000");

    var baseline = Report([recentUndated, staleUndated, legacyUndated, inWindow], now.AddMinutes(-5));
    var merged = ContinuousDiagnosticMerger.Merge(baseline, Report([], now), TimeSpan.FromHours(4));

    True(merged.Eventos.Any(e => e.Componente == "App recent"),
        "La evidencia sin timestamp ingerida dentro de la ventana se perdió al fusionar.");
    False(merged.Eventos.Any(e => e.Componente == "App stale"),
        "La evidencia sin timestamp ingerida antes de la ventana sobrevivió a la fusión.");
    True(merged.Eventos.Any(e => e.Componente == "App legacy"),
        "Un evento sin IngestedAt no puede ubicarse y no debe descartarse.");
    True(merged.Eventos.Any(e => e.Tipo == "SERVICE_START_FAILURE"),
        "El evento fechado dentro de la ventana se perdió en la fusión.");
    return Task.CompletedTask;
}

static async Task TransitionCarriesObservationInterval()
{
    var root = TempDir();
    try
    {
        var now = DateTimeOffset.Now;
        var store = new LocalStateStore(root);
        var snapA = StateSnapshotBuilder.Build(Report([ServiceStateEvent(now, "Running")], now), "1.0.0");
        await store.RecordAsync(snapA, "service-monitor");
        var snapB = StateSnapshotBuilder.Build(Report([ServiceStateEvent(now.AddSeconds(5), "Stopped")], now.AddSeconds(5)), "1.0.0");
        var result = await store.RecordAsync(snapB, "service-monitor");
        Equal(1, result.Transitions.Count, "precondición: Running→Stopped debe producir una transición.");
        True(result.Transitions[0].ChangedAfter == snapA.CapturedAt,
            "La transición no conserva la foto anterior como cota inferior del cambio.");
        Equal(snapB.CapturedAt, result.Transitions[0].Timestamp,
            "La transición dejó de fecharse en la foto actual (cota superior).");

        var report = StateReportIntegrator.AddTransitionsFromRecordResult(
            Report([ServiceStateEvent(now.AddSeconds(5), "Stopped")], now.AddSeconds(5)), result, "service-monitor");
        var transition = report.Eventos.Single(e => e.Tipo == "TDM_MONITOR_STATE_TRANSITION");
        True(transition.Evidencia!.Any(x => x.Clave == "Cambio después de" && x.Valor == snapA.CapturedAt.ToString("O")),
            "El evento de transición no declara la cota inferior del intervalo de cambio.");
    }
    finally { TryDelete(root); }
}

static Task LongitudinalPrecedenceUsesIntervalLowerBound()
{
    var root = FindRepoRoot();
    NotNull(root, "No se localizó TDM.sln; gate de la regla longitudinal no ejecutable.");
    var rules = File.ReadAllText(Path.Combine(root!, "src", "TDM.Correlation", "RootCauseCorrelator.Rules.Longitudinal.cs"));
    True(rules.Contains("\"Cambio después de\"", StringComparison.Ordinal),
        "La regla longitudinal no lee la cota inferior del intervalo de cambio.");
    True(rules.Contains("earliestPossible", StringComparison.Ordinal),
        "La precedencia de la transición no usa la cota inferior del intervalo.");
    return Task.CompletedTask;
}

static async Task RecentTransitionReadFailureIsDeclared()
{
    var now = DateTimeOffset.Now;
    var report = Report([ServiceStateEvent(now, "Running")], now);
    var result = await StateReportIntegrator.AddRecentMonitorTransitionsAsync(
        report, now.AddHours(-1), now, CancellationToken.None, "\0");
    True(result.Eventos.Any(e => e.Tipo == "TDM_RECENT_TRANSITIONS_UNAVAILABLE"),
        "Un fallo al leer el journal reciente se tragó sin declararlo.");
    var unavailable = result.Eventos.Single(e => e.Tipo == "TDM_RECENT_TRANSITIONS_UNAVAILABLE");
    True(unavailable.Evidencia!.Any(x => x.Clave == "Cobertura historial reciente" && x.Valor == "No evaluado"),
        "El fallo de lectura del journal no dejó la cobertura declarada como No evaluado.");
    Equal(report.Eventos.Count + 1, result.Eventos.Count,
        "El reporte original no quedó intacto al declarar el fallo del journal.");
    True(result.Eventos.Any(e => e.Componente == "Spooler"),
        "Los eventos originales desaparecieron cuando el journal falló.");
}

// Fase 15 (P7): §11 huecos 1 y 4 (canales reales/fallos) · §8a guard de dependencias · §9a auto-ampliación.
static async Task WindowsEventCollectorPinsSecurityAuditIdsEndToEnd()
{
    True(WindowsEventCollector.IsRelevant("Microsoft-Windows-Security-Auditing", 4625, "Security"),
        "El 4625 dejó de ser relevante en el canal Security.");
    True(WindowsEventCollector.IsRelevant("Microsoft-Windows-Security-Auditing", 4740, "Security"),
        "El 4740 dejó de ser relevante en el canal Security.");
    True(WindowsEventCollector.IsRelevant("Microsoft-Windows-Security-Auditing", 4771, "Security"),
        "El 4771 dejó de ser relevante en el canal Security.");
    True(WindowsEventCollector.IsRelevant("Microsoft-Windows-Security-Auditing", 4776, "Security"),
        "El 4776 dejó de ser relevante en el canal Security.");
    False(WindowsEventCollector.IsRelevant("Some Provider", 4625, "System"),
        "Un 4625 fuera de Security no debe pasar por la cláusula de auditoría.");
    False(WindowsEventCollector.IsRelevant("Microsoft-Windows-Security-Auditing", 4624, "Security"),
        "El canal Security dejó de restringirse a los IDs de auditoría relevantes.");

    var result = await new WindowsEventCollector().CollectAsync(Context(TimeSpan.FromHours(1)));
    var coverage = result.Eventos.LastOrDefault(e => e.Tipo == "WINDOWS_EVENT_COVERAGE");
    NotNull(coverage, "El collector base no emitió WINDOWS_EVENT_COVERAGE.");
    var channels = coverage!.Evidencia!
        .Where(x => x.Clave is "System" or "Application" or "Security").ToList();
    Equal(3, channels.Count, "Faltan canales base en la cobertura de eventos de Windows.");
    var security = channels.Single(x => x.Clave == "Security");
    if (security.Valor.StartsWith("Sin permisos", StringComparison.Ordinal))
    {
        True(result.Hallazgos.Any(f => f.Id == "EVT-Security-ACCESS"),
            "Security sin permisos no emitió el hallazgo EVT-Security-ACCESS.");
        True(WindowsEventCollector.IsPartialCoverage([security]),
            "Security sin permisos no dejó la cobertura parcial.");
    }
    else
    {
        foreach (var ev in result.Eventos.Where(e => e.Evidencia?.Any(x => x.Clave == "Log" && x.Valor == "Security") == true))
            True(ev.Codigo is "4625" or "4740" or "4771" or "4776",
                $"El canal Security emitió un evento fuera del conjunto de auditoría: ID {ev.Codigo}.");
    }
}

static async Task ForensicCollectorEndToEndDeclaresEveryChannelState()
{
    var result = await new WindowsForensicEventCollector().CollectAsync(Context(TimeSpan.FromHours(1)));
    var coverage = result.Eventos.LastOrDefault(e => e.Tipo == "WINDOWS_FORENSIC_COVERAGE");
    NotNull(coverage, "El collector forense no emitió su cobertura.");
    string[] expectedAreas =
        ["Sistema", "Aplicación", "RDP/LocalSessionManager", "Firewall de Windows",
         "AppLocker EXE/DLL", "AppLocker MSI/Script", "Rendimiento de Windows"];
    foreach (var area in expectedAreas)
        True(coverage!.Evidencia!.Any(x => x.Clave == area),
            $"La cobertura forense dejó de declarar el canal {area}.");
    foreach (var item in coverage!.Evidencia!)
    {
        var known = item.Valor.StartsWith("Disponible", StringComparison.Ordinal)
            || item.Valor.StartsWith("Parcial", StringComparison.Ordinal)
            || item.Valor.StartsWith("Sin permisos", StringComparison.Ordinal)
            || item.Valor.StartsWith("No legible", StringComparison.Ordinal)
            || item.Valor == "No existe en este SO"
            || item.Valor.StartsWith("No evaluado", StringComparison.Ordinal)
            || item.Clave is "Ventana solicitada" or "Duración solicitada" or "Descubrimiento dinámico de canales";
        True(known, $"Estado de canal inesperado para {item.Clave}: {item.Valor}");
    }
}

static Task MergerPreservesRequestedLookbackAndDeclaresExpansion()
{
    var now = DateTimeOffset.Now;
    var baseline = Report([ServiceStateEvent(now.AddHours(-1), "Running")], now.AddHours(-1));

    var requestedSmall = Report([], now) with { LookbackSolicitado = TimeSpan.FromHours(1) };
    var expanded = ContinuousDiagnosticMerger.Merge(baseline, requestedSmall, TimeSpan.FromHours(4));
    Equal(TimeSpan.FromHours(1), expanded.LookbackSolicitado,
        "La fusión enmascaró el lookback solicitado con el máximo de la ventana.");
    True(expanded.VentanaAutoAmpliada,
        "Ampliar la ventana continua más allá de lo solicitado no se declaró.");
    NotNull(expanded.MotivoAmpliacion, "La ampliación de ventana no explicó su motivo.");

    var requestedFull = Report([], now);
    var same = ContinuousDiagnosticMerger.Merge(baseline, requestedFull, TimeSpan.FromHours(4));
    False(same.VentanaAutoAmpliada, "Con la ventana igual a lo solicitado se declaró ampliación.");
    True(same.MotivoAmpliacion is null, "Sin ampliación no debe haber motivo de ampliación.");
    Equal(TimeSpan.FromHours(4), same.LookbackSolicitado, "El lookback solicitado cambió sin ampliación.");
    return Task.CompletedTask;
}

static async Task DependencyNotEvaluatedGuardChecksDependentsToo()
{
    var dir = TempDir();
    var emptyDir = TempDir();
    try
    {
        var now = DateTimeOffset.Now;
        var dependentsOnly = Report([new DiagnosticEvent(now, "Service Control Manager", "TermService",
            DiagnosticLayer.Windows, DiagnosticSeverity.Informativo, "SERVICE_DEPENDENT_STATE", "dependiente",
            Evidencia:
            [
                new EvidenceItem("Dependiente", "Spooler"),
                new EvidenceItem("Servicio", "TermService"),
                new EvidenceItem("Estado dependente", "Running")
            ])], now);
        var withTable = await ReportExporter.ExportAsync(dependentsOnly, dir, CancellationToken.None);
        var html = await File.ReadAllTextAsync(withTable.HtmlPath);
        True(html.Contains("Relaciones reales del Service Control Manager", StringComparison.Ordinal),
            "precondición: la tabla de relaciones debía renderizarse con sólo dependientes.");
        False(html.Contains("No evaluado: no se obtuvo evidencia suficiente de dependencias", StringComparison.Ordinal),
            "'No evaluado' coexistió con la tabla de relaciones de dependientes.");

        var withoutEvidence = await ReportExporter.ExportAsync(Report([], now), emptyDir, CancellationToken.None);
        var htmlEmpty = await File.ReadAllTextAsync(withoutEvidence.HtmlPath);
        True(htmlEmpty.Contains("No evaluado: no se obtuvo evidencia suficiente de dependencias", StringComparison.Ordinal),
            "Sin evidencia de dependencias el mensaje 'No evaluado' dejó de emitirse.");
    }
    finally
    {
        TryDelete(dir);
        TryDelete(emptyDir);
    }
}

static async Task RecentTransitionReadSkipsFilesOutsideWindow()
{
    var now = DateTimeOffset.Now;
    var today = now.LocalDateTime.Date;
    var names = new List<string>();
    for (var i = 0; i < 30; i++) names.Add($"transitions-{today.AddDays(-i):yyyy-MM-dd}.jsonl");
    names.Add("transitions-diagnostic-notadate.jsonl");
    names.Add("notes.txt");

    var selected = LocalStateStore.SelectRecentTransitionFiles(names, now.AddHours(-2), now);
    True(selected.Contains($"transitions-{today:yyyy-MM-dd}.jsonl"),
        "El archivo de hoy quedó fuera de la selección.");
    True(selected.Contains($"transitions-{today.AddDays(-1):yyyy-MM-dd}.jsonl"),
        "El archivo de ayer (holgura de 1 día) debía conservarse.");
    False(selected.Contains($"transitions-{today.AddDays(-2):yyyy-MM-dd}.jsonl"),
        "Un archivo de hace 2 días no debe abrirse para una ventana de 2 horas.");
    False(selected.Contains($"transitions-{today.AddDays(-29):yyyy-MM-dd}.jsonl"),
        "La retención completa (30 días) volvió a leerse para una ventana corta.");
    True(selected.Any(x => x.Contains("notadate", StringComparison.Ordinal)),
        "Un nombre de archivo no reconocido debe conservarse por seguridad.");
    True(selected.Any(x => x.Contains("notes", StringComparison.Ordinal)),
        "Un archivo sin fecha en el nombre debe conservarse por seguridad.");
    Equal(4, selected.Count, "La selección esperaba hoy + ayer + dos no reconocidos.");

    var root = TempDir();
    try
    {
        var store = new LocalStateStore(root);
        await store.RecordAsync(StateSnapshotBuilder.Build(
            Report([ServiceStateEvent(now, "Running")], now), "1.0.0"), "service-monitor");
        var resultB = await store.RecordAsync(StateSnapshotBuilder.Build(
            Report([ServiceStateEvent(now.AddSeconds(5), "Stopped")], now.AddSeconds(5)), "1.0.0"), "service-monitor");
        Equal(1, resultB.Transitions.Count, "precondición: Running→Stopped debe producir una transición.");

        var historyDir = Path.Combine(root, "history");
        var originals = Directory.GetFiles(historyDir, "transitions-service-monitor-*.jsonl");
        Equal(1, originals.Length, "precondición: el registro debió dejar un solo archivo de transiciones.");
        File.Copy(originals[0], Path.Combine(historyDir,
            $"transitions-service-monitor-{today.AddDays(-5):yyyy-MM-dd}.jsonl"));

        var rows = await store.ReadRecentTransitionsAsync(now.AddMinutes(-5), now.AddSeconds(30), "service-monitor");
        Equal(1, rows.Count,
            "El duplicado en un archivo con fecha de hace 5 días no debía leerse: la ventana corta ya no barre 30 días.");
    }
    finally { TryDelete(root); }
}

static async Task LocalHistoryUnavailableIsDeclaredInCoverage()
{
    var now = DateTimeOffset.Now;
    DiagnosticEvent Unavailable(string detail) => new(now, "TDM", "Historial local TDM",
        DiagnosticLayer.Desconocida, DiagnosticSeverity.Advertencia, "TDM_LOCAL_HISTORY_UNAVAILABLE",
        "No fue posible actualizar el historial local propio de TDM. El diagnóstico de Windows/TSplus continúa siendo válido con la evidencia recopilada.",
        Evidencia: [new EvidenceItem("Detalle", detail)]);
    DiagnosticEvent Status(string detail) => new(now, "TDM", "Historial local TDM",
        DiagnosticLayer.Desconocida, DiagnosticSeverity.Informativo, "TDM_LOCAL_HISTORY_STATUS",
        "Historial local actualizado",
        Evidencia: [new EvidenceItem("Almacén", "history"), new EvidenceItem("Detalle", detail)]);

    var unavailableReport = Report([Unavailable("Acceso denegado al historial")], now);
    var failed = DiagnosticCoverageAnalyzer.Analyze(unavailableReport);
    var source = failed.Fuentes.Single(x => x.Fuente == "Historial local TDM");
    Equal("No disponible", source.Estado,
        "El fallo del historial local no se declaró como fuente No disponible.");
    True(source.Detalle.Contains("Acceso denegado al historial", StringComparison.Ordinal),
        "El detalle del fallo no llegó a la fuente de cobertura.");
    True(failed.Limitaciones.Any(l => l.Contains("historial local TDM", StringComparison.OrdinalIgnoreCase)),
        "El fallo del historial local no dejó limitación declarada.");
    False(source.Critica, "El historial local propio no debe bloquear el score como fuente crítica.");

    var mixed = DiagnosticCoverageAnalyzer.Analyze(Report(
        [Status("actualizado"), Unavailable("fallo posterior")], now));
    Equal("No disponible",
        mixed.Fuentes.Single(x => x.Fuente == "Historial local TDM").Estado,
        "Un UNAVAILABLE posterior al STATUS debe prevalecer como estado final de la fuente.");

    var ok = DiagnosticCoverageAnalyzer.Analyze(Report([Status("actualizado")], now));
    Equal("Disponible", ok.Fuentes.Single(x => x.Fuente == "Historial local TDM").Estado,
        "El STATUS normal dejó de declarar la fuente Disponible.");

    var none = DiagnosticCoverageAnalyzer.Analyze(Report([], now));
    Equal("Parcial", none.Fuentes.Single(x => x.Fuente == "Historial local TDM").Estado,
        "Sin eventos de historial la fuente dejó de ser Parcial.");

    var dir = TempDir();
    try
    {
        var result = await ReportExporter.ExportAsync(unavailableReport, dir, CancellationToken.None);
        var html = await File.ReadAllTextAsync(result.HtmlPath);
        True(html.Contains("Historial local TDM", StringComparison.Ordinal),
            "El HTML dejó de mostrar la fila de historial local TDM.");
        True(html.Contains("No disponible — Acceso denegado al historial", StringComparison.Ordinal),
            "El HTML no declaró el fallo del historial local con su detalle.");
    }
    finally { TryDelete(dir); }
}

static Task DashboardDeclaresDependencyDataFreshness()
{
    var now = DateTimeOffset.Now;
    var stale = new ObservabilitySample
    {
        Timestamp = now.AddMinutes(-10),
        SampleKind = "diagnostic",
        ServiceStates = new Dictionary<string, string>
        {
            ["TermService"] = "Running",
            ["RemoteSupportUnattended-Service"] = "Running",
            ["TSplusGateway"] = "Running",
            ["gpsvc"] = "Stopped"
        },
        DependencyStates = new Dictionary<string, string>
        {
            ["gpsvc  ProfSvc"] = "Running"
        },
        ModuleHealth = new Dictionary<string, string>
        {
            ["RDP / Remote Access Core"] = "Saludable"
        }
    };
    var light = new ObservabilitySample
    {
        Timestamp = now,
        SampleKind = "monitor",
        ServiceStates = new Dictionary<string, string>
        {
            ["TermService"] = "Running",
            ["RemoteSupportUnattended-Service"] = "Running",
            ["TSplusGateway"] = "Running",
            ["gpsvc"] = "Stopped"
        }
    };

    var support = new SupportDashboardViewModel();
    support.Apply(new[] { stale, light });
    True(support.ServiceExtra.Contains("dependencias hace 10 min", StringComparison.Ordinal),
        $"Soporte no declaró la antigüedad de dependencias: '{support.ServiceExtra}'");
    True(support.ServiceExtra.Contains("salud hace 10 min", StringComparison.Ordinal),
        $"Soporte no declaró la antigüedad de salud: '{support.ServiceExtra}'");

    var preventive = new PreventiveDashboardViewModel();
    preventive.Apply(new[] { stale, light });
    True(preventive.DependencyDetail.Contains("datos hace 10 min", StringComparison.Ordinal),
        $"Preventivo no declaró la antigüedad de dependencias: '{preventive.DependencyDetail}'");
    True(preventive.ModuleDetail.Contains("datos hace 10 min", StringComparison.Ordinal),
        $"Preventivo no declaró la antigüedad de salud: '{preventive.ModuleDetail}'");

    var freshSupport = new SupportDashboardViewModel();
    freshSupport.Apply(new[] { stale });
    False(freshSupport.ServiceExtra.Contains("hace", StringComparison.Ordinal),
        $"Con datos del mismo instante no debe haber aviso de antigüedad: '{freshSupport.ServiceExtra}'");

    var freshPreventive = new PreventiveDashboardViewModel();
    freshPreventive.Apply(new[] { stale });
    False(freshPreventive.DependencyDetail.Contains("hace", StringComparison.Ordinal),
        $"Con datos del mismo instante no debe haber aviso en dependencias: '{freshPreventive.DependencyDetail}'");
    False(freshPreventive.ModuleDetail.Contains("hace", StringComparison.Ordinal),
        $"Con datos del mismo instante no debe haber aviso en salud: '{freshPreventive.ModuleDetail}'");
    return Task.CompletedTask;
}

static Task SafeWmiAppliesBoundedOptionsInBothBranches()
{
    // C1 (auditoría crítica FIX93): las opciones acotadas deben aplicarse en AMBAS ramas
    // (con y sin scope); antes la rama sin alcance las descartaba y perdía el timeout.
    using var withoutScope = SafeWmi.CreateSearcher("SELECT Name FROM Win32_OperatingSystem", null, null);
    Equal(TimeSpan.FromSeconds(15), withoutScope.Options.Timeout,
        "La rama sin scope no aplicó el timeout por defecto de 15 s.");
    True(withoutScope.Options.ReturnImmediately,
        "La rama sin scope no aplicó ReturnImmediately (operación semisíncrona acotada).");

    using var withScope = SafeWmi.CreateSearcher(
        "SELECT Name FROM Win32_OperatingSystem", @"\\.\root\cimv2", TimeSpan.FromSeconds(3));
    Equal(TimeSpan.FromSeconds(3), withScope.Options.Timeout,
        "La rama con scope no aplicó el timeout explícito.");
    True(withScope.Options.ReturnImmediately,
        "La rama con scope dejó ReturnImmediately en falso: la operación quedaría sin acotar.");

    Equal(TimeSpan.FromSeconds(15), SafeWmi.CreateOptions(null).Timeout,
        "CreateOptions(null) dejó de declarar el timeout por defecto de 15 s.");
    return Task.CompletedTask;
}

static Task SingleFlightCaptureReusesPendingFlightUntilAbandonAge()
{
    var flights = new SingleFlightCapture<int>();
    var calls = 0;
    using var gate = new ManualResetEventSlim(false);
    var startedAt = new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero);
    var abandonAge = TimeSpan.FromMinutes(2);

    int Factory()
    {
        var n = Interlocked.Increment(ref calls);
        gate.Wait();
        return n;
    }

    var first = flights.Start(Factory, abandonAge, startedAt);
    var reused = flights.Start(Factory, abandonAge, startedAt.AddMinutes(1));
    True(ReferenceEquals(first, reused),
        "Un vuelo pendiente y joven se duplicó en lugar de reutilizarse.");

    SpinUntil(() => Volatile.Read(ref calls) >= 1);
    Equal(1, Volatile.Read(ref calls), "La fábrica se invocó más de una vez para el mismo vuelo.");

    var replaced = flights.Start(Factory, abandonAge, startedAt.AddMinutes(2));
    True(!ReferenceEquals(first, replaced),
        "Un vuelo que superó la edad de abandono no fue reemplazado.");
    SpinUntil(() => Volatile.Read(ref calls) >= 2);
    Equal(2, Volatile.Read(ref calls), "El reemplazo no emitió una captura fresca.");
    True(ReferenceEquals(replaced, flights.InFlight),
        "El vuelo reemplazado no quedó registrado como activo.");

    gate.Set();
    True(first.Result == 1, "El vuelo original perdió su resultado.");
    True(replaced.Result == 2, "El vuelo reemplazado perdió su resultado.");
    True(ReferenceEquals(replaced, flights.TryTakeCompleted()),
        "El vuelo terminado no se cosechó.");
    True(flights.TryTakeCompleted() is null,
        "Tras cosechar no debe quedar ningún vuelo activo.");
    return Task.CompletedTask;

    static void SpinUntil(Func<bool> condition)
    {
        var deadline = Environment.TickCount64 + 10_000;
        while (!condition() && Environment.TickCount64 < deadline)
            Thread.Sleep(5);
    }
}

static async Task SingleFlightCaptureTakesCompletedAndRestartsAfterFault()
{
    var flights = new SingleFlightCapture<int>();
    var abandonAge = TimeSpan.FromMinutes(2);
    var now = DateTimeOffset.Now;

    var faulted = flights.Start(() => throw new InvalidOperationException("captura fallida"), abandonAge, now);
    var sawFault = false;
    try
    {
        await faulted;
    }
    catch (InvalidOperationException)
    {
        sawFault = true;
    }
    True(sawFault, "El vuelo fallido no propagó su excepción.");

    var taken = flights.TryTakeCompleted();
    NotNull(taken, "El vuelo terminado no se cosechó tras el fallo.");
    True(taken!.IsFaulted, "El vuelo cosechado dejó de estar en estado de fallo.");

    var fresh = flights.Start(() => 42, abandonAge, now);
    True(ReferenceEquals(fresh, flights.InFlight), "Tras el fallo no se emitió un vuelo fresco.");
    Equal(42, await fresh, "El vuelo fresco no produjo el resultado esperado.");
    True(ReferenceEquals(fresh, flights.TryTakeCompleted()), "El vuelo fresco no se cosechó.");
    True(flights.TryTakeCompleted() is null, "Tras cosechar no debe quedar ningún vuelo activo.");
}

static async Task IncidentLedgerGateSurvivesInterprocessLockFailure()
{
    var root = TempDir();
    try
    {
        Directory.CreateDirectory(Path.Combine(root, "incidents"));
        var ledger = new IncidentLedger(root);
        var lockPath = ledger.Path + ".lock";

        using (new FileStream(lockPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None))
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(150));
            var failed = false;
            try
            {
                await ledger.AddNoteAsync("TDM-2026-0001", "nota de prueba", cts.Token);
            }
            catch (Exception ex) when (ex is OperationCanceledException or IOException)
            {
                failed = true;
            }
            True(failed, "La adquisición del lock interproceso no falló con el fichero bloqueado.");
        }

        // Sin C4 la cancelación anterior saltaba el finally y ProcessGate quedaba tomado
        // para siempre: este AddNoteAsync colgaría y WaitAsync lanzaría TimeoutException.
        await ledger.AddNoteAsync("TDM-2026-0002", "segunda nota")
            .WaitAsync(TimeSpan.FromSeconds(5));
    }
    finally { TryDelete(root); }
}

static async Task HistoricalReadFailurePreservesRetentionHistory()
{
    var root = TempDir();
    try
    {
        var store = new HistoricalTelemetryStore(root);
        var json = new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
        var now = DateTimeOffset.Now;
        var hourStart = new DateTimeOffset(now.Year, now.Month, now.Day, now.Hour, 0, 0, now.Offset);
        const int seedCount = 5;
        for (var i = 1; i <= seedCount; i++)
        {
            var hour = new HistoricalTelemetryStore.HourlyTelemetry(
                hourStart.AddHours(-i),
                new Dictionary<string, HistoricalTelemetryStore.MetricStats>());
            await File.AppendAllTextAsync(store.HistoryPath, JsonSerializer.Serialize(hour, json) + "\n");
        }

        var seeded = await store.ReadAsync();
        Equal(seedCount, seeded.Count, "El seed del histórico no superó la lectura de validación.");

        // FileAccess.Read + share {Write, Delete}: la lectura del store se deniega (IO)
        // pero un movimiento/append sobre el fichero seguiría permitido. Sin la guarda
        // C5, el cleanup con History=[] reescribiría el fichero a 0 líneas.
        using (new FileStream(store.HistoryPath, FileMode.Open, FileAccess.Read, FileShare.Write | FileShare.Delete))
        {
            var snapshot = new PersistentStateSnapshot(1, "test", now, "TEST", "Windows", "11", "22631", "x64", true, null, []);
            await store.UpdateAndAnalyzeAsync(snapshot).WaitAsync(TimeSpan.FromSeconds(15));
        }

        var after = await store.ReadAsync();
        Equal(seedCount, after.Count,
            "La sesión con lectura fallida reescribió el histórico de 90 días (cleanup destructivo).");
    }
    finally { TryDelete(root); }
}

static async Task ResourceWindowReadFailureSkipsCompaction()
{
    var root = TempDir();
    try
    {
        var stateDir = Path.Combine(root, "state");
        Directory.CreateDirectory(stateDir);
        var windowPath = Path.Combine(stateDir, "resource-window.jsonl");
        var now = DateTimeOffset.Now;
        var json = new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
        var line = JsonSerializer.Serialize(
            new { timestamp = now.AddMinutes(-5), cpuPct = 10d, memoryFreePct = 80d }, json);

        var targetBytes = 4L * 1024 * 1024 + 128 * 1024;
        var lineBytes = System.Text.Encoding.UTF8.GetByteCount(line) + 2;
        var lineCount = (int)(targetBytes / lineBytes) + 1;
        using (var writer = new StreamWriter(windowPath, append: false))
        {
            for (var i = 0; i < lineCount; i++) writer.WriteLine(line);
        }
        var seededBytes = new FileInfo(windowPath).Length;
        True(seededBytes >= 4L * 1024 * 1024, $"El seed no alcanzó 4 MB ({seededBytes} bytes).");

        var observation = new PersistentObservation(
            "system-resource",
            DiagnosticEventTypes.SystemResourceState,
            "Recursos",
            "Windows",
            "Ninguno",
            "Informativo",
            "Metric.Cpu.Percent=10 | Metric.Memory.FreePercent=80",
            false,
            false);
        var snapshot = new PersistentStateSnapshot(1, "test", now, "TEST", "Windows", "11", "22631", "x64", true, null, [observation]);

        // Mismo truco de share que el test anterior: lectura denegada, movimiento permitido.
        // Sin H2, ShouldCompact reescribiría la ventana (state.Samples=[] por el fallo de
        // lectura) y el fichero caería de ~4 MB a unas pocas líneas.
        using (new FileStream(windowPath, FileMode.Open, FileAccess.Read, FileShare.Write | FileShare.Delete))
        {
            await ResourceTrendAnalyzer.UpdateAndAnalyzeAsync(snapshot, root)
                .WaitAsync(TimeSpan.FromSeconds(15));
        }

        var finalBytes = new FileInfo(windowPath).Length;
        True(finalBytes >= seededBytes,
            $"La compactación reescribió la ventana con lectura fallida: {seededBytes} -> {finalBytes} bytes.");
    }
    finally { TryDelete(root); }
}

static async Task LatestReportSaveKeepsPreviousOnFailedWrite()
{
    var root = TempDir();
    try
    {
        var store = new LocalStateStore(root);
        var now = DateTimeOffset.Now;
        static DiagnosticEvent Event(DateTimeOffset at, string text)
            => new(at, "TDM", "Test", DiagnosticLayer.Windows, DiagnosticSeverity.Informativo, "TEST_EVENT", text);

        await store.SaveLatestReportAsync(Report([Event(now, "primer informe")], now));
        var path = store.LatestReportPath;
        var original = await File.ReadAllTextAsync(path);
        True(original.Contains("primer informe", StringComparison.Ordinal),
            "El primer informe no se persistió correctamente.");

        using var cts = new CancellationTokenSource();
        cts.Cancel();
        var canceled = false;
        try
        {
            await store.SaveLatestReportAsync(
                Report([Event(now.AddMinutes(1), "segundo informe")], now.AddMinutes(1)), cts.Token);
        }
        catch (OperationCanceledException)
        {
            canceled = true;
        }
        True(canceled, "La escritura con token cancelado no lanzó OperationCanceledException.");

        var after = await File.ReadAllTextAsync(path);
        Equal(original, after, "El informe anterior cambió tras una escritura cancelada (H3).");
        var stateDir = Path.Combine(root, "state");
        False(Directory.EnumerateFiles(stateDir, "latest-report.json.tmp-*").Any(),
            "Quedó residuo *.tmp tras la cancelación de la escritura.");

        await store.SaveLatestReportAsync(Report([Event(now.AddMinutes(2), "tercer informe")], now.AddMinutes(2)))
            .WaitAsync(TimeSpan.FromSeconds(5));
        var final = await store.LoadLatestReportAsync();
        NotNull(final, "El informe no se pudo guardar tras recuperarse de la cancelación.");
    }
    finally { TryDelete(root); }
}

static Task TimeWindowParsesExactFormatsWithoutCulture()
{
    var start = new DateTimeOffset(2025, 5, 3, 0, 0, 0, TimeSpan.Zero);
    var end = new DateTimeOffset(2025, 5, 4, 23, 59, 59, TimeSpan.Zero);

    DiagnosticFinding WithFecha(string valor) => new("FECHA", "TSplus", DiagnosticSeverity.Error, "fecha", "",
        [new EvidenceItem("Fecha", valor)], ConfidenceLevel.Media, Capa: DiagnosticLayer.Tsplus);

    // Con cultura invariante (mes/día) "05/03" se leía como 3 de mayo y entraba en la ventana;
    // el formato exacto dd/MM/yyyy lo resuelve como 5 de marzo, fuera de la ventana.
    False(DiagnosticTimeWindow.IsFindingInside(WithFecha("05/03/2025 10:00:00"), start, end),
        "Una fecha dd/MM/yyyy HH:mm:ss se interpretó con la cultura del sistema.");
    // Los días ≥13 no parseaban con TryParse sin cultura y el hallazgo se conservaba para siempre.
    False(DiagnosticTimeWindow.IsFindingInside(WithFecha("25/12/2025 10:00:00"), start, end),
        "Una fecha declarada anterior a la ventana sobrevivió por fallo de parse.");
    // Round-trip "O" de los productores de Fecha/Último registro se resuelve por forma ISO 8601.
    True(DiagnosticTimeWindow.IsFindingInside(
        WithFecha(new DateTimeOffset(2025, 5, 3, 10, 0, 0, TimeSpan.Zero).ToString("O")), start, end),
        "Una fecha round-trip O dentro de la ventana fue descartada.");
    // El contrato de hallazgo de estado actual sin clave temporal se conserva.
    True(DiagnosticTimeWindow.IsFindingInside(
        new DiagnosticFinding("ESTADO", "TSplus", DiagnosticSeverity.Error, "estado", "",
            [new EvidenceItem("Estado", "Stopped")], ConfidenceLevel.Media, Capa: DiagnosticLayer.Tsplus), start, end),
        "Un hallazgo de estado actual sin timestamp se descartó.");
    return Task.CompletedTask;
}

static Task TdmSourcedEventsAreNotCausalSignals()
{
    var now = DateTimeOffset.Now;
    var derived = new DiagnosticEvent(now, "TDM", "Web Portal Service", DiagnosticLayer.Tsplus,
        DiagnosticSeverity.Critico, "APPLICATION_CRASH", "crash sintetizado por TDM",
        Producto: TsplusProduct.RemoteAccess);
    False(DiagnosticPrecisionAnalyzer.IsCausalSignal(derived),
        "Un evento con Fuente=TDM contó como señal causal independiente.");
    var observed = new DiagnosticEvent(now, "Application Error", "TSplus", DiagnosticLayer.Tsplus,
        DiagnosticSeverity.Critico, "APPLICATION_CRASH", "crash observado por Windows",
        Producto: TsplusProduct.RemoteAccess);
    True(DiagnosticPrecisionAnalyzer.IsCausalSignal(observed),
        "Un evento de fuente externa dejó de contar como señal causal.");
    return Task.CompletedTask;
}

static Task SaturatedDirectImpactStillElectsCausalPrimary()
{
    var now = DateTimeOffset.Now;
    var events = new List<DiagnosticEvent>();
    for (var i = 1; i <= 9; i++)
    {
        events.Add(new DiagnosticEvent(now.AddMinutes(-i), "TDM", $"Service{i}", DiagnosticLayer.Tsplus,
            DiagnosticSeverity.Critico, "SERVICE_STATE", "Estado actual: Stopped",
            Evidencia: [
                new EvidenceItem("Servicio", $"Service{i}"),
                new EvidenceItem("Nombre visible", $"Service {i}"),
                new EvidenceItem("Estado", "Stopped")
            ], Producto: TsplusProduct.RemoteAccess));
    }
    // Causa real con doble fuente: fallo SCM accionable + crash del mismo producto 1 min después.
    events.Add(new DiagnosticEvent(now.AddMinutes(-3), "Service Control Manager", "tsplus seguimiento",
        DiagnosticLayer.Windows, DiagnosticSeverity.Error, "SERVICE_START_FAILURE",
        "El servicio no se pudo iniciar: failed to start", Codigo: "7000",
        Producto: TsplusProduct.RemoteAccess));
    events.Add(new DiagnosticEvent(now.AddMinutes(-2), "Application Error", "tsplus.exe", DiagnosticLayer.Tsplus,
        DiagnosticSeverity.Error, "APPLICATION_CRASH", "tsplus.exe crashed",
        Evidencia: [new EvidenceItem("Aplicación", "tsplus.exe")], Producto: TsplusProduct.RemoteAccess));

    var analyzed = DiagnosticWorkflow.Analyze(Report(events, now));
    var direct = analyzed.CausasRaiz
        .Count(c => c.RolCausal.Equals("IMPACTO_DIRECTO_SIN_CAUSA_DEL_PARO", StringComparison.OrdinalIgnoreCase));
    True(direct >= 8, "La saturación de impacto directo no se reprodujo en el recorte de 8.");
    var scm = analyzed.CausasRaiz
        .FirstOrDefault(c => c.Id.StartsWith("ROOT-SCM-SERVICE-FAILURE", StringComparison.OrdinalIgnoreCase));
    NotNull(scm, "La causa real de los puestos 9-12 quedó fuera de CausasRaiz.");
    NotNull(analyzed.CausaRaizPrincipal,
        "Con ≥8 impactos directos la única causa real del pool completo fue descartada.");
    True(analyzed.CausaRaizPrincipal?.Id.StartsWith("ROOT-SCM-SERVICE-FAILURE", StringComparison.OrdinalIgnoreCase) == true,
        "La causa principal no fue el candidato causal del pool completo.");
    return Task.CompletedTask;
}

static Task CrashAndDependencyCandidateIdsAreUnique()
{
    var now = DateTimeOffset.Now;
    DiagnosticEvent Crash(string app, DateTimeOffset ts) => new(ts, "Application Error", app, DiagnosticLayer.Tsplus,
        DiagnosticSeverity.Error, "APPLICATION_CRASH", $"{app} crashed",
        Evidencia: [new EvidenceItem("Aplicación", app)], Producto: TsplusProduct.RemoteAccess);

    var candidates = RootCauseCorrelator.Analyze(Report(
        [Crash("alpha.exe", now.AddMinutes(-2)), Crash("beta.exe", now.AddMinutes(-1))], now));
    var crashes = candidates
        .Where(c => c.Id.StartsWith("ROOT-PROCESS-CRASH", StringComparison.OrdinalIgnoreCase))
        .ToList();
    Equal(2, crashes.Count, "No se generó un candidato de crash por aplicación.");
    False(string.Equals(crashes[0].Id, crashes[1].Id, StringComparison.OrdinalIgnoreCase),
        "Dos aplicaciones distintas compartieron el mismo Id de candidato.");
    True(crashes.All(c => c.Id != "ROOT-PROCESS-CRASH"), "Se siguió emitiendo el Id genérico compartido.");

    // El historial verificado ajusta sólo al candidato cuyo Id único coincide con el feedback.
    var a = VerifiedCandidate(crashes[0].Id, 70, independent: false);
    var b = VerifiedCandidate(crashes[1].Id, 72, independent: false);
    var adjusted = VerifiedHistoryCalibrator.ApplyVerifiedHistory([a, b], Rates((crashes[0].Id, 5, 0)));
    Equal(crashes[0].Id, adjusted[0].Id, "El candidato confirmado no encabezó el ranking.");
    Equal(85, adjusted[0].Puntaje, "El ajuste +15 no se aplicó al Id único confirmado.");
    Equal(72, adjusted[1].Puntaje, "El historial de otra aplicación alteró el puntaje de este candidato.");
    return Task.CompletedTask;
}

static Task EachFailingDependencyGetsItsOwnCandidate()
{
    var now = DateTimeOffset.Now;
    DiagnosticEvent Dep(string dll, DateTimeOffset at) => new(at, "SideBySide", "tsplus", DiagnosticLayer.Tsplus,
        DiagnosticSeverity.Error, "DEPENDENCY_LOAD_FAILURE", $"No se pudo cargar {dll}",
        Evidencia: [new EvidenceItem("Dependencia detectada", dll), new EvidenceItem("Clasificación de dependencia", "TSPLUS")],
        Producto: TsplusProduct.RemoteAccess);

    var candidates = RootCauseCorrelator.Analyze(Report(
        [Dep("alpha.dll", now.AddMinutes(-6)), Dep("beta.dll", now.AddMinutes(-4))], now));
    True(candidates.Any(c => c.Id.Equals("ROOT-DEPENDENCY-LOAD-ALPHADLL", StringComparison.OrdinalIgnoreCase)),
        "La primera dependencia fallida no generó su propio candidato (sólo se candidataba la última).");
    True(candidates.Any(c => c.Id.Equals("ROOT-DEPENDENCY-LOAD-BETADLL", StringComparison.OrdinalIgnoreCase)),
        "La última dependencia fallida dejó de generar candidato.");
    return Task.CompletedTask;
}

static Task PendingAndManualStopsDoNotClaimDirectImpact()
{
    var now = DateTimeOffset.Now;
    DiagnosticEvent State(string service, string estado, string? inicio = null, string? presentacion = null)
    {
        List<EvidenceItem> ev =
        [
            new("Servicio", service),
            new("Nombre visible", service),
            new("Estado", estado)
        ];
        if (inicio is not null) ev.Add(new EvidenceItem("Inicio", inicio));
        if (presentacion is not null) ev.Add(new EvidenceItem("Estado presentación", presentacion));
        return new DiagnosticEvent(now.AddMinutes(-2), "Service Control Manager", "Remote Access",
            DiagnosticLayer.Tsplus, DiagnosticSeverity.Critico, "SERVICE_STATE", $"Estado actual: {estado}",
            Evidencia: ev, Producto: TsplusProduct.RemoteAccess);
    }

    var candidates = RootCauseCorrelator.Analyze(Report(
        [
            State("GatewayAgent", "StopPending"),
            State("ManualHelper", "Stopped", inicio: "Manual", presentacion: "No requerido (inicio manual)"),
            State("CoreWorker", "Stopped")
        ], now));
    True(candidates.Any(c => c.Id.Equals("ROOT-TSPLUS-SERVICE-STOPPED-COREWORKER", StringComparison.OrdinalIgnoreCase)),
        "Un servicio detenido normal dejó de generar candidato de impacto directo.");
    False(candidates.Any(c => c.Id.Equals("ROOT-TSPLUS-SERVICE-STOPPED-GATEWAYAGENT", StringComparison.OrdinalIgnoreCase)),
        "Un estado StopPending (transición del SCM) afirmó impacto directo demostrado, contradiciendo al analizador de impacto.");
    False(candidates.Any(c => c.Id.Equals("ROOT-TSPLUS-SERVICE-STOPPED-MANUALHELPER", StringComparison.OrdinalIgnoreCase)),
        "Un servicio Manual 'No requerido' detenido afirmó impacto directo demostrado, contradiciendo al analizador de impacto.");
    return Task.CompletedTask;
}

static Task InterleavedBurstKeepsSharedIncidentTogether()
{
    var now = DateTimeOffset.Now;
    static DiagnosticEvent Agent(DateTimeOffset at) => new(at, "SCM", "TsplusAgent", DiagnosticLayer.Tsplus,
        DiagnosticSeverity.Error, "SERVICE_STATE", "Estado actual: Stopped",
        Evidencia: [new EvidenceItem("Servicio", "TsplusAgent"), new EvidenceItem("Estado", "Stopped")],
        Producto: TsplusProduct.RemoteAccess);
    var wmi = new DiagnosticEvent(now.AddMinutes(-4), "WMI", "WMI", DiagnosticLayer.Windows,
        DiagnosticSeverity.Critico, "WMI_EVENT_INCREMENTAL", "0x80041032");

    var clusters = IncidentClusterAnalyzer.Analyze(Report(
        [Agent(now.AddMinutes(-5)), wmi, Agent(now.AddMinutes(-3))], now));
    Equal(2, clusters.Count,
        "La ráfaga A-B-A se partió en 3 incidentes al comparar sólo contra el último grupo.");
    var agent = clusters.Single(c => c.Dominio == "TSPLUS_REMOTE_ACCESS");
    Equal(2, agent.Senales, "Las señales del mismo servicio no quedaron en un solo incidente.");
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

sealed record WindowsCursorFixture(Dictionary<string, long> Cursors, DateTimeOffset SavedAt, Dictionary<string, string> LastKnownGoodState, DateTimeOffset? LastSuccessUtc);

sealed record TsplusCursorFixture(Dictionary<string, TsplusFileCursorFixture> Files, DateTimeOffset SavedAt);

sealed record TsplusFileCursorFixture(long Offset, long CreationUtcTicks, string PartialLine, string FileHash);

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
