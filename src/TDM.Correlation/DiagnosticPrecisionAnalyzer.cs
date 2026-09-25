using TDM.Models;

namespace TDM.Correlation;

/// <summary>
/// Calibra la fuerza del diagnóstico con criterios conservadores: cobertura, evidencia
/// causal independiente, conflictos de origen y densidad de señales. El puntaje de
/// calidad NO es una probabilidad de que la causa sea correcta; describe cuánta
/// evidencia verificable respalda el análisis actual.
/// </summary>
public static class DiagnosticPrecisionAnalyzer
{
    public static IReadOnlyList<RootCauseCandidate> Calibrate(
        DiagnosticReport report,
        IReadOnlyList<RootCauseCandidate> candidates)
    {
        if (candidates.Count == 0) return candidates;

        var coverageComplete = CoverageBlockedSources(report) == 0;
        var hardBlocked = CoverageHardBlockedSources(report) > 0;
        var conflict = HasOriginConflict(candidates);
        var calibrated = new List<RootCauseCandidate>(candidates.Count);

        foreach (var candidate in candidates)
        {
            var confidence = candidate.Confianza;
            var score = candidate.Puntaje;
            var reasons = new List<string>();
            var independent = HasIndependentPrimaryEvidence(candidate);

            // Sólo un bloqueo duro (fuente ilegible) degrada la confianza. Una fuente
            // parcial conserva la evidencia que sí se leyó y se reporta como limitación.
            if (hardBlocked)
            {
                if (confidence == ConfidenceLevel.Confirmada)
                {
                    confidence = ConfidenceLevel.Alta;
                    score -= 7;
                    reasons.Add("cobertura crítica incompleta impide conservar estado CONFIRMADA");
                }
                else if (confidence == ConfidenceLevel.Alta)
                {
                    confidence = ConfidenceLevel.Media;
                    score -= 6;
                    reasons.Add("cobertura crítica incompleta impide conservar confianza ALTA");
                }
            }

            if (candidate.Id == "ROOT-PROCESS-CRASH" && confidence == ConfidenceLevel.Confirmada && !independent)
            {
                confidence = ConfidenceLevel.Alta;
                score -= 4;
                reasons.Add("el mecanismo de crash está confirmado, pero falta evidencia primaria independiente");
            }

            if (conflict && candidate.Puntaje >= 75 && IsCausalCandidate(candidate))
            {
                if (confidence == ConfidenceLevel.Confirmada) confidence = ConfidenceLevel.Alta;
                else if (confidence == ConfidenceLevel.Alta) confidence = ConfidenceLevel.Media;
                score -= 8;
                reasons.Add("existen candidatos fuertes de orígenes distintos dentro de la misma ventana");
            }

            if (candidate.OrigenClasificado == "INDETERMINADO" && confidence == ConfidenceLevel.Alta)
            {
                confidence = ConfidenceLevel.Media;
                score -= 5;
                reasons.Add("el origen Windows/TSplus todavía no está discriminado");
            }

            var evidence = candidate.Evidencia.ToList();
            evidence.Add(new EvidenceItem("Calibración de precisión RC18.14.3",
                reasons.Count == 0 ? "Sin penalizaciones; evidencia coherente con el estado actual" : string.Join("; ", reasons)));
            evidence.Add(new EvidenceItem("Cobertura crítica legible", hardBlocked ? "No" : "Sí"));
            evidence.Add(new EvidenceItem("Cobertura crítica completa", coverageComplete ? "Sí" : "No"));
            evidence.Add(new EvidenceItem("Conflicto entre orígenes fuertes", conflict ? "Sí" : "No"));
            if (!evidence.Any(e => e.Clave.Equals("Evidencia primaria independiente", StringComparison.OrdinalIgnoreCase)))
                evidence.Add(new EvidenceItem("Evidencia primaria independiente", independent ? "Sí" : "No"));

            calibrated.Add(candidate with
            {
                Puntaje = Math.Clamp(score, 0, 100),
                Confianza = confidence,
                Evidencia = evidence
            });
        }

        var ordered = calibrated
            .OrderByDescending(x => x.Puntaje)
            .ThenByDescending(x => ConfidenceRank(x.Confianza))
            .ThenByDescending(x => x.HoraIncidente ?? DateTimeOffset.MinValue)
            .ToList();

        var finalConflict = HasOriginConflict(ordered);
        var causalRanking = ordered.Where(IsCausalCandidate).ToList();
        var uniqueMargin = causalRanking.Count <= 1
            || causalRanking[0].Puntaje - causalRanking[1].Puntaje >= 5;

        return ordered
            .Select((x, index) =>
            {
                var evidence = x.Evidencia.ToList();
                var sameCauseRank = causalRanking.FindIndex(c => c.Id.Equals(x.Id, StringComparison.OrdinalIgnoreCase));
                var gap = sameCauseRank < 0 || sameCauseRank == 0 ? 0 : causalRanking[0].Puntaje - x.Puntaje;
                var rankState = sameCauseRank == 0 && !uniqueMargin
                    ? "EMPATE_TECNICO / HIPÓTESIS_COMPETITIVAS"
                    : sameCauseRank == 0
                        ? "CANDIDATO_PRINCIPAL"
                        : sameCauseRank > 0 && !uniqueMargin
                            ? "HIPÓTESIS_COMPETITIVA"
                            : "CANDIDATO_SECUNDARIO";
                evidence.RemoveAll(e => e.Clave.Equals("Conflicto entre orígenes fuertes", StringComparison.OrdinalIgnoreCase)
                                     || e.Clave.Equals("Estado de ranking", StringComparison.OrdinalIgnoreCase)
                                     || e.Clave.Equals("Diferencia contra mejor candidato causal", StringComparison.OrdinalIgnoreCase));
                evidence.Add(new EvidenceItem("Conflicto entre orígenes fuertes", finalConflict ? "Sí" : "No"));
                evidence.Add(new EvidenceItem("Estado de ranking", rankState));
                evidence.Add(new EvidenceItem("Diferencia contra mejor candidato causal", sameCauseRank < 0 ? "No aplica" : $"{gap} puntos"));
                return x with { Posicion = index + 1, Evidencia = evidence };
            })
            .ToList();
    }

    public static DiagnosticPrecisionAssessment Analyze(DiagnosticReport report)
    {
        var blockedSources = CoverageBlockedSources(report);
        var hardBlockedSources = CoverageHardBlockedSources(report);
        var coverageComplete = blockedSources == 0;
        var signals = report.Eventos.Count(IsCausalSignal);
        var context = report.Eventos.Count(e => !IsCurrentState(e) && !IsCausalSignal(e));
        var undated = report.Eventos.Count(e => e.Tipo == "UNDATED_LOG_EVIDENCE")
            + report.Hallazgos.Count(f => f.Evidencia.Any(e =>
                e.Valor.Contains("sin timestamp", StringComparison.OrdinalIgnoreCase) ||
                e.Clave.Contains("sin timestamp", StringComparison.OrdinalIgnoreCase)));
        var best = report.CausasRaiz.FirstOrDefault(IsCausalCandidate);
        var independent = best is not null && HasIndependentPrimaryEvidence(best);
        var conflict = HasOriginConflict(report.CausasRaiz);
        var forensicArtifacts = report.Eventos.Count(e => e.Tipo is "FORENSIC_WER_FOUND" or "FORENSIC_DUMP_FOUND" or "FORENSIC_LOG_FOUND");
        // Incidentes funcionales = evidencia operativa verificable (servicios caídos,
        // procesos con crash, sesiones/identidad correlacionada) ya detectada por TDM.
        var operationalIncidents = report.Eventos.Count(DiagnosticEventCatalog.IsFunctionalIncident);

        var score = 25;
        // Fuente parcial sigue siendo cobertura útil; sólo un bloqueo duro castiga.
        score += coverageComplete ? 15 : hardBlockedSources == 0 ? 2 : -10;
        if (best is not null) score += 18;
        if (best?.HoraIncidente is not null) score += 5;
        if (independent) score += 15;
        score += Math.Min(15, signals * 3);
        score += Math.Min(12, operationalIncidents * 2);
        if (forensicArtifacts > 0) score += 5;
        if (conflict) score -= 15;
        if (undated > 0) score -= Math.Min(8, undated * 2);
        if (best is null) score = Math.Min(score, 55);
        score = Math.Clamp(score, 0, 100);

        var level = score switch
        {
            >= 85 => "ALTA",
            >= 65 => "MEDIA",
            >= 45 => "LIMITADA",
            _ => "INSUFICIENTE"
        };

        var summary = best is null
            ? "No existe candidato causal en la ventana visible; la calidad mide cobertura, evidencia operativa detectada y señales disponibles, no una causa inexistente."
            : conflict
                ? "La evidencia contiene candidatos fuertes de orígenes distintos; TDM conserva el conflicto y evita una conclusión prematura."
                : hardBlockedSources > 0
                    ? "Existe un candidato, pero una o más fuentes críticas no pudieron leerse; el diagnóstico se mantiene conservador."
                    : !coverageComplete
                        ? "Existe un candidato con cobertura parcial en fuentes críticas; las conclusiones conservan esa limitación."
                        : independent
                            ? "Cobertura legible y evidencia primaria independiente respaldan el candidato principal."
                            : "La evidencia converge, pero todavía falta una fuente causal independiente para confirmar la causa primaria.";

        var evidence = new List<EvidenceItem>
        {
            new("Puntaje de calidad de evidencia", $"{score}/100 (no es probabilidad)"),
            new("Nivel de calidad", level),
            new("Cobertura crítica completa", coverageComplete ? "Sí" : "No"),
            new("Fuentes bloqueadas/no legibles", blockedSources.ToString()),
            new("Bloqueos duros de fuentes críticas", hardBlockedSources.ToString()),
            new("Señales causales/operativas", signals.ToString()),
            new("Incidentes funcionales detectados", operationalIncidents.ToString()),
            new("Eventos de contexto/telemetría", context.ToString()),
            new("Evidencia sin timestamp utilizable", undated.ToString()),
            new("Conflicto entre orígenes fuertes", conflict ? "Sí" : "No"),
            new("Evidencia primaria independiente", independent ? "Sí" : "No"),
            new("Artefactos forenses existentes", forensicArtifacts.ToString())
        };

        return new DiagnosticPrecisionAssessment(
            score,
            level,
            coverageComplete,
            blockedSources,
            signals,
            context,
            undated,
            conflict,
            independent,
            summary,
            evidence);
    }

    public static bool IsCausalSignal(DiagnosticEvent e)
    {
        // Una señal sin hora propia puede conservarse como evidencia, pero no debe
        // aumentar el puntaje de causalidad temporal ni simular una secuencia histórica.
        if (!e.Timestamp.HasValue) return false;
        // WMI/DCOM son señales de observabilidad/infraestructura de consulta.
        // No deben ganar causalidad sólo por ser eventos críticos, porque eso mezcla
        // el fallo para observar con el fallo que se está intentando explicar.
        if (e.Tipo is "WMI_EVENT_INCREMENTAL" or "DCOM_EVENT_INCREMENTAL") return false;
        // SERVICE_STATE demuestra estado/impacto; la causa del paro requiere SERVICE_TERMINATION,
        // SERVICE_START_FAILURE o un antecedente SCM explícito.
        if (e.Tipo.Equals("SERVICE_STATE", StringComparison.OrdinalIgnoreCase)) return false;
        if (e.Severidad == DiagnosticSeverity.Critico) return true;
        if (e.Tipo is "APPLICATION_CRASH" or "DOTNET_UNHANDLED_EXCEPTION" or "WER_REPORT" or
            "SERVICE_TERMINATION" or "SERVICE_START_FAILURE" or "RESOURCE_EXHAUSTION" or
            "STORAGE_FAILURE" or "SIDEBYSIDE_DEPENDENCY_FAILURE" or "DEPENDENCY_NOT_FOUND" or
            "DEPENDENCY_LOAD_FAILURE" or "DLL_NOT_FOUND" or "INVALID_IMAGE_FORMAT" or
            "DEFENDER_ACTION_TAKEN" or "DEFENDER_THREAT_DETECTED" or "USER_PROFILE_SERVICE_EVENT" or
            "USER_LOGON_FAILURE" or "USER_NLA_PASSWORD_FAILURE" or "ACCOUNT_LOCKOUT" or "KERBEROS_PREAUTH_FAILURE" or "TSPLUS_HTML5_JVM_CRASH" or
            "RDP_AUTHENTICATION_STAGE" or "RDP_SESSION_LOGON_STAGE" or "RDP_SHELL_START_STAGE" or
            "RDP_SHELL_START_GAP" or "RDP_SHELL_START_DELAY" or "TLS_SCHANNEL_EVENT" or "WINDOWS_AD_AUTH_DEPENDENCY_FAILURE" or
            "WINDOWS_AD_TERMSRV_SPN_FAILURE" or "WINDOWS_AD_DOMAIN_CONNECTIVITY_FAILURE" or
            "THIRD_PARTY_MODULE_TSPLUS_CRASH" or "THIRD_PARTY_SECURITY_INTERFERENCE_SIGNAL" or
            "TSPLUS_STARTUP_CONFIG_ENCODING_RISK" or "TSPLUS_CRASH_LOOP_PATTERN") return true;
        if (e.Codigo is "41" or "51" or "55" or "1000" or "1001" or "1026" or "2004" or
            "7000" or "7001" or "7009" or "7011" or "7023" or "7024" or "7031" or "7034") return true;
        return e.Tipo.StartsWith("PRINT_EVENT_", StringComparison.OrdinalIgnoreCase) &&
               e.Severidad != DiagnosticSeverity.Informativo;
    }

    private static bool IsCurrentState(DiagnosticEvent e) => DiagnosticEventCatalog.IsPrecisionCurrentState(e.Tipo);

    private static int CoverageBlockedSources(DiagnosticReport report)
        => DiagnosticCoverageAnalyzer.CriticalUnavailableCount(report);

    private static int CoverageHardBlockedSources(DiagnosticReport report)
        => DiagnosticCoverageAnalyzer.CriticalHardBlockedCount(report);

    private static bool HasOriginConflict(IReadOnlyList<RootCauseCandidate> candidates)
    {
        var strongOrigins = candidates
            .Where(IsCausalCandidate)
            .Where(c => c.Puntaje >= 75)
            .Select(c => c.OrigenClasificado)
            .Where(o => !string.IsNullOrWhiteSpace(o) && o != "INDETERMINADO")
            .Select(NormalizeOrigin)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        return strongOrigins.Count > 1;
    }

    private static bool IsCausalCandidate(RootCauseCandidate candidate)
        => !candidate.RolCausal.Equals("IMPACTO_DIRECTO_SIN_CAUSA_DEL_PARO", StringComparison.OrdinalIgnoreCase);

    private static string NormalizeOrigin(string value) => value == "DEPENDENCIA EXTERNA" ? "EXTERNO" : value;

    private static bool HasIndependentPrimaryEvidence(RootCauseCandidate candidate)
    {
        if (EvidenceValue(candidate, "Evidencia primaria independiente").Equals("Sí", StringComparison.OrdinalIgnoreCase))
            return true;

        if (candidate.Id == "ROOT-RDP-TERMSERVICE")
            return candidate.Evidencia.Any(e => e.Clave.Equals("Separación RDP → TSplus", StringComparison.OrdinalIgnoreCase));

        if (candidate.Id == "ROOT-SECURITY-DEFENDER-FILE")
        {
            var fileMissing = EvidenceValue(candidate, "Archivo presente").Equals("No", StringComparison.OrdinalIgnoreCase);
            var tsplusAfter = !EvidenceValue(candidate, "Error TSplus posterior").Equals("No verificable", StringComparison.OrdinalIgnoreCase) &&
                              !EvidenceValue(candidate, "Error TSplus posterior").Equals("N/D", StringComparison.OrdinalIgnoreCase);
            return fileMissing && tsplusAfter;
        }

        // R3: la independencia no es exclusiva de crashes/TermService/Defender. Cada regla con
        // doble fuente verificada (señal + síntoma/correlato sin recuperación intermedia) califica.
        // U6: exige además síntoma posterior correlacionado; sin par no hay doble fuente.
        if (candidate.Id == "ROOT-WINDOWS-AD-RDP-DEPENDENCY")
            return !EvidenceValue(candidate, "Síntoma Remote Access posterior").Equals("No correlacionado", StringComparison.OrdinalIgnoreCase)
                && EvidenceValue(candidate, "Recuperación entre señal y síntoma").Equals("No observada", StringComparison.OrdinalIgnoreCase);

        if (candidate.Id == "ROOT-WINDOWS-RDP-SHELL-PIPELINE")
        {
            // X1: la anomalía Winlogon/Userinit es un hallazgo estático sin timestamp; sin brecha
            // de shell existente no hay doble fuente. Perfil/AD sí están anclados a la brecha.
            var hasShellGap = !EvidenceValue(candidate, "Evento de shell").Equals("N/D", StringComparison.OrdinalIgnoreCase);
            return EvidenceValue(candidate, "Error de perfil correlacionado").Equals("Sí", StringComparison.OrdinalIgnoreCase)
                || EvidenceValue(candidate, "Señal AD/Netlogon correlacionada <=5 min").Equals("Sí", StringComparison.OrdinalIgnoreCase)
                || (hasShellGap && EvidenceValue(candidate, "Anomalía Winlogon/Userinit").Equals("Sí", StringComparison.OrdinalIgnoreCase));
        }

        if (candidate.Id == "ROOT-SCM-SERVICE-FAILURE")
            return EvidenceValue(candidate, "Crash posterior del mismo producto").Equals("Sí", StringComparison.OrdinalIgnoreCase);

        if (candidate.Id.StartsWith("ROOT-SERVICE-DEPENDENCY-", StringComparison.OrdinalIgnoreCase))
            return !EvidenceValue(candidate, "Falla SCM del mismo servicio/dependencia").Equals("No observada", StringComparison.OrdinalIgnoreCase);

        if (candidate.Id == "ROOT-TLS-SCHANNEL")
        {
            // U1 (revierte R3 aquí): la identidad compartida es condición de la regla, pero la
            // propia explicación del candidato dice que no basta para confirmar. Un TLS 72/Media
            // solitario no debe volverse primary por esta vía; en multi compite por puntaje.
            return false;
        }

        if (candidate.Id == "ROOT-DEPENDENCY-LOAD")
            return EvidenceValue(candidate, "Crash TSplus cercano").Equals("Sí", StringComparison.OrdinalIgnoreCase);

        return false;
    }

    private static string EvidenceValue(RootCauseCandidate candidate, string key) =>
        candidate.Evidencia.FirstOrDefault(e => e.Clave.Equals(key, StringComparison.OrdinalIgnoreCase))?.Valor ?? "N/D";

    private static int ConfidenceRank(ConfidenceLevel level) => level switch
    {
        ConfidenceLevel.Confirmada => 5,
        ConfidenceLevel.Alta => 4,
        ConfidenceLevel.Media => 3,
        ConfidenceLevel.Baja => 2,
        _ => 1
    };
}
