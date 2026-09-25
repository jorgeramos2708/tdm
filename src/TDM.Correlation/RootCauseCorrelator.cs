using TDM.KnowledgeBase;
using TDM.Models;

namespace TDM.Correlation;

public static partial class RootCauseCorrelator
{
    private sealed record CandidateDraft(
        string Id,
        string Component,
        DiagnosticLayer Layer,
        int Score,
        ConfidenceLevel Confidence,
        string Summary,
        string Explanation,
        IReadOnlyList<EvidenceItem> Evidence,
        string? GuidanceId,
        DateTimeOffset? IncidentTime = null,
        string OriginCategory = "INDETERMINADO",
        TsplusProduct Product = TsplusProduct.Desconocido,
        string CausalRole = "CAUSA_CANDIDATA");

    public static IReadOnlyList<RootCauseCandidate> Analyze(DiagnosticReport report)
    {
        // Sin Remote Access detectado no afirmamos causas de una falla TSplus Remote Access.
        // Los collectors siguen exponiendo evidencia de Windows/RDP para diagnóstico general.
        if (report.Sistema.TsplusEstadoDeteccion == TsplusDetectionState.ConfirmedAbsent) return [];

        var drafts = new List<CandidateDraft>();
        var tsplusErrors = Relevant(report, DiagnosticLayer.Tsplus)
            .Where(e => e.Producto is TsplusProduct.RemoteAccess or TsplusProduct.Ninguno)
            .Where(e => e.Tipo != "LICENSE")
            .ToList();
        var rdpErrors = Relevant(report, DiagnosticLayer.Rdp);
        var securityErrors = Relevant(report, DiagnosticLayer.Seguridad);
        var defenderTsplusEvents = securityErrors
            .Where(e => IsDefenderEvent(e) && TouchesTsplus(e, report.Sistema))
            .OrderBy(e => e.Timestamp)
            .ToList();
        var schannelErrors = report.Eventos
            .Where(e => e.Timestamp.HasValue && e.Severidad != DiagnosticSeverity.Informativo &&
                        e.Fuente.Contains("Schannel", StringComparison.OrdinalIgnoreCase))
            .OrderBy(e => e.Timestamp)
            .ToList();
        var tsplusCrashEvents = report.Eventos
            .Where(e => e.Timestamp.HasValue && e.Capa == DiagnosticLayer.Tsplus &&
                        e.Tipo is "APPLICATION_CRASH" or "DOTNET_UNHANDLED_EXCEPTION" or "WER_REPORT")
            .OrderBy(e => e.Timestamp)
            .ToList();

        AddDirectOperationalStateCandidates(report, drafts);
        AddBasicInfrastructureCandidates(report, drafts, tsplusErrors, rdpErrors, schannelErrors);
        AddRealServiceDependencyCandidates(report, drafts, tsplusErrors, rdpErrors);
        AddScmServiceCandidates(report, drafts, tsplusCrashEvents);
        AddCrashCandidates(report, drafts, tsplusCrashEvents);
        AddDependencyCandidates(report, drafts, tsplusCrashEvents);
        AddConfigurationAndIntegrityCandidates(report, drafts, tsplusErrors);
        AddLongitudinalHistoryCandidates(report, drafts);
        AddIdentityCandidates(report, drafts, tsplusErrors, rdpErrors, defenderTsplusEvents, schannelErrors);
        AddExternalSecurityCandidates(report, drafts, tsplusErrors, defenderTsplusEvents);
        AddWindowsCompatibilityCandidates(report, drafts);
        AddDirectorySessionAndFarmCandidates(report, drafts, tsplusErrors);

        // P1-drift→síntoma: post-pass acotado sobre drafts (no nuevos candidatos).
        ApplyConfigurationDriftProximity(report, drafts);

        // P0-03: Tie-breaker - impacto directo (sin causa demostrada) no gana a causa real.
            // Cuando dos candidatos tienen el mismo score, el que tiene rol IMPACTO_DIRECTO_SIN_CAUSA_DEL_PARO
            // queda por debajo. También aplica un pequeño penalty (-1) al score para estos roles
            // para que causas reales con score 96+ queden por encima de impacto directo 97.
            var ranked = drafts
                .Select(d => new
                {
                    Draft = d,
                    EffectiveScore = d.CausalRole == "IMPACTO_DIRECTO_SIN_CAUSA_DEL_PARO" ? d.Score - 1 : d.Score
                })
                .OrderByDescending(x => x.EffectiveScore)
                .ThenBy(x => x.Draft.CausalRole == "IMPACTO_DIRECTO_SIN_CAUSA_DEL_PARO")
                .ThenBy(x => x.Draft.Confidence)
                .ThenByDescending(x => x.Draft.IncidentTime ?? DateTimeOffset.MinValue)
                .Take(12)
                .Select((x, index) => ToCandidate(x.Draft, index + 1))
                .ToList();
            return ranked;
    }

    /// <summary>
    /// Promueve estados operativos directos que demuestran impacto funcional (por ejemplo,
    /// un servicio TSplus crítico detenido) sin afirmar que explican por qué se produjo el paro.
    /// Esto evita que una anomalía estática de configuración gane artificialmente a una falla
    /// operativa observable.
    /// </summary>
    private static void AddDirectOperationalStateCandidates(DiagnosticReport report, List<CandidateDraft> drafts)
    {
        var states = report.Eventos
            .Where(e => e.Tipo.Equals("SERVICE_STATE", StringComparison.OrdinalIgnoreCase))
            .Where(e => e.Timestamp.HasValue)
            .Where(e => e.Severidad is DiagnosticSeverity.Error or DiagnosticSeverity.Critico)
            .Where(e => e.Producto == TsplusProduct.RemoteAccess)
            .Where(e => string.Equals(EvidenceValue(e, "Estado"), "Stopped", StringComparison.OrdinalIgnoreCase)
                     || string.Equals(EvidenceValue(e, "Estado"), "StopPending", StringComparison.OrdinalIgnoreCase)
                     || string.Equals(EvidenceValue(e, "Estado"), "StartPending", StringComparison.OrdinalIgnoreCase))
            .GroupBy(e => EvidenceValue(e, "Servicio") ?? e.Componente, StringComparer.OrdinalIgnoreCase)
            .Select(g => g.OrderByDescending(e => e.Severidad).ThenByDescending(e => e.Timestamp).First())
            .ToList();

        foreach (var state in states)
        {
            var service = EvidenceValue(state, "Servicio") ?? state.Componente;
            var display = EvidenceValue(state, "Nombre visible") ?? state.Componente;
            var isWeb = display.Contains("Web Portal", StringComparison.OrdinalIgnoreCase)
                        || service.Contains("WebPortal", StringComparison.OrdinalIgnoreCase)
                        || display.Contains("HTML5", StringComparison.OrdinalIgnoreCase)
                        || service.Contains("HTML5", StringComparison.OrdinalIgnoreCase);
            var affected = isWeb ? "Web / HTML5 / Web Portal" : service;
            var score = isWeb ? 97 : 95;
            var role = "IMPACTO_DIRECTO_SIN_CAUSA_DEL_PARO";

            drafts.Add(new CandidateDraft(
                $"ROOT-TSPLUS-SERVICE-STOPPED-{SafeServiceId(service)}",
                $"{display} (servicio detenido)",
                DiagnosticLayer.Tsplus,
                score,
                ConfidenceLevel.Alta,
                isWeb
                    ? "TDM confirmó que el servicio Web Portal de TSplus está detenido y que el impacto Web/HTML5 es directo."
                    : $"TDM confirmó que el servicio TSplus {display} está detenido y su disponibilidad está comprometida.",
                "Este estado demuestra una condición operativa/impacto, pero no demuestra por sí mismo qué provocó el paro del servicio. La causa del paro debe buscarse en eventos SCM, logs TSplus, dependencias, configuración y cambios inmediatamente anteriores.",
                Merge(
                    state.Evidencia ?? [],
                    new EvidenceItem("Estado operativo demostrado", "Servicio no operativo"),
                    new EvidenceItem("Impacto funcional asociado", affected),
                    new EvidenceItem("Causa del paro demostrada", "No"),
                    new EvidenceItem("Rol causal", role)),
                null,
                state.Timestamp,
                "TSPLUS",
                TsplusProduct.RemoteAccess,
                role));
        }
    }

    private static string SafeServiceId(string? value)
        => new string((value ?? "SERVICE").Where(char.IsLetterOrDigit).Select(char.ToUpperInvariant).Take(40).ToArray());

    private static IReadOnlyList<List<DiagnosticEvent>> ClusterCrashes(IEnumerable<DiagnosticEvent> source, TimeSpan maxGap)
    {
        var ordered = source.Where(e => e.Timestamp.HasValue).OrderBy(e => e.Timestamp).ToList();
        var clusters = new List<List<DiagnosticEvent>>();
        foreach (var current in ordered)
        {
            if (clusters.Count == 0)
            {
                clusters.Add([current]);
                continue;
            }
            var lastCluster = clusters[^1];
            var previous = lastCluster[^1];
            // P10: además del hueco temporal, dos crashes de la misma app con huella distinta
            // (excepción/módulo conocidos y diferentes) son incidentes distintos aunque caigan ≤ maxGap.
            // Sin huella en ambos se conserva la regla temporal para no fragmentar de más.
            if (current.Timestamp!.Value - previous.Timestamp!.Value <= maxGap
                && !DistinctCrashFingerprint(previous, current)) lastCluster.Add(current);
            else clusters.Add([current]);
        }
        return clusters;
    }

    private static bool DistinctCrashFingerprint(DiagnosticEvent a, DiagnosticEvent b)
    {
        static string? Fingerprint(DiagnosticEvent e)
        {
            var exception = e.Evidencia?.FirstOrDefault(x => x.Clave.Equals("Tipo de excepción .NET", StringComparison.OrdinalIgnoreCase))?.Valor;
            var module = e.Evidencia?.FirstOrDefault(x => x.Clave.Equals("Módulo con error", StringComparison.OrdinalIgnoreCase))?.Valor;
            var text = $"{exception}|{module}".Trim(' ', '|');
            return string.IsNullOrWhiteSpace(text) ? null : text;
        }
        var fa = Fingerprint(a);
        var fb = Fingerprint(b);
        return fa is not null && fb is not null && !fa.Equals(fb, StringComparison.OrdinalIgnoreCase);
    }

    private static bool HasActionableScmCause(DiagnosticEvent e)
    {
        var text = $"{e.Mensaje} {e.Codigo}";
        string[] markers =
        [
            // Y2: se agregan formas de fallo de arranque en ES/EN (7000/7001): antes solo 7009/7011
            // pasaban fácil y el 7001 ("depende de...") jamás, porque "depende" no contiene "dependenc".
            "dependenc", "depende", "depends", "logon", "inicio de sesión", "account", "cuenta", "file not found",
            "archivo no", "path not found", "ruta no", "access denied", "acceso denegado",
            "timeout", "tiempo de espera", "did not respond", "no respondió", "error 2", "error 5", "error 1068",
            "no pudo iniciar", "no se pudo iniciar", "failed to start"
        ];
        return markers.Any(m => text.Contains(m, StringComparison.OrdinalIgnoreCase));
    }

    private static List<DiagnosticEvent> Relevant(DiagnosticReport report, DiagnosticLayer layer) =>
        report.Eventos
            .Where(e => e.Capa == layer && e.Timestamp.HasValue && e.Severidad != DiagnosticSeverity.Informativo)
            // Fallas de lectura/estado de TDM son huecos o contexto de dependencia, no síntomas
            // del componente auditado. Las dependencias funcionales TSplus -> Windows se consumen
            // mediante reglas específicas y nunca se autocorrelacionan como "error TSplus/RDP".
            .Where(e => !e.Fuente.Equals("TDM", StringComparison.OrdinalIgnoreCase))
            .Where(e => e.Tipo != "TSPLUS_WINDOWS_FUNCTIONAL_DEPENDENCY_STATE")
            .OrderBy(e => e.Timestamp)
            .ToList();

    private static (DiagnosticEvent before, DiagnosticEvent after, TimeSpan delta)? ClosestBefore(
        IReadOnlyList<DiagnosticEvent> before,
        IReadOnlyList<DiagnosticEvent> after,
        TimeSpan maxDelta)
    {
        (DiagnosticEvent before, DiagnosticEvent after, TimeSpan delta)? best = null;
        foreach (var b in before)
        {
            if (b.Timestamp is not DateTimeOffset bts) continue;
            foreach (var a in after)
            {
                if (a.Timestamp is not DateTimeOffset ats || bts > ats) continue;
                var delta = ats - bts;
                if (delta > maxDelta) continue;
                if (best is null || delta < best.Value.delta) best = (b, a, delta);
            }
        }
        return best;
    }


    private static bool IsNearAnalysisEnd(DiagnosticReport report, DiagnosticEvent e, TimeSpan maxAge)
    {
        if (e.Timestamp is not DateTimeOffset ts) return false;
        var end = report.PeriodoAnalizadoFin != default ? report.PeriodoAnalizadoFin : report.Fin;
        return ts <= end && end - ts <= maxAge;
    }

    private static bool SharesTlsIdentity(DiagnosticEvent left, DiagnosticEvent right)
    {
        static IEnumerable<string> Values(DiagnosticEvent e)
        {
            string[] keys = ["Endpoint", "Host", "Servidor", "Puerto", "Port", "Certificado", "Thumbprint", "Huella"];
            foreach (var key in keys)
            {
                var value = EvidenceReader.Value(e, key);
                if (!string.IsNullOrWhiteSpace(value) && !value.Equals("N/D", StringComparison.OrdinalIgnoreCase))
                    yield return value.Trim();
            }
        }

        var l = Values(left).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var r = Values(right).ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (l.Overlaps(r)) return true;

        // Si una fuente no estructuró el dato, aceptar únicamente un token de identidad
        // suficientemente específico presente en ambos textos; nunca sólo proximidad temporal.
        var lt = $"{left.Mensaje} {left.Archivo} {left.Componente}";
        var rt = $"{right.Mensaje} {right.Archivo} {right.Componente}";
        foreach (var token in l.Concat(r).Where(x => x.Length >= 4))
            if (lt.Contains(token, StringComparison.OrdinalIgnoreCase) && rt.Contains(token, StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

    private static bool IsDefenderEvent(DiagnosticEvent e) =>
        e.Tipo is "DEFENDER_THREAT_DETECTED" or "DEFENDER_ACTION_TAKEN";

    private static bool TouchesTsplus(DiagnosticEvent e, SystemSnapshot system)
    {
        var text = $"{e.Mensaje} {e.Archivo}";
        if (!string.IsNullOrWhiteSpace(system.TsplusRuta) && text.Contains(system.TsplusRuta, StringComparison.OrdinalIgnoreCase)) return true;
        string[] markers = ["TSplus", "\\wsession", "logonsession.exe", "alternateshell.exe", "removelastfolders.exe", "svcr.exe"];
        return markers.Any(m => text.Contains(m, StringComparison.OrdinalIgnoreCase));
    }

    private static DiagnosticEvent? FindMissingFileMatch(DiagnosticReport report, DiagnosticEvent defenderEvent)
    {
        var text = $"{defenderEvent.Mensaje} {defenderEvent.Archivo}";
        return report.Eventos.FirstOrDefault(e =>
        {
            if (e.Tipo == "TSPLUS_FILE_NOT_PRESENT" && !string.IsNullOrWhiteSpace(e.Archivo))
                return text.Contains(Path.GetFileName(e.Archivo), StringComparison.OrdinalIgnoreCase);
            if (e.Tipo != "TSPLUS_MODULE_CRITICAL_FILE_STATE") return false;
            var present = EvidenceValue(e, "Presente");
            var name = EvidenceValue(e, "Nombre");
            return present?.Equals("No", StringComparison.OrdinalIgnoreCase) == true
                   && !string.IsNullOrWhiteSpace(name)
                   && text.Contains(name, StringComparison.OrdinalIgnoreCase);
        });
    }

    private static string? EventIdentity(DiagnosticEvent e)
    {
        var user = EvidenceValue(e, "Usuario") ?? EvidenceValue(e, "User");
        var domain = EvidenceValue(e, "Dominio") ?? EvidenceValue(e, "Domain");
        if (string.IsNullOrWhiteSpace(user)) return null;
        if (user.Contains('\\')) return user.Trim();
        return string.IsNullOrWhiteSpace(domain) || domain == "N/D" ? user.Trim() : $"{domain}\\{user}";
    }

    private static bool SameIdentity(string left, string right)
    {
        static string Normalize(string value)
        {
            var v = value.Trim();
            var slash = v.LastIndexOf('\\');
            return slash >= 0 && slash < v.Length - 1 ? v[(slash + 1)..] : v;
        }
        return left.Equals(right, StringComparison.OrdinalIgnoreCase) ||
               Normalize(left).Equals(Normalize(right), StringComparison.OrdinalIgnoreCase);
    }

    private static string? EvidenceValue(DiagnosticEvent e, string key) =>
        e.Evidencia?.FirstOrDefault(x => x.Clave.Equals(key, StringComparison.OrdinalIgnoreCase))?.Valor;

    private static bool IsClose(DiagnosticEvent a, DiagnosticEvent b, TimeSpan maxDelta)
    {
        if (a.Timestamp is not DateTimeOffset ats || b.Timestamp is not DateTimeOffset bts) return false;
        return (ats - bts).Duration() <= maxDelta;
    }

    private static bool IsUnderTsplus(string? path, string? tsplusRoot)
    {
        if (string.IsNullOrWhiteSpace(path) || string.IsNullOrWhiteSpace(tsplusRoot)) return false;
        try
        {
            var fullPath = Path.GetFullPath(path);
            var fullRoot = Path.GetFullPath(tsplusRoot).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
            return fullPath.StartsWith(fullRoot, StringComparison.OrdinalIgnoreCase);
        }
        catch { return false; }
    }

    private static bool IsCommonWindowsFaultModule(string? module, string? modulePath)
    {
        string[] common = ["ntdll.dll", "kernelbase.dll", "kernel32.dll", "ucrtbase.dll", "msvcrt.dll"];
        if (!string.IsNullOrWhiteSpace(module) && common.Contains(module, StringComparer.OrdinalIgnoreCase)) return true;
        return !string.IsNullOrWhiteSpace(modulePath) &&
               modulePath.Contains("\\Windows\\System32\\", StringComparison.OrdinalIgnoreCase) &&
               common.Any(x => modulePath.EndsWith(x, StringComparison.OrdinalIgnoreCase));
    }

    private static IReadOnlyList<EvidenceItem> CompactEvidence(params EvidenceItem[] items) =>
        items.Where(x => !string.IsNullOrWhiteSpace(x.Valor)).ToList();

    private static IReadOnlyList<EvidenceItem> Merge(
        IReadOnlyList<EvidenceItem> source,
        params EvidenceItem?[] extra)
    {
        var list = new List<EvidenceItem>(source);
        list.AddRange(extra.Where(x => x is not null).Select(x => x!));
        return list;
    }

    private static bool IsStrongRemoteAccessSymptomForAd(DiagnosticEvent e)
    {
        if (e.Tipo is "RDP_SHELL_START_GAP" or "RDP_SHELL_START_DELAY" or "USER_NLA_PASSWORD_FAILURE") return true;
        if (e.Tipo.Equals("SESSION", StringComparison.OrdinalIgnoreCase)) return false;
        var text = $"{e.Tipo} {e.Mensaje} {e.Codigo}";
        if (text.Contains("0x800708CA", StringComparison.OrdinalIgnoreCase)
            || text.Contains("0x80070040", StringComparison.OrdinalIgnoreCase)
            || text.Contains("0x8007139F", StringComparison.OrdinalIgnoreCase)
            || text.Contains("Event_Disconnect", StringComparison.OrdinalIgnoreCase)) return false;
        return (e.Severidad is DiagnosticSeverity.Error or DiagnosticSeverity.Critico) && !e.Fuente.Equals("TDM", StringComparison.OrdinalIgnoreCase);
    }

    private static bool SameApplication(DiagnosticEvent e, string appName)
    {
        var evApp = EvidenceValue(e, "Aplicación") ?? e.Componente;
        if (evApp.Equals(appName, StringComparison.OrdinalIgnoreCase)) return true;
        return e.Mensaje.Contains(appName, StringComparison.OrdinalIgnoreCase);
    }

    private static bool MentionsSameService(DiagnosticEvent e, string appName)
    {
        var stem = Path.GetFileNameWithoutExtension(appName);
        if (string.IsNullOrWhiteSpace(stem)) return false;
        if (e.Mensaje.Contains(stem, StringComparison.OrdinalIgnoreCase)) return true;
        if (stem.Contains("ServerMonitoring", StringComparison.OrdinalIgnoreCase) && e.Mensaje.Contains("TSplus-ServerMonitoring", StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

    private static string? ExtractDotNetType(string message)
    {
        const string marker = "Información de la excepción:";
        var idx = message.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
        if (idx < 0) return null;
        var tail = message[(idx + marker.Length)..].TrimStart();
        var end = tail.IndexOfAny(['\r','\n']);
        return (end >= 0 ? tail[..end] : tail).Trim();
    }

    private static TsplusProduct ProductFromText(string text)
    {
        if (text.Contains("ServerMonitoring", StringComparison.OrdinalIgnoreCase)) return TsplusProduct.ServerMonitoring;
        if (text.Contains("TSplus-Security", StringComparison.OrdinalIgnoreCase) || text.Contains("Advanced Security", StringComparison.OrdinalIgnoreCase)) return TsplusProduct.AdvancedSecurity;
        if (text.Contains("RemoteSupport", StringComparison.OrdinalIgnoreCase) || text.Contains("Remote Support", StringComparison.OrdinalIgnoreCase)) return TsplusProduct.RemoteSupport;
        if (text.Contains("TwoFactor", StringComparison.OrdinalIgnoreCase) || text.Contains("2FA", StringComparison.OrdinalIgnoreCase)) return TsplusProduct.TwoFactorAuthentication;
        if (text.Contains("TSplus", StringComparison.OrdinalIgnoreCase) || text.Contains("Application Publishing", StringComparison.OrdinalIgnoreCase) || text.Contains("APSC", StringComparison.OrdinalIgnoreCase)) return TsplusProduct.RemoteAccess;
        return TsplusProduct.Desconocido;
    }

    private static string ProductName(TsplusProduct p) => p switch
    {
        TsplusProduct.RemoteAccess => "TSplus Remote Access",
        TsplusProduct.TwoFactorAuthentication => "TSplus 2FA",
        TsplusProduct.AdvancedSecurity => "TSplus Advanced Security",
        TsplusProduct.ServerMonitoring => "TSplus Server Monitoring",
        TsplusProduct.RemoteSupport => "TSplus Remote Support",
        _ => "producto TSplus"
    };

    private static string OriginFromLayer(DiagnosticLayer layer) => layer switch
    {
        DiagnosticLayer.Tsplus => "TSPLUS",
        DiagnosticLayer.Windows or DiagnosticLayer.Rdp or DiagnosticLayer.Red or DiagnosticLayer.Seguridad => "WINDOWS",
        _ => "INDETERMINADO"
    };

    private static RootCauseCandidate ToCandidate(CandidateDraft draft, int position)
    {
        var guidance = draft.GuidanceId is null ? null : OfficialKnowledgeBase.Get(draft.GuidanceId);
        return new RootCauseCandidate(
            position,
            draft.Id,
            draft.Component,
            draft.Layer,
            Math.Clamp(draft.Score, 0, 100),
            draft.Confidence,
            draft.Summary,
            draft.Explanation,
            draft.Evidence,
            guidance?.SolucionSugerida,
            guidance is null ? null : $"{guidance.Vendor} — {guidance.Titulo}",
            guidance?.Url,
            draft.Product == TsplusProduct.Desconocido ? ProductFromText(draft.Component) : draft.Product,
            draft.IncidentTime,
            draft.OriginCategory == "INDETERMINADO" ? OriginFromLayer(draft.Layer) : draft.OriginCategory,
            draft.CausalRole);
    }
}
