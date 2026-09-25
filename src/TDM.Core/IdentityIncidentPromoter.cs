using TDM.Models;

namespace TDM.Core;

/// <summary>
/// Mantiene los eventos Security de autenticación como señales hasta que exista una correlación
/// demostrable con un síntoma RDP/TSplus del mismo usuario/dominio y ventana temporal.
/// </summary>
public static class IdentityIncidentPromoter
{
    private static readonly HashSet<string> IdentityKinds = new(StringComparer.OrdinalIgnoreCase)
    {
        "ACCOUNT_LOCKOUT", "USER_LOGON_FAILURE", "USER_NLA_PASSWORD_FAILURE",
        "KERBEROS_PREAUTH_FAILURE", "WINDOWS_CREDENTIAL_VALIDATION_FAILURE"
    };

    public static IReadOnlyList<DiagnosticEvent> Promote(IEnumerable<DiagnosticEvent> input, TimeSpan? correlationWindow = null)
    {
        var events = input.ToList();
        var window = correlationWindow ?? TimeSpan.FromMinutes(5);
        var output = new List<DiagnosticEvent>(events.Count);

        foreach (var evt in events)
        {
            if (!IdentityKinds.Contains(evt.Tipo))
            {
                output.Add(evt);
                continue;
            }

            var user = NormalizeIdentity(EvidenceReader.Value(evt, "Usuario", "TargetUserName", "User"));
            var domain = NormalizeIdentity(EvidenceReader.Value(evt, "Dominio", "TargetDomainName", "Domain"));
            var ts = evt.Timestamp;
            if (string.IsNullOrWhiteSpace(user) || user == "n/d" || ts is null)
            {
                output.Add(Demote(evt, "Sin identidad o timestamp demostrable"));
                continue;
            }

            var correlated = events.Any(candidate =>
            {
                if (ReferenceEquals(candidate, evt) || IdentityKinds.Contains(candidate.Tipo)) return false;
                if (candidate.Severidad is not (DiagnosticSeverity.Error or DiagnosticSeverity.Critico)) return false;
                if (candidate.Capa is not (DiagnosticLayer.Rdp or DiagnosticLayer.Tsplus)) return false;
                var cts = candidate.Timestamp;
                if (cts is null || Math.Abs((cts.Value - ts.Value).TotalSeconds) > window.TotalSeconds) return false;
                var cUser = NormalizeIdentity(EvidenceReader.Value(candidate, "Usuario", "TargetUserName", "User"));
                if (string.IsNullOrWhiteSpace(cUser) || cUser == "n/d" || !string.Equals(cUser, user, StringComparison.OrdinalIgnoreCase)) return false;
                var cDomain = NormalizeIdentity(EvidenceReader.Value(candidate, "Dominio", "TargetDomainName", "Domain"));
                if (!string.IsNullOrWhiteSpace(domain) && domain != "n/d" && !string.IsNullOrWhiteSpace(cDomain) && cDomain != "n/d"
                    && !string.Equals(domain, cDomain, StringComparison.OrdinalIgnoreCase)) return false;
                return true;
            });

            if (!correlated)
            {
                output.Add(Demote(evt, "Sin síntoma RDP/TSplus severo de la misma identidad en la ventana"));
                continue;
            }

            var evidence = (evt.Evidencia ?? []).Concat([
                new EvidenceItem("Correlación funcional", "Confirmada"),
                new EvidenceItem("Regla", "misma identidad + síntoma RDP/TSplus ERROR/CRÍTICO + ventana temporal")
            ]).ToList();
            output.Add(evt with { Severidad = DiagnosticSeverity.Error, Evidencia = evidence });
        }

        return output;
    }

    private static DiagnosticEvent Demote(DiagnosticEvent evt, string reason)
    {
        var evidence = (evt.Evidencia ?? []).Concat([
            new EvidenceItem("Correlación funcional", "No confirmada"),
            new EvidenceItem("Regla", reason)
        ]).ToList();
        return evt with { Severidad = DiagnosticSeverity.Advertencia, Evidencia = evidence };
    }

    private static string? NormalizeIdentity(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        var v = value.Trim();
        var slash = v.LastIndexOf('\\');
        return (slash >= 0 ? v[(slash + 1)..] : v).Trim().ToLowerInvariant();
    }
}
