using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using TDM.Models;

namespace TDM.Reporting;

/// <summary>
/// Genera una representación pseudonimizada para el paquete de soporte.
/// No modifica el reporte en memoria ni los archivos originales del servidor.
/// RC18.14 endurece secretos ES/EN, Bearer, IPv6 y evita confundir claves técnicas con IP.
/// </summary>
public static class SupportBundleSanitizer
{
    private static readonly HashSet<string> ExactIpKeys = new(StringComparer.OrdinalIgnoreCase)
    {
        "ip", "ipv4", "ipv6", "direccion ip", "dirección ip", "ip origen", "ip destino",
        "source ip", "destination ip", "remote address", "remoteaddress", "client address", "clientaddress",
        "source address", "destination address"
    };

    private static readonly Regex SecretAssignmentRegex = new(
        """(?i)(?<prefix>["']?(?:password|contraseña|passwd|pwd|token|secret|secreto|credential|credencial|api[_ -]?key|apikey|client[_ -]?secret|private[_ -]?key|clave[_ -]?privada|license[_ -]?key|serial[_ -]?key|otp|totp|one[_ -]?time[_ -]?password|verification[_ -]?code|authentication[_ -]?code|auth[_ -]?code|2fa[_ -]?code|qr[_ -]?secret)["']?\s*[:=]\s*)(?<value>["'][^"']*["']|[^\s,;}&]+)""",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex AuthorizationBearerRegex = new(
        @"(?i)(?<prefix>authorization\s*[:=]\s*bearer\s+)(?<value>[A-Z0-9._~+/=-]+)",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex XmlSecretRegex = new(
        @"(?is)(?<open><\s*(?:password|contraseña|passwd|pwd|token|secret|secreto|credential|credencial|apikey|api_key|client_secret|otp|totp|one_time_password|verification_code|authentication_code|auth_code|2fa_code|qr_secret)\b[^>]*>)(?<value>.*?)(?<close><\s*/\s*(?:password|contraseña|passwd|pwd|token|secret|secreto|credential|credencial|apikey|api_key|client_secret|otp|totp|one_time_password|verification_code|authentication_code|auth_code|2fa_code|qr_secret)\s*>)",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex UserPathRegex = new(
        @"(?i)\b(?<root>[A-Z]:\\Users)\\(?<user>[^\\/\r\n]+?)(?=\\|/|$)",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex UncUserPathRegex = new(
        @"(?i)(?<prefix>\\\\)(?<host>[^\\/\s]+)\\(?<share>(?:[A-Z]\$\\)?Users)\\(?<user>[^\\/\r\n]+?)(?=\\|/|$)",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    // Soporta dominio\usuario en mayúsculas o minúsculas. Los lookbehind evitan volver a
    // interpretar pseudónimos generados por TDM como si fueran una identidad nueva.
    private static readonly Regex DomainUserRegex = new(
        @"(?i)(?<!DOM-)(?<!USR-)(?<!HOST-)(?<!MAIL-)(?<![A-Za-z]:)(?<![\\/])\b(?!DOM-|USR-|HOST-|IP-|MAIL-)(?<domain>[A-Za-z0-9][A-Za-z0-9._-]{1,})\\(?<user>[A-Za-z0-9._ -]{2,})\b",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex Ipv4Regex = new(
        @"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex Ipv6CandidateRegex = new(
        @"(?<![0-9A-Fa-f:])(?=[0-9A-Fa-f:]*:[0-9A-Fa-f:]*:)[0-9A-Fa-f:]{3,}(?![0-9A-Fa-f:])",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex EmailRegex = new(
        @"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
        RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    private static readonly Regex LabeledUserRegex = new(
        @"(?im)(?<prefix>\b(?:Usuario|User|Username|Nombre de usuario)\s*:\s*)(?<value>[^\r\n<|]+)",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex LabeledDomainRegex = new(
        @"(?im)(?<prefix>\b(?:Dominio|Domain)\s*:\s*)(?<value>[A-Za-z0-9._-]{2,})",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex LabeledClientRegex = new(
        @"(?im)(?<prefix>\b(?:Cliente|Client|Equipo cliente|Client name)\s*:\s*)(?<value>[^\r\n<|]+)",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex DomainPhraseRegex = new(
        @"(?<prefix>\ben el dominio\s+)(?<value>[A-Z][A-Z0-9._-]{1,})\b",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex SidRegex = new(
        @"\bS-1-(?:\d+-){2,}\d+\b",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);


    public static DiagnosticReport Sanitize(DiagnosticReport report)
    {
        var system = report.Sistema with
        {
            Equipo = Pseudonym("HOST", report.Sistema.Equipo),
            TsplusRuta = SanitizeText(report.Sistema.TsplusRuta)
        };

        var findings = report.Hallazgos.Select(SanitizeFinding).ToList();
        var events = report.Eventos.Select(SanitizeEvent).ToList();
        var causes = report.CausasRaiz.Select(SanitizeCause).ToList();
        var patterns = report.PatronesFalla.Select(p => p with
        {
            Componente = SanitizeText(p.Componente) ?? p.Componente,
            ComponenteSemantico = SanitizeText(p.ComponenteSemantico) ?? p.ComponenteSemantico,
            Evidencia = p.Evidencia.Select(SanitizeEvidence).ToList()
        }).ToList();

        return report with
        {
            Sistema = system,
            Hallazgos = findings,
            Eventos = events,
            CausasRaiz = causes,
            PatronesFalla = patterns,
            ResolucionesGuiadas = report.ResolucionesGuiadas.Select(SanitizeGuidedResolution).ToList(),
            ImpactoFuncional = SanitizeImpact(report.ImpactoFuncional),
            PlanAccion = SanitizePlan(report.PlanAccion),
            CoberturaDiagnostica = SanitizeCoverage(report.CoberturaDiagnostica)
        };
    }

    private static DiagnosticFinding SanitizeFinding(DiagnosticFinding f) => f with
    {
        Componente = SanitizeText(f.Componente) ?? f.Componente,
        Resumen = SanitizeText(f.Resumen) ?? f.Resumen,
        Detalle = SanitizeText(f.Detalle) ?? f.Detalle,
        Evidencia = f.Evidencia.Select(SanitizeEvidence).ToList(),
        SolucionSugerida = SanitizeText(f.SolucionSugerida)
    };

    private static DiagnosticEvent SanitizeEvent(DiagnosticEvent e) => e with
    {
        Fuente = SanitizeText(e.Fuente) ?? e.Fuente,
        Componente = SanitizeText(e.Componente) ?? e.Componente,
        Mensaje = SanitizeText(e.Mensaje) ?? e.Mensaje,
        Codigo = SanitizeText(e.Codigo),
        Archivo = SanitizePath(e.Archivo),
        Evidencia = e.Evidencia?.Select(SanitizeEvidence).ToList()
    };

    private static RootCauseCandidate SanitizeCause(RootCauseCandidate c) => c with
    {
        Componente = SanitizeText(c.Componente) ?? c.Componente,
        Resumen = SanitizeText(c.Resumen) ?? c.Resumen,
        Explicacion = SanitizeText(c.Explicacion) ?? c.Explicacion,
        Evidencia = c.Evidencia.Select(SanitizeEvidence).ToList(),
        SolucionSugerida = SanitizeText(c.SolucionSugerida)
    };

    private static GuidedResolutionResult SanitizeGuidedResolution(GuidedResolutionResult result) => result with
    {
        Componente = SanitizeText(result.Componente) ?? result.Componente,
        Sintoma = SanitizeText(result.Sintoma) ?? result.Sintoma,
        CausaProbable = SanitizeText(result.CausaProbable) ?? result.CausaProbable,
        Impacto = SanitizeText(result.Impacto) ?? result.Impacto,
        Comprobaciones = result.Comprobaciones.Select(c => c with
        {
            Nombre = SanitizeText(c.Nombre) ?? c.Nombre,
            Estado = SanitizeText(c.Estado) ?? c.Estado,
            Detalle = SanitizeText(c.Detalle) ?? c.Detalle
        }).ToList(),
        Evidencia = result.Evidencia.Select(SanitizeEvidence).ToList(),
        ComoCorregir = result.ComoCorregir.Select(x => SanitizeText(x) ?? x).ToList(),
        ComoValidar = result.ComoValidar.Select(x => SanitizeText(x) ?? x).ToList(),
        NoHacerPrimero = result.NoHacerPrimero.Select(x => SanitizeText(x) ?? x).ToList(),
        Cobertura = SanitizeText(result.Cobertura) ?? result.Cobertura
    };

    private static FunctionalImpactAssessment? SanitizeImpact(FunctionalImpactAssessment? impact)
    {
        if (impact is null) return null;
        return impact with
        {
            Resumen = SanitizeText(impact.Resumen) ?? impact.Resumen,
            Impactos = impact.Impactos.Select(i => i with
            {
                Funcion = SanitizeText(i.Funcion) ?? i.Funcion,
                Modulo = SanitizeText(i.Modulo) ?? i.Modulo,
                Resumen = SanitizeText(i.Resumen) ?? i.Resumen,
                Evidencia = i.Evidencia.Select(SanitizeEvidence).ToList()
            }).ToList()
        };
    }

    private static SafeActionPlan? SanitizePlan(SafeActionPlan? plan)
    {
        if (plan is null) return null;
        SafeActionItem Clean(SafeActionItem i) => i with
        {
            Accion = SanitizeText(i.Accion) ?? i.Accion,
            Motivo = SanitizeText(i.Motivo) ?? i.Motivo
        };
        return plan with
        {
            Resumen = SanitizeText(plan.Resumen) ?? plan.Resumen,
            DondeEmpezar = plan.DondeEmpezar.Select(Clean).ToList(),
            NoTocarPrimero = plan.NoTocarPrimero.Select(Clean).ToList(),
            Verificaciones = plan.Verificaciones.Select(Clean).ToList()
        };
    }

    private static DiagnosticCoverageAssessment? SanitizeCoverage(DiagnosticCoverageAssessment? coverage)
    {
        if (coverage is null) return null;
        return coverage with
        {
            Resumen = SanitizeText(coverage.Resumen) ?? coverage.Resumen,
            Fuentes = coverage.Fuentes.Select(f => f with { Detalle = SanitizeText(f.Detalle) ?? f.Detalle }).ToList(),
            Limitaciones = coverage.Limitaciones.Select(x => SanitizeText(x) ?? x).ToList()
        };
    }

    private static EvidenceItem SanitizeEvidence(EvidenceItem item)
    {
        if (IsSecretKey(item.Clave)) return new EvidenceItem(item.Clave, "[REDACTADO]");
        if (IsIdentityKey(item.Clave)) return new EvidenceItem(item.Clave, Pseudonym("USR", item.Valor));
        if (IsDomainKey(item.Clave)) return new EvidenceItem(item.Clave, Pseudonym("DOM", item.Valor));
        if (IsClientIdentityKey(item.Clave)) return new EvidenceItem(item.Clave, Pseudonym("HOST", item.Valor));
        if (IsIpKey(item.Clave)) return new EvidenceItem(item.Clave, Pseudonym("IP", item.Valor));
        if (item.Clave.Contains("Archivo", StringComparison.OrdinalIgnoreCase) || item.Clave.Contains("Ruta", StringComparison.OrdinalIgnoreCase))
            return new EvidenceItem(item.Clave, SanitizePath(item.Valor) ?? string.Empty);
        return new EvidenceItem(item.Clave, SanitizeText(item.Valor) ?? string.Empty);
    }

    private static bool IsSecretKey(string key)
    {
        var k = NormalizeKey(key);
        var tokens = new[]
        {
            "password", "contraseña", "passwd", "pwd", "token", "secret", "secreto", "credential", "credencial",
            "api key", "apikey", "private key", "clave privada", "client secret", "license key", "serial key",
            "authorization", "bearer", "password hash", "credential hash", "otp", "totp", "one time password",
            "one-time password", "verification code", "authentication code", "auth code", "2fa code", "qr secret"
        };
        return tokens.Any(x => k.Contains(x, StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsIdentityKey(string key)
    {
        var k = NormalizeKey(key);
        return k is "usuario" or "user" or "cuenta" or "nombre de usuario" or "nombre completo" or "usuario afectado"
               || k.Contains("targetuser", StringComparison.OrdinalIgnoreCase)
               || k.Contains("account name", StringComparison.OrdinalIgnoreCase)
               || k.Contains("usuarios asignados", StringComparison.OrdinalIgnoreCase)
               || k.Contains("grupos asignados", StringComparison.OrdinalIgnoreCase)
               || k.Contains("assigned users", StringComparison.OrdinalIgnoreCase)
               || k.Contains("assigned groups", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsDomainKey(string key)
    {
        var k = NormalizeKey(key);
        return k is "dominio" or "domain" or "targetdomainname" or "account domain";
    }

    private static bool IsClientIdentityKey(string key)
    {
        var k = NormalizeKey(key);
        return k is "cliente" or "client" or "nombre de cliente" or "client name" or "equipo cliente" or "client device";
    }

    private static bool IsIpKey(string key)
    {
        var k = NormalizeKey(key);
        if (ExactIpKeys.Contains(k)) return true;
        return k.StartsWith("ip ", StringComparison.OrdinalIgnoreCase)
               || k.EndsWith(" ip", StringComparison.OrdinalIgnoreCase)
               || k.Contains("direccion ip", StringComparison.OrdinalIgnoreCase)
               || k.Contains("dirección ip", StringComparison.OrdinalIgnoreCase);
    }

    private static string NormalizeKey(string? key)
        => Regex.Replace((key ?? string.Empty).Trim(), @"\s+", " ");

    public static string? SanitizePath(string? value)
        => SanitizeText(value);

    public static string? SanitizeText(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return value;
        var output = value;
        output = AuthorizationBearerRegex.Replace(output, m => $"{m.Groups["prefix"].Value}[REDACTADO]");
        output = XmlSecretRegex.Replace(output, m => $"{m.Groups["open"].Value}[REDACTADO]{m.Groups["close"].Value}");
        output = SecretAssignmentRegex.Replace(output, m => $"{m.Groups["prefix"].Value}[REDACTADO]");

        // Las rutas de perfil se procesan ANTES de dominio\usuario. Así se evita que una
        // porción de un pseudónimo (USR-XXXXXXXX) o un segmento de ruta se reinterprete
        // como identidad. Cada valor sensible se pseudonimiza siempre; no se confía en
        // prefijos que podrían pertenecer a un nombre real con formato similar.
        output = UncUserPathRegex.Replace(output, UncUserPathEvaluator);
        output = UserPathRegex.Replace(output, UserPathEvaluator);
        output = DomainUserRegex.Replace(output, DomainUserEvaluator);
        output = LabeledUserRegex.Replace(output, m => $"{m.Groups["prefix"].Value}{Pseudonym("USR", m.Groups["value"].Value.Trim())}");
        output = LabeledDomainRegex.Replace(output, m => $"{m.Groups["prefix"].Value}{Pseudonym("DOM", m.Groups["value"].Value.Trim())}");
        output = LabeledClientRegex.Replace(output, m => $"{m.Groups["prefix"].Value}{Pseudonym("HOST", m.Groups["value"].Value.Trim())}");
        output = DomainPhraseRegex.Replace(output, m => $"{m.Groups["prefix"].Value}{Pseudonym("DOM", m.Groups["value"].Value)}");
        output = SidRegex.Replace(output, m => Pseudonym("SID", m.Value));

        output = EmailRegex.Replace(output, m => Pseudonym("MAIL", m.Value));
        output = Ipv4Regex.Replace(output, m => Pseudonym("IP", m.Value));
        output = Ipv6CandidateRegex.Replace(output, Ipv6Evaluator);
        return output;
    }

    private static string UserPathEvaluator(Match match)
    {
        var user = match.Groups["user"].Value;
        return $"{match.Groups["root"].Value}\\{Pseudonym("USR", user)}";
    }

    private static string UncUserPathEvaluator(Match match)
    {
        var host = match.Groups["host"].Value;
        var user = match.Groups["user"].Value;
        return $@"\\{Pseudonym("HOST", host)}\{match.Groups["share"].Value}\{Pseudonym("USR", user)}";
    }

    private static string DomainUserEvaluator(Match match)
    {
        var domain = match.Groups["domain"].Value;
        var user = match.Groups["user"].Value;
        var pathRoots = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "HKLM", "HKCU", "HKCR", "HKU", "HKEY_LOCAL_MACHINE", "HKEY_CURRENT_USER",
            "Windows", "System32", "Clients", "UserDesktop", "wsession", "ProgramData", "Users", "Temp", "Software"
        };
        if (pathRoots.Contains(domain)) return match.Value;
        return $"{Pseudonym("DOM", domain)}\\{Pseudonym("USR", user)}";
    }

    private static string Ipv6Evaluator(Match match)
    {
        if (IPAddress.TryParse(match.Value, out var address) && address.AddressFamily == AddressFamily.InterNetworkV6)
            return Pseudonym("IP", match.Value);
        return match.Value;
    }

    private static string Pseudonym(string prefix, string? value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Equals("N/D", StringComparison.OrdinalIgnoreCase)) return value ?? "N/D";
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(value.Trim().ToUpperInvariant()));
        return $"{prefix}-{Convert.ToHexString(hash)[..8]}";
    }
}
