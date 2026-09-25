using System.Globalization;
using System.Text.RegularExpressions;
using TDM.Models;

namespace TDM.Collectors.TSplus;

public static partial class TsplusLogParser
{
    private static readonly string[] CriticalTokens =
    [
        "fatal", "critical", "panic", "catastrophic"
    ];

    private static readonly string[] ErrorTokens =
    [
        "error", "exception", "crash", "failed", "failure",
        "cannot", "can't", "unable", "access denied", "file not found",
        "connection refused", "address already in use"
    ];

    public static DiagnosticEvent? ParseLine(
        string sourceComponent,
        string filePath,
        string line,
        int lineNumber,
        DiagnosticContext context,
        DiagnosticLayer layer = DiagnosticLayer.Tsplus,
        string sourceName = "TSplus Log",
        TsplusProduct product = TsplusProduct.RemoteAccess,
        TsplusReleaseProfile? profile = null)
    {
        if (string.IsNullOrWhiteSpace(line)) return null;

        // Las trazas de pila contienen términos como timeoutMs, Prepare(), etc.
        // No son eventos autónomos y no deben convertirse en falsos positivos.
        if (LooksLikeStackTrace(line)) return null;

        var timestamp = TryParseTimestamp(line, context);
        if (timestamp.HasValue && !IsInsideWindow(timestamp.Value, context)) return null;

        var severity = ClassifySeverity(line);
        if (severity == DiagnosticSeverity.Informativo) return null;

        var type = ClassifyType(line, severity);
        var evidence = new List<EvidenceItem>
        {
            new("Log", filePath),
            new("Línea", lineNumber.ToString()),
            new("Correlación temporal", timestamp.HasValue ? "Disponible" : "No disponible")
        };
        var user = ExtractExplicitUser(line);
        if (!string.IsNullOrWhiteSpace(user)) evidence.Add(new EvidenceItem("Usuario", user));

        return new DiagnosticEvent(
            timestamp,
            sourceName,
            sourceComponent,
            layer,
            severity,
            type,
            line.Trim(),
            ExtractErrorCode(line),
            filePath,
            lineNumber,
            evidence,
            product,
            IngestedAt: DateTimeOffset.Now);
    }

    private static bool IsInsideWindow(DateTimeOffset timestamp, DiagnosticContext context)
        => DiagnosticWindow.Resolve(context).Contains(timestamp);

    private static DiagnosticSeverity ClassifySeverity(string line)
    {
        // Si el propio log declara un nivel, éste manda. Evita etiquetar como Error
        // una línea WARN sólo porque el texto contiene la palabra "error".
        if (Regex.IsMatch(line, @"^\s*(?:\[[^\]]+\]\s*)?DEBUG\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
            return DiagnosticSeverity.Informativo;
        if (Regex.IsMatch(line, @"^\s*(?:\[[^\]]+\]\s*)?(?:FATAL|CRITICAL)\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
            return DiagnosticSeverity.Critico;
        if (Regex.IsMatch(line, @"^\s*(?:\[[^\]]+\]\s*)?(?:ERROR|ERR)\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
            return DiagnosticSeverity.Error;
        if (Regex.IsMatch(line, @"^\s*(?:\[[^\]]+\]\s*)?(?:WARNING|WARN)\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
            return DiagnosticSeverity.Advertencia;

        // Resúmenes sanos como "errors: 0", "0 failures" o "without error" no deben
        // convertirse en ERROR sólo por contener una palabra negativa. Se eliminan únicamente
        // esas expresiones benignas; cualquier otra señal negativa de la misma línea permanece.
        var signalLine = BenignFailureSummaryRegex().Replace(line, " ");

        if (CriticalTokens.Any(t => signalLine.Contains(t, StringComparison.OrdinalIgnoreCase)))
            return DiagnosticSeverity.Critico;

        if (ErrorTokens.Any(t => signalLine.Contains(t, StringComparison.OrdinalIgnoreCase)))
            return DiagnosticSeverity.Error;

        if (WarningRegex().IsMatch(signalLine))
            return DiagnosticSeverity.Advertencia;

        return DiagnosticSeverity.Informativo;
    }

    private static string ClassifyType(string line, DiagnosticSeverity severity)
    {
        if (ContainsAny(line, "access denied", "unauthorized")) return "ACCESS_DENIED";
        if (ContainsAny(line, "file not found", "cannot find", "missing file")) return "FILE_NOT_FOUND";
        if (TimeoutRegex().IsMatch(line)) return "TIMEOUT";
        if (ContainsAny(line, "certificate", "ssl", "tls")) return "CERTIFICATE_OR_TLS";
        // P21: JAVA antes que LICENSE: una línea con ambos ("openjdk ... license ...") es
        // evidencia del runtime JVM, y la señal LICENSE se pierde con el orden inverso.
        if (ContainsAny(line, "java", "openjdk")) return "JAVA";
        if (ContainsAny(line, "license", "licence")) return "LICENSE";
        if (ContainsAny(line,
            "appcontrol", "published application", "application publishing", "start application", "starting application",
            "launch application", "application failed", "failed to start application", "application not found",
            "createprocess", "initial program", "startup program", "start program", "shell application")) return "APPLICATION_PUBLISHING";
        if (ContainsAny(line,
            "html5", "html5service", "httpwebs", "websocket", "xhr", "web server", "web portal", "cgi-bin",
            "http server", "gateway", "weblog")) return "WEB";
        if (ContainsAny(line, "connection client", "rdp6", "remoteapp client", "client generator", "seamless client")) return "CONNECTION_CLIENT";
        if (ContainsAny(line, "universal printer", "virtual printer", "novapdf", "print job", "printing", "printer")) return "PRINTING";
        if (ContainsAny(line, "sqlite", "database is locked", "sql logic error")) return "DATABASE";
        if (ContainsAny(line, "session", "logon", "login", "logonsession", "apsc")) return "SESSION";
        if (ContainsAny(line, "address already in use", "failed to bind", "cannot bind")) return "PORT_BIND";
        if (ContainsAny(line, "exception", "fatal", "crash")) return "EXCEPTION";
        if (ContainsAny(line, "failed", "failure", "unable", "cannot")) return "OPERATION_FAILED";
        return severity switch
        {
            DiagnosticSeverity.Critico => "LOG_CRITICAL",
            DiagnosticSeverity.Error => "LOG_ERROR",
            DiagnosticSeverity.Advertencia => "LOG_WARNING",
            _ => "LOG_EVENT"
        };
    }

    public static bool IsContinuationLine(string line)
    {
        if (string.IsNullOrWhiteSpace(line)) return false;
        var t = line.TrimStart();
        return LooksLikeStackTrace(line)
               || line.Length > t.Length
               || t.StartsWith("--->", StringComparison.OrdinalIgnoreCase)
               || t.StartsWith("Inner Exception", StringComparison.OrdinalIgnoreCase)
               || t.StartsWith("Caused by", StringComparison.OrdinalIgnoreCase);
    }

    private static bool LooksLikeStackTrace(string line)
    {
        var t = line.TrimStart();
        return t.StartsWith("at ", StringComparison.OrdinalIgnoreCase)
            || t.StartsWith("en ", StringComparison.OrdinalIgnoreCase)
            || t.StartsWith("--- End of", StringComparison.OrdinalIgnoreCase)
            || StackFrameRegex().IsMatch(t);
    }


    private static string? ExtractExplicitUser(string line)
    {
        var match = ExplicitUserRegex().Match(line);
        if (!match.Success) return null;
        var value = match.Groups["user"].Value.Trim().Trim('"', '\'');
        if (string.IsNullOrWhiteSpace(value) || value.Length > 160) return null;
        return value;
    }

    private static string? ExtractErrorCode(string line)
    {
        var match = ErrorCodeRegex().Match(line);
        return match.Success ? match.Value : null;
    }

    public static DateTimeOffset? TryParseTimestamp(string line)
        => TryParseTimestampCore(line, null);

    public static DateTimeOffset? TryParseTimestamp(string line, DiagnosticContext context)
        => TryParseTimestampCore(line, context);

    private static DateTimeOffset? TryParseTimestampCore(string line, DiagnosticContext? context)
    {
        var match = TimestampRegex().Match(line);
        if (!match.Success) return null;
        var value = match.Value.Trim('[', ']', '(', ')', ' ');

        // dd/MM y MM/dd son indistinguibles cuando ambos componentes están entre 1 y 12.
        // Si conocemos la ventana de diagnóstico, evaluamos ambas interpretaciones y aceptamos
        // únicamente la que cae de forma inequívoca dentro de esa ventana. Si ambas son plausibles,
        // no inventamos EventTime y la evidencia permanece como contexto no temporal.
        var ambiguous = Regex.Match(value, @"^(?<a>\d{2})[/-](?<b>\d{2})[/-](?<y>\d{4})\s");
        if (ambiguous.Success
            && int.TryParse(ambiguous.Groups["a"].Value, out var a)
            && int.TryParse(ambiguous.Groups["b"].Value, out var b)
            && a is >= 1 and <= 12 && b is >= 1 and <= 12 && a != b)
        {
            var candidates = new List<DateTimeOffset>();
            foreach (var format in new[] { "dd/MM/yyyy HH:mm:ss.fff", "dd/MM/yyyy HH:mm:ss", "MM/dd/yyyy HH:mm:ss.fff", "MM/dd/yyyy HH:mm:ss",
                                           "dd-MM-yyyy HH:mm:ss.fff", "dd-MM-yyyy HH:mm:ss", "MM-dd-yyyy HH:mm:ss.fff", "MM-dd-yyyy HH:mm:ss" })
            {
                if (DateTimeOffset.TryParseExact(value, format, CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal, out var candidate)
                    && !candidates.Any(x => x == candidate))
                    candidates.Add(candidate);
            }

            if (context is null) return null;
            var window = DiagnosticWindow.Resolve(context);
            var inside = candidates.Where(window.Contains).Distinct().ToList();
            return inside.Count == 1 ? inside[0] : null;
        }

        string[] formats =
        [
            "yyyy-MM-dd HH:mm:ss.fff", "yyyy-MM-dd HH:mm:ss",
            "yyyy/MM/dd HH:mm:ss.fff", "yyyy/MM/dd HH:mm:ss",
            "dd/MM/yyyy HH:mm:ss.fff", "dd/MM/yyyy HH:mm:ss",
            "MM/dd/yyyy HH:mm:ss.fff", "MM/dd/yyyy HH:mm:ss",
            "dd-MM-yyyy HH:mm:ss.fff", "dd-MM-yyyy HH:mm:ss",
            "MM-dd-yyyy HH:mm:ss.fff", "MM-dd-yyyy HH:mm:ss",
            "yyyy-MM-dd'T'HH:mm:ss.fffK", "yyyy-MM-dd'T'HH:mm:ssK"
        ];

        foreach (var format in formats)
        {
            if (DateTimeOffset.TryParseExact(value, format, CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeLocal, out var dto)) return dto;
        }

        return DateTimeOffset.TryParse(value, CultureInfo.GetCultureInfo("es-MX"),
            DateTimeStyles.AssumeLocal, out var parsed) ? parsed : null;
    }

    private static bool ContainsAny(string text, params string[] values) =>
        values.Any(v => text.Contains(v, StringComparison.OrdinalIgnoreCase));


    [GeneratedRegex(@"(?i)\b(?:user(?:name)?|usuario|account|login)\s*[:=]\s*[""']?(?<user>[A-Za-z0-9_.@-]+(?:\\[A-Za-z0-9_.@$-]+)?)[""']?", RegexOptions.CultureInvariant)]
    private static partial Regex ExplicitUserRegex();

    [GeneratedRegex(@"(?<!\d)(?:\d{4}[-/]\d{2}[-/]\d{2}|\d{2}[-/]\d{2}[-/]\d{4})[ T]\d{2}:\d{2}:\d{2}(?:[\.,]\d{1,7})?(?:Z|[+-]\d{2}:?\d{2})?", RegexOptions.CultureInvariant)]
    private static partial Regex TimestampRegex();

    [GeneratedRegex(@"(?i)(?:0x[0-9a-f]{4,16}|HRESULT\s*[:=]?\s*0x[0-9a-f]+|error\s*(?:code)?\s*[:=]?\s*-?\d+)", RegexOptions.CultureInvariant)]
    private static partial Regex ErrorCodeRegex();

    [GeneratedRegex(@"(?ix)\b(?:(?:no|without)\s+(?:errors?|failures?|exceptions?)|(?:errors?|failures?|exceptions?|failed\s+attempts?)\s*(?:count\s*)?[:=]\s*(?:0|none|false|n/?a)|0\s+(?:errors?|failures?|exceptions?|failed\s+attempts?)|(?:last\s+)?error\s*[:=]\s*(?:0|none|false|n/?a))\b", RegexOptions.CultureInvariant)]
    private static partial Regex BenignFailureSummaryRegex();

    [GeneratedRegex(@"(?i)\b(?:warning|warn|timeout|timed\s+out|retry|denied|not\s+found|unavailable)\b", RegexOptions.CultureInvariant)]
    private static partial Regex WarningRegex();

    [GeneratedRegex(@"(?i)\b(?:timeout|timed\s+out)\b", RegexOptions.CultureInvariant)]
    private static partial Regex TimeoutRegex();

    [GeneratedRegex(@"(?i)^(?:System|Microsoft|Newtonsoft|TSplus|SQLite|Mono|java|sun)\.[A-Za-z0-9_.`]+(?:\(|:)", RegexOptions.CultureInvariant)]
    private static partial Regex StackFrameRegex();
}
