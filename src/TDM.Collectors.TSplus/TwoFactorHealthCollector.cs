using System.ServiceProcess;
using System.Text;
using System.Text.RegularExpressions;
using TDM.Core;
using TDM.Models;

namespace TDM.Collectors.TSplus;

/// <summary>
/// Diagnóstico dirigido de 2FA. Sólo lee artefactos principales conocidos y un tail acotado
/// del log TwoFactor.Admin.log. No extrae ni persiste valores de QR/secretos/códigos, no valida TOTP y no modifica usuarios.
/// </summary>
public sealed partial class TwoFactorHealthCollector : IReadOnlyCollector
{
    public string Nombre => "TSplus 2FA / diagnóstico guiado";
    private const int MaxTailBytes = 256 * 1024;

    public async Task<CollectorResult> CollectAsync(DiagnosticContext context, CancellationToken cancellationToken = default)
    {
        if (!context.Sistema.TsplusDetectado || string.IsNullOrWhiteSpace(context.Sistema.TsplusRuta))
            return CollectorResult.Empty;

        var root = context.Sistema.TsplusRuta!;
        var adminExe = Path.Combine(root, "UserDesktop", "files", "TwoFactor.Admin.exe");
        var adminProbe = FileSystemProbe.File(adminExe);
        if (adminProbe.IsAbsent) return CollectorResult.Empty;

        var events = new List<DiagnosticEvent>();
        var findings = new List<DiagnosticFinding>();
        if (adminProbe.IsUnavailable)
        {
            findings.Add(new DiagnosticFinding(
                "TSPLUS-2FA-DETECTION-COVERAGE", "Two-Factor Authentication (2FA)", DiagnosticSeverity.Advertencia,
                "La presencia de 2FA quedó NO EVALUADA.",
                "TDM no interpreta un fallo de acceso/E/S sobre TwoFactor.Admin.exe como ausencia del módulo.",
                [new("Ruta", adminExe), new("Estado", adminProbe.StatusText), new("Detalle", adminProbe.Detail ?? "N/D")],
                ConfidenceLevel.Confirmada, Capa: DiagnosticLayer.Tsplus));
        }
        var log = Path.Combine(root, "UserDesktop", "files", "TwoFactor.Admin.log");
        var w32Time = ReadService("W32Time");
        var farm = TsplusFarmTopologyDiscovery.Discover(root);
        var signals = await ReadLogSignalsAsync(log, cancellationToken).ConfigureAwait(false);

        events.Add(new DiagnosticEvent(
            DateTimeOffset.Now, "TDM", "Two-Factor Authentication (2FA)", DiagnosticLayer.Tsplus,
            DiagnosticSeverity.Informativo, "TSPLUS_2FA_HEALTH_STATE",
            "Estado dirigido de 2FA capturado sin leer secretos ni ejecutar autenticaciones.",
            Evidencia:
            [
                new("TwoFactor.Admin.exe", FileSystemProbe.Display(adminProbe)),
                new("TwoFactor.Admin.log", signals.SourceState),
                new("Windows Time (W32Time)", w32Time),
                new("Rol TSplus local", farm.LocalRole),
                new("Farm detectada", farm.FarmDetected ? "Sí" : "No"),
                new("Application Servers detectados", farm.ApplicationServers.Count.ToString()),
                new("Señales código/TOTP", signals.InvalidCode.ToString()),
                new("Señales HTTPS/TLS", signals.Https.ToString()),
                new("Señales enrollment/activación", signals.Enrollment.ToString()),
                new("Señales genéricas de error", signals.Evaluated ? signals.Errors.ToString() : "NO EVALUADO"),
                new("Cobertura de log 2FA", signals.Evaluated ? "Disponible" : signals.SourceState),
                new("Privacidad", "No se extraen ni persisten valores de QR, secretos TOTP, códigos ni credenciales; sólo se cuentan patrones de error")
            ],
            Producto: TsplusProduct.TwoFactorAuthentication));

        if (!w32Time.Equals("Running", StringComparison.OrdinalIgnoreCase))
        {
            findings.Add(new DiagnosticFinding(
                "TSPLUS-2FA-TIME-SYNC-REVIEW",
                "Two-Factor Authentication / tiempo",
                DiagnosticSeverity.Advertencia,
                "La sincronización horaria del servidor requiere verificación para 2FA.",
                $"Windows Time (W32Time) se observa como {w32Time}. TSplus requiere que servidor y dispositivo estén sincronizados para códigos basados en tiempo; este hallazgo no demuestra por sí solo que exista desfase real.",
                [new("W32Time", w32Time), new("Regla", "Servidor y dispositivo deben estar sincronizados")],
                ConfidenceLevel.Media,
                "TSplus — Two-factor Authentication",
                "https://docs.tsplus.net/tsplus/twofactorauthentication/",
                "Verifique la sincronización NTP/Windows Time y la hora automática del dispositivo antes de resetear usuarios 2FA.",
                DiagnosticLayer.Tsplus));
        }

        if (signals.Evaluated && signals.InvalidCode > 0)
        {
            findings.Add(new DiagnosticFinding(
                "TSPLUS-2FA-CODE-REJECTIONS",
                "Two-Factor Authentication / códigos",
                DiagnosticSeverity.Advertencia,
                "El log 2FA contiene señales compatibles con rechazo de código/verificación.",
                "TDM conserva únicamente el conteo y no persiste valores de códigos/secretos. El rechazo puede deberse a tiempo, enrollment, cliente incompatible u otra condición del flujo 2FA.",
                [new("Señales", signals.InvalidCode.ToString()), new("Log", "TwoFactor.Admin.log (tail acotado)")],
                ConfidenceLevel.Media,
                "TSplus — Two-factor Authentication",
                "https://docs.tsplus.net/tsplus/twofactorauthentication/",
                "Revise primero tiempo/TOTP, método de cliente y estado del usuario en Manage Users.",
                DiagnosticLayer.Tsplus));
        }

        if (signals.Evaluated && signals.Https > 0)
        {
            findings.Add(new DiagnosticFinding(
                "TSPLUS-2FA-HTTPS-REVIEW",
                "Two-Factor Authentication / HTTPS",
                DiagnosticSeverity.Advertencia,
                "El log 2FA contiene señales compatibles con HTTPS/TLS.",
                "Los clientes TSplus generados con soporte 2FA validan el código contra el Web Portal mediante HTTPS. Un cambio de puerto o una falla TLS puede impedir esa validación.",
                [new("Señales", signals.Https.ToString()), new("Log", "TwoFactor.Admin.log (tail acotado)")],
                ConfidenceLevel.Media,
                "TSplus — Portable Client Generator / 2FA",
                "https://docs.tsplus.net/tsplus/portable-client-generator/",
                "Valide Web Portal/HTTPS y regenere clientes 2FA si el puerto HTTPS cambió.",
                DiagnosticLayer.Tsplus));
        }

        return new CollectorResult(findings, events);
    }

    private static string ReadService(string serviceName)
    {
        try
        {
            using var service = new ServiceController(serviceName);
            return service.Status.ToString();
        }
        catch (InvalidOperationException) { return "No disponible"; }
        catch { return "N/D"; }
    }

    private static async Task<LogSignals> ReadLogSignalsAsync(string path, CancellationToken ct)
    {
        var probe = FileSystemProbe.File(path);
        if (probe.IsAbsent) return new(false, 0, 0, 0, 0, "Ausente confirmado / logging puede estar deshabilitado");
        if (probe.IsUnavailable) return new(false, 0, 0, 0, 0, $"NO EVALUADO · {probe.StatusText}");
        try
        {
            await using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 8192, FileOptions.Asynchronous | FileOptions.SequentialScan);
            var length = fs.Length;
            if (length > MaxTailBytes)
            {
                fs.Seek(length - MaxTailBytes, SeekOrigin.Begin);
                using var discard = new StreamReader(fs, Encoding.UTF8, true, 8192, leaveOpen: true);
                _ = await discard.ReadLineAsync(ct).ConfigureAwait(false);
                var text = await discard.ReadToEndAsync(ct).ConfigureAwait(false);
                return CountSignals(text, "Disponible · tail acotado");
            }
            using var reader = new StreamReader(fs, Encoding.UTF8, true, 8192, leaveOpen: true);
            return CountSignals(await reader.ReadToEndAsync(ct).ConfigureAwait(false), "Disponible");
        }
        catch (UnauthorizedAccessException ex) { return new(false, 0, 0, 0, 0, "NO EVALUADO · acceso denegado: " + ex.Message); }
        catch (IOException ex) { return new(false, 0, 0, 0, 0, "NO EVALUADO · E/S: " + ex.Message); }
    }

    private static LogSignals CountSignals(string text, string sourceState)
        => new(true,
            InvalidCodeRegex().Matches(text).Count,
            HttpsErrorRegex().Matches(text).Count,
            EnrollmentErrorRegex().Matches(text).Count,
            GenericErrorRegex().Matches(text).Count,
            sourceState);

    [GeneratedRegex(@"(?im)(?:invalid|wrong|expired|reject(?:ed)?|fail(?:ed|ure)?)\s*(?:verification\s*)?(?:code|token|totp)|(?:code|token|totp).{0,40}(?:invalid|wrong|expired|reject(?:ed)?|fail(?:ed|ure)?)", RegexOptions.CultureInvariant)]
    private static partial Regex InvalidCodeRegex();

    [GeneratedRegex(@"(?im)(?:https|ssl|tls|certificate).{0,80}(?:error|fail(?:ed|ure)?|invalid|refused|timeout)|(?:error|fail(?:ed|ure)?|invalid|refused|timeout).{0,80}(?:https|ssl|tls|certificate)", RegexOptions.CultureInvariant)]
    private static partial Regex HttpsErrorRegex();

    [GeneratedRegex(@"(?im)(?:enroll|activation|activate|qr|registration).{0,80}(?:error|fail(?:ed|ure)?|invalid)|(?:error|fail(?:ed|ure)?|invalid).{0,80}(?:enroll|activation|activate|qr|registration)", RegexOptions.CultureInvariant)]
    private static partial Regex EnrollmentErrorRegex();

    [GeneratedRegex(@"(?im)\b(?:error|failed|failure|exception)\b", RegexOptions.CultureInvariant)]
    private static partial Regex GenericErrorRegex();

    private sealed record LogSignals(bool Evaluated, int InvalidCode, int Https, int Enrollment, int Errors, string SourceState);
}
