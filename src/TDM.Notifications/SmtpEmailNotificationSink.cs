using System.Net;
using System.Net.Mail;
using System.Text;
using System.Text.Json;
using TDM.Persistence;

namespace TDM.Notifications;

public sealed record EmailDeliveryResult(bool Success, string Message, DateTimeOffset Timestamp);
internal sealed record EmailDeliveryJournalEntry(
    DateTimeOffset Timestamp,
    bool Success,
    string Transition,
    string Severity,
    string Title,
    int RecipientCount,
    string Detail);

/// <summary>
/// Sink SMTP de mejor esfuerzo. Nunca rompe el dispatcher si el servidor de correo falla:
/// registra el resultado y deja intactos el journal de escritorio y el estado anti-ruido.
/// La configuración se relee en cada envío para aplicar cambios sin reiniciar TDM.Service.
/// </summary>
public sealed class SmtpEmailNotificationSink : INotificationSink
{
    private const long RotateAfterBytes = 2L * 1024 * 1024;
    private readonly EmailNotificationSettingsStore _store;
    private readonly JsonSerializerOptions _json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
    private readonly SemaphoreSlim _journalGate = new(1, 1);

    public string JournalPath { get; }
    public string PreviousJournalPath => JournalPath + ".1";

    public SmtpEmailNotificationSink(string? rootPath = null)
    {
        var root = string.IsNullOrWhiteSpace(rootPath) ? TdmDataPaths.MachineRootPath : Path.GetFullPath(rootPath);
        _store = new EmailNotificationSettingsStore(root);
        JournalPath = Path.Combine(root, "notifications", "email-journal.jsonl");
    }

    public async Task SendAsync(IncidentNotification notification, CancellationToken ct = default)
    {
        try
        {
            var settings = await _store.LoadAsync(ct).ConfigureAwait(false);
            if (!ShouldSend(settings, notification)) return;
            _ = await SendCoreAsync(settings, notification, passwordOverride: null, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex)
        {
            await TryWriteJournalAsync(new EmailDeliveryJournalEntry(
                DateTimeOffset.Now, false, notification.Transition.ToString(), notification.Severity,
                notification.Title, 0, SafeDetail(ex.Message)), CancellationToken.None).ConfigureAwait(false);
        }
    }

    public async Task<EmailDeliveryResult> SendTestAsync(
        EmailNotificationSettings? settingsOverride = null,
        string? passwordOverride = null,
        CancellationToken ct = default)
    {
        var settings = settingsOverride ?? await _store.LoadAsync(ct).ConfigureAwait(false);
        var effectiveSettings = settings with { Enabled = true };
        var errors = EmailNotificationSettingsValidator.Validate(effectiveSettings);
        if (errors.Count > 0)
            return new EmailDeliveryResult(false, string.Join(" ", errors), DateTimeOffset.Now);

        var signal = new IncidentNotification(
            "EMAIL-TEST-" + Guid.NewGuid().ToString("N")[..12],
            DateTimeOffset.Now,
            NotificationTransition.Opened,
            "Informativo",
            "TDM · Prueba de correo",
            "Esta es una prueba manual del canal de notificaciones por correo de TDM. No representa una falla del servidor.",
            "EmailSelfTest",
            Environment.MachineName);
        return await SendCoreAsync(effectiveSettings, signal, passwordOverride, ct, force: true).ConfigureAwait(false);
    }

    public static bool ShouldSend(EmailNotificationSettings settings, IncidentNotification notification)
    {
        if (!settings.Enabled || !EmailNotificationSettingsValidator.IsValid(settings)) return false;
        if (notification.Transition == NotificationTransition.Opened && !settings.NotifyOpened) return false;
        if (notification.Transition == NotificationTransition.Escalated && !settings.NotifyEscalated) return false;
        var conditionSeverity = notification.ConditionSeverity ?? notification.Severity;
        if (notification.Transition == NotificationTransition.Recovered)
            return false;
        return SeverityRank(conditionSeverity) >= SeverityRank(settings.MinimumSeverity);
    }

    private async Task<EmailDeliveryResult> SendCoreAsync(
        EmailNotificationSettings settings,
        IncidentNotification notification,
        string? passwordOverride,
        CancellationToken ct,
        bool force = false)
    {
        // FIX93: una recuperación nunca debe generar correo visible, incluso si una llamada
        // futura intenta forzar el envío saltándose la política normal.
        if (notification.Transition == NotificationTransition.Recovered)
            return new EmailDeliveryResult(true, "Notificación de cierre omitida por política FIX93.", DateTimeOffset.Now);

        if (!force && !ShouldSend(settings, notification))
            return new EmailDeliveryResult(true, "Notificación omitida por política de correo.", DateTimeOffset.Now);

        var errors = EmailNotificationSettingsValidator.Validate(settings);
        if (errors.Count > 0)
            return await FinishAsync(false, notification, settings.Recipients.Count, string.Join(" ", errors), ct).ConfigureAwait(false);

        var password = passwordOverride;
        if (password is null && !string.IsNullOrWhiteSpace(settings.UserName))
            password = await _store.ReadPasswordAsync(ct).ConfigureAwait(false);

        try
        {
            using var message = new MailMessage
            {
                From = new MailAddress(settings.FromAddress.Trim()),
                Subject = BuildSubject(notification),
                Body = BuildBody(notification),
                SubjectEncoding = Encoding.UTF8,
                BodyEncoding = Encoding.UTF8,
                IsBodyHtml = false
            };
            foreach (var recipient in settings.Recipients)
                message.To.Add(new MailAddress(recipient));

            using var client = new SmtpClient(settings.SmtpHost.Trim(), settings.SmtpPort)
            {
                EnableSsl = settings.UseTls,
                DeliveryMethod = SmtpDeliveryMethod.Network,
                UseDefaultCredentials = false
            };
            if (!string.IsNullOrWhiteSpace(settings.UserName))
                client.Credentials = new NetworkCredential(settings.UserName.Trim(), password ?? string.Empty);

            var sendTask = client.SendMailAsync(message);
            await sendTask.WaitAsync(TimeSpan.FromSeconds(settings.TimeoutSeconds), ct).ConfigureAwait(false);
            return await FinishAsync(true, notification, message.To.Count, "Correo enviado correctamente.", ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex) when (ex is SmtpException or InvalidOperationException or FormatException or TimeoutException or IOException)
        {
            return await FinishAsync(false, notification, settings.Recipients.Count, SafeDetail(ex.Message), ct).ConfigureAwait(false);
        }
    }

    private async Task<EmailDeliveryResult> FinishAsync(
        bool success,
        IncidentNotification notification,
        int recipientCount,
        string detail,
        CancellationToken ct)
    {
        var now = DateTimeOffset.Now;
        await TryWriteJournalAsync(new EmailDeliveryJournalEntry(
            now, success, notification.Transition.ToString(), notification.Severity,
            notification.Title, recipientCount, SafeDetail(detail)), ct).ConfigureAwait(false);
        return new EmailDeliveryResult(success, detail, now);
    }

    private async Task TryWriteJournalAsync(EmailDeliveryJournalEntry entry, CancellationToken ct)
    {
        try
        {
            await _journalGate.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(JournalPath)!);
                RotateIfNeeded();
                var line = JsonSerializer.Serialize(entry, _json) + Environment.NewLine;
                var bytes = Encoding.UTF8.GetBytes(line);
                await using var stream = new FileStream(JournalPath, FileMode.Append, FileAccess.Write,
                    FileShare.Read, 16 * 1024, FileOptions.Asynchronous | FileOptions.WriteThrough);
                await stream.WriteAsync(bytes, ct).ConfigureAwait(false);
                await stream.FlushAsync(ct).ConfigureAwait(false);
                stream.Flush(true);
            }
            finally { _journalGate.Release(); }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    private void RotateIfNeeded()
    {
        try
        {
            if (!File.Exists(JournalPath) || new FileInfo(JournalPath).Length < RotateAfterBytes) return;
            if (File.Exists(PreviousJournalPath)) File.Delete(PreviousJournalPath);
            File.Move(JournalPath, PreviousJournalPath);
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    private static string BuildSubject(IncidentNotification n)
        => $"[TDM][{TransitionLabel(n.Transition)}] {NormalizeSeverity(n.ConditionSeverity ?? n.Severity)} · {CleanHeader(n.Title)}";

    private static string BuildBody(IncidentNotification n)
        => string.Join(Environment.NewLine,
        new[]
        {
            "TSplus Diagnostic Monitor (TDM)",
            "",
            $"Estado: {TransitionLabel(n.Transition)}",
            $"Severidad de la condición: {NormalizeSeverity(n.ConditionSeverity ?? n.Severity)}",
            $"Hora: {n.Timestamp.ToLocalTime():dd/MM/yyyy HH:mm:ss zzz}",
            $"Servidor: {Environment.MachineName}",
            $"Título: {n.Title}",
            $"Resumen: {n.Summary}",
            $"Origen: {n.SourceKind}",
            string.IsNullOrWhiteSpace(n.SourceId) ? "" : $"Referencia: {n.SourceId}",
            "",
            "Mensaje generado automáticamente por TDM."
        }.Where(x => x.Length > 0));

    private static string TransitionLabel(NotificationTransition transition) => transition switch
    {
        NotificationTransition.Opened => "APERTURA",
        NotificationTransition.Escalated => "ESCALAMIENTO",
        NotificationTransition.Recovered => "OMITIDO",
        _ => transition.ToString().ToUpperInvariant()
    };

    private static string NormalizeSeverity(string? severity)
        => severity?.Trim().ToLowerInvariant() switch
        {
            "critico" or "crítico" => "Crítico",
            "advertencia" => "Advertencia",
            "error" => "Error",
            _ => "Informativo"
        };

    private static int SeverityRank(string? value)
        => value?.Trim().ToLowerInvariant() switch
        {
            "critico" or "crítico" => 4,
            "error" => 3,
            "advertencia" => 2,
            _ => 1
        };

    private static string CleanHeader(string? text)
        => (text ?? string.Empty).Replace('\r', ' ').Replace('\n', ' ').Trim();

    private static string SafeDetail(string? value)
    {
        var text = CleanHeader(value);
        if (text.Length > 500) text = text[..500];
        return text;
    }
}
