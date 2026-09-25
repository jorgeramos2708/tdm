using System.Net.Mail;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;

namespace TDM.Persistence;

/// <summary>
/// Configuración SMTP compartida por la GUI y TDM.Service.
/// La contraseña nunca se serializa en JSON: se guarda aparte cifrada con DPAPI de ámbito local-machine.
/// </summary>
public sealed record EmailNotificationSettings
{
    public bool Enabled { get; init; }
    public string SmtpHost { get; init; } = string.Empty;
    public int SmtpPort { get; init; } = 587;
    public bool UseTls { get; init; } = true;
    public string UserName { get; init; } = string.Empty;
    public string FromAddress { get; init; } = string.Empty;
    public List<string> Recipients { get; init; } = [];
    public string MinimumSeverity { get; init; } = "Error";
    public bool NotifyOpened { get; init; } = true;
    public bool NotifyEscalated { get; init; } = true;
    public bool NotifyRecovered { get; init; } = false;
    public int TimeoutSeconds { get; init; } = 15;

    public static EmailNotificationSettings Default { get; } = new();
}

public static class EmailNotificationSettingsValidator
{
    private static readonly HashSet<string> AllowedSeverities = new(StringComparer.OrdinalIgnoreCase)
    {
        "Advertencia", "Error", "Crítico", "Critico"
    };

    public static IReadOnlyList<string> Validate(EmailNotificationSettings? value)
    {
        var errors = new List<string>();
        if (value is null)
        {
            errors.Add("La configuración de correo está vacía.");
            return errors;
        }

        if (value.SmtpPort is < 1 or > 65535)
            errors.Add("Puerto SMTP: use un valor entre 1 y 65535.");
        if (value.TimeoutSeconds is < 3 or > 120)
            errors.Add("Tiempo máximo SMTP: use un valor entre 3 y 120 segundos.");
        if (!AllowedSeverities.Contains(value.MinimumSeverity ?? string.Empty))
            errors.Add("Severidad mínima: use Advertencia, Error o Crítico.");
        if (!value.Enabled) return errors;

        var recipients = value.Recipients ?? new List<string>();
        if (recipients.Count > 50)
            errors.Add("Destinatarios: se permiten hasta 50 direcciones.");

        var unique = recipients
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Select(x => x.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        if (unique.Count != recipients.Count(x => !string.IsNullOrWhiteSpace(x)))
            errors.Add("Destinatarios: hay direcciones duplicadas.");

        foreach (var recipient in unique)
            if (!IsValidAddress(recipient))
                errors.Add($"Destinatario no válido: {recipient}");

        if (string.IsNullOrWhiteSpace(value.SmtpHost) || value.SmtpHost.Length > 255)
            errors.Add("Servidor SMTP: indique un host válido de hasta 255 caracteres.");
        if (string.IsNullOrWhiteSpace(value.FromAddress) || !IsValidAddress(value.FromAddress))
            errors.Add("Remitente: indique una dirección de correo válida.");
        if (unique.Count == 0)
            errors.Add("Destinatarios: indique al menos una dirección de correo.");
        if (!value.NotifyOpened && !value.NotifyEscalated)
            errors.Add("Seleccione al menos un tipo de notificación: apertura o escalamiento.");
        if ((value.UserName ?? string.Empty).Length > 320)
            errors.Add("Usuario SMTP: el valor es demasiado largo.");

        return errors;
    }

    public static bool IsValid(EmailNotificationSettings? value) => Validate(value).Count == 0;

    private static bool IsValidAddress(string? address)
    {
        if (string.IsNullOrWhiteSpace(address) || address.Length > 320) return false;
        try
        {
            var parsed = new MailAddress(address.Trim());
            return string.Equals(parsed.Address, address.Trim(), StringComparison.OrdinalIgnoreCase);
        }
        catch (FormatException) { return false; }
    }
}

public sealed class EmailNotificationSettingsStore
{
    private readonly JsonSerializerOptions _json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase, WriteIndented = true };
    private readonly SemaphoreSlim _gate = new(1, 1);

    public string RootPath { get; }
    public string SettingsPath { get; }
    public string SecretPath { get; }

    public EmailNotificationSettingsStore(string? rootPath = null)
    {
        RootPath = string.IsNullOrWhiteSpace(rootPath) ? TdmDataPaths.MachineRootPath : Path.GetFullPath(rootPath);
        SettingsPath = Path.Combine(RootPath, "settings", "email-notifications.json");
        SecretPath = Path.Combine(RootPath, "settings", "email-smtp.secret");
    }

    public async Task<EmailNotificationSettings> LoadAsync(CancellationToken ct = default)
    {
        if (!File.Exists(SettingsPath)) return EmailNotificationSettings.Default;
        try
        {
            await using var stream = new FileStream(SettingsPath, FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete, 16 * 1024,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            var loaded = await JsonSerializer.DeserializeAsync<EmailNotificationSettings>(stream, _json, ct).ConfigureAwait(false);
            if (loaded is null) return EmailNotificationSettings.Default;
            return loaded with
            {
                Recipients = NormalizeRecipients(loaded.Recipients),
                MinimumSeverity = NormalizeSeverity(loaded.MinimumSeverity),
                NotifyRecovered = false
            };
        }
        catch (JsonException) { return EmailNotificationSettings.Default; }
        catch (IOException) { return EmailNotificationSettings.Default; }
        catch (UnauthorizedAccessException) { return EmailNotificationSettings.Default; }
    }

    public async Task SaveAsync(
        EmailNotificationSettings settings,
        string? newPassword = null,
        bool clearStoredPassword = false,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(settings);
        var normalized = settings with
        {
            SmtpHost = (settings.SmtpHost ?? string.Empty).Trim(),
            UserName = (settings.UserName ?? string.Empty).Trim(),
            FromAddress = (settings.FromAddress ?? string.Empty).Trim(),
            Recipients = NormalizeRecipients(settings.Recipients),
            MinimumSeverity = NormalizeSeverity(settings.MinimumSeverity),
            NotifyRecovered = false
        };
        var errors = EmailNotificationSettingsValidator.Validate(normalized);
        if (errors.Count > 0)
            throw new ArgumentOutOfRangeException(nameof(settings), string.Join(" ", errors));

        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(SettingsPath)!);
            await WriteJsonAtomicAsync(SettingsPath, normalized, ct).ConfigureAwait(false);

            if (clearStoredPassword)
            {
                try { if (File.Exists(SecretPath)) File.Delete(SecretPath); } catch (FileNotFoundException) { }
            }
            else if (!string.IsNullOrEmpty(newPassword))
            {
                if (newPassword.Length > 4096)
                    throw new ArgumentOutOfRangeException(nameof(newPassword), "La contraseña SMTP es demasiado larga.");
                var clearBytes = Encoding.UTF8.GetBytes(newPassword);
                try
                {
                    var protectedBytes = MachineDpapi.Protect(clearBytes);
                    await WriteBytesAtomicAsync(SecretPath, protectedBytes, ct).ConfigureAwait(false);
                }
                finally { Array.Clear(clearBytes, 0, clearBytes.Length); }
            }
        }
        finally { _gate.Release(); }
    }

    public Task<bool> HasStoredPasswordAsync(CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();
        try { return Task.FromResult(File.Exists(SecretPath) && new FileInfo(SecretPath).Length > 0); }
        catch (IOException) { return Task.FromResult(false); }
        catch (UnauthorizedAccessException) { return Task.FromResult(false); }
    }

    public async Task ClearStoredPasswordAsync(CancellationToken ct = default)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            try { if (File.Exists(SecretPath)) File.Delete(SecretPath); }
            catch (FileNotFoundException) { }
        }
        finally { _gate.Release(); }
    }

    public async Task<string?> ReadPasswordAsync(CancellationToken ct = default)
    {
        if (!File.Exists(SecretPath)) return null;
        try
        {
            var protectedBytes = await File.ReadAllBytesAsync(SecretPath, ct).ConfigureAwait(false);
            if (protectedBytes.Length == 0) return null;
            var clear = MachineDpapi.Unprotect(protectedBytes);
            try { return Encoding.UTF8.GetString(clear); }
            finally { Array.Clear(clear, 0, clear.Length); }
        }
        catch (CryptographicException) { return null; }
        catch (IOException) { return null; }
        catch (UnauthorizedAccessException) { return null; }
    }

    public static List<string> ParseRecipients(string? text)
        => NormalizeRecipients((text ?? string.Empty)
            .Split([',', ';', '\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));

    private static List<string> NormalizeRecipients(IEnumerable<string>? recipients)
        => (recipients ?? Array.Empty<string>())
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Select(x => x.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

    private static string NormalizeSeverity(string? value)
        => value?.Trim().ToLowerInvariant() switch
        {
            "advertencia" => "Advertencia",
            "critico" or "crítico" => "Crítico",
            _ => "Error"
        };

    private async Task WriteJsonAtomicAsync(string path, EmailNotificationSettings value, CancellationToken ct)
    {
        var tmp = path + ".tmp-" + Guid.NewGuid().ToString("N");
        try
        {
            await using (var stream = new FileStream(tmp, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                16 * 1024, FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await JsonSerializer.SerializeAsync(stream, value, _json, ct).ConfigureAwait(false);
                await stream.FlushAsync(ct).ConfigureAwait(false);
                stream.Flush(true);
            }
            File.Move(tmp, path, true);
        }
        finally { try { if (File.Exists(tmp)) File.Delete(tmp); } catch { } }
    }

    private static async Task WriteBytesAtomicAsync(string path, byte[] bytes, CancellationToken ct)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var tmp = path + ".tmp-" + Guid.NewGuid().ToString("N");
        try
        {
            await using (var stream = new FileStream(tmp, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                16 * 1024, FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await stream.WriteAsync(bytes, ct).ConfigureAwait(false);
                await stream.FlushAsync(ct).ConfigureAwait(false);
                stream.Flush(true);
            }
            File.Move(tmp, path, true);
        }
        finally { try { if (File.Exists(tmp)) File.Delete(tmp); } catch { } }
    }
}

internal static class MachineDpapi
{
    private const uint CryptProtectUiForbidden = 0x1;
    private const uint CryptProtectLocalMachine = 0x4;

    public static byte[] Protect(byte[] clear)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("El almacenamiento seguro de la credencial SMTP requiere Windows.");
        return Transform(clear, protect: true);
    }

    public static byte[] Unprotect(byte[] encrypted)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("El almacenamiento seguro de la credencial SMTP requiere Windows.");
        return Transform(encrypted, protect: false);
    }

    private static byte[] Transform(byte[] input, bool protect)
    {
        if (input.Length == 0) return [];
        var inputPtr = Marshal.AllocHGlobal(input.Length);
        try
        {
            Marshal.Copy(input, 0, inputPtr, input.Length);
            var inputBlob = new DataBlob { cbData = input.Length, pbData = inputPtr };
            DataBlob outputBlob;
            var flags = CryptProtectUiForbidden | CryptProtectLocalMachine;
            var ok = protect
                ? CryptProtectData(ref inputBlob, "TDM SMTP", IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, flags, out outputBlob)
                : CryptUnprotectData(ref inputBlob, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, flags, out outputBlob);
            if (!ok)
                throw new System.Security.Cryptography.CryptographicException(Marshal.GetLastWin32Error());
            try
            {
                var output = new byte[outputBlob.cbData];
                if (output.Length > 0) Marshal.Copy(outputBlob.pbData, output, 0, output.Length);
                return output;
            }
            finally
            {
                if (outputBlob.pbData != IntPtr.Zero) LocalFree(outputBlob.pbData);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(inputPtr);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct DataBlob
    {
        public int cbData;
        public IntPtr pbData;
    }

    [DllImport("Crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptProtectData(
        ref DataBlob pDataIn,
        string? szDataDescr,
        IntPtr pOptionalEntropy,
        IntPtr pvReserved,
        IntPtr pPromptStruct,
        uint dwFlags,
        out DataBlob pDataOut);

    [DllImport("Crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptUnprotectData(
        ref DataBlob pDataIn,
        IntPtr ppszDataDescr,
        IntPtr pOptionalEntropy,
        IntPtr pvReserved,
        IntPtr pPromptStruct,
        uint dwFlags,
        out DataBlob pDataOut);

    [DllImport("Kernel32.dll", SetLastError = true)]
    private static extern IntPtr LocalFree(IntPtr hMem);
}
