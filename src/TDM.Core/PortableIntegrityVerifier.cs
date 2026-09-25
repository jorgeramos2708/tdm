using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Runtime.InteropServices;

namespace TDM.Core;

/// <summary>
/// Verificación de integridad del ejecutable portable en tiempo de ejecución.
/// Compara el SHA256 del archivo TDM.exe contra un hash embebido (firmado al publicar).
/// </summary>
public static class PortableIntegrityVerifier
{
    private const string EmbeddedHashResourceName = "TDM_EXE_SHA256";
    private static string? _cachedComputedHash;
    private static VerificationResult? _cachedResult;

    public sealed record VerificationResult(
        bool IsValid,
        string ComputedHash,
        string? ExpectedHash,
        string ExecutablePath,
        string? ErrorMessage);

    /// <summary>
    /// Verifica la integridad del ejecutable actual.
    /// </summary>
    public static VerificationResult Verify()
    {
        if (_cachedResult is not null) return _cachedResult;

        var exePath = GetExecutablePath();
        if (string.IsNullOrEmpty(exePath) || !File.Exists(exePath))
        {
            _cachedResult = new VerificationResult(false, string.Empty, null, exePath ?? "unknown",
                "No se pudo determinar la ruta del ejecutable");
            return _cachedResult;
        }

        var computedHash = ComputeFileHash(exePath);
        _cachedComputedHash = computedHash;

        var expectedHash = GetExpectedHash();
        var isValid = !string.IsNullOrEmpty(expectedHash) &&
                      string.Equals(computedHash, expectedHash, StringComparison.OrdinalIgnoreCase);

        _cachedResult = new VerificationResult(
            isValid,
            computedHash,
            expectedHash,
            exePath,
            isValid ? null : $"Hash mismatch: computed={computedHash}, expected={expectedHash}");

        return _cachedResult;
    }

    /// <summary>
    /// Verifica y lanza excepción si falla (fail-fast para uso en startup).
    /// </summary>
    public static void VerifyOrThrow()
    {
        var result = Verify();
        if (!result.IsValid)
        {
            throw new InvalidOperationException(
                $"INTEGRIDAD DEL EJECUTABLE COMPROMETIDA:\n" +
                $"  Archivo: {result.ExecutablePath}\n" +
                $"  Hash calculado: {result.ComputedHash}\n" +
                $"  Hash esperado: {result.ExpectedHash ?? "N/A (no embebido)"}\n" +
                $"  Detalle: {result.ErrorMessage}");
        }
    }

    /// <summary>
    /// Establece el hash esperado (usado en tiempo de publicación para firmar).
    /// </summary>
    public static void SetExpectedHash(string sha256Hash)
    {
        if (string.IsNullOrWhiteSpace(sha256Hash))
            throw new ArgumentException("Hash no puede ser vacío", nameof(sha256Hash));

        // Validar formato SHA256 (64 chars hex)
        if (sha256Hash.Length != 64 || !IsHex(sha256Hash))
            throw new ArgumentException("Hash debe ser SHA256 (64 chars hex)", nameof(sha256Hash));

        // Guardar en recurso embebido o archivo sidecar
        var exePath = GetExecutablePath();
        if (!string.IsNullOrEmpty(exePath))
        {
            var hashFile = exePath + ".sha256";
            File.WriteAllText(hashFile, sha256Hash.ToLowerInvariant());
        }
    }

    private static string GetExecutablePath()
    {
        // En portable (single-file): AppContext.BaseDirectory + assembly name
        // En servicio: Process.GetCurrentProcess().MainModule?.FileName
        try
        {
            var asm = System.Reflection.Assembly.GetEntryAssembly();
            if (asm is not null)
            {
                var location = asm.Location;
                if (!string.IsNullOrEmpty(location))
                    return location;

                // Single-file app: Location is empty, construct from BaseDirectory
                var baseDir = AppContext.BaseDirectory;
                if (!string.IsNullOrEmpty(baseDir))
                {
                    var exeName = asm.GetName().Name + ".exe";
                    var candidate = Path.Combine(baseDir, exeName);
                    if (File.Exists(candidate))
                        return candidate;
                }
            }
        }
        catch { }

        try
        {
            using var proc = Process.GetCurrentProcess();
            var mainModule = proc.MainModule;
            if (mainModule is not null && !string.IsNullOrEmpty(mainModule.FileName))
                return mainModule.FileName;
        }
        catch { }

        return Environment.ProcessPath ?? string.Empty;
    }

    private static string ComputeFileHash(string path)
    {
        using var sha256 = SHA256.Create();
        using var stream = File.OpenRead(path);
        var hash = sha256.ComputeHash(stream);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static string? GetExpectedHash()
    {
        // 1. Intentar leer desde archivo sidecar (.sha256)
        var exePath = GetExecutablePath();
        if (!string.IsNullOrEmpty(exePath))
        {
            var hashFile = exePath + ".sha256";
            if (File.Exists(hashFile))
            {
                try { return File.ReadAllText(hashFile).Trim().ToLowerInvariant(); }
                catch { }
            }
        }

        // 2. Intentar leer desde recurso embebido (si se compila con el hash)
        try
        {
            var asm = System.Reflection.Assembly.GetExecutingAssembly();
            using var stream = asm.GetManifestResourceStream(EmbeddedHashResourceName);
            if (stream is not null)
            {
                using var reader = new StreamReader(stream);
                return reader.ReadToEnd().Trim().ToLowerInvariant();
            }
        }
        catch { }

        return null;
    }

    private static bool IsHex(string s)
    {
        foreach (var c in s)
        {
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
                return false;
        }
        return true;
    }
}