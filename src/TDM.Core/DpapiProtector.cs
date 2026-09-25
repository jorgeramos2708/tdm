using System;
using System.Security.Cryptography;

#pragma warning disable CA1416 // ProtectedData is Windows-only

namespace TDM.Core;

/// <summary>
/// Protección DPAPI para secrets (credenciales SMTP, API keys, etc.).
/// Solo Windows; usa DataProtectionScope.CurrentUser (usuario) o LocalMachine (servicio).
/// </summary>
public static class DpapiProtector
{
    private static readonly DataProtectionScope Scope = OperatingSystem.IsWindows()
        ? DataProtectionScope.CurrentUser
        : throw new PlatformNotSupportedException("DPAPI solo disponible en Windows");

    /// <summary>
    /// Protege (encripta) un string usando DPAPI.
    /// </summary>
    public static string Protect(string plainText, string? optionalEntropy = null)
    {
        if (string.IsNullOrEmpty(plainText)) return string.Empty;
        var data = System.Text.Encoding.UTF8.GetBytes(plainText);
        var entropy = string.IsNullOrEmpty(optionalEntropy) ? null : System.Text.Encoding.UTF8.GetBytes(optionalEntropy);
        var protectedData = ProtectedData.Protect(data, entropy, Scope);
        return Convert.ToBase64String(protectedData);
    }

    /// <summary>
    /// Desprotege (desencripta) un string protegido con DPAPI.
    /// </summary>
    public static string Unprotect(string protectedBase64, string? optionalEntropy = null)
    {
        if (string.IsNullOrEmpty(protectedBase64)) return string.Empty;
        try
        {
            var data = Convert.FromBase64String(protectedBase64);
            var entropy = string.IsNullOrEmpty(optionalEntropy) ? null : System.Text.Encoding.UTF8.GetBytes(optionalEntropy);
            var unprotected = ProtectedData.Unprotect(data, entropy, Scope);
            return System.Text.Encoding.UTF8.GetString(unprotected);
        }
        catch (CryptographicException)
        {
            // Datos corruptos, clave cambiada, o distinto usuario/máquina
            return string.Empty;
        }
    }

    /// <summary>
    /// Verifica si un texto parece ya protegido (Base64 válido, longitud > 0).
    /// </summary>
    public static bool IsProtected(string? value)
        => !string.IsNullOrWhiteSpace(value) && value.Length > 20 && IsBase64(value);

    private static bool IsBase64(string s)
    {
        Span<byte> buffer = new byte[s.Length];
        return Convert.TryFromBase64String(s, buffer, out _);
    }
}