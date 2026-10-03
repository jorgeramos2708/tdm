using System.Security.Cryptography;
using System.Text;

namespace TDM.Models;

/// <summary>
/// Pseudónimo estable "{prefijo}-{8 hex}" (SHA-256 del valor normalizado). Se usa en origen
/// (correladores y collectors) y en el export (SupportBundleSanitizer) con el MISMO algoritmo:
/// un valor ya pseudonimizado no se re-hashea (idempotencia por prefijo-XXXXXXXX) y todas las
/// capas producen el mismo identificador. Los paquetes de soporte no deben llevar SIDs (formato
/// oficial S-1-…: learn.microsoft.com/en-us/windows/win32/secauthz/sid-structure), nombres de
/// cuenta ni dominios en claro dentro de Ids, Componente o Resumen.
/// </summary>
public static class TdmPseudonym
{
    public static string Create(string prefix, string? value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Equals("N/D", StringComparison.OrdinalIgnoreCase)) return value ?? "N/D";
        if (value.StartsWith(prefix + "-", StringComparison.Ordinal))
        {
            var tail = value[(prefix.Length + 1)..];
            if (tail.Length == 8 && tail.All(Uri.IsHexDigit)) return value;
        }
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(value.Trim().ToUpperInvariant()));
        return $"{prefix}-{Convert.ToHexString(hash)[..8]}";
    }
}
