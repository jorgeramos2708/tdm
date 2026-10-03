using System.Security.Cryptography;
using System.Text;

namespace TDM.Models;

/// <summary>
/// Pseudónimo estable "{prefijo}-{8 hex}" derivado con HMAC-SHA256 y una sal aleatoria de
/// 32 bytes POR INSTALACIÓN (archivo pseudonym.salt en la raíz de datos; se crea la primera
/// vez con entropía aleatoria). Sin sal, SHA-256 puro es reidentificable por diccionario
/// (listas de usuarios/dominios habituales); con sal, el hash deja de ser universal y sólo
/// es reproducible en esta instalación. Se usa en origen (correladores y collectors) y en el
/// export (SupportBundleSanitizer) con el MISMO algoritmo y sal: un valor ya pseudonimizado
/// no se re-hashea (idempotencia por prefijo-XXXXXXXX) y todas las capas producen el mismo
/// identificador. Los paquetes de soporte no deben llevar SIDs (formato oficial S-1-…:
/// learn.microsoft.com/en-us/windows/win32/secauthz/sid-structure), nombres de cuenta ni
/// dominios en claro dentro de Ids, Componente o Resumen.
/// </summary>
public static class TdmPseudonym
{
    private const int SaltLength = 32;
    private static readonly object SaltGate = new();
    private static byte[]? _salt;
    private static bool _saltResolved;

    /// <summary>
    /// Fuerza una sal concreta (pruebas). null = volver a resolver la sal por instalación.
    /// Una sal explícita queda marcada como resuelta para que la lectura de disco no la pise.
    /// </summary>
    public static void ConfigureSalt(byte[]? salt)
    {
        lock (SaltGate)
        {
            _salt = salt is null ? null : (byte[])salt.Clone();
            _saltResolved = salt is not null;
        }
    }

    public static string Create(string prefix, string? value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Equals("N/D", StringComparison.OrdinalIgnoreCase)) return value ?? "N/D";
        if (value.StartsWith(prefix + "-", StringComparison.Ordinal))
        {
            var tail = value[(prefix.Length + 1)..];
            if (tail.Length == 8 && tail.All(Uri.IsHexDigit)) return value;
        }
        var normalized = Encoding.UTF8.GetBytes(value.Trim().ToUpperInvariant());
        var salt = ResolveSalt();
        var hash = salt is null
            // Degradado documentado: sin acceso a la raíz de datos compartida (la primera
            // ejecución bajo servicio/instalador crea la sal) se conserva el algoritmo legado.
            ? SHA256.HashData(normalized)
            : HMACSHA256.HashData(salt, normalized);
        return $"{prefix}-{Convert.ToHexString(hash)[..8]}";
    }

    private static byte[]? ResolveSalt()
    {
        lock (SaltGate)
        {
            if (_saltResolved) return _salt;

            // Misma resolución de raíz que TdmDataPaths (TDM.Models no puede referenciar
            // TDM.Persistence): explícita TDM_DATA_DIR y, si no, la raíz de ProgramData que
            // comparten GUI y servicio. Sin fallback por usuario a propósito: una sal por
            // usuario rompería la equivalencia de pseudónimos entre procesos.
            var explicitPath = Environment.GetEnvironmentVariable("TDM_DATA_DIR");
            var root = !string.IsNullOrWhiteSpace(explicitPath)
                ? Path.GetFullPath(explicitPath)
                : Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                    "TSplus Diagnostic Monitor", "Data");
            var saltPath = Path.Combine(root, "pseudonym.salt");

            _salt = TryReadSalt(saltPath) ?? TryCreateSalt(saltPath);
            _saltResolved = true;
            return _salt;
        }
    }

    private static byte[]? TryReadSalt(string path)
    {
        try
        {
            if (!File.Exists(path)) return null;
            var bytes = File.ReadAllBytes(path);
            return bytes.Length == SaltLength ? bytes : null;
        }
        catch { return null; }
    }

    private static byte[]? TryCreateSalt(string path)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            var salt = RandomNumberGenerator.GetBytes(SaltLength);
            // CreateNew: dos procesos en carrera no se pisan; el perdedor relee la sal ganadora.
            using (var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read))
                stream.Write(salt);
            return salt;
        }
        catch (IOException)
        {
            return TryReadSalt(path);
        }
        catch { return null; }
    }
}
