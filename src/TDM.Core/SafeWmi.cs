using System;
using System.Management;
using System.Runtime.InteropServices;

#pragma warning disable CA1416 // WMI is Windows-only

namespace TDM.Core;

/// <summary>
/// Wrapper seguro para operaciones WMI/CIM.
/// Captura ManagementException, COMException, UnauthorizedAccessException
/// y devuelve null/empty en lugar de propagar excepciones.
/// </summary>
public static class SafeWmi
{
    /// <summary>
    /// Ejecuta una query WMI y aplica un selector a cada objeto resultado.
    /// Retorna lista vacía en caso de cualquier error WMI/COM/permisos.
    /// </summary>
    public static IReadOnlyList<T> Query<T>(
        string wql,
        Func<ManagementObject, T> selector,
        string? scope = null,
        TimeSpan? timeout = null)
    {
        try
        {
            var options = new System.Management.EnumerationOptions
            {
                ReturnImmediately = false,
                BlockSize = 100,
                Timeout = timeout ?? TimeSpan.FromSeconds(15),
                Rewindable = false
            };

            var searcher = string.IsNullOrWhiteSpace(scope)
                ? new ManagementObjectSearcher(wql)
                : new ManagementObjectSearcher(new ManagementScope(scope), new ObjectQuery(wql), options);

            var results = new List<T>();
            foreach (ManagementObject obj in searcher.Get())
            {
                try
                {
                    results.Add(selector(obj));
                }
                catch
                {
                    // Ignorar objetos individuales que fallen
                }
            }
            return results;
        }
        catch (ManagementException)
        {
            // Clase no existe, query inválido, proveedor no disponible
            return Array.Empty<T>();
        }
        catch (COMException ex) when (ex.ErrorCode == unchecked((int)0x80041003))
        {
            // WBEM_E_ACCESS_DENIED - sin permisos
            return Array.Empty<T>();
        }
        catch (COMException)
        {
            // RPC no disponible, servicio WMI detenido, etc.
            return Array.Empty<T>();
        }
        catch (UnauthorizedAccessException)
        {
            // Sin permisos para el namespace
            return Array.Empty<T>();
        }
        catch (SystemException)
        {
            // OutOfMemory, StackOverflow, etc. - no recuperar
            throw;
        }
    }

    /// <summary>
    /// Ejecuta una query WMI y retorna la primera propiedad de tipo string.
    /// </summary>
    public static string? GetString(string wql, string propertyName, string? scope = null)
        => Query(wql, o => o[propertyName]?.ToString() ?? string.Empty, scope).FirstOrDefault();

    /// <summary>
    /// Ejecuta una query WMI y retorna la primera propiedad como int.
    /// </summary>
    public static int? GetInt32(string wql, string propertyName, string? scope = null)
    {
        var val = Query(wql, o => o[propertyName], scope).FirstOrDefault();
        return val switch
        {
            null => null,
            int i => i,
            uint u => (int)u,
            long l => (int)l,
            ulong ul => (int)ul,
            string s when int.TryParse(s, out var parsed) => parsed,
            _ => null
        };
    }

    /// <summary>
    /// Ejecuta una query WMI y retorna la primera propiedad como uint.
    /// </summary>
    public static uint? GetUInt32(string wql, string propertyName, string? scope = null)
    {
        var val = Query(wql, o => o[propertyName], scope).FirstOrDefault();
        return val switch
        {
            null => (uint?)null,
            uint u => u,
            int i => (uint)i,
            long l => (uint)l,
            ulong ul => (uint)ul,
            string s when uint.TryParse(s, out var parsed) => parsed,
            _ => (uint?)null
        };
    }

    /// <summary>
    /// Ejecuta una query WMI y retorna la primera propiedad como ulong (para tamaños de disco).
    /// </summary>
    public static ulong? GetUInt64(string wql, string propertyName, string? scope = null)
    {
        var val = Query(wql, o => o[propertyName], scope).FirstOrDefault();
        return val switch
        {
            null => null,
            ulong ul => ul,
            long l => (ulong)l,
            uint u => u,
            int i => (ulong)i,
            string s when ulong.TryParse(s, out var parsed) => parsed,
            _ => null
        };
    }

    /// <summary>
    /// Verifica si el servicio WMI está disponible y accesible.
    /// </summary>
    public static bool IsAvailable()
    {
        try
        {
            using var searcher = new ManagementObjectSearcher("SELECT Name FROM Win32_OperatingSystem");
            using var results = searcher.Get();
            return results.Count > 0;
        }
        catch { return false; }
    }

    /// <summary>
    /// Convierte un valor de ManagementObject a double de forma segura.
    /// </summary>
    public static double ToDouble(object? value)
    {
        if (value is null) return -1;
        return value switch
        {
            double d => d,
            float f => f,
            int i => i,
            uint u => u,
            long l => l,
            ulong ul => ul,
            string s when double.TryParse(s, out var parsed) => parsed,
            _ => -1
        };
    }

    /// <summary>
    /// Convierte un valor de ManagementObject a ulong de forma segura.
    /// </summary>
    public static ulong ToUlong(object? value)
    {
        if (value is null) return 0;
        return value switch
        {
            ulong ul => ul,
            long l => l >= 0 ? (ulong)l : 0,
            uint u => u,
            int i => i >= 0 ? (ulong)i : 0,
            string s when ulong.TryParse(s, out var parsed) => parsed,
            _ => 0
        };
    }
}