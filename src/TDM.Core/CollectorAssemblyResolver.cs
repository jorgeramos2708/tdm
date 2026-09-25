using System.Reflection;
using System.Runtime.Loader;

namespace TDM.Core;

/// <summary>
/// Resuelve ensamblados de collectors/plugins desde directorios conocidos.
/// Evita FileNotFoundException cuando un collector referencia dependencias
/// que no están en la carpeta base (ej. plugins opcionales, collectors dinámicos).
/// </summary>
public static class CollectorAssemblyResolver
{
    private static readonly string[] ProbeDirectories =
    [
        "collectors",
        "plugins",
        "extensions",
        "modules"
    ];

    private static bool _initialized;

    /// <summary>
    /// Registra el handler de resolución en el AssemblyLoadContext por defecto.
    /// Llamar una sola vez al inicio (App.axaml.cs / Program.cs / TdmWorker.cs).
    /// </summary>
    public static void Initialize(string? baseDirectory = null)
    {
        if (_initialized) return;
        _initialized = true;

        var baseDir = baseDirectory ?? AppContext.BaseDirectory;
        var probePaths = ProbeDirectories
            .Select(d => Path.Combine(baseDir, d))
            .Where(Directory.Exists)
            .ToList();

        AssemblyLoadContext.Default.Resolving += (context, name) =>
        {
            foreach (var probe in probePaths)
            {
                var candidate = Path.Combine(probe, name.Name + ".dll");
                if (File.Exists(candidate))
                {
                    try { return context.LoadFromAssemblyPath(candidate); }
                    catch { /* siguiente probe */ }
                }
            }
            return null;
        };
    }
}