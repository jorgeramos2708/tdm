namespace TDM.Persistence;

/// <summary>
/// Rutas explícitas para evitar que procesos distintos elijan almacenes diferentes.
/// El servicio siempre usa MachineRootPath. La GUI usa MachineRootPath cuando detecta
/// un servicio activo; sin servicio conserva el fallback por usuario para compatibilidad.
/// </summary>
public static class TdmDataPaths
{
    public static string MachineRootPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "TSplus Diagnostic Monitor", "Data");

    public static string UserRootPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "TSplus Diagnostic Monitor", "Data");

    public static string NotifierUserStatePath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "TSplus Diagnostic Monitor", "Notifier");

    public static string ResolveWritableDefault()
    {
        var explicitPath = Environment.GetEnvironmentVariable("TDM_DATA_DIR");
        if (!string.IsNullOrWhiteSpace(explicitPath)) return Path.GetFullPath(explicitPath);

        var machine = MachineRootPath;
        try
        {
            Directory.CreateDirectory(machine);
            var probe = Path.Combine(machine, ".write-probe-" + Guid.NewGuid().ToString("N"));
            File.WriteAllText(probe, string.Empty);
            File.Delete(probe);
            return machine;
        }
        catch
        {
            return UserRootPath;
        }
    }
}
