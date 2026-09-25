namespace TDM.Core;

/// <summary>
/// Sondas de existencia que conservan la diferencia entre ausencia real y fallo de acceso/E/S.
/// File.Exists/Directory.Exists ocultan varias excepciones devolviendo false.
/// </summary>
public static class FileSystemProbe
{
    public static ProbeResult<bool> File(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return ProbeResult<bool>.Unavailable("Ruta vacía");
        try
        {
            var attributes = System.IO.File.GetAttributes(path);
            return (attributes & FileAttributes.Directory) != 0
                ? ProbeResult<bool>.Absent("La ruta existe pero es un directorio")
                : ProbeResult<bool>.Available(true);
        }
        catch (FileNotFoundException) { return ProbeResult<bool>.Absent(); }
        catch (DirectoryNotFoundException) { return ProbeResult<bool>.Absent(); }
        catch (UnauthorizedAccessException ex) { return ProbeResult<bool>.AccessDenied(ex.Message); }
        catch (System.Security.SecurityException ex) { return ProbeResult<bool>.AccessDenied(ex.Message); }
        catch (IOException ex) { return ProbeResult<bool>.Error(ex.Message); }
        catch (Exception ex) { return ProbeResult<bool>.Error(ex.Message); }
    }

    public static ProbeResult<bool> Directory(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return ProbeResult<bool>.Unavailable("Ruta vacía");
        try
        {
            var attributes = System.IO.File.GetAttributes(path);
            return (attributes & FileAttributes.Directory) != 0
                ? ProbeResult<bool>.Available(true)
                : ProbeResult<bool>.Absent("La ruta existe pero no es un directorio");
        }
        catch (FileNotFoundException) { return ProbeResult<bool>.Absent(); }
        catch (DirectoryNotFoundException) { return ProbeResult<bool>.Absent(); }
        catch (UnauthorizedAccessException ex) { return ProbeResult<bool>.AccessDenied(ex.Message); }
        catch (System.Security.SecurityException ex) { return ProbeResult<bool>.AccessDenied(ex.Message); }
        catch (IOException ex) { return ProbeResult<bool>.Error(ex.Message); }
        catch (Exception ex) { return ProbeResult<bool>.Error(ex.Message); }
    }

    public static string Display(ProbeResult<bool> probe, string presentText = "Presente", string absentText = "No presente")
        => probe.State switch
        {
            ProbeState.Available => presentText,
            ProbeState.Absent => absentText,
            ProbeState.AccessDenied => "NO EVALUADO · acceso denegado",
            ProbeState.Error => "NO EVALUADO · error de E/S",
            _ => "NO EVALUADO"
        };
}
