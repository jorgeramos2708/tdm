using System.Diagnostics;

namespace TDM.Collectors.Windows;

/// <summary>
/// Snapshot ligero, de solo lectura y sin WMI, para mantener visibles en la UI
/// los procesos principales y el estado de discos aun sin ejecutar un diagnóstico.
/// Se limita a los 8 procesos con mayor Working Set y sólo consulta Handles/Threads
/// para esos procesos, reduciendo el coste del refresco de 5 segundos.
/// </summary>
public sealed record LightweightProcessResource(
    string Name,
    int Pid,
    double RamMb,
    int Handles,
    int Threads);

public sealed record LightweightDiskResource(
    string Drive,
    double FreePercent,
    long FreeBytes,
    long TotalBytes);

public sealed record LightweightProcessDiskSnapshot(
    DateTimeOffset Timestamp,
    IReadOnlyList<LightweightProcessResource> Processes,
    IReadOnlyList<LightweightDiskResource> Disks)
{
    public static LightweightProcessDiskSnapshot Empty { get; } =
        new(DateTimeOffset.MinValue, Array.Empty<LightweightProcessResource>(), Array.Empty<LightweightDiskResource>());
}

public static class LightweightResourceSnapshotReader
{
    public static LightweightProcessDiskSnapshot Capture(CancellationToken cancellationToken = default)
        => new(DateTimeOffset.Now, CaptureProcesses(cancellationToken), CaptureDisks(cancellationToken));

    private static IReadOnlyList<LightweightProcessResource> CaptureProcesses(CancellationToken cancellationToken)
    {
        Process[] processes;
        try
        {
            processes = Process.GetProcesses();
        }
        catch
        {
            return Array.Empty<LightweightProcessResource>();
        }

        try
        {
            var candidates = new List<(Process Process, string Name, int Pid, double RamMb)>();
            foreach (var process in processes)
            {
                cancellationToken.ThrowIfCancellationRequested();
                try
                {
                    process.Refresh();
                    candidates.Add((
                        process,
                        process.ProcessName,
                        process.Id,
                        Math.Max(0d, process.WorkingSet64 / 1024d / 1024d)));
                }
                catch
                {
                    // Algunos procesos protegidos o efímeros pueden no exponer métricas.
                }
            }

            var top = candidates
                .OrderByDescending(x => x.RamMb)
                .ThenBy(x => x.Name, StringComparer.OrdinalIgnoreCase)
                .Take(8)
                .ToList();

            var output = new List<LightweightProcessResource>(top.Count);
            foreach (var row in top)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var handles = 0;
                var threads = 0;
                try
                {
                    row.Process.Refresh();
                    handles = Math.Max(0, row.Process.HandleCount);
                    threads = Math.Max(0, row.Process.Threads.Count);
                }
                catch
                {
                    // El proceso pudo finalizar entre la selección y la lectura detallada.
                }

                output.Add(new LightweightProcessResource(row.Name, row.Pid, row.RamMb, handles, threads));
            }

            return output;
        }
        finally
        {
            foreach (var process in processes)
                process.Dispose();
        }
    }

    private static IReadOnlyList<LightweightDiskResource> CaptureDisks(CancellationToken cancellationToken)
    {
        var output = new List<LightweightDiskResource>();
        DriveInfo[] drives;
        try
        {
            drives = DriveInfo.GetDrives();
        }
        catch
        {
            return output;
        }

        foreach (var drive in drives)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                if (drive.DriveType != DriveType.Fixed || !drive.IsReady)
                    continue;

                var total = Math.Max(0L, drive.TotalSize);
                var free = Math.Max(0L, drive.AvailableFreeSpace);
                var freePercent = total > 0 ? free * 100d / total : 0d;
                output.Add(new LightweightDiskResource(drive.Name, freePercent, free, total));
            }
            catch
            {
                // Una unidad no accesible no impide mostrar el resto.
            }
        }

        return output.OrderBy(x => x.Drive, StringComparer.OrdinalIgnoreCase).ToList();
    }
}
