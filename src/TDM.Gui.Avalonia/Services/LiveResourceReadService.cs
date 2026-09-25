using TDM.Collectors.Windows;

namespace TDM.Gui.Avalonia.Services;

/// <summary>
/// Lectura puntual para la UI. Se ejecuta fuera del hilo visual y permite que las tarjetas
/// Procesos principales / Discos se refresquen cada 5 s aunque TDM.Service sea la fuente
/// principal de telemetría y aunque todavía no se haya ejecutado un diagnóstico completo.
/// </summary>
public sealed class LiveResourceReadService
{
    public async Task<LightweightProcessDiskSnapshot> ReadAsync(CancellationToken ct = default)
    {
        try
        {
            return await Task.Run(() => LightweightResourceSnapshotReader.Capture(ct), ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return LightweightProcessDiskSnapshot.Empty;
        }
    }
}
