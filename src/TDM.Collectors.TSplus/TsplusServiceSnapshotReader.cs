using System.ServiceProcess;
using TDM.Core;

namespace TDM.Collectors.TSplus;

/// <summary>
/// Lectura compartida del Service Control Manager para collectors TSplus. La cobertura
/// se expresa de forma explícita: un fallo del SCM nunca se convierte en una lista vacía
/// que pueda interpretarse como "servicio no instalado" o "sin fallas".
/// </summary>
internal static class TsplusServiceSnapshotReader
{
    public static ProbeResult<IReadOnlyDictionary<string, (string DisplayName, ServiceControllerStatus Status)>> Read(
        CancellationToken cancellationToken = default)
    {
        try
        {
            var output = new Dictionary<string, (string, ServiceControllerStatus)>(StringComparer.OrdinalIgnoreCase);
            var services = ServiceController.GetServices();
            var readable = 0;
            foreach (var service in services)
            {
                cancellationToken.ThrowIfCancellationRequested();
                using (service)
                {
                    try
                    {
                        output[service.ServiceName] = (service.DisplayName, service.Status);
                        readable++;
                    }
                    catch (InvalidOperationException)
                    {
                        // El servicio puede desaparecer entre la enumeración y la lectura.
                    }
                    catch (System.ComponentModel.Win32Exception)
                    {
                        // Un servicio individual puede no ser consultable; no invalida los demás.
                    }
                }
            }

            if (services.Length > 0 && readable == 0)
                return ProbeResult<IReadOnlyDictionary<string, (string DisplayName, ServiceControllerStatus Status)>>.Unavailable(
                    "Windows enumeró servicios, pero ninguno pudo leerse de forma confiable.");

            return ProbeResult<IReadOnlyDictionary<string, (string DisplayName, ServiceControllerStatus Status)>>.Available(output);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (UnauthorizedAccessException ex)
        {
            return ProbeResult<IReadOnlyDictionary<string, (string DisplayName, ServiceControllerStatus Status)>>.AccessDenied(ex.Message);
        }
        catch (System.ComponentModel.Win32Exception ex) when (ex.NativeErrorCode == 5)
        {
            return ProbeResult<IReadOnlyDictionary<string, (string DisplayName, ServiceControllerStatus Status)>>.AccessDenied(ex.Message);
        }
        catch (Exception ex)
        {
            return ProbeResult<IReadOnlyDictionary<string, (string DisplayName, ServiceControllerStatus Status)>>.Error(ex.Message);
        }
    }
}
