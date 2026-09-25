using TDM.Collectors.Network;
using TDM.Collectors.Rdp;
using TDM.Collectors.Security;
using TDM.Collectors.TSplus;
using TDM.Collectors.Windows;
using TDM.Core;

namespace TDM.Application;

/// <summary>
/// Fuente única de composición de collectors. GUI y CLI consumen el mismo catálogo para
/// evitar diferencias silenciosas de cobertura entre interfaces.
/// </summary>
public static class CollectorCatalog
{
    public static IReadOnlyList<IReadOnlyCollector> CreateFull() =>
    [
        // Primero: estado funcional y evidencia causal primaria de Windows/TSplus.
        // Así una ventana de 72 h no pierde las fuentes críticas si se agota el presupuesto global.
        new WindowsServiceCollector(),
        new ServiceDependencyGraphCollector(),
        new TsplusWindowsFunctionalDependencyCollector(),
        new TsplusProductStateCollector(),
        new TsplusDependencyHealthCollector(),
        new RemoteAccessModuleCoverageCollector(),
        new TsplusInternalConfigurationCollector(),
        new TsplusConfigurationDriftCollector(),
        new ServiceDependencyDriftCollector(),
        new TsplusProcessDependencyCollector(),
        new RdpHealthCollector(),
        new RdpEventCollector(),
        new WindowsLogonHealthCollector(),
        new UserSessionProfileCollector(),
        new WindowsEventCollector(),
        new WindowsPushEventCollector(),
        new RdpEtwCollector(),
        new WindowsLogIntegrityCollector(),
        new WindowsForensicEventCollector(),
        new WindowsChangeEventCollector(),
        new CrashEventCollector(),
        new DependencyLoadEventCollector(),
        new TsplusLogCollector(),
        new TwoFactorHealthCollector(),
        new AdvancedSecurityModuleHealthCollector(),
        new TsplusDeepInstallationCollector(),
        new SchannelEventCollector(),
        new DefenderEventCollector(),
        new NetworkHealthCollector(),
        new PrintingHealthCollector(),
        new ThirdPartyInterferenceCollector(),

        // Segundo: compatibilidad, recursos, artefactos, inventario y estado longitudinal.
        new WindowsCompatibilityCollector(),
        new SystemResourceCollector(),
        new ForensicArtifactCollector(),
        new TsplusFileIntegrityCollector(),
        new TsplusBaselineCollector(),
        new TsplusInventoryCollector(),
        new WindowsLongitudinalStateCollector(calculateHashes: false),
        new TsplusLongitudinalStateCollector(calculateHashes: false),
        new RemoteAppEncodingCompatibilityCollector()
    ];

    public static List<IReadOnlyCollector> CreateLightweight(ResourceLoadGuard.Snapshot resourceSnapshot) =>
    [
        new WindowsServiceCollector(),
        new LightweightSystemResourceCollector(resourceSnapshot),
        new LightweightRdpStateCollector(),
        new LightweightNetworkStateCollector(),
        new LightweightTsplusStateCollector()
    ];

    /// <summary>
    /// Auditoría longitudinal de estado estable. Se ejecuta a baja frecuencia y en un canal
    /// separado para que las muestras ligeras no borren la referencia anterior de configuración.
    /// </summary>
    public static IReadOnlyList<IReadOnlyCollector> CreateForensicStateMonitor() =>
    [
        new WindowsServiceCollector(),
        new ServiceDependencyGraphCollector(),
        new TsplusWindowsFunctionalDependencyCollector(),
        new WindowsCompatibilityCollector(),
        new WindowsLongitudinalStateCollector(calculateHashes: false),
        new TsplusProductStateCollector(),
        new TsplusDependencyHealthCollector(),
        new TsplusInternalConfigurationCollector(),
        new RemoteAccessModuleCoverageCollector(calculateHashes: false),
        new TsplusLongitudinalStateCollector(calculateHashes: false)
    ];

    /// <summary>
    /// Auditoría de integridad física. Calcula hashes sólo en archivos críticos y con límites
    /// de tamaño, por lo que puede conservarse a una cadencia mucho menor que las métricas.
    /// </summary>
    public static IReadOnlyList<IReadOnlyCollector> CreateIntegrityStateMonitor() =>
    [
        new WindowsLongitudinalStateCollector(calculateHashes: true),
        new RemoteAccessModuleCoverageCollector(calculateHashes: true),
        new TsplusLongitudinalStateCollector(calculateHashes: true)
    ];

    public static IReadOnlyList<IReadOnlyCollector> CreateCliMonitor() =>
    [
        new WindowsServiceCollector(),
        new TsplusWindowsFunctionalDependencyCollector(),
        new SystemResourceCollector(),
        new PrintingHealthCollector(),
        new RdpHealthCollector(),
        new UserSessionProfileCollector(),
        new NetworkHealthCollector(),
        new AdvancedSecurityModuleHealthCollector(),
        new TsplusProductStateCollector(),
        new TwoFactorHealthCollector(),
        new TsplusDependencyHealthCollector(),
        new RemoteAccessModuleCoverageCollector(calculateHashes: false)
    ];


    /// <summary>
    /// Catálogo para TDM.Service. La ruta normal utiliza collectors ligeros cada 60 s;
    /// cada cierto número de ciclos el servicio solicita includeHeavy para renovar
    /// disco/procesos/certificados/sesiones sin cargar esas fuentes en cada muestra.
    /// </summary>
    public static List<IReadOnlyCollector> CreateServiceMonitor(ResourceLoadGuard.Snapshot resourceSnapshot, bool includeHeavy)
    {
        var collectors = new List<IReadOnlyCollector>
        {
            new WindowsServiceCollector()
        };

        if (includeHeavy)
        {
            // FIX64: renueva periódicamente el grafo SCM real para que Servicios/Dependencias
            // conserve relaciones de Windows y TSplus aun sin ejecutar un diagnóstico manual.
            collectors.Add(new ServiceDependencyGraphCollector());
            collectors.Add(new TsplusWindowsFunctionalDependencyCollector());
            collectors.Add(new SystemResourceCollector());
            collectors.Add(new RdpHealthCollector());
            collectors.Add(new UserSessionProfileCollector());
            collectors.Add(new NetworkHealthCollector());
            collectors.Add(new AdvancedSecurityModuleHealthCollector());
            collectors.Add(new TsplusProductStateCollector());
            collectors.Add(new TwoFactorHealthCollector());
            collectors.Add(new TsplusDependencyHealthCollector());
            collectors.Add(new WindowsLogonHealthCollector());
            collectors.Add(new WindowsLogIntegrityCollector());
            collectors.Add(new WindowsPushEventCollector());
            collectors.Add(new ServiceDependencyDriftCollector());
            collectors.Add(new TsplusProcessDependencyCollector());
            collectors.Add(new RemoteAccessModuleCoverageCollector(calculateHashes: false));
        }
        else
        {
            collectors.Add(new LightweightSystemResourceCollector(resourceSnapshot));
            collectors.Add(new LightweightRdpStateCollector());
            collectors.Add(new LightweightNetworkStateCollector());
            collectors.Add(new LightweightTsplusStateCollector());
        }

        return collectors;
    }
}
