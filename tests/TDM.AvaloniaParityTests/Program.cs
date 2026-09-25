using System.Text.Json;
using TDM.Collectors.Windows;
using TDM.Gui.Avalonia.Services;
using TDM.Gui.Avalonia.ViewModels;
using TDM.Models;
using TDM.Notifications;
using TDM.Persistence;

namespace TDM.AvaloniaParityTests;

internal static class Program
{
    private static int _passed;
    private static int _failed;

    private static int Main()
    {
        var now = DateTimeOffset.Now;
        var sessionIncident = new ObservabilityIncident(
            now.AddSeconds(-20), "ACCOUNT_LOCKOUT", "RDP/Auth", "Error", "Bloqueo correlacionado con sesión",
            Classification: "IdentityCorrelated");
        var serviceIncident = new ObservabilityIncident(
            now.AddSeconds(-10), "SERVICE_TERMINATION", "TermService", "Critico", "Remote Desktop Services terminó inesperadamente",
            Product: "TSplus");

        var earlier = new ObservabilitySample
        {
            Timestamp = now.AddMinutes(-1),
            SampleKind = "monitor",
            CpuPercent = 88,
            MemoryFreePercent = 44,
            MemoryTotalBytes = 8d * 1024 * 1024 * 1024,
            NetworkReceiveMbps = 1.2,
            NetworkSendMbps = 0.4,
            TdmCpuPercent = 1.5,
            TdmWorkingSetMb = 92,
            TdmHandleCount = 210,
            TdmThreadCount = 22,
            DiagnosticDurationMs = 650,
            MonitorIntervalSeconds = 60,
            MonitorMode = "NORMAL"
        };

        var latest = new ObservabilitySample
        {
            Timestamp = now,
            SampleKind = "diagnostic",
            CpuPercent = 82.5,
            MemoryFreePercent = 35,
            MemoryTotalBytes = 8d * 1024 * 1024 * 1024,
            NetworkReceiveMbps = 2.5,
            NetworkSendMbps = 0.75,
            TcpEphemeralUsagePercent = 72,
            TcpTimeWait = 123,
            TcpEstablished = 45,
            ActiveSessions = 3,
            DisconnectedSessions = 1,
            SessionCoverage = "Parcial",
            LogonFailures = 4,
            NlaFailures = 2,
            ProcessRamMb = new Dictionary<string, double> { ["wsession"] = 500, ["svcapp"] = 220 },
            ProcessHandles = new Dictionary<string, double> { ["wsession"] = 1200, ["svcapp"] = 300 },
            ProcessThreads = new Dictionary<string, double> { ["wsession"] = 60, ["svcapp"] = 25 },
            DiskFreePercent = new Dictionary<string, double> { ["C:"] = 9, ["D:"] = 55 },
            DiskFreeBytes = new Dictionary<string, double> { ["C:"] = 9d * 1024 * 1024 * 1024, ["D:"] = 110d * 1024 * 1024 * 1024 },
            ServiceStates = new Dictionary<string, string>
            {
                ["TermService"] = "Running",
                ["RemoteSupportUnattended-Service"] = "Complementario · Unknown",
                ["TSplusGateway"] = "Stopped",
                ["gpsvc"] = "Stopped"
            },
            DependencyStates = new Dictionary<string, string>
            {
                ["RemoteSupportUnattended-Service → RPCSS"] = "Running",
                ["gpsvc → ProfSvc"] = "Stopped"
            },
            Incidents = new[] { sessionIncident, serviceIncident },
            ModuleHealth = new Dictionary<string, string>
            {
                ["RDP / Remote Access Core"] = "Saludable",
                ["Web / HTML5 / Web Portal"] = "Advertencia"
            },
            WarningFindings = 1,
            BaselineDifferences = 1,
            CrashLoops = 1,
            Transitions = 2,
            CoverageScore = 91,
            MonitorIntervalSeconds = 60,
            MonitorMode = "NORMAL",
            TdmCpuPercent = 2.2,
            TdmWorkingSetMb = 105,
            TdmHandleCount = 240,
            TdmThreadCount = 26,
            DiagnosticDurationMs = 720,
            CollectorTimeouts = 0,
            SlowestCollector = "WindowsEvent",
            SlowestCollectorMs = 180,
            ObservabilityBytes = 4096,
            CausalOrigin = "WINDOWS",
            Originator = "TermService"
        };

        IReadOnlyList<ObservabilitySample> samples = new[] { earlier, latest };

        Run("Telemetry_PeriodsUpToThreeDays", () =>
        {
            var telemetry = new TelemetryReadService();
            True(!telemetry.PeriodOptions.Contains("5 minutos"), "5 minutos fue sólo un ejemplo y no debe aparecer como periodo disponible.");
            Equal(11, telemetry.PeriodOptions.Count);
            True(telemetry.PeriodOptions.SequenceEqual(new[] { "Tiempo real", "15 minutos", "30 minutos", "1 hora", "2 horas", "4 horas", "8 horas", "12 horas", "1 día", "2 días", "3 días" }), "Los periodos visibles no coinciden con la lista acordada.");
            True(telemetry.PeriodOptions.Contains("8 horas"), "Falta periodo de 8 horas.");
            True(telemetry.PeriodOptions.Contains("12 horas"), "Falta periodo de 12 horas.");
            True(!telemetry.PeriodOptions.Contains("24 horas"), "24 horas fue retirado del selector por solicitud de UI.");
            True(telemetry.PeriodOptions.Contains("1 día"), "Falta periodo de 1 día.");
            True(telemetry.PeriodOptions.Contains("2 días"), "Falta periodo de 2 días.");
            True(telemetry.PeriodOptions.Contains("3 días"), "Falta periodo de 3 días.");
            Equal(TimeSpan.FromHours(8), TelemetryReadService.WindowForPeriod("8 horas"));
            Equal(TimeSpan.FromHours(12), TelemetryReadService.WindowForPeriod("12 horas"));
            Equal(TimeSpan.FromDays(1), TelemetryReadService.WindowForPeriod("1 día"));
            Equal(TimeSpan.FromDays(2), TelemetryReadService.WindowForPeriod("2 días"));
            Equal(TimeSpan.FromDays(3), TelemetryReadService.WindowForPeriod("3 días"));
            Equal(TimeSpan.FromDays(3), ObservabilityStore.MaximumRetention);

            var diagnostic = new DiagnosticExecutionService();
            True(!diagnostic.LookbackOptions.Contains("5 minutos"), "Diagnóstico: 5 minutos no debe aparecer como opción disponible.");
            Equal(11, diagnostic.LookbackOptions.Count);
            True(diagnostic.LookbackOptions.SequenceEqual(telemetry.PeriodOptions), "Diagnóstico y telemetría deben exponer exactamente los mismos periodos.");
            True(diagnostic.LookbackOptions.Contains("8 horas"), "Diagnóstico: falta periodo de 8 horas.");
            True(diagnostic.LookbackOptions.Contains("12 horas"), "Diagnóstico: falta periodo de 12 horas.");
            True(!diagnostic.LookbackOptions.Contains("24 horas"), "Diagnóstico: 24 horas fue retirado del selector.");
            True(diagnostic.LookbackOptions.Contains("1 día"), "Diagnóstico: falta periodo de 1 día.");
            True(diagnostic.LookbackOptions.Contains("2 días"), "Diagnóstico: falta periodo de 2 días.");
            True(diagnostic.LookbackOptions.Contains("3 días"), "Diagnóstico: falta periodo de 3 días.");
            Equal(TimeSpan.FromDays(3), DiagnosticExecutionService.LookbackForPeriod("3 días"));
            Equal((TimeSpan?)null, DiagnosticExecutionService.ExecutionLimitForPeriod("Tiempo real"));
            Equal(TimeSpan.FromMinutes(15), DiagnosticExecutionService.ExecutionLimitForPeriod("15 minutos"));
            Equal(TimeSpan.FromMinutes(30), DiagnosticExecutionService.ExecutionLimitForPeriod("30 minutos"));
            Equal(TimeSpan.FromHours(1), DiagnosticExecutionService.ExecutionLimitForPeriod("1 hora"));
            Equal(TimeSpan.FromHours(2), DiagnosticExecutionService.ExecutionLimitForPeriod("2 horas"));
            Equal(TimeSpan.FromHours(4), DiagnosticExecutionService.ExecutionLimitForPeriod("4 horas"));
            Equal(TimeSpan.FromHours(8), DiagnosticExecutionService.ExecutionLimitForPeriod("8 horas"));
            Equal(TimeSpan.FromHours(12), DiagnosticExecutionService.ExecutionLimitForPeriod("12 horas"));
            Equal(TimeSpan.FromDays(1), DiagnosticExecutionService.ExecutionLimitForPeriod("1 día"));
            Equal(TimeSpan.FromDays(2), DiagnosticExecutionService.ExecutionLimitForPeriod("2 días"));
            Equal(TimeSpan.FromDays(3), DiagnosticExecutionService.ExecutionLimitForPeriod("3 días"));
        });

        Run("Realtime_CadenceIsFiveSeconds", () =>
        {
            Equal(5, IntegratedMonitoringService.RealtimeIntervalSeconds);
            Equal(TimeSpan.FromMinutes(5), TelemetryReadService.WindowForPeriod("Tiempo real"));
        });

        Run("ExecutionClock_PauseResumeAndExplicitReset", () =>
        {
            var clock = new ResumableExecutionClock();
            clock.Start();
            Thread.Sleep(35);
            clock.Pause();
            var firstSegment = clock.Elapsed;
            True(firstSegment >= TimeSpan.FromMilliseconds(20), "El primer segmento no fue contabilizado.");

            Thread.Sleep(25);
            True((clock.Elapsed - firstSegment).Duration() < TimeSpan.FromMilliseconds(8), "El cronómetro avanzó mientras estaba pausado.");

            clock.Start();
            Thread.Sleep(35);
            clock.Pause();
            True(clock.Elapsed >= firstSegment + TimeSpan.FromMilliseconds(20), "Reanudar sustituyó el tiempo acumulado en lugar de sumarlo.");

            clock.Reset(continueRunning: false);
            True(clock.Elapsed < TimeSpan.FromMilliseconds(5), "El reinicio explícito no regresó el cronómetro a cero.");
        });

        Run("ReportExport_SelectedDirectoryCreatesHtmlAndJson", () =>
        {
            var directory = Path.Combine(Path.GetTempPath(), "TDM-export-test-" + Guid.NewGuid().ToString("N"));
            try
            {
                var snapshot = new SystemSnapshot(
                    "EQUIPO-PRUEBA", "Windows", "11", "22631", "x64", TimeSpan.FromHours(4), now,
                    TsplusDetectado: true, TsplusRuta: null, TsplusVersion: "prueba");
                var report = new DiagnosticReport(snapshot, [], [], now.AddSeconds(-1), now);
                var result = new DiagnosticExecutionService()
                    .ExportAsync(report, directory, CancellationToken.None).GetAwaiter().GetResult();

                True(Path.GetFullPath(result.HtmlPath).StartsWith(Path.GetFullPath(directory), StringComparison.OrdinalIgnoreCase), "El HTML no se guardó en la carpeta elegida.");
                True(Path.GetFullPath(result.JsonPath).StartsWith(Path.GetFullPath(directory), StringComparison.OrdinalIgnoreCase), "El JSON no se guardó en la carpeta elegida.");
                True(File.Exists(result.HtmlPath) && new FileInfo(result.HtmlPath).Length > 0, "El HTML exportado está ausente o vacío.");
                True(File.Exists(result.JsonPath) && new FileInfo(result.JsonPath).Length > 0, "El JSON exportado está ausente o vacío.");
            }
            finally
            {
                if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
            }
        });

        Run("Support_ServiceRatio", () =>
        {
            var vm = new SupportDashboardViewModel(); vm.Apply(samples);
            Equal("3/4", vm.ServiceValue);
            Equal(0.25d, vm.ServiceFraction);
            Equal("1 detenido", vm.ServiceDetail);
            Equal("Servicios 2/3 · Dependencias 1/1", vm.ServiceExtra);
            vm.ShowServicesDetailCommand.Execute(null);
            True(vm.DetailText.Contains("Servicios: 2/3; detenidos: 1; revisar: 0", StringComparison.Ordinal), "El detalle no desglosa servicios.");
            True(vm.DetailText.Contains("Dependencias: 1/1; detenidas: 0; revisar: 0", StringComparison.Ordinal), "El detalle no desglosa dependencias.");
            var refreshed = latest with
            {
                ServiceStates = new Dictionary<string, string>
                {
                    ["TermService"] = "Running",
                    ["RemoteSupportUnattended-Service"] = "Running",
                    ["TSplusGateway"] = "Stopped"
                }
            };
            vm.Apply(new[] { refreshed });
            Equal("3/4", vm.ServiceValue);
            True(vm.DetailText.Contains("Saludables/neutrales: 3/4", StringComparison.Ordinal), "El detalle abierto no se actualizó con el mismo snapshot de la tarjeta.");

            var services = new ServicesDashboardViewModel(); services.Apply(samples);
            var allowedOperationalStates = new HashSet<string>(StringComparer.Ordinal)
            {
                "En ejecución", "Detenido", "Bajo demanda", "No requerido", "Complementario", "Revisar", "No evaluado"
            };
            True(services.Services.All(x => allowedOperationalStates.Contains(x.Status)), "Servicios expone un estado fuera del contrato visible permitido.");
            True(services.Dependencies.All(x => allowedOperationalStates.Contains(x.Status)), "Dependencias expone un estado fuera del contrato visible permitido.");
            True(!services.Services.Any(x => x.Name.Equals("gpsvc", StringComparison.OrdinalIgnoreCase)), "Se mostró un servicio sin relación con TSplus.");
            True(!services.Dependencies.Any(x => x.Name.Contains("ProfSvc", StringComparison.OrdinalIgnoreCase)), "Se mostró una dependencia ajena al subgrafo TSplus.");
            Equal("En ejecución", services.Services.Single(x => x.Name.Equals("TermService", StringComparison.OrdinalIgnoreCase)).Status);
            Equal("Detenido", services.Services.Single(x => x.Name.Equals("TSplusGateway", StringComparison.OrdinalIgnoreCase)).Status);
            Equal("Complementario", services.Services.Single(x => x.Name.Equals("RemoteSupportUnattended-Service", StringComparison.OrdinalIgnoreCase)).Status);
            Equal("En ejecución", services.Dependencies.Single(x => x.Name.Equals("RemoteSupportUnattended-Service → RPCSS", StringComparison.OrdinalIgnoreCase)).Status);
        });

        Run("Support_TsplusModuleErrors", () =>
        {
            var moduleSample = latest with
            {
                ModuleHealth = new Dictionary<string, string>
                {
                    ["RDP / Remote Access Core"] = "Saludable",
                    ["Web / HTML5 / Web Portal"] = "Error",
                    ["Advanced Security"] = "Crítico",
                    ["Two-Factor Authentication (2FA)"] = "Advertencia"
                }
            };
            var vm = new SupportDashboardViewModel(); vm.Apply(new[] { moduleSample });
            Equal("2/4", vm.ModuleValue);
            Equal("1 crítico · 1 con error", vm.ModuleDetail);
            Equal(0.5d, vm.ModuleFraction);
            vm.ShowModulesDetailCommand.Execute(null);
            True(vm.DetailText.Contains("Módulos con error o estado crítico: 2/4", StringComparison.Ordinal), "El detalle modular no muestra el total afectado.");
        });

        Run("Services_OnlyTsplusReachableSubgraph", () =>
        {
            var graphSample = new ObservabilitySample
            {
                Timestamp = now,
                ServiceStates = new Dictionary<string, string>
                {
                    ["RemoteSupportUnattended-Service"] = "Running",
                    ["RpcSs"] = "Running",
                    ["DcomLaunch"] = "Running",
                    ["gpsvc"] = "Stopped"
                },
                DependencyStates = new Dictionary<string, string>
                {
                    ["RemoteSupportUnattended-Service → RpcSs"] = "Running",
                    ["RpcSs → DcomLaunch"] = "Running",
                    ["gpsvc → ProfSvc"] = "Stopped"
                }
            };
            var vm = new ServicesDashboardViewModel(); vm.Apply(new[] { graphSample });
            True(vm.Services.Any(x => x.Name.Equals("RemoteSupportUnattended-Service", StringComparison.OrdinalIgnoreCase)), "Falta el servicio raíz TSplus.");
            True(vm.Services.Any(x => x.Name.Equals("RpcSs", StringComparison.OrdinalIgnoreCase)), "Falta una dependencia directa de TSplus.");
            True(vm.Services.Any(x => x.Name.Equals("DcomLaunch", StringComparison.OrdinalIgnoreCase)), "Falta una dependencia transitiva de TSplus.");
            True(!vm.Services.Any(x => x.Name.Equals("gpsvc", StringComparison.OrdinalIgnoreCase)), "Se conservó un servicio ajeno al subgrafo TSplus.");
            Equal(2, vm.Dependencies.Count);
        });

        Run("Notifications_CollapseRelatedWindowsCrashEvents", () =>
        {
            var runtimeKey = NotificationSignalPolicy.CanonicalKey("incident|LOCAL|Application: TDM.Notifier.exe CoreCLR Version: 8.0.29 Description: unhandled exception|DOTNET_UNHANDLED_EXCEPTION");
            var applicationKey = NotificationSignalPolicy.CanonicalKey("incident|LOCAL|TDM.Notifier.exe|APPLICATION_CRASH");
            var werKey = NotificationSignalPolicy.CanonicalKey("incident|LOCAL|Aplicación: TDM.Notifier.exe|WER_REPORT");
            Equal(applicationKey, runtimeKey);
            Equal(applicationKey, werKey);
            True(applicationKey.EndsWith("|PROCESS_CRASH", StringComparison.Ordinal), "El crash no se normalizó como una condición única.");
        });

        Run("Incidents_CollapseRelatedWindowsCrashRows", () =>
        {
            var crashTime = now.AddSeconds(-5);
            var crashSample = new ObservabilitySample
            {
                Timestamp = crashTime,
                Incidents = new[]
                {
                    new ObservabilityIncident(crashTime, "DOTNET_UNHANDLED_EXCEPTION", "Application: TDM.Notifier.exe CoreCLR Version: 8.0.29", "Error", "The process was terminated due to an unhandled exception."),
                    new ObservabilityIncident(crashTime, "APPLICATION_CRASH", "TDM.Notifier.exe", "Error", "Nombre del módulo con errores: KERNELBASE.dll"),
                    new ObservabilityIncident(crashTime, "WER_REPORT", "Aplicación: TDM.Notifier.exe", "Error", "Windows Error Reporting")
                }
            };
            var vm = new IncidentsDashboardViewModel(); vm.Apply(new[] { crashSample });
            Equal("1", vm.Total);
            Equal(1, vm.Incidents.Count);
            Equal("Crash de aplicación", vm.Incidents[0].Kind);
        });

        Run("Support_IncidentsAndSessions", () =>
        {
            var vm = new SupportDashboardViewModel(); vm.Apply(samples);
            Equal("4", vm.SessionValue);
            Equal("Activas: 3 · Desconectadas: 1", vm.SessionCounts);
            Equal("1 incidente de sesión", vm.SessionSummary);
            Equal("2", vm.IncidentValue);
            Equal(1, vm.CriticalIncidents);
            Equal(1, vm.ErrorIncidents);
        });

        Run("Tsplus_NoSpacesAroundSlashes", () =>
        {
            var vm = new TsplusDashboardViewModel(); vm.Apply(samples);
            True(!vm.OverallDetail.Contains(" / ", StringComparison.Ordinal), "Salud global conserva espacios alrededor de '/'.");
            True(vm.Modules.All(x => !x.Name.Contains(" / ", StringComparison.Ordinal)), "Un nombre de módulo conserva espacios alrededor de '/'.");
            True(vm.Modules.All(x => !x.Detail.Contains(" / ", StringComparison.Ordinal)), "Un detalle de módulo conserva espacios alrededor de '/'.");
            Equal("Remote Access/RDP", vm.Modules[0].Name);
            Equal("Web/HTML5", vm.Modules[1].Name);
        });

        Run("Performance_CoreMetrics", () =>
        {
            var vm = new PerformanceDashboardViewModel(); vm.Apply(samples);
            Equal("82.5%", vm.CpuValue);
            Equal("65.0% usada", vm.MemoryValue);
            Equal("↓ 2.50 Mbps", vm.NetworkReceiveValue);
            Equal("↑ 0.75 Mbps", vm.NetworkSendValue);
        });

        Run("Performance_ProcessAndDisk", () =>
        {
            var vm = new PerformanceDashboardViewModel(); vm.Apply(samples);
            Equal("wsession", vm.TopProcesses[0].Name);
            Equal("500 MB", vm.TopProcesses[0].Value);
            Equal("C:", vm.Disks[0].Name);
            Equal("9.0% libre", vm.Disks[0].Value);
        });

        Run("Performance_LiveResourcesWithoutDiagnostic", () =>
        {
            var live = new LightweightProcessDiskSnapshot(
                now,
                new[] { new LightweightProcessResource("explorer", 4321, 256, 700, 32) },
                new[] { new LightweightDiskResource("C:\\", 48.5, 97L * 1024 * 1024 * 1024, 200L * 1024 * 1024 * 1024) });
            var vm = new PerformanceDashboardViewModel();
            vm.Apply(Array.Empty<ObservabilitySample>(), live);
            Equal("explorer[PID 4321]", vm.TopProcesses[0].Name);
            Equal("256 MB", vm.TopProcesses[0].Value);
            Equal("C:", vm.Disks[0].Name);
            Equal("48.5% libre", vm.Disks[0].Value);
        });

        Run("Sessions_Parity", () =>
        {
            var vm = new SessionsDashboardViewModel(); vm.Apply(samples);
            Equal("3", vm.ActiveValue); Equal("1", vm.DisconnectedValue); Equal("Parcial", vm.Coverage);
            Equal("4", vm.LogonFailures); Equal("2", vm.NlaFailures); Equal(1, vm.SessionIncidents.Count);
        });

        Run("Incidents_Parity", () =>
        {
            var vm = new IncidentsDashboardViewModel(); vm.Apply(samples);
            Equal("2", vm.Total); Equal("1", vm.Critical); Equal("1", vm.Errors); Equal("2", vm.AffectedComponents);
            Equal("TDM.Notifier.exe", TdmVisibleText.Sanitize("TDM.Notifier.Avalonia.exe"));
            Equal("Application: TDM.Application.exe", TdmVisibleText.Sanitize("Application: TDM.Gui.Avalonia.exe"));
            True(!TdmVisibleText.Sanitize("NotifierAvalonia Avalonia").Contains("Avalonia", StringComparison.OrdinalIgnoreCase), "El sanitizador dejó visible el nombre técnico del framework.");
        });

        Run("General_Parity", () =>
        {
            var vm = new GeneralDashboardViewModel(); vm.Apply(samples);
            Equal("82.5%", vm.Cpu); Equal("35.0%", vm.MemoryFree); Equal("91%", vm.Coverage); Equal("1", vm.CrashLoops);
            True(vm.Modules.Count >= 2, "Se esperaban módulos de salud.");
        });

        Run("Preventive_Signals", () =>
        {
            var vm = new PreventiveDashboardViewModel(); vm.Apply(samples);
            Equal("82.5%", vm.CpuValue);
            Equal("65.0% usada", vm.MemoryValue);
            True(vm.Signals.Any(x => x.Name.Contains("puertos efímeros", StringComparison.OrdinalIgnoreCase)), "Falta señal TCP preventiva.");
            True(vm.Signals.Any(x => x.Name.Contains("Disco C:", StringComparison.OrdinalIgnoreCase)), "Falta señal preventiva de disco.");
        });

        Run("Preventive_RiskAndForecast", () =>
        {
            var vm = new PreventiveDashboardViewModel(); vm.Apply(samples);
            True(vm.PreventiveRisk is "ALTO" or "CRÍTICO", "El riesgo preventivo no refleja servicio detenido/recurrencia/recursos.");
            True(vm.PreventiveScore.EndsWith("/100", StringComparison.Ordinal), "El score preventivo no usa escala 0-100.");
            True(vm.SaturationForecast is "RIESGO ALTO" or "RIESGO CRÍTICO" or "ATENCIÓN", "No se detectó riesgo de saturación actual.");
            True(vm.Actions.Count > 0, "No se generaron acciones preventivas.");
        });

        Run("Preventive_FIX91_LocalizesVisibleOperationalStates", () =>
        {
            var vm = new PreventiveDashboardViewModel(); vm.Apply(samples);
            var visibleText = vm.Signals.Concat(vm.StabilityRows).Concat(vm.Actions)
                .SelectMany(x => new[] { x.Name, x.Detail })
                .ToList();
            True(visibleText.Any(x => x.Contains("Detenido", StringComparison.OrdinalIgnoreCase)), "El estado Stopped no se tradujo a Detenido.");
            True(visibleText.All(x => !x.Contains("Stopped", StringComparison.OrdinalIgnoreCase)), "Permanece Stopped en las tarjetas preventivas.");
            True(visibleText.All(x => !x.Contains("Running", StringComparison.OrdinalIgnoreCase)), "Permanece Running en las tarjetas preventivas.");
            True(visibleText.All(x => !x.Contains("Unknown", StringComparison.OrdinalIgnoreCase)), "Permanece Unknown en las tarjetas preventivas.");
        });

        Run("Preventive_ServiceAndDependencyInstability", () =>
        {
            var preventiveSamples = Enumerable.Range(0, 8).Select(i => new ObservabilitySample
            {
                Timestamp = now.AddMinutes(-7 + i),
                CpuPercent = 55 + i * 4,
                MemoryFreePercent = 48 - i * 3,
                DiskFreePercent = new Dictionary<string, double> { ["C:"] = 30 - i * 2 },
                ServiceStates = new Dictionary<string, string> { ["TSplusGateway"] = i % 2 == 0 ? "Running" : "Stopped" },
                DependencyStates = new Dictionary<string, string> { ["RPCSS"] = i % 3 == 0 ? "Stopped" : "Running" },
                ModuleHealth = new Dictionary<string, string> { ["RDP / Remote Access Core"] = "Saludable" }
            }).ToArray();

            var vm = new PreventiveDashboardViewModel(); vm.Apply(preventiveSamples);
            True(vm.StabilityRows.Any(x => x.Name.Contains("Servicio inestable", StringComparison.OrdinalIgnoreCase)), "No se detectó flapping de servicio.");
            True(vm.StabilityRows.Any(x => x.Name.Contains("Dependencia inestable", StringComparison.OrdinalIgnoreCase)), "No se detectó inestabilidad de dependencia.");
            True(vm.InstabilityCount != "0", "El contador de inestabilidad quedó en cero.");
            True(vm.SaturationForecast != "ESTABLE", "La tendencia creciente de recursos no fue proyectada.");
        });

        Run("Preventive_FIX47_MergesLiveResourcesWithLastOperationalState", () =>
        {
            var diagnosticState = new ObservabilitySample
            {
                Timestamp = now.AddMinutes(-2),
                SampleKind = "diagnostic",
                CpuPercent = 35,
                MemoryFreePercent = 70,
                ServiceStates = new Dictionary<string, string> { ["TSplusGateway"] = "Stopped" },
                DependencyStates = new Dictionary<string, string> { ["RPCSS"] = "Running" },
                ModuleHealth = new Dictionary<string, string> { ["RDP / Remote Access Core"] = "Saludable" }
            };
            var liveState = new ObservabilitySample
            {
                Timestamp = now,
                SampleKind = "monitor",
                CpuPercent = 92,
                MemoryFreePercent = 18
            };

            var vm = new PreventiveDashboardViewModel(); vm.Apply(new[] { diagnosticState, liveState });
            Equal("RIESGO ALTO", vm.DependencyRisk);
            Equal("RIESGO CRÍTICO", vm.SaturationForecast);
            True(vm.Signals.Any(x => x.Name.Contains("CPU", StringComparison.OrdinalIgnoreCase)), "La muestra en tiempo real de CPU no se usó en Preventivo.");
        });



        Run("TdmHealth_Parity", () =>
        {
            var vm = new TdmHealthDashboardViewModel(); vm.Apply(samples);
            Equal("NORMAL", vm.MonitorMode); Equal("60 seg", vm.Frequency); Equal("2.2%", vm.Cpu); Equal("1.3%", vm.Ram);
            Equal(100d, vm.CpuMemoryMaximum);
            Equal("240", vm.Handles); Equal("26", vm.Threads); Equal("4.0 KB", vm.Jsonl);
        });

        Run("TdmHealth_FIX91_UsesConfiguredCpuAndMemoryThresholds", () =>
        {
            var thresholds = SupportMonitoringSettings.Default.Thresholds with
            {
                TdmCpuWarning = 4,
                TdmCpuCritical = 8,
                TdmMemoryWarningPercent = 6.25,
                TdmMemoryCriticalPercent = 12.5
            };
            var vm = new TdmHealthDashboardViewModel(); vm.Apply(samples, thresholds);
            Equal<double?>(4d, vm.CpuWarningThreshold);
            Equal<double?>(8d, vm.CpuCriticalThreshold);
            Equal<double?>(6.25d, vm.MemoryWarningThreshold);
            Equal<double?>(12.5d, vm.MemoryCriticalThreshold);
        });

        Run("SupportThresholds_FIX92_ValidatesTdmMemoryAsPercentage", () =>
        {
            Equal(0, SupportThresholdsValidator.Validate(SupportMonitoringSettings.Default.Thresholds).Count);
            var invalid = SupportMonitoringSettings.Default.Thresholds with
            {
                TdmMemoryWarningPercent = 101,
                TdmMemoryCriticalPercent = 102
            };
            True(SupportThresholdsValidator.Validate(invalid).Any(x => x.Contains("Memoria de TDM (%)", StringComparison.Ordinal)), "La memoria de TDM no se valida como porcentaje.");

            const string legacyJson = "{\"thresholds\":{\"cpuWarning\":72,\"cpuCritical\":88,\"tdmRamWarningMb\":512,\"tdmRamCriticalMb\":1024}}";
            var migrated = JsonSerializer.Deserialize<SupportMonitoringSettings>(legacyJson, new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase });
            True(migrated is not null, "La configuración anterior no pudo cargarse.");
            Equal(72d, migrated!.Thresholds.CpuWarning);
            Equal(5d, migrated.Thresholds.TdmMemoryWarningPercent);
            Equal(10d, migrated.Thresholds.TdmMemoryCriticalPercent);
        });

        Run("Federation_PartitionCountsAddUp", () =>
        {
            FederationNodeStatus Status(string name, string connectivity, string health) => new(
                new FederationNode($"node-{name.ToLowerInvariant()}", name, "Granja", "Nodo", @"C:\estados\node.json"),
                connectivity, health, now, 12, 41.5, 63.0, 2, 1, null, null, 0.5,
                new Dictionary<string, string>(), new Dictionary<string, string>(), "Detalle de nodo");

            var statuses = new[]
            {
                Status("Saludable-01", "EN LÍNEA", "SALUDABLE"),
                Status("Falla-02", "EN LÍNEA", "FALLA"),
                Status("Atrasado-03", "ATRASADO", "SALUDABLE"),
                Status("SinDatos-04", "SIN DATOS", "SALUDABLE"),
                Status("SinAcceso-05", "NO ACCESIBLE", "SALUDABLE")
            };

            var vm = new MultiServerDashboardViewModel();
            vm.Apply("COORD-PRUEBA", statuses);
            Equal("5", vm.Total);
            Equal("1", vm.Online);
            Equal("2", vm.Degraded);
            Equal("2", vm.Offline);
            Equal(5, int.Parse(vm.Online) + int.Parse(vm.Degraded) + int.Parse(vm.Offline));
            Equal(5, vm.Nodes.Count);
            Equal("COORD-PRUEBA", vm.Coordinator);
        });

        Run("EmptyWindowShowsNotEvaluated", () =>
        {
            var incidents = new IncidentsDashboardViewModel();
            incidents.Apply(Array.Empty<ObservabilitySample>());
            Equal("No evaluado", incidents.Total);
            Equal("No evaluado", incidents.Critical);
            Equal("No evaluado", incidents.Errors);

            var sessions = new SessionsDashboardViewModel();
            sessions.Apply(Array.Empty<ObservabilitySample>());
            Equal("No evaluado", sessions.Coverage);
            Equal("No evaluado", sessions.LogonFailures);
            Equal("No evaluado", sessions.NlaFailures);
            Equal("0", sessions.ActiveValue);

            var support = new SupportDashboardViewModel();
            support.Apply(Array.Empty<ObservabilitySample>());
            Equal("N/D", support.SessionValue);
            Equal("Sin datos de sesiones", support.SessionCounts);
            True(support.SessionCoverage.Contains("No evaluado", StringComparison.Ordinal), "La cobertura de soporte no marca 'No evaluado' sin ventana de sesiones.");
        });

        Run("LastPresentSampleWins", () =>
        {
            var light = new ObservabilitySample
            {
                Timestamp = now.AddSeconds(5),
                SampleKind = "monitor"
            };
            var trailing = new[] { earlier, latest, light };

            var perf = new PerformanceDashboardViewModel();
            perf.Apply(trailing);
            Equal("82.5%", perf.CpuValue);
            Equal("65.0% usada", perf.MemoryValue);
            Equal("↓ 2.50 Mbps", perf.NetworkReceiveValue);
            Equal("↑ 0.75 Mbps", perf.NetworkSendValue);
            Equal("C:", perf.Disks[0].Name);

            var general = new GeneralDashboardViewModel();
            general.Apply(trailing);
            Equal("82.5%", general.Cpu);
            True(general.Modules.Count >= 2, "La muestra ligera vacía sustituyó la salud de módulos en General.");

            var tsplus = new TsplusDashboardViewModel();
            tsplus.Apply(trailing);
            Equal("Remote Access/RDP", tsplus.Modules[0].Name);

            var sessions = new SessionsDashboardViewModel();
            sessions.Apply(trailing);
            Equal("Parcial", sessions.Coverage);

            var tdm = new TdmHealthDashboardViewModel();
            tdm.Apply(trailing);
            Equal("NORMAL", tdm.MonitorMode);
            Equal("240", tdm.Handles);
        });

        Run("DiskFreeThresholds_Configurable", () =>
        {
            var defaults = new SupportThresholds();
            Equal(10d, defaults.DiskFreeWarningPercent);
            Equal(5d, defaults.DiskFreeCriticalPercent);
            Equal(0, SupportThresholdsValidator.Validate(defaults).Count);

            var reversed = defaults with { DiskFreeWarningPercent = 5, DiskFreeCriticalPercent = 10 };
            True(SupportThresholdsValidator.Validate(reversed).Any(x => x.Contains("Disco libre", StringComparison.Ordinal)),
                "El umbral de disco libre no valida que el aviso ocurra con más espacio libre que el crítico.");

            var defaultsVm = new PerformanceDashboardViewModel();
            defaultsVm.Apply(samples);
            True(!Equals(defaultsVm.Disks[0].Accent, defaultsVm.Disks[1].Accent),
                "Con los valores por defecto, C: (9% libre) y D: (55% libre) deben tener acentos distintos.");

            var strict = defaults with { DiskFreeWarningPercent = 60, DiskFreeCriticalPercent = 55 };
            var strictVm = new PerformanceDashboardViewModel();
            strictVm.Apply(samples, null, strict);
            True(Equals(strictVm.Disks[0].Accent, strictVm.Disks[1].Accent),
                "Los acentos de disco no siguen los umbrales configurados.");
        });

        Run("EmptySample_Reset", () =>
        {
            var support = new SupportDashboardViewModel(); support.Apply(Array.Empty<ObservabilitySample>()); Equal("N/D", support.ServiceValue);
            var perf = new PerformanceDashboardViewModel(); perf.Apply(Array.Empty<ObservabilitySample>()); Equal("N/D", perf.CpuValue);
            var sessions = new SessionsDashboardViewModel(); sessions.Apply(Array.Empty<ObservabilitySample>()); Equal("0", sessions.ActiveValue);
        });

        Console.WriteLine();
        Console.WriteLine($"TDM_PARITY_TESTS: passed={_passed} failed={_failed}");
        return _failed == 0 ? 0 : 1;
    }

    private static void Run(string name, Action action)
    {
        try { action(); _passed++; Console.WriteLine($"[PASS] {name}"); }
        catch (Exception ex) { _failed++; Console.WriteLine($"[FAIL] {name}: {ex.Message}"); }
    }

    private static void Equal<T>(T expected, T actual)
    {
        if (!EqualityComparer<T>.Default.Equals(expected, actual)) throw new InvalidOperationException($"Esperado '{expected}', actual '{actual}'.");
    }

    private static void True(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
    }
}
