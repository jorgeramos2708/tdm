using Microsoft.Win32;
using System.Diagnostics.Eventing.Reader;
using System.ServiceProcess;
using TDM.Core;
using TDM.Models;

namespace TDM.Collectors.Windows;

/// <summary>
/// Audita la pila de impresión de Windows y los componentes server-side de Universal Printer y
/// Virtual Printer. Todo es de solo lectura; no reinicia Spooler, no instala impresoras y no cambia drivers.
/// </summary>
public sealed class PrintingHealthCollector : IReadOnlyCollector
{
    public string Nombre => "Impresión Windows / TSplus";

    public Task<CollectorResult> CollectAsync(DiagnosticContext context, CancellationToken cancellationToken = default)
    {
        var findings = new List<DiagnosticFinding>();
        var events = new List<DiagnosticEvent>();
        var spoolerProbe = GetServiceState("Spooler");
        var novaProbe = GetServiceState("NovaPDF11Service");
        var spoolerState = spoolerProbe.IsAvailable ? spoolerProbe.Value ?? "N/D" : spoolerProbe.IsAbsent ? "No localizado" : "NO EVALUADO";
        var novaState = novaProbe.IsAvailable ? novaProbe.Value ?? "N/D" : novaProbe.IsAbsent ? "No localizado" : "NO EVALUADO";

        if (spoolerProbe.IsAvailable)
        {
            events.Add(new DiagnosticEvent(DateTimeOffset.Now, "Service Control Manager", "Print Spooler", DiagnosticLayer.Windows,
                spoolerState.Equals("Running", StringComparison.OrdinalIgnoreCase) ? DiagnosticSeverity.Informativo : DiagnosticSeverity.Critico,
                "PRINT_SPOOLER_STATE", $"Spooler: {spoolerState}", Evidencia: [new("Servicio", "Spooler"), new("Estado", spoolerState)]));
        }
        else if (spoolerProbe.IsUnavailable)
        {
            findings.Add(new DiagnosticFinding("PRINT-SPOOLER-COVERAGE", "Print Spooler", DiagnosticSeverity.Advertencia,
                "El estado de Print Spooler quedó NO EVALUADO.",
                "TDM no interpreta un fallo de SCM como servicio ausente o detenido.",
                [new("Estado", spoolerProbe.StatusText), new("Detalle", spoolerProbe.Detail ?? "N/D")], ConfidenceLevel.Confirmada, Capa: DiagnosticLayer.Windows));
        }

        var printersProbe = ReadPrinters(cancellationToken);
        var printers = printersProbe.IsAvailable ? printersProbe.Value ?? [] : [];
        if (printersProbe.IsUnavailable)
            findings.Add(new DiagnosticFinding("PRINT-WMI-COVERAGE", "Win32_Printer", DiagnosticSeverity.Advertencia,
                "La enumeración de impresoras quedó NO EVALUADA.",
                "TDM no interpreta un fallo WMI como cero impresoras.",
                [new("Estado", printersProbe.StatusText), new("Detalle", printersProbe.Detail ?? "N/D")], ConfidenceLevel.Confirmada, Capa: DiagnosticLayer.Windows));
        var related = printers.Where(p => ContainsAny(p.Name, "TSplus", "Universal", "Virtual")
            || ContainsAny(p.Driver, "TSplus", "novaPDF", "Virtual Devices", "FabulaTech", "Universal", "Virtual")).ToList();
        var universal = related.Where(p => ContainsAny(p.Name, "Universal") || ContainsAny(p.Driver, "novaPDF", "Universal")).ToList();
        var virtualPrinters = related.Where(p => ContainsAny(p.Name, "Virtual", "Virtual Devices")
            || ContainsAny(p.Driver, "Virtual Devices", "FabulaTech", "Virtual Printer")).ToList();

        events.Add(new DiagnosticEvent(DateTimeOffset.Now, "TDM", "Pila de impresión", DiagnosticLayer.Windows,
            spoolerProbe.IsUnavailable || printersProbe.IsUnavailable ? DiagnosticSeverity.Advertencia : DiagnosticSeverity.Informativo,
            "PRINTING_STATE", printersProbe.IsAvailable
                ? $"Spooler={spoolerState}; impresoras TSplus/Universal/Virtual detectadas={related.Count}"
                : $"Spooler={spoolerState}; impresoras=NO EVALUADO",
            Evidencia: [
                new("Spooler", spoolerState),
                new("Cobertura Spooler", spoolerProbe.StatusText),
                new("Impresoras relacionadas", printersProbe.IsAvailable ? FormatPrinters(related) : "NO EVALUADO"),
                new("Cobertura WMI impresoras", printersProbe.StatusText)
            ], Producto: TsplusProduct.RemoteAccess));

        var install = context.Sistema.TsplusRuta;
        var universalFeatureObserved = false;
        var virtualFeatureObserved = false;
        if (context.Sistema.TsplusDetectado && !string.IsNullOrWhiteSpace(install))
        {
            universalFeatureObserved = UniversalPrinterFeatureObserved(install!, novaProbe, universal);
            virtualFeatureObserved = VirtualPrinterFeatureObserved(install!, virtualPrinters);
            AuditUniversalPrinter(install!, spoolerState, novaState, universal, events, findings);
            AuditVirtualPrinter(install!, spoolerState, virtualPrinters, events, findings);
        }

        // P08: el evento PRINT_SPOOLER_STATE solo es Crítico cuando hay impresión TSplus
        // observada; sin ella, un Spooler detenido es Advertencia (no incidente). El hallazgo
        // PRINT-SPOOLER-DOWN ya exigía esta condición; el evento quedaba inconsistente.
        if (spoolerProbe.IsAvailable && !spoolerState.Equals("Running", StringComparison.OrdinalIgnoreCase))
        {
            var printingObserved = universalFeatureObserved || virtualFeatureObserved || related.Count > 0;
            var spoolerEventIndex = events.FindIndex(e => e.Tipo == "PRINT_SPOOLER_STATE");
            if (spoolerEventIndex >= 0)
            {
                var original = events[spoolerEventIndex];
                var evidence = original.Evidencia?.ToList() ?? [];
                evidence.Add(new EvidenceItem("Impresión TSplus observada", printingObserved ? "Sí" : "No"));
                events[spoolerEventIndex] = original with
                {
                    Severidad = printingObserved ? DiagnosticSeverity.Critico : DiagnosticSeverity.Advertencia,
                    Evidencia = evidence
                };
            }
        }

        if (context.Sistema.TsplusDetectado && spoolerProbe.IsAvailable
            && (universalFeatureObserved || virtualFeatureObserved || related.Count > 0)
            && !spoolerState.Equals("Running", StringComparison.OrdinalIgnoreCase))
        {
            findings.Add(new DiagnosticFinding("PRINT-SPOOLER-DOWN", "Print Spooler", DiagnosticSeverity.Critico,
                "La pila de impresión de Windows no está operativa y puede afectar Universal/Virtual Printer.",
                "TDM confirmó que existe un componente server-side de impresión TSplus y que Spooler no está Running. Esto demuestra una dependencia Windows degradada; para declararla causa raíz alta debe correlacionarse además con un síntoma de impresión de la misma ventana.",
                [
                    new("Spooler", spoolerState),
                    new("Universal Printer observado", universalFeatureObserved ? "Sí" : "No"),
                    new("Virtual Printer observado", virtualFeatureObserved ? "Sí" : "No"),
                    new("Impresoras relacionadas", printersProbe.IsAvailable ? FormatPrinters(related) : "NO EVALUADO")
                ], ConfidenceLevel.Alta,
                SolucionSugerida: "Investiga primero por qué Print Spooler no está operativo y correlaciona Microsoft-Windows-PrintService antes de reinstalar o modificar TSplus. TDM no reinicia servicios.",
                Capa: DiagnosticLayer.Windows));
        }

        try
        {
            ReadPrintEvents(context, events, cancellationToken);
        }
        catch (Exception ex) when (ex is EventLogException or UnauthorizedAccessException)
        {
            // V5: un fallo del log PrintService no debe tumbar el estado Spooler ya capturado
            // (antes el engine lo volvía COLLECTOR-ERROR y se perdía todo el collector).
            findings.Add(new DiagnosticFinding(
                "PRINT-EVENTLOG-READ", "PrintService", DiagnosticSeverity.Advertencia,
                "La lectura de eventos de impresión quedó parcial.",
                "El estado de Spooler e impresoras ya capturado sigue siendo válido; solo los eventos del log quedan no evaluados.",
                [new EvidenceItem("Cobertura", "Parcial"), new EvidenceItem("Detalle", ex.Message)],
                ConfidenceLevel.Media, Capa: DiagnosticLayer.Windows));
        }
        return Task.FromResult(new CollectorResult(findings, events));
    }

    private static void AuditUniversalPrinter(string install, string spoolerState, string novaState,
        IReadOnlyList<PrinterEntry> universal, List<DiagnosticEvent> events, List<DiagnosticFinding> findings)
    {
        var systemDrive = Path.GetPathRoot(Environment.SystemDirectory) ?? @"C:\";
        var logDir = Path.Combine(systemDrive, "wsession", "UniversalPrinter", "logs");
        var sessionTrace = Path.Combine(systemDrive, "wsession", "trace");
        var configDir = Path.Combine(install, "UserDesktop", "files", "UniversalPrinter");
        var adminToolLog = Path.Combine(install, "UserDesktop", "files", "AdminTool.log");
        var html5Settings = Path.Combine(install, "Clients", "www", "software", "html5", "settings.js");
        var observed = universal.Count > 0 || !novaState.Equals("No localizado", StringComparison.OrdinalIgnoreCase)
            || Directory.Exists(configDir) || Directory.Exists(logDir);

        events.Add(new DiagnosticEvent(DateTimeOffset.Now, "TDM", "TSplus Universal Printer (novaPDF)", DiagnosticLayer.Tsplus,
            DiagnosticSeverity.Informativo, "TSPLUS_UNIVERSAL_PRINTER_STATE",
            observed ? "Componentes server-side de Universal Printer observados." : "Universal Printer no presenta evidencia server-side suficiente en esta captura; puede ser opcional/no instalado.",
            Evidencia:
            [
                new("Spooler", spoolerState),
                new("NovaPDF11Service", novaState),
                new("Impresoras Universal/novaPDF", FormatPrinters(universal)),
                new("C:\\wsession\\UniversalPrinter\\logs", FileSystemProbe.Display(FileSystemProbe.Directory(logDir))),
                new("C:\\wsession\\trace", FileSystemProbe.Display(FileSystemProbe.Directory(sessionTrace), "Presente", "No presente / logging puede estar deshabilitado")),
                new("UserDesktop\\files\\UniversalPrinter", FileSystemProbe.Display(FileSystemProbe.Directory(configDir))),
                new("AdminTool.log", FileSystemProbe.Display(FileSystemProbe.File(adminToolLog), adminToolLog, "No presente / logging puede estar deshabilitado")),
                new("HTML5 settings.js", FileSystemProbe.Display(FileSystemProbe.File(html5Settings), html5Settings, "No localizado")),
                new("Cobertura", "Servicio novaPDF + impresora/driver + artefactos server-side + logs de sesión/AdminTool + PrintService")
            ], Producto: TsplusProduct.RemoteAccess));

        if (observed && !novaState.Equals("No localizado", StringComparison.OrdinalIgnoreCase)
            && !novaState.Equals("Running", StringComparison.OrdinalIgnoreCase))
        {
            findings.Add(new DiagnosticFinding("TSPLUS-UNIVERSAL-PRINTER-NOVAPDF-SERVICE", "TSplus Universal Printer",
                DiagnosticSeverity.Advertencia,
                "NovaPDF11Service está presente pero no se observa Running.",
                "TSplus documenta NovaPDF11Service como componente del Universal Printer. TDM no reinicia el servicio ni asume por sí solo que sea la causa de una falla de impresión.",
                [new("NovaPDF11Service", novaState), new("Impresoras", FormatPrinters(universal))], ConfidenceLevel.Media,
                FuenteOficial: "TSplus Documentation — Universal Printer (novaPDF)",
                UrlOficial: "https://docs.tsplus.net/tsplus/universal-printer/",
                Capa: DiagnosticLayer.Tsplus));
        }
    }

    private static void AuditVirtualPrinter(string install, string spoolerState,
        IReadOnlyList<PrinterEntry> virtualPrinters, List<DiagnosticEvent> events, List<DiagnosticFinding> findings)
    {
        var addons = Path.Combine(install, "UserDesktop", "files", "addons");
        var serverSetup = Path.Combine(addons, "Setup-VirtualPrinter-Server.exe");
        var clientSetup = Path.Combine(addons, "Setup-VirtualPrinter-Client.exe");
        var clientMsi = Path.Combine(addons, "Setup-VirtualPrinter-Client.msi");
        var tool = Path.Combine(install, "UserDesktop", "files", "VirtualPrinterTool.exe");
        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var v2Root = string.IsNullOrWhiteSpace(programFiles) ? string.Empty : Path.Combine(programFiles, "Virtual Devices", "Virtual Printer (Server)");
        var v2Installed = !string.IsNullOrWhiteSpace(v2Root) && Directory.Exists(v2Root);
        var policiesZip = string.IsNullOrWhiteSpace(v2Root) ? string.Empty : Path.Combine(v2Root, "policies.zip");
        var windowsDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var admx = string.IsNullOrWhiteSpace(windowsDir) ? string.Empty : Path.Combine(windowsDir, "PolicyDefinitions", "VirtualDevices.admx");
        var adml = string.IsNullOrWhiteSpace(windowsDir) ? string.Empty : Path.Combine(windowsDir, "PolicyDefinitions", "en-US", "VirtualDevices.adml");
        var v2Policy = ReadVirtualPrinterV2Policy();
        // El instalador puede formar parte del paquete de TSplus aunque la función no esté instalada.
        // Para evitar falsos positivos, sólo contamos evidencia server-side realmente instalada/activa.
        var observed = virtualPrinters.Count > 0 || v2Installed || File.Exists(tool);

        events.Add(new DiagnosticEvent(DateTimeOffset.Now, "TDM", "TSplus Virtual Printer", DiagnosticLayer.Tsplus,
            DiagnosticSeverity.Informativo, "TSPLUS_VIRTUAL_PRINTER_STATE",
            observed ? "Componentes server-side de Virtual Printer observados." : "Virtual Printer no presenta evidencia server-side suficiente en esta captura; puede ser opcional/no instalado.",
            Evidencia:
            [
                new("Spooler", spoolerState),
                new("Impresoras Virtual/Virtual Devices", FormatPrinters(virtualPrinters)),
                new("Setup-VirtualPrinter-Server.exe", File.Exists(serverSetup) ? serverSetup : "No localizado"),
                new("Setup-VirtualPrinter-Client.exe", File.Exists(clientSetup) ? clientSetup : "No localizado"),
                new("Setup-VirtualPrinter-Client.msi", File.Exists(clientMsi) ? clientMsi : "No localizado"),
                new("VirtualPrinterTool.exe", File.Exists(tool) ? tool : "No localizado"),
                new("Virtual Printer v2 server", v2Installed ? v2Root : "No localizado"),
                new("Virtual Printer v2 policies.zip", !string.IsNullOrWhiteSpace(policiesZip) && File.Exists(policiesZip) ? policiesZip : "No localizado / sólo requerido para plantilla de políticas v2"),
                new("VirtualDevices.admx", !string.IsNullOrWhiteSpace(admx) && File.Exists(admx) ? admx : "No localizado / sólo requerido para administración GPO avanzada"),
                new("VirtualDevices.adml", !string.IsNullOrWhiteSpace(adml) && File.Exists(adml) ? adml : "No localizado / sólo requerido para administración GPO avanzada"),
                new("Política v2 observada", v2Policy),
                new("Cobertura", "Spooler + componentes v1/v2 + impresoras de sesión + configuración GPO v2 cuando existe + PrintService"),
                new("Nota v2", "Las impresoras v2 se crean por sesión; su ausencia fuera de una sesión activa no se considera falla.")
            ], Producto: TsplusProduct.RemoteAccess));
    }

    private static bool UniversalPrinterFeatureObserved(string install, ProbeResult<string> novaProbe, IReadOnlyList<PrinterEntry> universal)
    {
        if (universal.Count > 0 || novaProbe.IsAvailable) return true;
        var systemDrive = Path.GetPathRoot(Environment.SystemDirectory) ?? @"C:\";
        return FileSystemProbe.Directory(Path.Combine(install, "UserDesktop", "files", "UniversalPrinter")).IsAvailable
               || FileSystemProbe.Directory(Path.Combine(systemDrive, "wsession", "UniversalPrinter")).IsAvailable;
    }

    private static bool VirtualPrinterFeatureObserved(string install, IReadOnlyList<PrinterEntry> virtualPrinters)
    {
        if (virtualPrinters.Count > 0) return true;
        if (FileSystemProbe.File(Path.Combine(install, "UserDesktop", "files", "VirtualPrinterTool.exe")).IsAvailable) return true;
        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        return !string.IsNullOrWhiteSpace(programFiles)
               && FileSystemProbe.Directory(Path.Combine(programFiles, "Virtual Devices", "Virtual Printer (Server)")).IsAvailable;
    }

    private static string ReadVirtualPrinterV2Policy()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Virtual Devices\Virtual Printer (Server)", writable: false);
            if (key is null) return "No configurada por política local/GPO";
            var values = key.GetValueNames()
                .Take(20)
                .Select(name => $"{name}={key.GetValue(name)?.ToString() ?? "N/D"}")
                .ToList();
            return values.Count == 0 ? "Clave presente sin valores observados" : string.Join(" | ", values);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException or IOException)
        {
            return "No legible: " + ex.Message;
        }
    }

    private static ProbeResult<IReadOnlyList<PrinterEntry>> ReadPrinters(CancellationToken cancellationToken)
    {
        var printers = new List<PrinterEntry>();
        try
        {
            var results = SafeWmi.Query(
                "SELECT Name,DriverName,PortName FROM Win32_Printer",
                o => new PrinterEntry(
                    o["Name"]?.ToString() ?? "N/D",
                    o["DriverName"]?.ToString() ?? "N/D",
                    o["PortName"]?.ToString() ?? "N/D"));
            foreach (var p in results)
            {
                cancellationToken.ThrowIfCancellationRequested();
                printers.Add(p);
            }
            return ProbeResult<IReadOnlyList<PrinterEntry>>.Available(printers);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception ex) { return ProbeResult<IReadOnlyList<PrinterEntry>>.Error(ex.Message); }
    }

    private static ProbeResult<string> GetServiceState(string serviceName)
    {
        try
        {
            using var service = new ServiceController(serviceName);
            return ProbeResult<string>.Available(service.Status.ToString());
        }
        catch (InvalidOperationException ex)
        {
            // ServiceController usa InvalidOperationException tanto para servicio inexistente como para SCM inaccesible.
            // Verificamos la colección SCM para distinguir ausencia real de lectura fallida.
            try
            {
                var exists = ServiceController.GetServices().Any(s =>
                {
                    using (s) return s.ServiceName.Equals(serviceName, StringComparison.OrdinalIgnoreCase);
                });
                return exists ? ProbeResult<string>.Error(ex.Message) : ProbeResult<string>.Absent();
            }
            catch (UnauthorizedAccessException denied) { return ProbeResult<string>.AccessDenied(denied.Message); }
            catch (Exception lookup) { return ProbeResult<string>.Error(lookup.Message); }
        }
        catch (UnauthorizedAccessException ex) { return ProbeResult<string>.AccessDenied(ex.Message); }
        catch (Exception ex) { return ProbeResult<string>.Error(ex.Message); }
    }

    private static string FormatPrinters(IReadOnlyList<PrinterEntry> printers)
        => printers.Count == 0 ? "Ninguna detectada" : string.Join(" || ", printers.Select(p => $"{p.Name} | Driver={p.Driver} | Port={p.Port}"));

    private static bool ContainsAny(string value, params string[] tokens)
        => tokens.Any(t => value.Contains(t, StringComparison.OrdinalIgnoreCase));

    private static void ReadPrintEvents(DiagnosticContext context, List<DiagnosticEvent> events, CancellationToken ct)
    {
        var timeClause = DiagnosticWindow.EventLogTimeClause(context);
        var max = context.Lookback.TotalHours switch
        {
            <= 4 => 100,
            <= 12 => 200,
            <= 24 => 400,
            _ => 800
        };
        try
        {
            var q = new EventLogQuery("Microsoft-Windows-PrintService/Admin", PathType.LogName,
                $"*[System[(Level=1 or Level=2 or Level=3) and {timeClause}]]") { ReverseDirection = true };
            using var r = new EventLogReader(q); var count = 0;
            for (EventRecord? record = r.ReadEvent(); record is not null && count < max; record = r.ReadEvent())
            {
                ct.ThrowIfCancellationRequested(); using (record)
                {
                    string msg; try { msg = record.FormatDescription() ?? "Descripción no disponible."; } catch { msg = "Descripción no disponible."; }
                    var severity = record.Level switch
                    {
                        1 => DiagnosticSeverity.Critico,
                        2 => DiagnosticSeverity.Error,
                        3 => DiagnosticSeverity.Advertencia,
                        _ => DiagnosticSeverity.Advertencia
                    };
                    events.Add(new DiagnosticEvent(record.TimeCreated is null ? null : new DateTimeOffset(record.TimeCreated.Value),
                        "Microsoft-Windows-PrintService/Admin", "Windows Printing", DiagnosticLayer.Windows, severity,
                        $"PRINT_EVENT_{record.Id}", msg, record.Id.ToString(), Producto: TsplusProduct.RemoteAccess));
                    count++;
                }
            }
        }
        catch (EventLogNotFoundException ex)
        {
            events.Add(new DiagnosticEvent(DateTimeOffset.Now, "Windows Event Log", "PrintService/Admin", DiagnosticLayer.Windows,
                DiagnosticSeverity.Advertencia, "WINDOWS_EVENT_SOURCE_UNAVAILABLE", "PrintService/Admin quedó NO EVALUADO.",
                Evidencia: [new("Cobertura", "No evaluado"), new("Detalle", ex.Message)]));
        }
        catch (UnauthorizedAccessException ex)
        {
            events.Add(new DiagnosticEvent(DateTimeOffset.Now, "Windows Event Log", "PrintService/Admin", DiagnosticLayer.Windows,
                DiagnosticSeverity.Advertencia, "WINDOWS_EVENT_SOURCE_UNAVAILABLE", "PrintService/Admin quedó NO EVALUADO por permisos.",
                Evidencia: [new("Cobertura", "No evaluado"), new("Detalle", ex.Message)]));
        }
    }

    private sealed record PrinterEntry(string Name, string Driver, string Port);
}
