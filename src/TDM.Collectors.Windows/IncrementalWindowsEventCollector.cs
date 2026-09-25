using System.Diagnostics.Eventing.Reader;
using System.ServiceProcess;
using System.Xml.Linq;
using TDM.Core;
using TDM.Models;

namespace TDM.Collectors.Windows;

/// <summary>
/// Lee únicamente registros creados después del último RecordId observado.
/// Se activa sólo cuando existe una sesión de diagnóstico continuo.
/// </summary>
public sealed class IncrementalWindowsEventCollector : IReadOnlyCollector
{
    public string Nombre => "Eventos Windows incrementales";

    private readonly object _sync = new();
    private readonly Dictionary<string, long> _lastRecordIds = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, string> _lastKnownGoodState = new(StringComparer.OrdinalIgnoreCase);
    private string? _cursorPersistenceWarning;
    private bool _primed;
    private bool _forceReplayAfterCursorLoss;
    private DateTimeOffset? _lastSuccessUtc;

    private sealed record WindowsCursorState(
    Dictionary<string, long> Cursors,
    DateTimeOffset SavedAt,
    Dictionary<string, string> LastKnownGoodState);

    private static readonly ChannelSpec[] Channels =
    [
        // P17: incluye fallos de arranque SCM (7000/7001/7009/7011/7023/7024); coherente con
        // DiagnosticPrecisionAnalyzer.IsCausalSignal que ya los reconoce como causales.
        new("System", "*[System[(EventID=7000 or EventID=7001 or EventID=7009 or EventID=7011 or EventID=7023 or EventID=7024 or EventID=7031 or EventID=7034 or EventID=7040 or EventID=7045 or EventID=41 or EventID=51 or EventID=55)]]", DiagnosticLayer.Windows),
        new("Application", "*[System[(Level=1 or Level=2)]]", DiagnosticLayer.Windows),
        new("Security", "*[System[(EventID=4625 or EventID=4740 or EventID=4771 or EventID=4776)]]", DiagnosticLayer.Seguridad),
        new("Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", "*[System[(EventID=21 or EventID=22 or EventID=23 or EventID=24 or EventID=25 or Level=1 or Level=2)]]", DiagnosticLayer.Rdp),
        new("Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational", "*[System[(EventID=1149 or Level=1 or Level=2)]]", DiagnosticLayer.Rdp),
        new("Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational", "*[System[(Level=1 or Level=2)]]", DiagnosticLayer.Rdp),
        new("Microsoft-Windows-PrintService/Admin", "*[System[(Level=1 or Level=2 or Level=3)]]", DiagnosticLayer.Windows),
        new("Microsoft-Windows-WMI-Activity/Operational", "*[System[(Level=1 or Level=2 or Level=3)]]", DiagnosticLayer.Windows),
        new("Microsoft-Windows-Windows Defender/Operational", "*[System[(Level=1 or Level=2 or Level=3)]]", DiagnosticLayer.Seguridad),
        new("Microsoft-Windows-Windows Firewall With Advanced Security/Firewall", "*[System[(Level=1 or Level=2 or Level=3)]]", DiagnosticLayer.Seguridad),
        new("Microsoft-Windows-WindowsUpdateClient/Operational", "*[System[(Level=1 or Level=2 or Level=3)]]", DiagnosticLayer.Windows),
        new("Microsoft-Windows-Resource-Exhaustion-Detector/Operational", "*[System[(Level=1 or Level=2 or Level=3)]]", DiagnosticLayer.Windows),
        new("Microsoft-Windows-DiskDiagnostic/Operational", "*[System[(Level=1 or Level=2 or Level=3)]]", DiagnosticLayer.Windows),
        new("Microsoft-Windows-GroupPolicy/Operational", "*[System[(Level=1 or Level=2 or Level=3)]]", DiagnosticLayer.Windows),
        new("Microsoft-Windows-DNS-Client/Operational", "*[System[(Level=1 or Level=2 or Level=3)]]", DiagnosticLayer.Red),
        new("Microsoft-Windows-NetworkProfile/Operational", "*[System[(Level=1 or Level=2 or Level=3)]]", DiagnosticLayer.Red),
        new("Microsoft-Windows-CAPI2/Operational", "*[System[(Level=1 or Level=2 or Level=3)]]", DiagnosticLayer.Seguridad),
        new("Microsoft-Windows-CodeIntegrity/Operational", "*[System[(Level=1 or Level=2 or Level=3)]]", DiagnosticLayer.Seguridad),
        new("Microsoft-Windows-AppLocker/EXE and DLL", "*[System[(Level=1 or Level=2 or Level=3)]]", DiagnosticLayer.Seguridad),
        new("Microsoft-Windows-AppLocker/MSI and Script", "*[System[(Level=1 or Level=2 or Level=3)]]", DiagnosticLayer.Seguridad)
    ];

public void Prime()
        {
            lock (_sync)
            {
                _lastRecordIds.Clear();
                _lastKnownGoodState.Clear();
                var loaded = CollectorCursorStore.TryLoad<WindowsCursorState>("windows-event-cursors", out var state, out var error)
                             && state?.Cursors is not null;
                _forceReplayAfterCursorLoss = !loaded && !string.IsNullOrWhiteSpace(error);
                _cursorPersistenceWarning = error;
                if (loaded)
                {
                    foreach (var pair in state!.Cursors)
                        _lastRecordIds[pair.Key] = Math.Max(0, pair.Value);
                    if (state.LastKnownGoodState is not null)
                    {
                        foreach (var pair in state.LastKnownGoodState)
                            _lastKnownGoodState[pair.Key] = pair.Value;
                    }
                }

            foreach (var channel in Channels)
            {
                if (_lastRecordIds.ContainsKey(channel.Name)) continue;
                var latest = ReadLatestRecordId(channel.Name);
                if (latest.HasValue)
                    _lastRecordIds[channel.Name] = loaded || _forceReplayAfterCursorLoss ? 0 : latest.Value;
            }
            if (_forceReplayAfterCursorLoss)
                _cursorPersistenceWarning = string.IsNullOrWhiteSpace(error)
                    ? "Cursor no disponible; se conserva sólo una ventana de replay acotada."
                    : "Cursor no recuperable; se conserva sólo una ventana de replay acotada: " + error;
            _primed = true;
        }
    }

    public Task<CollectorResult> CollectAsync(DiagnosticContext context, CancellationToken cancellationToken = default)
    {
        if (!_primed) Prime();
        var events = new List<DiagnosticEvent>();
        var findings = new List<DiagnosticFinding>();
        var coverage = new List<EvidenceItem>();

        foreach (var channel in Channels)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var cursor = Cursor(channel.Name);
            var latestBeforeRead = ReadLatestRecordId(channel.Name);
            var replayAfterReset = _forceReplayAfterCursorLoss || (cursor > 0 && latestBeforeRead.HasValue && latestBeforeRead.Value < cursor);
            if (replayAfterReset)
            {
                SetCursor(channel.Name, 0);
                cursor = 0;
                // T3: el replay acotado (15 min) no es cobertura disponible: lo anterior a la
                // ventana se perdió. Se declara Parcial para que cuente en `lost` y no avance éxito.
                coverage.Add(new EvidenceItem(channel.Name, _forceReplayAfterCursorLoss
                    ? "Parcial; cursor no recuperable; replay acotado de 15 min, historial previo perdido."
                    : "Parcial; discontinuidad detectada; replay acotado de 15 min, historial previo perdido."));
                // P0-02: Emit synthetic TDM_STATE_TRANSITION for services with known last good state.
                // This reconstructs the transition (Running→Stopped or Stopped→Running) that occurred
                // during the cursor loss gap, so the ledger and correlator don't miss it.
                if (_forceReplayAfterCursorLoss && _lastKnownGoodState.Count > 0)
                {
                    foreach (var kv in _lastKnownGoodState)
                    {
                        var serviceName = kv.Key;
                        var lastState = kv.Value;
                        // Emit a transition event with evidence that it was reconstructed.
                        events.Add(new DiagnosticEvent(
                            DateTimeOffset.Now,
                            "TDM",
                            serviceName,
                            DiagnosticLayer.Windows,
                            DiagnosticSeverity.Informativo,
                            "TDM_STATE_TRANSITION",
                            $"Estado reconstruido tras pérdida de cursor: {serviceName} → {lastState}",
                            "RECONSTRUCTED",
                            Evidencia:
                            [
                                new EvidenceItem("Servicio", serviceName),
                                new EvidenceItem("Estado reconstruido", lastState),
                                new EvidenceItem("Origen", "LastKnownGoodState (cursor loss recovery)"),
                                new EvidenceItem("Nota", "Transición sintética generada porque el cursor se perdió y el replay de 15 min no cubre el hueco.")
                            ],
                            Producto: TsplusProduct.Ninguno));
                    }
                }
                // W6: no añadir después una segunda entrada "Disponible tras replay" que duplique la cobertura.
            }
            else if (_lastSuccessUtc.HasValue && DateTimeOffset.Now - _lastSuccessUtc.Value > TimeSpan.FromMinutes(15))
            {
                // P18/S1: hueco no recuperable por el incremental; se declara explícitamente en vez
                // de fingir continuidad. Sufijo hash: Sanitize(28) colisionaba entre los dos canales
                // TerminalServices largos y el segundo GAP perdía su origen.
                findings.Add(new DiagnosticFinding(
                    $"LIVE-EVT-GAP-{Sanitize(channel.Name)}-{StableHash(channel.Name):X4}",
                    $"Event Viewer / {channel.Name}",
                    DiagnosticSeverity.Advertencia,
                    "Discontinuidad de Event Viewer fuera de la ventana de replay.",
                    "El cursor se perdió y la última muestra exitosa supera 15 min; el replay acotado no cubre el hueco. Ejecute un diagnóstico puntual de 24 h para cerrar la ventana.",
                    [new EvidenceItem("Canal", channel.Name),
                     new EvidenceItem("Última muestra exitosa", _lastSuccessUtc.Value.ToString("O")),
                     new EvidenceItem("Replay aplicado", "15 min"),
                     new EvidenceItem("Cobertura", "Parcial; hueco no recuperable por el incremental")],
                    ConfidenceLevel.Alta,
                    Capa: channel.Layer));
            }
            var baseFilter = replayAfterReset ? AppendRecentWindow(channel.Filter, TimeSpan.FromMinutes(15)) : channel.Filter;
            var xpath = AppendCursor(baseFilter, cursor);
            try
            {
                var query = new EventLogQuery(channel.Name, PathType.LogName, xpath) { ReverseDirection = false };
                using var reader = new EventLogReader(query);
                var read = 0;
                var backlog = false;
                long maxRecord = cursor;
                long? firstRecord = null;
                while (reader.ReadEvent() is { } record)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    using (record)
                    {
                        // Se lee un registro adicional sólo para detectar backlog. No se adelanta el cursor
                        // sobre evidencia que todavía no fue procesada.
                        if (read >= 250)
                        {
                            backlog = true;
                            break;
                        }

                        read++;
                        if (record.RecordId.HasValue) maxRecord = Math.Max(maxRecord, record.RecordId.Value);
                        firstRecord ??= record.RecordId;
                        var converted = ConvertRecord(channel, record, context);
                        if (converted is null) continue;
                        events.Add(converted);
                        if (converted.Severidad is DiagnosticSeverity.Advertencia or DiagnosticSeverity.Error or DiagnosticSeverity.Critico)
                        {
                            findings.Add(new DiagnosticFinding(
                                $"LIVE-EVT-{Sanitize(channel.Name)}-{record.RecordId ?? record.Id}",
                                converted.Componente,
                                converted.Severidad,
                                $"Nueva evidencia durante el diagnóstico continuo: {converted.Tipo}",
                                converted.Mensaje,
                                converted.Evidencia ?? [],
                                ConfidenceLevel.Media,
                                Capa: converted.Capa));
                        }
                    }
                }
                UpdateCursor(channel.Name, maxRecord);
                // P1-pérdida: rango RecordId primero..último leído para contabilidad forense.
                var rangeText = RangeText(read, firstRecord, maxRecord);
                // W6: si hubo replay, la entrada "Parcial; ..." ya está en coverage; no añadir
                // segunda entrada que duplique la cobertura. Se actualiza con el resultado real.
                if (!replayAfterReset)
                {
                    coverage.Add(new EvidenceItem(channel.Name,
                        FormatChannelCoverage(backlog, read, firstRecord, maxRecord)));
                }
                else
                {
                    var replayIdx = coverage.FindIndex(c => c.Clave == channel.Name && c.Valor.StartsWith("Parcial;", StringComparison.OrdinalIgnoreCase));
                    if (replayIdx >= 0)
                    {
                        coverage[replayIdx] = new EvidenceItem(channel.Name,
                            backlog
                                ? $"Parcial; replay de discontinuidad; registros leídos={read}; backlog pendiente; rango={rangeText}"
                                : $"Parcial; replay de discontinuidad; registros leídos={read}; rango={rangeText}");
                    }
                }
            }
            catch (EventLogNotFoundException ex)
            {
                coverage.Add(new EvidenceItem(channel.Name, "Canal no disponible"));
                events.Add(CoverageLossEvent(channel, "Canal no disponible", ex.Message));
            }
            catch (UnauthorizedAccessException ex)
            {
                coverage.Add(new EvidenceItem(channel.Name, "Sin permisos de lectura"));
                events.Add(CoverageLossEvent(channel, "Sin permisos de lectura", ex.Message));
            }
            catch (EventLogException ex)
            {
                coverage.Add(new EvidenceItem(channel.Name, "No legible: " + ex.Message));
                events.Add(CoverageLossEvent(channel, "Error de lectura", ex.Message));
            }
}
        // P0-02: Refresh LastKnownGoodState with current service states for relevant services.
        // This ensures we have the latest known state even if no failure events were emitted.
        RefreshLastKnownGoodState(context);
        
        Dictionary<string, long> snapshot;
        Dictionary<string, string> stateSnapshot;
        lock (_sync)
        {
            snapshot = new Dictionary<string, long>(_lastRecordIds, StringComparer.OrdinalIgnoreCase);
            stateSnapshot = new Dictionary<string, string>(_lastKnownGoodState, StringComparer.OrdinalIgnoreCase);
        }
        var persistOk = CollectorCursorStore.TrySave("windows-event-cursors", new WindowsCursorState(snapshot, DateTimeOffset.Now, stateSnapshot), out var persistError);
        if (!persistOk)
        {
            _cursorPersistenceWarning = persistError ?? "No fue posible persistir el bookmark incremental.";
            coverage.Add(new EvidenceItem("Persistencia de cursores", "NO EVALUADO · " + _cursorPersistenceWarning));
            events.Add(new DiagnosticEvent(DateTimeOffset.Now, "TDM", "Persistencia Event Viewer", DiagnosticLayer.Windows,
                DiagnosticSeverity.Advertencia, "WINDOWS_INCREMENTAL_CURSOR_NOT_PERSISTED",
                "Los eventos se leyeron, pero TDM no pudo persistir el cursor durable; la continuidad después de reiniciar no está garantizada.",
                Evidencia: [new EvidenceItem("Cobertura", "Parcial"), new EvidenceItem("Detalle", _cursorPersistenceWarning)]));
        }
        else
        {
            _forceReplayAfterCursorLoss = false;
        }

        var lost = coverage.Count(x => x.Valor.StartsWith("Sin permisos", StringComparison.OrdinalIgnoreCase)
            || x.Valor.StartsWith("No legible", StringComparison.OrdinalIgnoreCase)
            || x.Valor.StartsWith("Canal no disponible", StringComparison.OrdinalIgnoreCase)
            || x.Valor.StartsWith("NO EVALUADO", StringComparison.OrdinalIgnoreCase)
            // T3: "Parcial" genérico cubre backlog y replay acotado (historial previo perdido).
            || x.Valor.StartsWith("Parcial", StringComparison.OrdinalIgnoreCase));
        events.Add(new DiagnosticEvent(DateTimeOffset.Now, "TDM", "Cobertura incremental Windows", DiagnosticLayer.Windows,
            lost > 0 ? DiagnosticSeverity.Advertencia : DiagnosticSeverity.Informativo,
            "WINDOWS_INCREMENTAL_COVERAGE",
            lost > 0 ? $"{lost} canal(es) de Event Viewer perdieron cobertura durante el monitoreo continuo." : "Cobertura incremental de Event Viewer actualizada.",
            Evidencia: [new EvidenceItem("Cobertura", lost > 0 ? "Parcial" : "Disponible"), .. coverage]));

        // P18: la marca de éxito solo avanza con cobertura total y cursor persistido;
        // una muestra parcial/backlog no debe hacer creer continuidad a la detección de huecos.
        if (lost == 0 && persistOk)
            _lastSuccessUtc = DateTimeOffset.Now;
        return Task.FromResult(new CollectorResult(findings, events));
    }

    private static DiagnosticEvent CoverageLossEvent(ChannelSpec channel, string state, string detail) =>
        new(DateTimeOffset.Now, "Windows Event Log", channel.Name, channel.Layer,
            DiagnosticSeverity.Advertencia, "WINDOWS_EVENT_SOURCE_UNAVAILABLE",
            $"La fuente incremental '{channel.Name}' quedó NO EVALUADA durante esta muestra.",
            Evidencia:
            [
                new EvidenceItem("Canal", channel.Name),
                new EvidenceItem("Cobertura", "No evaluado"),
                new EvidenceItem("Estado", state),
                new EvidenceItem("Detalle", detail)
            ]);

    private DiagnosticEvent? ConvertRecord(ChannelSpec channel, EventRecord record, DiagnosticContext context)
    {
        var provider = record.ProviderName ?? "Windows Event Log";
        if (channel.Name.Equals("Application", StringComparison.OrdinalIgnoreCase) && !IsRelevantApplication(provider, record.Id))
            return null;

        string message;
        try { message = record.FormatDescription() ?? "Descripción no disponible."; }
        catch { message = "Descripción no disponible."; }
        if (message.Length > 4000) message = message[..4000] + "…";

        var timestamp = record.TimeCreated.HasValue ? new DateTimeOffset(record.TimeCreated.Value) : (DateTimeOffset?)null;
        var severity = record.Level switch
        {
            1 => DiagnosticSeverity.Critico,
            2 => DiagnosticSeverity.Error,
            3 => DiagnosticSeverity.Advertencia,
            _ => DiagnosticSeverity.Informativo
        };

        var type = ClassifyType(channel.Name, provider, record.Id);
        if (type == "SERVICE_TERMINATION") severity = DiagnosticSeverity.Error;
        if (type is "USER_LOGON_FAILURE" or "USER_NLA_PASSWORD_FAILURE" or "WINDOWS_CREDENTIAL_VALIDATION_FAILURE") severity = DiagnosticSeverity.Advertencia;
        if (type == "ACCOUNT_LOCKOUT") severity = DiagnosticSeverity.Advertencia;
        if (type == "KERBEROS_PREAUTH_FAILURE") severity = DiagnosticSeverity.Advertencia;

        var evidence = new List<EvidenceItem>
        {
            new("Canal", channel.Name),
            new("EventId", record.Id.ToString()),
            new("Provider", provider),
            new("RecordId", record.RecordId?.ToString() ?? "N/D"),
            new("Fecha", record.TimeCreated?.ToString("O") ?? "N/D"),
            // Parseo profundo: identificadores numéricos siempre disponibles para identidad exacta.
            new("Opcode", record.Opcode?.ToString() ?? "N/D"),
            new("Categoría de tarea", record.Task?.ToString() ?? "N/D"),
            new("Modo captura", "Incremental por RecordId")
        };

        if (channel.Name.Equals("Security", StringComparison.OrdinalIgnoreCase))
        {
            var securityData = ParseEventData(record);
            string? S(params string[] keys) => FirstValue(securityData, keys);
            if (record.Id == 4776)
            {
                var errorCode = S("ErrorCode", "Status", "param4") ?? "N/D";
                if (errorCode.Equals("0x0", StringComparison.OrdinalIgnoreCase) || errorCode.Equals("0", StringComparison.OrdinalIgnoreCase))
                    return null; // 4776 exitoso no es una incidencia.
                type = "WINDOWS_CREDENTIAL_VALIDATION_FAILURE";
                AddEvidence(evidence, "Usuario", S("TargetUserName", "LogonAccount", "param1"));
                AddEvidence(evidence, "Estación", S("Workstation", "SourceWorkstation", "param2"));
                AddEvidence(evidence, "Código de error", errorCode);
            }
            else if (record.Id == 4625)
            {
                var logonType = S("LogonType") ?? "N/D";
                var status = S("Status") ?? "N/D";
                var subStatus = S("SubStatus") ?? "N/D";
                if (logonType == "10")
                    type = "USER_LOGON_FAILURE";
                else if (logonType == "3" && IsNlaCredentialStatus(status, subStatus))
                    type = "USER_NLA_PASSWORD_FAILURE";
                else
                    return null; // 4625 ajeno a RDP/NLA no contamina Observabilidad de Remote Access.
                AddEvidence(evidence, "Usuario", S("TargetUserName"));
                AddEvidence(evidence, "Dominio", S("TargetDomainName"));
                AddEvidence(evidence, "IP origen", S("IpAddress"));
                AddEvidence(evidence, "LogonType", logonType);
                AddEvidence(evidence, "Status", status);
                AddEvidence(evidence, "SubStatus", subStatus);
            }
            else if (record.Id == 4740)
            {
                AddEvidence(evidence, "Usuario", S("TargetUserName"));
                AddEvidence(evidence, "Dominio", S("TargetDomainName"));
                AddEvidence(evidence, "Equipo originador", S("CallerComputerName"));
            }
            else if (record.Id == 4771)
            {
                AddEvidence(evidence, "Usuario", S("TargetUserName"));
                AddEvidence(evidence, "IP origen", S("IpAddress"));
                AddEvidence(evidence, "Código de falla", S("Status", "FailureCode"));
                AddEvidence(evidence, "Tipo preautenticación", S("PreAuthType"));
            }
        }

        string? serviceName = null;
        if (type == "SERVICE_TERMINATION")
        {
            var serviceData = ParseEventData(record);
            serviceName = FirstValue(serviceData, "ServiceName", "param1");
            if (!IsRelevantService(serviceName, message, context.Sistema)) return null;
            AddEvidence(evidence, "Servicio", serviceName);
            // P0-02: Track last known good state for cursor loss recovery.
            if (!string.IsNullOrWhiteSpace(serviceName))
            {
                lock (_sync) _lastKnownGoodState[serviceName] = "Stopped";
            }
        }
        else if (type == "SERVICE_START_FAILURE")
        {
            // Y2: extraer el nombre real del servicio (param1 en 7000/7001/7009/7011/7023/7024)
            // para el gate de misión y mejor granularidad en el ledger. Sin filtrar: todo fallo
            // de arranque SCM es visible; la misión solo decide candidatura a causa raíz.
            var serviceData = ParseEventData(record);
            serviceName = FirstValue(serviceData, "ServiceName", "param1");
            AddEvidence(evidence, "Servicio", serviceName);
        }

        string? application = null;
        string? applicationPath = null;
        string? module = null;
        string? modulePath = null;
        string? exceptionCode = null;
        string? reportId = null;
        if (type is "APPLICATION_CRASH" or "WER_REPORT" or "DOTNET_UNHANDLED_EXCEPTION")
        {
            var data = ParseEventData(record);
            string? Get(params string[] keys)
            {
                foreach (var key in keys)
                    if (data.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value)) return value.Trim();
                return null;
            }
            application = record.Id == 1000 ? Get("AppName", "FaultingApplicationName", "param1") : Get("AppName", "ApplicationName", "param1");
            applicationPath = record.Id == 1000 ? Get("AppPath", "FaultingApplicationPath", "param11") : Get("AppPath", "ApplicationPath");
            module = Get("ModuleName", "FaultingModuleName", "param4");
            modulePath = Get("ModulePath", "FaultingModulePath", "param12");
            exceptionCode = Get("ExceptionCode", "param7");
            reportId = Get("ReportId", "ReportIdValue", "param13");
            AddEvidence(evidence, "Aplicación", application);
            AddEvidence(evidence, "Ruta de aplicación", applicationPath);
            AddEvidence(evidence, "Módulo con error", module);
            AddEvidence(evidence, "Ruta del módulo", modulePath);
            AddEvidence(evidence, "Código de excepción", exceptionCode);
            AddEvidence(evidence, "ReportId", reportId);
        }

        var joined = $"{serviceName} {application} {applicationPath} {module} {modulePath} {message}";
        var product = ClassifyProduct(joined, context.Sistema);
        var layer = product == TsplusProduct.Ninguno ? channel.Layer : DiagnosticLayer.Tsplus;
        var component = serviceName ?? application ?? ResolveComponent(provider, type);

        return new DiagnosticEvent(
            timestamp,
            provider,
            component,
            layer,
            severity,
            type,
            message,
            exceptionCode ?? record.Id.ToString(),
            applicationPath,
            Evidencia: evidence,
            Producto: product);
    }

    private static Dictionary<string, string> ParseEventData(EventRecord record)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            var doc = XDocument.Parse(record.ToXml());
            XNamespace ns = "http://schemas.microsoft.com/win/2004/08/events/event";
            var data = doc.Descendants(ns + "EventData").Elements(ns + "Data").ToList();
            for (var i = 0; i < data.Count; i++)
            {
                var name = data[i].Attribute("Name")?.Value;
                var value = data[i].Value;
                if (!string.IsNullOrWhiteSpace(name)) result[name] = value;
                result[$"param{i + 1}"] = value;
            }
        }
        catch { }
        return result;
    }

    private static string? FirstValue(IReadOnlyDictionary<string, string> values, params string[] keys)
    {
        foreach (var key in keys)
            if (values.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value)) return value.Trim();
        return null;
    }

    private static bool IsRelevantService(string? serviceName, string message, SystemSnapshot system)
    {
        var text = $"{serviceName} {message}";
        string[] known =
        [
            "TermService", "Remote Desktop Services", "RpcSs", "Remote Procedure Call", "DcomLaunch",
            "EventLog", "Windows Event Log", "Winmgmt", "Windows Management Instrumentation", "Spooler",
            "TSplus", "APSC", "Application Publishing", "HTML5", "Gateway"
        ];
        _ = system; // mantiene la firma preparada para reglas dependientes del inventario sin exponer rutas.
        return known.Any(x => text.Contains(x, StringComparison.OrdinalIgnoreCase));
    }

    private static void AddEvidence(List<EvidenceItem> evidence, string key, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value)) evidence.Add(new EvidenceItem(key, value));
    }

    private static TsplusProduct ClassifyProduct(string text, SystemSnapshot system)
    {
        if (text.Contains("ServerMonitoring", StringComparison.OrdinalIgnoreCase)) return TsplusProduct.ServerMonitoring;
        if (text.Contains("TSplus-Security", StringComparison.OrdinalIgnoreCase) || text.Contains("Advanced Security", StringComparison.OrdinalIgnoreCase)) return TsplusProduct.AdvancedSecurity;
        if (text.Contains("RemoteSupport", StringComparison.OrdinalIgnoreCase) || text.Contains("Remote Support", StringComparison.OrdinalIgnoreCase)) return TsplusProduct.RemoteSupport;
        if (text.Contains("TwoFactor", StringComparison.OrdinalIgnoreCase) || text.Contains("2FA", StringComparison.OrdinalIgnoreCase)) return TsplusProduct.TwoFactorAuthentication;
        var tsplusRoot = system.TsplusRuta;
        if (!string.IsNullOrWhiteSpace(tsplusRoot) && text.Contains(tsplusRoot, StringComparison.OrdinalIgnoreCase)) return TsplusProduct.RemoteAccess;
        string[] markers = ["tsplus", "wsession", "logonsession", "alternateshell", "svcr.exe", "admintool", "gateway", "html5"];
        return markers.Any(x => text.Contains(x, StringComparison.OrdinalIgnoreCase)) ? TsplusProduct.RemoteAccess : TsplusProduct.Ninguno;
    }

    private static string ClassifyType(string channel, string provider, int id)
    {
        if (provider.Contains("Service Control Manager", StringComparison.OrdinalIgnoreCase) && id is 7031 or 7034)
            return "SERVICE_TERMINATION";
        // V1: los fallos de arranque SCM ya se consultan (P17) pero caían a WINDOWS_EVENT_INCREMENTAL,
        // invisible para ledger y para ROOT-SCM-SERVICE-FAILURE. Mismo mapeo que el forense.
        if (provider.Contains("Service Control Manager", StringComparison.OrdinalIgnoreCase) && id is 7000 or 7001 or 7009 or 7011 or 7023 or 7024)
            return "SERVICE_START_FAILURE";
        if (channel.Equals("Application", StringComparison.OrdinalIgnoreCase))
        {
            if (provider.Contains("Application Error", StringComparison.OrdinalIgnoreCase) || id == 1000)
                return "APPLICATION_CRASH";
            if (provider.Contains("Windows Error Reporting", StringComparison.OrdinalIgnoreCase) || id == 1001)
                return "WER_REPORT";
            if (provider.Contains(".NET Runtime", StringComparison.OrdinalIgnoreCase) || id == 1026)
                return "DOTNET_UNHANDLED_EXCEPTION";
        }
        if (channel.Equals("Security", StringComparison.OrdinalIgnoreCase))
        {
            if (id == 4740) return "ACCOUNT_LOCKOUT";
            if (id == 4771) return "KERBEROS_PREAUTH_FAILURE";
            if (id == 4625) return "USER_LOGON_FAILURE";
            if (id == 4776) return "WINDOWS_CREDENTIAL_VALIDATION_FAILURE";
        }
        if (channel.Contains("LocalSessionManager", StringComparison.OrdinalIgnoreCase))
        {
            return id switch
            {
                21 => "RDP_SESSION_LOGON_STAGE",
                22 => "RDP_SHELL_START_STAGE",
                23 => "RDP_SESSION_LOGOFF_STAGE",
                24 => "RDP_SESSION_DISCONNECT_STAGE",
                25 => "RDP_SESSION_RECONNECT_STAGE",
                _ => "RDP_EVENT_INCREMENTAL"
            };
        }
        if (channel.Contains("RemoteConnectionManager", StringComparison.OrdinalIgnoreCase) && id == 1149)
            return "RDP_AUTHENTICATION_STAGE";
        if (channel.Contains("CodeIntegrity", StringComparison.OrdinalIgnoreCase)) return "CODE_INTEGRITY_EVENT";
        if (channel.Contains("AppLocker", StringComparison.OrdinalIgnoreCase)) return "APPLOCKER_EVENT";
        if (channel.Contains("PrintService", StringComparison.OrdinalIgnoreCase)) return "PRINT_EVENT_INCREMENTAL";
        if (channel.Contains("Defender", StringComparison.OrdinalIgnoreCase)) return "DEFENDER_EVENT_INCREMENTAL";
        if (channel.Contains("Firewall", StringComparison.OrdinalIgnoreCase)) return "FIREWALL_EVENT_INCREMENTAL";
        if (channel.Contains("CAPI2", StringComparison.OrdinalIgnoreCase)) return "CAPI2_EVENT_INCREMENTAL";
        if (channel.Contains("WMI", StringComparison.OrdinalIgnoreCase)) return "WMI_EVENT_INCREMENTAL";
        if (channel.Contains("DNS", StringComparison.OrdinalIgnoreCase) || channel.Contains("NetworkProfile", StringComparison.OrdinalIgnoreCase)) return "NETWORK_EVENT_INCREMENTAL";
        if (channel.Contains("Resource-Exhaustion", StringComparison.OrdinalIgnoreCase)) return "RESOURCE_EXHAUSTION";
        if (channel.Contains("DiskDiagnostic", StringComparison.OrdinalIgnoreCase)) return "STORAGE_FAILURE";
        return "WINDOWS_EVENT_INCREMENTAL";
    }

    private static bool IsNlaCredentialStatus(string status, string subStatus)
    {
        static bool Match(string value) => value.Equals("0xC000006A", StringComparison.OrdinalIgnoreCase) ||
                                           value.Equals("0xC0000071", StringComparison.OrdinalIgnoreCase) ||
                                           value.Equals("0xC0000224", StringComparison.OrdinalIgnoreCase) ||
                                           value.Equals("0xC0000234", StringComparison.OrdinalIgnoreCase) ||
                                           value.Equals("0xC0000064", StringComparison.OrdinalIgnoreCase);
        return Match(status) || Match(subStatus);
    }

    private static string ResolveComponent(string provider, string type)
    {
        if (type == "SERVICE_TERMINATION") return "Service Control Manager";
        if (type == "ACCOUNT_LOCKOUT") return "Cuenta de usuario bloqueada";
        if (type == "KERBEROS_PREAUTH_FAILURE") return "Kerberos / preautenticación";
        if (type == "USER_NLA_PASSWORD_FAILURE") return "Windows NLA / credenciales";
        if (type == "WINDOWS_CREDENTIAL_VALIDATION_FAILURE") return "Validación de credenciales Windows";
        if (type == "USER_LOGON_FAILURE") return "Autenticación Windows";
        if (type.StartsWith("RDP_", StringComparison.OrdinalIgnoreCase)) return "Remote Desktop Services";
        return provider;
    }

    private static bool IsRelevantApplication(string provider, int id)
        => provider.Contains("Application Error", StringComparison.OrdinalIgnoreCase)
           || provider.Contains(".NET Runtime", StringComparison.OrdinalIgnoreCase)
           || provider.Contains("Windows Error Reporting", StringComparison.OrdinalIgnoreCase)
           || provider.Contains("TSplus", StringComparison.OrdinalIgnoreCase)
           || id is 1000 or 1001 or 1026;

    private long Cursor(string channel)
    {
        lock (_sync) return _lastRecordIds.TryGetValue(channel, out var value) ? value : 0;
    }

    private void UpdateCursor(string channel, long value)
    {
        lock (_sync) _lastRecordIds[channel] = Math.Max(CursorUnsafe(channel), value);
    }

    private long CursorUnsafe(string channel)
        => _lastRecordIds.TryGetValue(channel, out var value) ? value : 0;

    private void SetCursor(string channel, long value)
    {
        lock (_sync) _lastRecordIds[channel] = Math.Max(0, value);
    }

    private static string AppendRecentWindow(string filter, TimeSpan window)
    {
        var ms = Math.Max(1, (long)window.TotalMilliseconds);
        var inner = filter.StartsWith("*[System[", StringComparison.Ordinal) && filter.EndsWith("]]", StringComparison.Ordinal)
            ? filter[9..^2]
            : string.Empty;
        var time = $"TimeCreated[timediff(@SystemTime) <= {ms}]";
        return string.IsNullOrWhiteSpace(inner)
            ? $"*[System[{time}]]"
            : $"*[System[({inner}) and {time}]]";
    }

    private static long? ReadLatestRecordId(string channel)
    {
        try
        {
            var query = new EventLogQuery(channel, PathType.LogName, "*") { ReverseDirection = true };
            using var reader = new EventLogReader(query);
            using var record = reader.ReadEvent();
            return record?.RecordId;
        }
        catch { return null; }
    }

    private static string AppendCursor(string filter, long cursor)
    {
        if (cursor <= 0) return filter;
        var inner = filter.StartsWith("*[System[", StringComparison.Ordinal) && filter.EndsWith("]]", StringComparison.Ordinal)
            ? filter[9..^2]
            : string.Empty;
        return string.IsNullOrWhiteSpace(inner)
            ? $"*[System[(EventRecordID > {cursor})]]"
            : $"*[System[(EventRecordID > {cursor}) and ({inner})]]";
    }

    /// <summary>
    /// Texto de cobertura con contabilidad de pérdida: registros leídos y rango
    /// RecordId primero..último. Puro y pineado por tests.
    /// </summary>
    public static string FormatChannelCoverage(bool backlog, int read, long? firstRecordId, long? lastRecordId)
    {
        var range = RangeText(read, firstRecordId, lastRecordId);
        return backlog
            ? $"Parcial; backlog pendiente; registros procesados={read}; rango={range}"
            : $"Disponible; registros leídos={read}; rango={range}";
    }

    private static string RangeText(int read, long? firstRecordId, long? lastRecordId)
        => read == 0 ? "N/D" : FormatId(firstRecordId) + ".." + FormatId(lastRecordId);

    private static string FormatId(long? value) => value.HasValue ? value.Value.ToString() : "N/D";

    private static string Sanitize(string value)
        => new(value.Where(char.IsLetterOrDigit).Take(28).ToArray());

    private static uint StableHash(string value)
    {
        const uint offset = 2166136261;
        const uint prime = 16777619;
        var hash = offset;
        foreach (var ch in value)
        {
            hash ^= char.ToUpperInvariant(ch);
            hash *= prime;
        }
        return hash;
    }

    /// <summary>
    /// P0-02: Query current state of relevant services to keep LastKnownGoodState fresh.
    /// Called at the end of each incremental collection cycle.
    /// </summary>
    private void RefreshLastKnownGoodState(DiagnosticContext context)
    {
        try
        {
            var relevantServices = new[]
            {
                "TermService", "RpcSs", "DcomLaunch", "EventLog", "Winmgmt", "Spooler",
                "TSplus", "APSC", "TSplus HTML5", "TSplus WebPortal", "TSplus Gateway",
                "TSplus Session", "TSplus Print", "TSplus Licensing"
            };
            var services = ServiceController.GetServices();
            try
            {
                foreach (var sc in services)
                {
                    if (relevantServices.Any(r => sc.ServiceName.Equals(r, StringComparison.OrdinalIgnoreCase) ||
                        sc.DisplayName.Contains(r, StringComparison.OrdinalIgnoreCase)))
                    {
                        try
                        {
                            var state = sc.Status.ToString();
                            lock (_sync) _lastKnownGoodState[sc.ServiceName] = state;
                        }
                        catch { /* Ignore individual service query failures */ }
                    }
                }
            }
            finally
            {
                foreach (var sc in services) sc.Dispose();
            }
        }
        catch { /* Ignore overall SCM query failures */ }
    }

    private sealed record ChannelSpec(string Name, string Filter, DiagnosticLayer Layer);
}
