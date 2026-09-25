using System.Diagnostics;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using TDM.Core;
using TDM.Models;

namespace TDM.Collectors.Network;

public sealed class NetworkHealthCollector : IReadOnlyCollector
{
    public string Nombre => "Network Health";

    public async Task<CollectorResult> CollectAsync(DiagnosticContext context, CancellationToken cancellationToken)
    {
        var findings = new List<DiagnosticFinding>();
        var events = new List<DiagnosticEvent>();

        var adapters = NetworkInterface.GetAllNetworkInterfaces()
            .Where(n => n.NetworkInterfaceType != NetworkInterfaceType.Loopback)
            .ToList();
        var up = adapters.Where(n => n.OperationalStatus == OperationalStatus.Up).ToList();
        var addresses = up.SelectMany(n => n.GetIPProperties().UnicastAddresses)
            .Where(a => a.Address.AddressFamily == AddressFamily.InterNetwork)
            .Select(a => a.Address.ToString()).Distinct().ToList();
        var gateways = up.SelectMany(n => n.GetIPProperties().GatewayAddresses)
            .Select(g => g.Address.ToString())
            .Where(x => x != "0.0.0.0" && x != "::")
            .Distinct().ToList();
        var dns = up.SelectMany(n => n.GetIPProperties().DnsAddresses)
            .Select(a => a.ToString()).Distinct().ToList();

        var portAudit = await AuditTsplusPortsAsync(context, cancellationToken).ConfigureAwait(false);

        var evidence = new List<EvidenceItem>
        {
            new("Adaptadores detectados", adapters.Count.ToString()),
            new("Adaptadores activos", up.Count.ToString()),
            new("IPv4", addresses.Count == 0 ? "N/D" : string.Join(", ", addresses.Take(5))),
            new("Gateway", gateways.Count == 0 ? "No detectado" : string.Join(", ", gateways.Take(3))),
            new("DNS", dns.Count == 0 ? "No detectado" : string.Join(", ", dns.Take(4))),
            new("Puertos TSplus inspeccionados", portAudit.Checked.Count == 0 ? "N/D" : string.Join(", ", portAudit.Checked.Select(x => x.Port).Distinct().Order())),
            new("Interferencias de puerto detectadas", portAudit.Conflicts.Count.ToString()),
            new("Cobertura de puertos", portAudit.ListenersEvaluated ? "Completa" : $"Parcial: {portAudit.CoverageDetail}")
        };

        foreach (var item in portAudit.Checked)
            evidence.Add(new EvidenceItem(item.Label, $"{item.Port} | listener={(item.Listening ? "Sí" : "No")} | proceso={item.Owner} | tcp={(string.IsNullOrWhiteSpace(item.TcpLocal) ? "N/D" : item.TcpLocal)}" + (string.IsNullOrWhiteSpace(item.HttpLocal) ? string.Empty : $" | http={item.HttpLocal}")));
        foreach (var conflict in portAudit.Conflicts.Take(10))
            evidence.Add(new EvidenceItem("Posible interferencia", conflict));

        events.Add(new DiagnosticEvent(
            DateTimeOffset.Now,
            "Network Snapshot",
            "Pila de red",
            DiagnosticLayer.Red,
            portAudit.ListenersEvaluated ? DiagnosticSeverity.Informativo : DiagnosticSeverity.Advertencia,
            "NETWORK_STATE",
            portAudit.ListenersEvaluated
                ? $"Adaptadores activos={up.Count}; IPv4={addresses.Count}; Gateways={gateways.Count}; DNS={dns.Count}; conflictosPuerto={portAudit.Conflicts.Count}"
                : $"Adaptadores activos={up.Count}; la inspección de listeners/puertos quedó no evaluada ({portAudit.CoverageDetail}).",
            Evidencia: evidence));

        if (context.Sistema.TsplusDetectado && !portAudit.ListenersEvaluated)
        {
            findings.Add(new DiagnosticFinding(
                "NETWORK-PORT-COVERAGE",
                "Puertos TSplus",
                DiagnosticSeverity.Advertencia,
                "No fue posible evaluar los listeners TCP configurados para TSplus.",
                "TDM no interpreta una consulta netstat fallida o agotada como ausencia de listener. La cobertura de puertos queda parcial.",
                [new EvidenceItem("Cobertura", portAudit.CoverageDetail)],
                ConfidenceLevel.Confirmada,
                Capa: DiagnosticLayer.Red));
        }

        if (context.Sistema.TsplusDetectado && up.Count == 0)
        {
            findings.Add(new DiagnosticFinding(
                "NETWORK-NO-UP-INTERFACE",
                "Pila de red",
                DiagnosticSeverity.Critico,
                "No se detectó ninguna interfaz de red activa.",
                "Sin una interfaz de red operativa, las conexiones remotas no pueden alcanzar TSplus. Este hallazgo pertenece a Windows/red, no al motor de TSplus.",
                [new EvidenceItem("Adaptadores activos", "0")],
                ConfidenceLevel.Alta,
                "Microsoft Learn",
                "https://learn.microsoft.com/windows-server/networking/",
                "Revisar el estado del adaptador, controlador y conectividad siguiendo la documentación de Microsoft. TDM no habilita ni modifica interfaces.",
                DiagnosticLayer.Red));
        }

        foreach (var conflict in portAudit.Conflicts)
        {
            findings.Add(new DiagnosticFinding(
                $"NETWORK-TSPLUS-PORT-CONFLICT-{Sanitize(conflict)}",
                "Puertos TSplus",
                DiagnosticSeverity.Advertencia,
                "Se detectó una posible interferencia de puerto que puede afectar a TSplus.",
                conflict,
                [new EvidenceItem("Conflicto observado", conflict)],
                ConfidenceLevel.Media,
                "TSplus Documentation / Support — Built-in Web Server and port management",
                "https://docs.tsplus.net/tsplus/built-in-web-server/",
                "Verifique qué proceso debe poseer el puerto según la configuración real de TSplus. No termine procesos ni cambie puertos hasta confirmar que no se usa un proxy/servidor web externo de forma intencional.",
                DiagnosticLayer.Red));
        }

        return new CollectorResult(findings, events);
    }

    private static async Task<PortAudit> AuditTsplusPortsAsync(DiagnosticContext context, CancellationToken ct)
    {
        var listenersProbe = await ReadTcpListenersAsync(ct).ConfigureAwait(false);
        var listeners = listenersProbe.IsAvailable ? listenersProbe.Value ?? new Dictionary<int, List<string>>() : new Dictionary<int, List<string>>();
        var checkedPorts = new List<PortCheck>();
        var conflicts = new List<string>();
        if (!context.Sistema.TsplusDetectado) return new PortAudit(checkedPorts, conflicts, listenersProbe.IsAvailable, listenersProbe.StatusText);
        if (listenersProbe.IsUnavailable)
            return new PortAudit(checkedPorts, conflicts, false, listenersProbe.StatusText + (string.IsNullOrWhiteSpace(listenersProbe.Detail) ? string.Empty : $": {listenersProbe.Detail}"));

        var rdpPort = ReadRdpPort();
        AddCheck("RDP configurado", rdpPort, listeners, p => IsExpectedOwner(p, "svchost", "system", "termsrv"), checkedPorts, conflicts, "RDP/TermService");

        var install = context.Sistema.TsplusRuta;
        int? webHttpPort = null;
        int? webHttpsPort = null;
        if (!string.IsNullOrWhiteSpace(install))
        {
            var (http, https) = ReadWebPorts(install);
            webHttpPort = http;
            webHttpsPort = https;
            if (http.HasValue)
                AddCheck("Web HTTP configurado", http.Value, listeners, IsTsplusWebOwner, checkedPorts, conflicts, "TSplus Web/HTML5");
            if (https.HasValue)
                AddCheck("Web HTTPS configurado", https.Value, listeners, IsTsplusWebOwner, checkedPorts, conflicts, "TSplus Web/HTML5");
            if (!http.HasValue && !https.HasValue)
            {
                AddObservedOnly("Web HTTP predeterminado", 80, listeners, checkedPorts);
                AddObservedOnly("Web HTTPS predeterminado", 443, listeners, checkedPorts);
            }
        }

        var programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        var smInstalled = Directory.Exists(Path.Combine(programFilesX86, "TSplus-ServerMonitoring"));
        if (smInstalled)
            // V4: el binario esperado es ServerMonitoring.Service.exe (nombre con punto), que la
            // igualdad exacta anterior rechazaba y generaba un conflicto espurio en el 7778.
            AddCheck("Server Monitoring", 7778, listeners, p => IsExpectedOwner(p, "servermonitoring", "tsplus-servermonitoring", "servermonitoring.service"), checkedPorts, conflicts, "TSplus Server Monitoring");

        var rsInstalled = Directory.Exists(Path.Combine(programFilesX86, "TSplus-RemoteSupport"));
        if (rsInstalled)
            AddObservedOnly("Remote Support HTTPS (si este equipo aloja el servidor)", 443, listeners, checkedPorts);

        // Sonda funcional pasiva (solo lectura): verifica que cada puerto con listener acepta
        // realmente conexiones TCP locales, no solo que netstat lo liste. Un listener zombie o
        // ligado a otra interfaz responde distinto que uno operativo; el fallo aquí NO genera
        // hallazgo por sí solo (un bind a IP específica rechaza 127.0.0.1 legítimamente), pero
        // un OK confirma capacidad funcional y alimenta al analizador de impacto.
        var tcpProbe = await ProbeTcpLocalAsync(checkedPorts.Where(p => p.Listening).Select(p => p.Port), ct).ConfigureAwait(false);
        for (var i = 0; i < checkedPorts.Count; i++)
        {
            var checked_ = checkedPorts[i];
            if (checked_.Listening && tcpProbe.TryGetValue(checked_.Port, out var probe))
                checkedPorts[i] = checked_ with { TcpLocal = probe };
        }

        // Sonda HTTP funcional (solo lectura): un puerto TCP abierto no demuestra que el portal
        // sirva contenido. GET local con timeout corto; certificado autofirmado aceptado porque
        // solo se valida respuesta, no identidad. Sin hallazgos por fallo: un 404/redirección
        // también confirma "alguien responde"; el silencio total queda como evidencia.
        var webTargets = new List<(int Port, bool Https)>();
        if (webHttpPort.HasValue) webTargets.Add((webHttpPort.Value, false));
        if (webHttpsPort.HasValue) webTargets.Add((webHttpsPort.Value, true));
        if (webTargets.Count == 0)
        {
            webTargets.Add((80, false));
            webTargets.Add((443, true));
        }
        var httpProbe = await ProbeHttpLocalAsync(webTargets, ct).ConfigureAwait(false);
        for (var i = 0; i < checkedPorts.Count; i++)
        {
            var checked_ = checkedPorts[i];
            if (httpProbe.TryGetValue(checked_.Port, out var httpResult))
                checkedPorts[i] = checked_ with { HttpLocal = httpResult };
        }

        return new PortAudit(checkedPorts, conflicts, true, "Disponible");
    }

    private static async Task<Dictionary<int, string>> ProbeTcpLocalAsync(IEnumerable<int> ports, CancellationToken ct)
    {
        var result = new Dictionary<int, string>();

        async Task ProbeOne(int port)
        {
            using var client = new TcpClient();
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeoutCts.CancelAfter(TimeSpan.FromMilliseconds(1500));
            var sw = Stopwatch.StartNew();
            try
            {
                await client.ConnectAsync("127.0.0.1", port, timeoutCts.Token).ConfigureAwait(false);
                lock (result) result[port] = $"OK {(int)sw.Elapsed.TotalMilliseconds} ms";
            }
            catch (Exception ex)
            {
                if (ct.IsCancellationRequested) throw;
                var timedOut = timeoutCts.IsCancellationRequested;
                lock (result) result[port] = timedOut
                    ? "Sin respuesta (timeout 1,5 s)"
                    : $"Rechazado: {TrimProbeError(ex.Message)}";
            }
        }

        await Task.WhenAll(ports.Distinct().Select(ProbeOne)).ConfigureAwait(false);
        return result;
    }

    private static string TrimProbeError(string? message)
    {
        if (string.IsNullOrWhiteSpace(message)) return "sin detalle";
        var firstLine = message.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries).FirstOrDefault() ?? string.Empty;
        firstLine = firstLine.Trim();
        return firstLine.Length <= 80 ? firstLine : firstLine[..80].TrimEnd() + "…";
    }

    private static async Task<Dictionary<int, string>> ProbeHttpLocalAsync(IEnumerable<(int Port, bool Https)> targets, CancellationToken ct)
    {
        var result = new Dictionary<int, string>();
        using var handler = new HttpClientHandler
        {
            // Monitoreo local pasivo: se valida que el portal responda, no la identidad del
            // certificado (TSplus usa autofirmados). Nunca se envían credenciales ni datos.
            ServerCertificateCustomValidationCallback = (_, _, _, _) => true
        };
        using var client = new HttpClient(handler) { Timeout = Timeout.InfiniteTimeSpan };

        async Task ProbeOne(int port, bool https)
        {
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeoutCts.CancelAfter(TimeSpan.FromMilliseconds(2500));
            var sw = Stopwatch.StartNew();
            try
            {
                using var response = await client.GetAsync($"http{(https ? "s" : "")}://127.0.0.1:{port}/", HttpCompletionOption.ResponseHeadersRead, timeoutCts.Token).ConfigureAwait(false);
                lock (result) result[port] = $"HTTP {(int)response.StatusCode} {(int)sw.Elapsed.TotalMilliseconds} ms";
            }
            catch (Exception ex)
            {
                if (ct.IsCancellationRequested) throw;
                var timedOut = timeoutCts.IsCancellationRequested;
                lock (result) result[port] = timedOut
                    ? "Sin respuesta (timeout 2,5 s)"
                    : $"Fallo: {TrimProbeError(ex.Message)}";
            }
        }

        await Task.WhenAll(targets.Distinct().Select(t => ProbeOne(t.Port, t.Https))).ConfigureAwait(false);
        return result;
    }

    private static void AddCheck(
        string label,
        int port,
        Dictionary<int, List<string>> listeners,
        Func<string, bool> expectedOwner,
        List<PortCheck> checks,
        List<string> conflicts,
        string component)
    {
        var owners = listeners.TryGetValue(port, out var list)
            ? list.Distinct(StringComparer.OrdinalIgnoreCase).ToList()
            : [];
        var listening = owners.Count > 0;
        var ownerText = listening ? string.Join(", ", owners) : "sin listener";
        checks.Add(new PortCheck(label, port, listening, ownerText));
        if (!listening || owners.Any(expectedOwner)) return;
        conflicts.Add($"Puerto {port} requerido/configurado para {component} está ocupado por un proceso no reconocido como propietario esperado: {ownerText}.");
    }

    private static void AddObservedOnly(string label, int port, Dictionary<int, List<string>> listeners, List<PortCheck> checks)
    {
        var owners = listeners.TryGetValue(port, out var list)
            ? list.Distinct(StringComparer.OrdinalIgnoreCase).ToList()
            : [];
        checks.Add(new PortCheck(label, port, owners.Count > 0, owners.Count > 0 ? string.Join(", ", owners) : "sin listener"));
    }

    private static bool IsTsplusWebOwner(string process)
    {
        if (!IsExpectedOwner(process, "html5service", "java", "javaw", "httpwebs", "tsplus")) return false;
        // P19: un java/javaw genérico solo es propietario TSplus si su ruta pertenece a TSplus
        // o no pudo leerse (criterio conservador heredado). Un impostor con el mismo nombre
        // pero ruta ajena genera conflicto en vez de validarse como sano.
        if (IsExpectedOwner(process, "java", "javaw") && !IsExpectedOwner(process, "html5service", "httpwebs", "tsplus"))
            return process.Contains("PID sin nombre", StringComparison.OrdinalIgnoreCase)
                || process.Contains("tsplus", StringComparison.OrdinalIgnoreCase);
        return true;
    }

    private static bool IsExpectedOwner(string process, params string[] tokens)
    {
        // S6: coincidencia sobre el NOMBRE del proceso (parte previa a " · " o " (PID"), con
        // igualdad exacta insensible a mayúsculas. El Contains anterior aceptaba como "system"
        // a cualquier "system_evil.exe" y validaba la ruta System32 como nombre.
        var name = OwnerProcessName(process);
        return tokens.Any(t => name.Equals(t, StringComparison.OrdinalIgnoreCase));
    }

    private static string OwnerProcessName(string owner)
    {
        if (string.IsNullOrWhiteSpace(owner)) return string.Empty;
        var end = owner.IndexOf(" · ", StringComparison.Ordinal);
        if (end < 0) end = owner.IndexOf(" (PID", StringComparison.Ordinal);
        return (end < 0 ? owner : owner[..end]).Trim();
    }

    private static int ReadRdpPort()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp");
            var value = key?.GetValue("PortNumber");
            return value is int i && i is > 0 and <= 65535 ? i : 3389;
        }
        catch
        {
            return 3389;
        }
    }

    private static (int? Http, int? Https) ReadWebPorts(string install)
    {
        var fromBat = ReadWebPortsFromBat(install);
        if (fromBat.Http.HasValue || fromBat.Https.HasValue) return fromBat;
        return ReadWebPortsFromStartupConfig(install);
    }

    private static (int? Http, int? Https) ReadWebPortsFromBat(string install)
    {
        try
        {
            var run = Path.Combine(install, "Clients", "webserver", "runwebserver.bat");
            if (!File.Exists(run)) return (null, null);
            var fi = new FileInfo(run);
            var content = fi.Length <= 512 * 1024
                ? File.ReadAllText(run)
                : string.Join(Environment.NewLine, File.ReadLines(run).Take(250));
            var match = Regex.Match(
                content,
                @"NSIOServer\s+(?<http>\d{1,5})\s+(?<https>\d{1,5})",
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
            if (!match.Success) return (null, null);
            int? http = int.TryParse(match.Groups["http"].Value, out var hp) && hp is > 0 and <= 65535 ? hp : null;
            int? https = int.TryParse(match.Groups["https"].Value, out var sp) && sp is > 0 and <= 65535 ? sp : null;
            return (http, https);
        }
        catch
        {
            return (null, null);
        }
    }

    private static (int? Http, int? Https) ReadWebPortsFromStartupConfig(string install)
    {
        try
        {
            var configPath = Path.Combine(install, "Clients", "webserver", "startup.config");
            if (!File.Exists(configPath)) return (null, null);
            var content = File.ReadAllText(configPath);
            var httpMatch = Regex.Match(content, @"HttpPort[""'\s:=]+(\d{1,5})", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
            var httpsMatch = Regex.Match(content, @"HttpsPort[""'\s:=]+(\d{1,5})", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
            int? http = httpMatch.Success && int.TryParse(httpMatch.Groups[1].Value, out var hp) && hp is > 0 and <= 65535 ? hp : null;
            int? https = httpsMatch.Success && int.TryParse(httpsMatch.Groups[1].Value, out var sp) && sp is > 0 and <= 65535 ? sp : null;
            return (http, https);
        }
        catch
        {
            return (null, null);
        }
    }

    private static async Task<ProbeResult<Dictionary<int, List<string>>>> ReadTcpListenersAsync(CancellationToken ct)
    {
        var result = new Dictionary<int, List<string>>();
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = Path.Combine(Environment.SystemDirectory, "netstat.exe"),
                Arguments = "-ano -p tcp",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            }
        };

        try
        {
            if (!process.Start()) return ProbeResult<Dictionary<int, List<string>>>.Unavailable("netstat.exe no pudo iniciarse.");

            var stdoutTask = process.StandardOutput.ReadToEndAsync();
            var stderrTask = process.StandardError.ReadToEndAsync();
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeoutCts.CancelAfter(TimeSpan.FromSeconds(4));

            try
            {
                await process.WaitForExitAsync(timeoutCts.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested && timeoutCts.IsCancellationRequested)
            {
                TryKillChild(process);
                await DrainAfterKillAsync(stdoutTask, stderrTask).ConfigureAwait(false);
                return ProbeResult<Dictionary<int, List<string>>>.Unavailable("netstat.exe excedió 4 segundos.");
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                TryKillChild(process);
                await DrainAfterKillAsync(stdoutTask, stderrTask).ConfigureAwait(false);
                throw;
            }

            var output = await stdoutTask.ConfigureAwait(false);
            var errorOutput = await stderrTask.ConfigureAwait(false);
            if (process.ExitCode != 0)
                return ProbeResult<Dictionary<int, List<string>>>.Unavailable($"netstat.exe terminó con código {process.ExitCode}{(string.IsNullOrWhiteSpace(errorOutput) ? string.Empty : $": {errorOutput.Trim()}")}");

            foreach (var raw in output.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries))
            {
                ct.ThrowIfCancellationRequested();
                var parts = raw.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 5 || !parts[0].Equals("TCP", StringComparison.OrdinalIgnoreCase)) continue;
                if (!parts[3].Equals("LISTENING", StringComparison.OrdinalIgnoreCase)) continue;
                var port = ParsePort(parts[1]);
                if (!port.HasValue || !int.TryParse(parts[4], out var pid)) continue;
                var owner = ProcessName(pid);
                if (!result.TryGetValue(port.Value, out var owners)) result[port.Value] = owners = [];
                owners.Add($"{owner} (PID {pid})");
            }
            return ProbeResult<Dictionary<int, List<string>>>.Available(result);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (UnauthorizedAccessException ex) { return ProbeResult<Dictionary<int, List<string>>>.AccessDenied(ex.Message); }
        catch (Exception ex) { return ProbeResult<Dictionary<int, List<string>>>.Error(ex.Message); }
    }

    private static void TryKillChild(Process process)
    {
        try
        {
            if (!process.HasExited) process.Kill(entireProcessTree: true);
        }
        catch { }
    }

    private static async Task DrainAfterKillAsync(Task<string> stdout, Task<string> stderr)
    {
        try { await Task.WhenAll(stdout, stderr).WaitAsync(TimeSpan.FromSeconds(1)).ConfigureAwait(false); }
        catch { }
    }

    private static int? ParsePort(string endpoint)
    {
        var idx = endpoint.LastIndexOf(':');
        if (idx < 0 || idx == endpoint.Length - 1) return null;
        return int.TryParse(endpoint[(idx + 1)..], out var port) ? port : null;
    }

    private static string ProcessName(int pid)
    {
        // P19: incluye la ruta del ejecutable para validar propiedad real (no solo nombre).
        try
        {
            using var proc = Process.GetProcessById(pid);
            string? path = null;
            try { path = proc.MainModule?.FileName; } catch { }
            return string.IsNullOrWhiteSpace(path) ? proc.ProcessName : $"{proc.ProcessName} · {path}";
        }
        catch { return "PID sin nombre"; }
    }

    private static string Sanitize(string value)
    {
        var chars = value.Where(char.IsLetterOrDigit).Take(80).ToArray();
        return chars.Length == 0 ? "UNKNOWN" : new string(chars);
    }

    private sealed record PortCheck(string Label, int Port, bool Listening, string Owner, string TcpLocal = "", string HttpLocal = "");
    private sealed record PortAudit(List<PortCheck> Checked, List<string> Conflicts, bool ListenersEvaluated, string CoverageDetail);
}
