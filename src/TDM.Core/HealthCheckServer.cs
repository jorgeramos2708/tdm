using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using TDM.Models;
using TDM.Persistence;

namespace TDM.Core;

/// <summary>
/// Servidor HTTP ligero para health checks (/health, /ready).
/// Se inicia en TDM.Service y opcionalmente en GUI portable.
/// </summary>
public sealed class HealthCheckServer : IDisposable
{
    private readonly HttpListener _listener;
    private readonly TdmHealthCheck _healthCheck;
    private readonly string[] _prefixes;
    private readonly CancellationTokenSource _cts = new();
    private Task? _runTask;
    private readonly ConcurrentDictionary<string, DateTimeOffset> _lastReadyCheck = new();
    private bool _disposed;

    public HealthCheckServer(TdmHealthCheck healthCheck, int port = 51821)
    {
        _healthCheck = healthCheck;
        _prefixes = new[] { $"http://localhost:{port}/", $"http://127.0.0.1:{port}/" };
        _listener = new HttpListener();
        foreach (var p in _prefixes) _listener.Prefixes.Add(p);
    }

    public void Start()
    {
        if (_runTask is not null) return;
        _listener.Start();
        _runTask = RunAsync(_cts.Token);
    }

    public async Task StopAsync(CancellationToken ct = default)
    {
        _cts.Cancel();
        _listener.Stop();
        if (_runTask is not null)
        {
            try { await _runTask.WaitAsync(TimeSpan.FromSeconds(5), ct); } catch { }
        }
        _listener.Close();
    }

    private async Task RunAsync(CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested)
            {
                HttpListenerContext? context = null;
                try
                {
                    context = await _listener.GetContextAsync().ConfigureAwait(false);
                }
                catch (HttpListenerException) when (ct.IsCancellationRequested) { break; }
                catch (ObjectDisposedException) { break; }

                if (context is null) continue;

                _ = Task.Run(() => HandleRequestAsync(context!), ct);
            }
        }
        catch { /* Best effort */ }
    }

    private async Task HandleRequestAsync(HttpListenerContext context)
    {
        var path = context.Request.Url?.AbsolutePath ?? "/";
        var method = context.Request.HttpMethod;

        if (method != "GET" && method != "HEAD")
        {
            context.Response.StatusCode = 405;
            context.Response.Close();
            return;
        }

        try
        {
            if (path.Equals("/health", StringComparison.OrdinalIgnoreCase))
            {
                await RespondAsync(context, await _healthCheck.CheckAsync(), detailed: true);
            }
            else if (path.Equals("/ready", StringComparison.OrdinalIgnoreCase))
            {
                // /ready es más estricto: requiere stores OK, último ciclo OK, circuit breakers cerrados
                var result = await _healthCheck.CheckAsync();
                var ready = result.Overall == HealthStatus.Healthy &&
                           result.Checks.All(c => c.Name != "circuit_breakers" || c.Status == HealthStatus.Healthy) &&
                           result.Checks.All(c => c.Name != "last_cycle" || c.Status == HealthStatus.Healthy);
                context.Response.StatusCode = ready ? 200 : 503;
                await WriteJsonAsync(context, new { ready, timestamp = DateTimeOffset.UtcNow, checks = result.Checks });
            }
            else if (path.Equals("/live", StringComparison.OrdinalIgnoreCase))
            {
                // /live solo indica que el proceso está vivo
                context.Response.StatusCode = 200;
                await WriteJsonAsync(context, new { alive = true, timestamp = DateTimeOffset.UtcNow });
            }
            else
            {
                context.Response.StatusCode = 404;
                context.Response.Close();
            }
        }
        catch
        {
            context.Response.StatusCode = 500;
            context.Response.Close();
        }
    }

    private async Task RespondAsync(HttpListenerContext context, HealthCheckResult result, bool detailed)
    {
        context.Response.StatusCode = result.Overall == HealthStatus.Critical ? 503 :
                                     result.Overall == HealthStatus.Degraded ? 200 : 200;

        if (detailed)
        {
            await WriteJsonAsync(context, new
            {
                status = result.Overall.ToString().ToLowerInvariant(),
                timestamp = result.Timestamp,
                uptime = result.Uptime.ToString(),
                checks = result.Checks.Select(c => new { c.Name, status = c.Status.ToString().ToLowerInvariant(), c.Detail })
            });
        }
        else
        {
            context.Response.StatusCode = 200;
            await WriteJsonAsync(context, new { status = "ok" });
        }
    }

    private static async Task WriteJsonAsync(HttpListenerContext context, object payload)
    {
        context.Response.ContentType = "application/json; charset=utf-8";
        var json = System.Text.Json.JsonSerializer.Serialize(payload, new System.Text.Json.JsonSerializerOptions
        {
            PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase
        });
        var buffer = System.Text.Encoding.UTF8.GetBytes(json);
        context.Response.ContentLength64 = buffer.Length;
        await context.Response.OutputStream.WriteAsync(buffer).ConfigureAwait(false);
        context.Response.Close();
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _cts.Cancel();
        try { _listener?.Stop(); _listener?.Close(); } catch { }
        _cts.Dispose();
    }
}