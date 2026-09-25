using System.Security.Cryptography;
using System.Text;
using TDM.Core;
using TDM.Persistence;
using TDM.Notifications;

namespace TDM.Gui.Avalonia.Services;

public sealed record OperationalConfigurationSnapshot(
    string RootPath,
    string Source,
    SupportMonitoringSettings Settings,
    LocalStoreStatus StoreStatus,
    FederationConfiguration Federation,
    EmailNotificationSettings EmailSettings,
    bool EmailPasswordStored,
    string EmailSettingsPath);

public sealed class OperationalConfigurationService
{
    private static string NotificationRoot => PortableRuntime.IsEnabled
        ? LocalStateStore.DefaultRootPath
        : TdmDataPaths.MachineRootPath;

    public async Task<OperationalConfigurationSnapshot> LoadAsync(CancellationToken ct = default)
    {
        var (root, source) = await ResolveRootAsync(ct).ConfigureAwait(false);
        var settingsStore = new SupportMonitoringSettingsStore(root);
        var settings = await settingsStore.LoadAsync(ct).ConfigureAwait(false);
        var localStore = new LocalStateStore(root);
        var status = await localStore.GetStatusAsync(ct).ConfigureAwait(false);
        var federation = await new FederationStore(LocalStateStore.DefaultRootPath).LoadConfigurationAsync(ct).ConfigureAwait(false);
        var emailStore = new EmailNotificationSettingsStore(NotificationRoot);
        var emailSettings = await emailStore.LoadAsync(ct).ConfigureAwait(false);
        var emailPasswordStored = await emailStore.HasStoredPasswordAsync(ct).ConfigureAwait(false);
        return new OperationalConfigurationSnapshot(root, source, settings, status, federation, emailSettings, emailPasswordStored, emailStore.SettingsPath);
    }

    public async Task SaveSettingsAsync(SupportMonitoringSettings settings, CancellationToken ct = default)
    {
        var (root, _) = await ResolveRootAsync(ct).ConfigureAwait(false);
        await new SupportMonitoringSettingsStore(root).SaveAsync(settings, ct).ConfigureAwait(false);
    }


    public async Task SaveEmailSettingsAsync(
        EmailNotificationSettings settings,
        string? newPassword,
        bool clearStoredPassword,
        CancellationToken ct = default)
    {
        var store = new EmailNotificationSettingsStore(NotificationRoot);
        await store.SaveAsync(settings, newPassword, clearStoredPassword, ct).ConfigureAwait(false);
    }

    public Task ClearEmailPasswordAsync(CancellationToken ct = default)
        => new EmailNotificationSettingsStore(NotificationRoot).ClearStoredPasswordAsync(ct);

    public async Task<EmailDeliveryResult> SendTestEmailAsync(CancellationToken ct = default)
    {
        var sink = new SmtpEmailNotificationSink(NotificationRoot);
        return await sink.SendTestAsync(ct: ct).ConfigureAwait(false);
    }

    public async Task<FederationConfiguration> SaveFederationAsync(string editorText, CancellationToken ct = default)
    {
        var (root, _) = await ResolveRootAsync(ct).ConfigureAwait(false);
        var store = new FederationStore(LocalStateStore.DefaultRootPath);
        var current = await store.LoadConfigurationAsync(ct).ConfigureAwait(false);
        var nodes = ParseNodes(editorText);
        var config = new FederationConfiguration(
            string.IsNullOrWhiteSpace(current.CoordinatorName) ? Environment.MachineName : current.CoordinatorName,
            nodes);
        await store.SaveConfigurationAsync(config, ct).ConfigureAwait(false);
        return config;
    }

    public static string FormatFederation(FederationConfiguration config)
        => string.Join(Environment.NewLine, config.Nodes.Select(n =>
            $"{n.DisplayName} | {n.Group} | {n.Role} | {n.ObservabilityRoot}"));

    public static string LocalNodeLine(string rootPath)
        => $"{Environment.MachineName} | Standalone | Servidor | {rootPath}";

    public static IReadOnlyList<FederationNode> ParseNodes(string text)
    {
        var nodes = new List<FederationNode>();
        foreach (var raw in (text ?? string.Empty).Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var parts = raw.Split('|', 4, StringSplitOptions.TrimEntries);
            if (parts.Length < 4 || string.IsNullOrWhiteSpace(parts[0]) || string.IsNullOrWhiteSpace(parts[3]))
                continue;
            var name = parts[0].Trim();
            var group = string.IsNullOrWhiteSpace(parts[1]) ? "Standalone" : parts[1].Trim();
            var role = string.IsNullOrWhiteSpace(parts[2]) ? "Servidor" : parts[2].Trim();
            var path = parts[3].Trim();
            nodes.Add(new FederationNode(NodeId(name, group), name, group, role, path, true));
        }

        return nodes
            .GroupBy(n => n.Id, StringComparer.OrdinalIgnoreCase)
            .Select(g => g.Last())
            .ToList();
    }

    private static string NodeId(string name, string group)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes($"{group}|{name}".ToUpperInvariant()));
        return Convert.ToHexString(hash)[..12];
    }

    private static async Task<(string Root, string Source)> ResolveRootAsync(CancellationToken ct)
    {
        if (PortableRuntime.IsEnabled)
            return (LocalStateStore.DefaultRootPath, "TDM Portable · Configuración local");

        var machine = TdmDataPaths.MachineRootPath;
        try
        {
            var heartbeat = await new ServiceHeartbeatStore(machine).ReadAsync(ct).ConfigureAwait(false);
            if (ServiceHeartbeatStore.IsFresh(heartbeat) &&
                !string.Equals(heartbeat?.Status, "STOPPED", StringComparison.OrdinalIgnoreCase))
                return (machine, $"TDM.Service · {heartbeat?.Status}");
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }

        return (LocalStateStore.DefaultRootPath, "Monitor GUI/local");
    }
}
