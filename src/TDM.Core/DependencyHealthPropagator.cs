using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using TDM.Models;

namespace TDM.Core;

/// <summary>
/// Health propagation engine that propagates health states through the dependency graph.
/// </summary>
public sealed class DependencyHealthPropagator
{
    private readonly Dictionary<string, ServiceNode> _nodes = new();
    private readonly Dictionary<string, List<string>> _dependencies = new(); // service -> dependencies
    private readonly Dictionary<string, List<string>> _dependents = new(); // service -> dependents

    /// <summary>
    /// Adds a service node to the graph.
    /// </summary>
    public void AddNode(string serviceName, ServiceHealth initialHealth = ServiceHealth.Unknown)
    {
        if (!_nodes.ContainsKey(serviceName))
        {
            _nodes[serviceName] = new ServiceNode(serviceName, initialHealth);
            _dependencies[serviceName] = new List<string>();
            _dependents[serviceName] = new List<string>();
        }
        else
        {
            _nodes[serviceName].Health = initialHealth;
        }
    }

    /// <summary>
    /// Adds a dependency edge: dependent -> dependency (dependent requires dependency)
    /// </summary>
    public void AddDependency(string dependent, string dependency)
    {
        if (!_nodes.ContainsKey(dependent)) AddNode(dependent);
        if (!_nodes.ContainsKey(dependency)) AddNode(dependency);

        if (!_dependencies[dependent].Contains(dependency))
            _dependencies[dependent].Add(dependency);

        if (!_dependents[dependency].Contains(dependent))
            _dependents[dependency].Add(dependent);
    }

    /// <summary>
    /// Removes a dependency edge.
    /// </summary>
    public void RemoveDependency(string dependent, string dependency)
    {
        _dependencies[dependent]?.Remove(dependency);
        _dependents[dependency]?.Remove(dependent);
    }

    /// <summary>
    /// Updates health of a service and propagates to dependents.
    /// </summary>
    public HealthPropagationResult UpdateHealth(string serviceName, ServiceHealth newHealth, string reason = "")
    {
        if (!_nodes.TryGetValue(serviceName, out var node))
        {
            return new HealthPropagationResult(false, [], $"Service {serviceName} not found");
        }

        var oldHealth = node.Health;
        node.Health = newHealth;
        node.LastUpdated = DateTimeOffset.UtcNow;
        node.LastChangeReason = reason;

        var affected = new List<ServiceHealthChange>();
        affected.Add(new ServiceHealthChange(serviceName, oldHealth, newHealth, reason));

        // Propagate to dependents
        PropagateHealth(serviceName, newHealth, affected, new HashSet<string> { serviceName });

        return new HealthPropagationResult(true, affected.ToImmutableList(), $"Health updated for {serviceName}: {oldHealth} -> {newHealth}");
    }

    private void PropagateHealth(string sourceService, ServiceHealth sourceHealth, List<ServiceHealthChange> affected, HashSet<string> visited)
    {
        if (!_dependents.TryGetValue(sourceService, out var dependents)) return;

        foreach (var dependent in dependents)
        {
            if (visited.Contains(dependent)) continue;
            visited.Add(dependent);

            if (!_nodes.TryGetValue(dependent, out var depNode)) continue;

            // Determine new health based on dependency health
            var newHealth = CalculateDependentHealth(dependent, sourceHealth);

            if (newHealth != depNode.Health)
            {
                var oldHealth = depNode.Health;
                depNode.Health = newHealth;
                depNode.LastUpdated = DateTimeOffset.UtcNow;
                depNode.LastChangeReason = $"Propagated from {sourceService} ({sourceHealth})";

                affected.Add(new ServiceHealthChange(dependent, oldHealth, newHealth, $"Propagated from {sourceService} ({sourceHealth})"));

                // Recursively propagate further
                PropagateHealth(dependent, newHealth, affected, visited);
            }
        }
    }

    private ServiceHealth CalculateDependentHealth(string dependentService, ServiceHealth dependencyHealth)
    {
        var dependencies = _dependencies.GetValueOrDefault(dependentService, new List<string>());
        if (dependencies.Count == 0) return ServiceHealth.Unknown;

        var dependencyHealths = dependencies
            .Select(d => _nodes.TryGetValue(d, out var n) ? n.Health : ServiceHealth.Unknown)
            .Where(h => h != ServiceHealth.Unknown)
            .ToList();

        if (dependencyHealths.Count == 0) return ServiceHealth.Unknown;

        // If any critical dependency is down -> critical
        if (dependencyHealths.Any(h => h == ServiceHealth.Critical)) return ServiceHealth.Critical;

        // If any error -> error
        if (dependencyHealths.Any(h => h == ServiceHealth.Error)) return ServiceHealth.Error;

        // If any warning -> warning
        if (dependencyHealths.Any(h => h == ServiceHealth.Warning)) return ServiceHealth.Warning;

        // If all healthy -> healthy
        if (dependencyHealths.All(h => h == ServiceHealth.Healthy)) return ServiceHealth.Healthy;

        return ServiceHealth.Unknown;
    }

    /// <summary>
    /// Gets current health of a service.
    /// </summary>
    public ServiceHealth GetHealth(string serviceName)
        => _nodes.TryGetValue(serviceName, out var node) ? node.Health : ServiceHealth.Unknown;

    /// <summary>
    /// Gets the full propagation path from a service to its dependents.
    /// </summary>
    public IReadOnlyList<string> GetPropagationPath(string fromService)
    {
        var path = new List<string>();
        var visited = new HashSet<string>();
        DFSPropagationPath(fromService, path, new HashSet<string>());
        return path.ToImmutableList();

        void DFSPropagationPath(string service, List<string> path, HashSet<string> visited)
        {
            if (visited.Contains(service)) return;
            visited.Add(service);
            path.Add(service);

            if (_dependents.TryGetValue(service, out var dependents))
            {
                foreach (var dep in dependents)
                {
                    if (!visited.Contains(dep))
                        DFSPropagationPath(dep, path, visited);
                }
            }
        }
    }

    /// <summary>
    /// Gets all nodes in the graph.
    /// </summary>
    public IReadOnlyDictionary<string, ServiceNode> GetNodes()
        => _nodes.ToImmutableDictionary();

    /// <summary>
    /// Gets dependencies for a service.
    /// </summary>
    public IReadOnlyList<string> GetDependencies(string service)
        => _dependencies.TryGetValue(service, out var deps) ? deps.ToImmutableList() : ImmutableList<string>.Empty;

    /// <summary>
    /// Gets dependents for a service.
    /// </summary>
    public IReadOnlyList<string> GetDependents(string service)
        => _dependents.TryGetValue(service, out var deps) ? deps.ToImmutableList() : ImmutableList<string>.Empty;
}

/// <summary>
/// Service health states.
/// </summary>
public enum ServiceHealth
{
    Unknown = 0,
    Healthy = 1,
    Warning = 2,
    Error = 3,
    Critical = 4
}

/// <summary>
/// Service node in the dependency graph.
/// </summary>
public sealed class ServiceNode
{
    public string Name { get; }
    public ServiceHealth Health { get; set; }
    public DateTimeOffset LastUpdated { get; set; }
    public string LastChangeReason { get; set; } = "";

    public ServiceNode(string name, ServiceHealth initialHealth = ServiceHealth.Unknown)
    {
        Name = name;
        Health = initialHealth;
        LastUpdated = DateTimeOffset.UtcNow;
    }
}

/// <summary>
/// Result of health propagation.
/// </summary>
public sealed record HealthPropagationResult(
    bool Success,
    IReadOnlyList<ServiceHealthChange> Changes,
    string Message);

/// <summary>
/// Health change for a service.
/// </summary>
public sealed record ServiceHealthChange(
    string ServiceName,
    ServiceHealth OldHealth,
    ServiceHealth NewHealth,
    string Reason);