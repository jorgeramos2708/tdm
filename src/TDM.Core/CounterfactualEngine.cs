using System;
using System.Collections.Generic;
using System.Linq;

namespace TDM.Core;

/// <summary>
/// Counterfactual Engine - Basic what-if simulator for operational decisions.
/// Simulates the impact of actions (restart service, kill process, etc.) using
/// the dependency graph and health propagation model.
/// </summary>
public static class CounterfactualEngine
{
    public sealed record Action(
        string Id,
        ActionType Type,
        string Target,
        string? Parameter = null,
        DateTimeOffset? ScheduledAt = null);

    public enum ActionType
    {
        RestartService,
        StopService,
        StartService,
        KillProcess,
        RestartProcess,
        ClearCache,
        ResetConnection,
        RebootHost
    }

    public sealed record SimulationResult(
        string ActionId,
        ActionType ActionType,
        string Target,
        SimulatedImpact OverallImpact,
        IReadOnlyList<ServiceImpact> AffectedServices,
        IReadOnlyList<string> Warnings,
        bool IsSafe,
        string Summary);

    public enum SimulatedImpact
    {
        None,
        Low,
        Medium,
        High,
        Critical
    }

    public sealed record ServiceImpact(
        string ServiceName,
        ServiceHealth CurrentHealth,
        ServiceHealth SimulatedHealth,
        ImpactReason Reason,
        TimeSpan EstimatedRecovery);

    public enum ImpactReason
    {
        DirectAction,
        DependencyDownstream,
        DependencyUpstream,
        SharedResource,
        CascadeFailure
    }

    /// <summary>
    /// Simulates the impact of a proposed action using the current system state.
    /// </summary>
    public static SimulationResult Simulate(
        Action action,
        DependencyHealthPropagator propagator,
        IReadOnlyDictionary<string, ServiceHealth>? baselineHealth = null)
    {
        var warnings = new List<string>();
        var affectedServices = new List<ServiceImpact>();

        var nodes = propagator.GetNodes();
        if (!nodes.TryGetValue(action.Target, out var targetNode))
        {
            warnings.Add($"Target '{action.Target}' not found in service graph");
            return new SimulationResult(
                action.Id,
                action.Type,
                action.Target,
                SimulatedImpact.None,
                affectedServices,
                warnings,
                false,
                $"Cannot simulate: target service '{action.Target}' not in dependency graph");
        }

        // Get current health from propagator
        var currentHealth = new Dictionary<string, ServiceHealth>();
        foreach (var node in nodes)
        {
            currentHealth[node.Key] = propagator.GetHealth(node.Key);
        }

        var simulatedHealth = new Dictionary<string, ServiceHealth>(currentHealth);
        var visited = new HashSet<string>();

        // Apply the direct action effect
        var directImpact = ApplyDirectAction(action.Type, targetNode, simulatedHealth, visited);
        affectedServices.Add(directImpact);

        // Propagate through dependencies using propagator's internal graph
        var propagatedImpacts = PropagateImpact(
            targetNode.Name,
            action.Type,
            propagator,
            simulatedHealth,
            visited);
        affectedServices.AddRange(propagatedImpacts);

        // Calculate overall impact
        var overallImpact = CalculateOverallImpact(affectedServices);
        var isSafe = overallImpact <= SimulatedImpact.Medium && !warnings.Any();

        var summary = BuildSummary(action, overallImpact, affectedServices.Count, warnings.Count);

        return new SimulationResult(
            action.Id,
            action.Type,
            action.Target,
            overallImpact,
            affectedServices,
            warnings,
            isSafe,
            summary);
    }

    /// <summary>
    /// Simulates multiple actions in sequence (what-if scenario planning).
    /// </summary>
    public static IReadOnlyList<SimulationResult> SimulateScenario(
        IEnumerable<Action> actions,
        DependencyHealthPropagator propagator)
    {
        var results = new List<SimulationResult>();

        foreach (var action in actions)
        {
            var result = Simulate(action, propagator);
            results.Add(result);

            // Update propagator state for next action (apply the simulated changes)
            foreach (var impact in result.AffectedServices)
            {
                propagator.UpdateHealth(impact.ServiceName, impact.SimulatedHealth, $"Simulated: {action.Type}");
            }
        }

        return results;
    }

    /// <summary>
    /// Finds safe remediation actions for a degraded service.
    /// </summary>
    public static IReadOnlyList<SimulationResult> FindRemediationActions(
        string degradedService,
        DependencyHealthPropagator propagator,
        int maxResults = 5)
    {
        var nodes = propagator.GetNodes();
        if (!nodes.TryGetValue(degradedService, out var node))
            return Array.Empty<SimulationResult>();

        var currentHealth = nodes.ToDictionary(k => k.Key, k => propagator.GetHealth(k.Key));
        var health = currentHealth.GetValueOrDefault(degradedService, ServiceHealth.Unknown);

        var candidates = new List<Action>();

        // Direct remediation actions
        if (health != ServiceHealth.Healthy && health != ServiceHealth.Unknown)
        {
            candidates.Add(new Action(Guid.NewGuid().ToString("N")[..8], ActionType.RestartService, degradedService));
            candidates.Add(new Action(Guid.NewGuid().ToString("N")[..8], ActionType.StopService, degradedService));
            candidates.Add(new Action(Guid.NewGuid().ToString("N")[..8], ActionType.StartService, degradedService));
        }

        // Dependency-based actions (restart unhealthy dependencies)
        var dependencies = propagator.GetDependencies(degradedService);
        foreach (var dep in dependencies)
        {
            var depHealth = currentHealth.GetValueOrDefault(dep, ServiceHealth.Unknown);
            if (depHealth != ServiceHealth.Healthy && depHealth != ServiceHealth.Unknown)
            {
                candidates.Add(new Action(Guid.NewGuid().ToString("N")[..8], ActionType.RestartService, dep));
            }
        }

        // Dependent services that might be causing load (if they're unhealthy)
        var dependents = propagator.GetDependents(degradedService);
        foreach (var dependent in dependents)
        {
            var depHealth = currentHealth.GetValueOrDefault(dependent, ServiceHealth.Unknown);
            if (depHealth == ServiceHealth.Error || depHealth == ServiceHealth.Critical)
            {
                candidates.Add(new Action(Guid.NewGuid().ToString("N")[..8], ActionType.RestartService, dependent));
            }
        }

        var results = candidates
            .Select(a => Simulate(a, propagator))
            .Where(r => r.IsSafe)
            .OrderBy(r => r.OverallImpact)
            .Take(maxResults)
            .ToList();

        return results;
    }

    private static ServiceImpact ApplyDirectAction(
        ActionType actionType,
        ServiceNode targetNode,
        Dictionary<string, ServiceHealth> simulatedHealth,
        HashSet<string> visited)
    {
        var current = simulatedHealth.GetValueOrDefault(targetNode.Name, ServiceHealth.Unknown);
        var simulated = current;

        switch (actionType)
        {
            case ActionType.RestartService:
            case ActionType.StopService:
                simulated = ServiceHealth.Critical; // During restart/stop, service is effectively down
                break;
            case ActionType.StartService:
                simulated = ServiceHealth.Healthy;
                break;
            case ActionType.KillProcess:
            case ActionType.RestartProcess:
                simulated = ServiceHealth.Error;
                break;
            case ActionType.ClearCache:
            case ActionType.ResetConnection:
                simulated = current == ServiceHealth.Warning || current == ServiceHealth.Error
                    ? ServiceHealth.Healthy
                    : current;
                break;
            case ActionType.RebootHost:
                simulated = ServiceHealth.Critical;
                break;
        }

        simulatedHealth[targetNode.Name] = simulated;
        visited.Add(targetNode.Name);

        var recovery = EstimateRecovery(actionType);

        return new ServiceImpact(
            targetNode.Name,
            current,
            simulated,
            ImpactReason.DirectAction,
            recovery);
    }

    private static List<ServiceImpact> PropagateImpact(
        string sourceService,
        ActionType actionType,
        DependencyHealthPropagator propagator,
        Dictionary<string, ServiceHealth> simulatedHealth,
        HashSet<string> visited)
    {
        var impacts = new List<ServiceImpact>();

        // Downstream dependents (services that depend on source)
        var downstream = propagator.GetDependents(sourceService);

        foreach (var dependentName in downstream)
        {
            if (visited.Contains(dependentName)) continue;
            if (!propagator.GetNodes().TryGetValue(dependentName, out var dependentNode)) continue;

            var current = simulatedHealth.GetValueOrDefault(dependentName, ServiceHealth.Unknown);
            var simulated = current;

            // If source is stopped/restarted/rebooted, dependents degrade
            if (actionType == ActionType.RestartService
                || actionType == ActionType.StopService
                || actionType == ActionType.RebootHost)
            {
                if (current == ServiceHealth.Healthy)
                    simulated = ServiceHealth.Warning;
                else if (current == ServiceHealth.Warning)
                    simulated = ServiceHealth.Error;
                else if (current == ServiceHealth.Error)
                    simulated = ServiceHealth.Critical;
            }
            // If starting a service, dependents might improve
            else if (actionType == ActionType.StartService)
            {
                if (current == ServiceHealth.Error || current == ServiceHealth.Critical)
                    simulated = ServiceHealth.Warning;
                else if (current == ServiceHealth.Warning)
                    simulated = ServiceHealth.Healthy;
            }

            if (simulated != current)
            {
                simulatedHealth[dependentName] = simulated;
                visited.Add(dependentName);

                impacts.Add(new ServiceImpact(
                    dependentName,
                    current,
                    simulated,
                    ImpactReason.DependencyDownstream,
                    EstimateRecovery(actionType)));

                // Recursive propagation
                impacts.AddRange(PropagateImpact(dependentName, actionType, propagator, simulatedHealth, visited));
            }
        }

        // Upstream dependencies (services source depends on) - for start actions
        if (actionType == ActionType.StartService)
        {
            var upstream = propagator.GetDependencies(sourceService);
            foreach (var depName in upstream)
            {
                if (visited.Contains(depName)) continue;
                if (!propagator.GetNodes().TryGetValue(depName, out _)) continue;

                var current = simulatedHealth.GetValueOrDefault(depName, ServiceHealth.Unknown);
                // Starting a service requires healthy dependencies
                if (current != ServiceHealth.Healthy && current != ServiceHealth.Unknown)
                {
                    visited.Add(depName);
                    impacts.Add(new ServiceImpact(
                        depName,
                        current,
                        current, // No change, just a requirement
                        ImpactReason.DependencyUpstream,
                        TimeSpan.FromMinutes(5)));
                }
            }
        }

        return impacts;
    }

    private static SimulatedImpact CalculateOverallImpact(List<ServiceImpact> impacts)
    {
        if (!impacts.Any()) return SimulatedImpact.None;

        var maxSeverity = impacts.Max(i =>
        {
            var delta = HealthDelta(i.CurrentHealth, i.SimulatedHealth);
            return delta switch
            {
                >= 3 => SimulatedImpact.Critical,
                2 => SimulatedImpact.High,
                1 => SimulatedImpact.Medium,
                _ => SimulatedImpact.Low
            };
        });

        var criticalCount = impacts.Count(i => HealthDelta(i.CurrentHealth, i.SimulatedHealth) >= 3);
        var highCount = impacts.Count(i => HealthDelta(i.CurrentHealth, i.SimulatedHealth) == 2);

        if (criticalCount > 0) return SimulatedImpact.Critical;
        if (highCount > 1) return SimulatedImpact.High;
        if (highCount == 1 || impacts.Count > 3) return SimulatedImpact.Medium;
        return SimulatedImpact.Low;
    }

    private static int HealthDelta(ServiceHealth from, ServiceHealth to)
    {
        var order = new Dictionary<ServiceHealth, int>
        {
            [ServiceHealth.Healthy] = 0,
            [ServiceHealth.Warning] = 1,
            [ServiceHealth.Error] = 2,
            [ServiceHealth.Critical] = 3,
            [ServiceHealth.Unknown] = 0
        };

        var fromVal = order.GetValueOrDefault(from, 0);
        var toVal = order.GetValueOrDefault(to, 0);
        return Math.Max(0, toVal - fromVal);
    }

    private static TimeSpan EstimateRecovery(ActionType actionType)
    {
        return actionType switch
        {
            ActionType.RestartService => TimeSpan.FromMinutes(2),
            ActionType.StopService => TimeSpan.FromMinutes(1),
            ActionType.StartService => TimeSpan.FromMinutes(3),
            ActionType.KillProcess => TimeSpan.FromMinutes(1),
            ActionType.RestartProcess => TimeSpan.FromMinutes(2),
            ActionType.ClearCache => TimeSpan.FromSeconds(30),
            ActionType.ResetConnection => TimeSpan.FromSeconds(10),
            ActionType.RebootHost => TimeSpan.FromMinutes(10),
            _ => TimeSpan.FromMinutes(5)
        };
    }

    private static string BuildSummary(Action action, SimulatedImpact impact, int affectedCount, int warningCount)
    {
        var actionName = action.Type switch
        {
            ActionType.RestartService => "reiniciar",
            ActionType.StopService => "detener",
            ActionType.StartService => "iniciar",
            ActionType.KillProcess => "matar proceso",
            ActionType.RestartProcess => "reiniciar proceso",
            ActionType.ClearCache => "limpiar caché",
            ActionType.ResetConnection => "resetear conexión",
            ActionType.RebootHost => "reiniciar host",
            _ => action.Type.ToString()
        };

        var impactText = impact switch
        {
            SimulatedImpact.None => "sin impacto",
            SimulatedImpact.Low => "impacto bajo",
            SimulatedImpact.Medium => "impacto medio",
            SimulatedImpact.High => "impacto alto",
            SimulatedImpact.Critical => "impacto CRÍTICO",
            _ => "desconocido"
        };

        return $"Simulación: {actionName} '{action.Target}' → {impactText} ({affectedCount} servicios afectados" +
               (warningCount > 0 ? $", {warningCount} advertencias" : "") + ")";
    }
}