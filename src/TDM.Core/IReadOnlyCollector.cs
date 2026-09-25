using TDM.Models;

namespace TDM.Core;

public interface IReadOnlyCollector
{
    string Nombre { get; }
    Task<CollectorResult> CollectAsync(DiagnosticContext context, CancellationToken cancellationToken = default);
}
