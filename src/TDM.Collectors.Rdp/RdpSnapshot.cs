namespace TDM.Collectors.Rdp;

public sealed record RdpSessionInfo(
    int SessionId,
    string StationName,
    string State);

public sealed record RdpSnapshot(
    string TermServiceStatus,
    int ConfiguredPort,
    bool PortListening,
    IReadOnlyList<RdpSessionInfo> Sessions,
    string? CertificateThumbprint,
    bool CertificateFound,
    DateTimeOffset? CertificateNotAfter,
    string? CertificateSubject)
{
    public bool TermServiceEvaluated { get; init; } = true;
    public bool PortConfigurationEvaluated { get; init; } = true;
    public bool ListenerEvaluated { get; init; } = true;
    public bool SessionsEvaluated { get; init; } = true;
    public bool CertificateConfigurationEvaluated { get; init; } = true;
    public bool CertificateStoreEvaluated { get; init; } = true;
    public IReadOnlyList<string> CoverageLimitations { get; init; } = [];
    public bool CoreStateComplete => TermServiceEvaluated && PortConfigurationEvaluated && ListenerEvaluated;
}
