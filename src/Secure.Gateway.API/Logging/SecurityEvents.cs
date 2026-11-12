namespace Secure.Gateway.API.Logging;

/// <summary>
/// Structured security events. Every event carries "SecurityEvent" so a SIEM / log query can
/// filter on it, e.g. Seq: <c>SecurityEvent is not null</c>, Elastic: <c>SecurityEvent:*</c>.
/// </summary>
public static partial class SecurityEvents
{
    [LoggerMessage(EventId = 4001, Level = LogLevel.Warning,
        Message = "SecurityEvent {SecurityEvent}: WAF rule {RuleId} ({Category}) matched in {Location} from {ClientIp} {Method} {Path} action={Action}")]
    public static partial void WafMatch(ILogger logger, string securityEvent, string ruleId, string category,
        string location, string clientIp, string method, string path, string action);

    [LoggerMessage(EventId = 4002, Level = LogLevel.Warning,
        Message = "SecurityEvent {SecurityEvent}: rate limit exceeded for {Partition} {Method} {Path}")]
    public static partial void RateLimited(ILogger logger, string securityEvent, string partition, string method, string path);

    [LoggerMessage(EventId = 4003, Level = LogLevel.Warning,
        Message = "SecurityEvent {SecurityEvent}: IP {ClientIp} rejected ({Reason})")]
    public static partial void IpRejected(ILogger logger, string securityEvent, string clientIp, string reason);

    [LoggerMessage(EventId = 4004, Level = LogLevel.Warning,
        Message = "SecurityEvent {SecurityEvent}: request rejected with {StatusCode} ({Reason}) from {ClientIp} {Method} {Path}")]
    public static partial void RequestRejected(ILogger logger, string securityEvent, int statusCode, string reason,
        string clientIp, string method, string path);

    [LoggerMessage(EventId = 4005, Level = LogLevel.Warning,
        Message = "SecurityEvent {SecurityEvent}: authentication failed via {Scheme} from {ClientIp}: {Reason}")]
    public static partial void AuthFailed(ILogger logger, string securityEvent, string scheme, string clientIp, string reason);
}
