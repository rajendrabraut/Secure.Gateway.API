using System.Net;
using Microsoft.Extensions.Options;
using Secure.Gateway.API.Logging;
using Secure.Gateway.API.Options;

namespace Secure.Gateway.API.Security;

/// <summary>IP / CIDR allow- and deny-lists (IPv4 + IPv6). Deny always wins.</summary>
public sealed class IpFilterMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<IpFilterMiddleware> _logger;
    private volatile IPNetwork[] _allow;
    private volatile IPNetwork[] _deny;

    public IpFilterMiddleware(RequestDelegate next, IOptionsMonitor<GatewayOptions> options, ILogger<IpFilterMiddleware> logger)
    {
        _next = next;
        _logger = logger;
        (_allow, _deny) = Parse(options.CurrentValue.IpFilter);
        options.OnChange(o => (_allow, _deny) = Parse(o.IpFilter));
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var allow = _allow;
        var deny = _deny;
        if (allow.Length == 0 && deny.Length == 0)
        {
            await _next(context);
            return;
        }

        var ip = context.Connection.RemoteIpAddress;
        if (ip is { IsIPv4MappedToIPv6: true }) ip = ip.MapToIPv4();

        string? reason = ip is null ? "unknown client address"
            : deny.Any(n => n.Contains(ip)) ? "deny-list"
            : allow.Length > 0 && !allow.Any(n => n.Contains(ip)) ? "not in allow-list"
            : null;

        if (reason is not null)
        {
            SecurityEvents.IpRejected(_logger, "IpFilter", ip?.ToString() ?? "unknown", reason);
            await GatewayProblem.WriteAsync(context, StatusCodes.Status403Forbidden, "Forbidden");
            return;
        }

        await _next(context);
    }

    internal static (IPNetwork[] Allow, IPNetwork[] Deny) Parse(IpFilterSettings s) => (ToNetworks(s.Allow), ToNetworks(s.Deny));

    internal static IPNetwork[] ToNetworks(IEnumerable<string> entries) =>
        entries.Where(e => !string.IsNullOrWhiteSpace(e)).Select(ParseNetwork).ToArray();

    internal static IPNetwork ParseNetwork(string entry)
    {
        entry = entry.Trim();
        if (entry.Contains('/')) return IPNetwork.Parse(entry);
        var address = IPAddress.Parse(entry);
        return new IPNetwork(address, address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 32 : 128);
    }
}
