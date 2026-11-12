using System.Globalization;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Options;
using Secure.Gateway.API.Logging;
using Secure.Gateway.API.Options;
using Secure.Gateway.API.Security;

namespace Secure.Gateway.API.RateLimiting;

/// <summary>
/// Layered rate limiting (built-in System.Threading.RateLimiting):
///  1. Global limiter on every request: per-client token bucket (burst control) chained with a
///     per-client concurrency limiter (slow-request / connection-hogging protection).
///  2. Named route policies for YARP routes ("RateLimiterPolicy" in route config):
///     "standard" - sliding window per client, "strict" - fixed window for login/OTP-style endpoints.
/// Clients are partitioned by authenticated identity, falling back to IP address.
/// Limits are in-memory per instance; for a multi-instance fleet put a shared limiter (e.g. Redis)
/// or the load balancer's limiter in front as well.
/// </summary>
public static class RateLimitingExtensions
{
    // "default" / "disable" are reserved by YARP.
    public const string DefaultPolicy = "standard";
    public const string StrictPolicy = "strict";

    public static IServiceCollection AddGatewayRateLimiting(this IServiceCollection services)
    {
        services.AddRateLimiter(o =>
        {
            o.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

            o.GlobalLimiter = PartitionedRateLimiter.CreateChained(
                PartitionedRateLimiter.Create<HttpContext, string>(ctx =>
                {
                    var s = Settings(ctx);
                    if (!s.Enabled || IsHealthCheck(ctx)) return RateLimitPartition.GetNoLimiter("none");
                    return RateLimitPartition.GetTokenBucketLimiter(PartitionKey(ctx), _ => new TokenBucketRateLimiterOptions
                    {
                        TokenLimit = s.GlobalTokenLimit,
                        TokensPerPeriod = s.GlobalTokensPerPeriod,
                        ReplenishmentPeriod = TimeSpan.FromSeconds(s.GlobalReplenishmentSeconds),
                        QueueLimit = 0,
                        AutoReplenishment = true,
                    });
                }),
                PartitionedRateLimiter.Create<HttpContext, string>(ctx =>
                {
                    var s = Settings(ctx);
                    if (!s.Enabled || IsHealthCheck(ctx)) return RateLimitPartition.GetNoLimiter("none");
                    return RateLimitPartition.GetConcurrencyLimiter(PartitionKey(ctx), _ => new ConcurrencyLimiterOptions
                    {
                        PermitLimit = s.ConcurrencyLimitPerClient,
                        QueueLimit = 0,
                    });
                }));

            o.AddPolicy(DefaultPolicy, ctx =>
            {
                var s = Settings(ctx);
                if (!s.Enabled) return RateLimitPartition.GetNoLimiter("none");
                return RateLimitPartition.GetSlidingWindowLimiter(PartitionKey(ctx), _ => new SlidingWindowRateLimiterOptions
                {
                    PermitLimit = s.DefaultPermitLimit,
                    Window = TimeSpan.FromSeconds(s.DefaultWindowSeconds),
                    SegmentsPerWindow = Math.Max(1, s.DefaultSegmentsPerWindow),
                    QueueLimit = 0,
                    AutoReplenishment = true,
                });
            });

            o.AddPolicy(StrictPolicy, ctx =>
            {
                var s = Settings(ctx);
                if (!s.Enabled) return RateLimitPartition.GetNoLimiter("none");
                // Strict limits are always per IP: credential-stuffing tools rotate identities, not IPs, as fast.
                return RateLimitPartition.GetFixedWindowLimiter("ip:" + IpOf(ctx), _ => new FixedWindowRateLimiterOptions
                {
                    PermitLimit = s.StrictPermitLimit,
                    Window = TimeSpan.FromSeconds(s.StrictWindowSeconds),
                    QueueLimit = 0,
                    AutoReplenishment = true,
                });
            });

            o.OnRejected = async (ctx, ct) =>
            {
                var http = ctx.HttpContext;
                // Chained limiters do not always surface lease metadata; fall back to the global replenishment period.
                var retrySeconds = ctx.Lease.TryGetMetadata(MetadataName.RetryAfter, out var retryAfter)
                    ? (int)Math.Ceiling(retryAfter.TotalSeconds)
                    : Settings(http).GlobalReplenishmentSeconds;
                http.Response.Headers.RetryAfter = Math.Max(1, retrySeconds).ToString(CultureInfo.InvariantCulture);

                var logger = http.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("Secure.Gateway.RateLimiting");
                SecurityEvents.RateLimited(logger, "RateLimited", PartitionKey(http), http.Request.Method, LogSanitizer.Clean(http.Request.Path.Value));

                await GatewayProblem.WriteAsync(http, StatusCodes.Status429TooManyRequests, "Too many requests", "Rate limit exceeded. Retry later.");
            };
        });

        return services;
    }

    private static RateLimitSettings Settings(HttpContext ctx) =>
        ctx.RequestServices.GetRequiredService<IOptionsMonitor<GatewayOptions>>().CurrentValue.RateLimiting;

    private static bool IsHealthCheck(HttpContext ctx) => ctx.Request.Path.StartsWithSegments("/health");

    internal static string PartitionKey(HttpContext ctx)
    {
        var user = ctx.User;
        if (user.Identity?.IsAuthenticated == true)
        {
            var id = user.FindFirst("client_id")?.Value ?? user.FindFirst("sub")?.Value ?? user.Identity.Name;
            if (!string.IsNullOrEmpty(id)) return "client:" + id;
        }
        return "ip:" + IpOf(ctx);
    }

    private static string IpOf(HttpContext ctx)
    {
        var ip = ctx.Connection.RemoteIpAddress;
        if (ip is null) return "unknown";
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();

        // Group IPv6 clients by /64: a single host typically owns a whole /64 and can rotate within it.
        if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
        {
            var bytes = ip.GetAddressBytes();
            Array.Clear(bytes, 8, 8);
            return new System.Net.IPAddress(bytes) + "/64";
        }

        return ip.ToString();
    }
}
