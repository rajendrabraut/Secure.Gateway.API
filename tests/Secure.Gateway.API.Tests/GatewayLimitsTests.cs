using System.Net;
using System.Text;
using Secure.Gateway.API.Tests.Infrastructure;

namespace Secure.Gateway.API.Tests;

/// <summary>Tests that need a gateway with non-default limits (own factory per test).</summary>
public sealed class GatewayLimitsTests : IAsyncLifetime
{
    private readonly UpstreamServer _upstream = new();

    public Task InitializeAsync() => _upstream.InitializeAsync();
    public Task DisposeAsync() => _upstream.DisposeAsync();

    [Fact]
    public async Task GlobalRateLimit_Returns429_WithRetryAfter()
    {
        await using var factory = new GatewayFactory(_upstream.Url, new Dictionary<string, string?>
        {
            ["Gateway:RateLimiting:GlobalTokenLimit"] = "3",
            ["Gateway:RateLimiting:GlobalTokensPerPeriod"] = "1",
            ["Gateway:RateLimiting:GlobalReplenishmentSeconds"] = "60",
        });
        var client = factory.CreateClient();

        for (var i = 0; i < 3; i++)
        {
            Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/api/public/items")).StatusCode);
        }

        var limited = await client.GetAsync("/api/public/items");
        Assert.Equal(HttpStatusCode.TooManyRequests, limited.StatusCode);
        Assert.True(limited.Headers.RetryAfter is not null);
        Assert.Equal("application/problem+json", limited.Content.Headers.ContentType?.MediaType);

        // Health probes are never rate limited.
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/health/live")).StatusCode);
    }

    [Fact]
    public async Task StrictPolicy_LimitsAuthEndpoints()
    {
        await using var factory = new GatewayFactory(_upstream.Url, new Dictionary<string, string?>
        {
            ["Gateway:RateLimiting:StrictPermitLimit"] = "2",
        });
        var client = factory.CreateClient();

        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/api/auth/login")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/api/auth/login")).StatusCode);
        Assert.Equal(HttpStatusCode.TooManyRequests, (await client.GetAsync("/api/auth/login")).StatusCode);
    }

    [Fact]
    public async Task BodyLargerThanInspectionLimit_IsRejected()
    {
        await using var factory = new GatewayFactory(_upstream.Url, new Dictionary<string, string?>
        {
            ["Gateway:Waf:MaxBodyInspectionBytes"] = "1024",
        });
        var json = "{\"data\":\"" + new string('a', 4096) + "\"}";

        var response = await factory.CreateClient().PostAsync("/api/public/items", new StringContent(json, Encoding.UTF8, "application/json"));

        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, response.StatusCode);
    }

    [Fact]
    public async Task WafDetectMode_LogsButAllows()
    {
        await using var factory = new GatewayFactory(_upstream.Url, new Dictionary<string, string?>
        {
            ["Gateway:Waf:Mode"] = "Detect",
        });

        var response = await factory.CreateClient().GetAsync("/api/public/users?id=1' OR '1'='1");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }
}
