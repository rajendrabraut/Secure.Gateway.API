using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Secure.Gateway.API.Security.Authentication;

namespace Secure.Gateway.API.Tests.Infrastructure;

public sealed class GatewayFactory(string upstreamUrl, IReadOnlyDictionary<string, string?>? overrides = null)
    : WebApplicationFactory<Program>
{
    public const string ApiKey = "test-api-key-0123456789abcdef";
    public const string ApiClientId = "integration-tests";

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");
        builder.UseSetting("ReverseProxy:Clusters:backend:Destinations:primary:Address", upstreamUrl);
        builder.UseSetting("Serilog:MinimumLevel:Default", "Warning");
        builder.UseSetting("Serilog:WriteTo:1:Args:path", Path.Combine(Path.GetTempPath(), "secure-gateway-tests", "gateway-.json"));
        builder.UseSetting("Authentication:ApiKey:Clients:0:ClientId", ApiClientId);
        builder.UseSetting("Authentication:ApiKey:Clients:0:KeyHash", ApiKeyAuthenticationHandler.HashKey(ApiKey));

        foreach (var (key, value) in overrides ?? new Dictionary<string, string?>())
        {
            builder.UseSetting(key, value);
        }
    }
}

/// <summary>One upstream + one default gateway shared by most tests.</summary>
public sealed class GatewayFixture : IAsyncLifetime
{
    public UpstreamServer Upstream { get; } = new();
    public GatewayFactory Factory { get; private set; } = null!;

    public async Task InitializeAsync()
    {
        await Upstream.InitializeAsync();
        Factory = new GatewayFactory(Upstream.Url);
    }

    public async Task DisposeAsync()
    {
        await Factory.DisposeAsync();
        await Upstream.DisposeAsync();
    }
}
