using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace Secure.Gateway.API.Tests.Infrastructure;

/// <summary>A real Kestrel backend on a random port that echoes what the gateway forwarded to it.</summary>
public sealed class UpstreamServer : IAsyncLifetime
{
    private WebApplication? _app;

    public string Url { get; private set; } = string.Empty;

    public async Task InitializeAsync()
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        builder.Logging.ClearProviders();

        _app = builder.Build();
        _app.MapGet("/health", () => "ok");
        _app.Map("/{**path}", (HttpContext ctx, string? path) =>
        {
            // Fingerprinting headers the gateway must strip.
            ctx.Response.Headers["X-Powered-By"] = "PHP/5.6.40";
            ctx.Response.Headers["X-AspNet-Version"] = "4.0.30319";

            return Results.Json(new
            {
                path,
                method = ctx.Request.Method,
                acceptEncoding = ctx.Request.Headers.AcceptEncoding.ToString(),
                authenticatedClient = ctx.Request.Headers["X-Authenticated-Client"].ToString(),
                apiKeyForwarded = ctx.Request.Headers.ContainsKey("X-API-Key"),
                correlationId = ctx.Request.Headers["X-Correlation-ID"].ToString(),
                items = Enumerable.Range(0, 200).Select(i => new { id = i, name = $"item-{i}", description = "Lorem ipsum dolor sit amet, consectetur adipiscing elit." }),
            });
        });

        await _app.StartAsync();
        Url = _app.Urls.First().TrimEnd('/') + "/";
    }

    public async Task DisposeAsync()
    {
        if (_app is not null) await _app.DisposeAsync();
    }
}
