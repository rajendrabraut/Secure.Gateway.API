using System.Text.Json;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Secure.Gateway.API.Compression;
using Secure.Gateway.API.Logging;
using Secure.Gateway.API.Options;
using Secure.Gateway.API.RateLimiting;
using Secure.Gateway.API.Security;
using Secure.Gateway.API.Security.Authentication;
using Secure.Gateway.API.Security.Waf;
using Serilog;
using Yarp.ReverseProxy.Transforms;

// Utility: `dotnet run -- hash-key <api-key>` prints the SHA-256 hash to put in Authentication:ApiKey:Clients.
if (args is ["hash-key", var keyToHash])
{
    Console.WriteLine(ApiKeyAuthenticationHandler.HashKey(keyToHash));
    return;
}

// Startup logger (replaced by the fully configured Serilog pipeline once the host is built).
Log.Logger = new LoggerConfiguration().WriteTo.Console().CreateLogger();

try
{
    var builder = WebApplication.CreateBuilder(args);

    // ---------- Kestrel hardening (limits come from the "Kestrel:Limits" config section) ----------
    builder.WebHost.ConfigureKestrel(k => k.AddServerHeader = false);

    // ---------- Logging & telemetry ----------
    builder.AddGatewayLogging();
    builder.AddGatewayTelemetry();

    // ---------- Options ----------
    builder.Services.AddOptions<GatewayOptions>()
        .Bind(builder.Configuration.GetSection(GatewayOptions.SectionName))
        .ValidateOnStart();

    var gateway = builder.Configuration.GetSection(GatewayOptions.SectionName).Get<GatewayOptions>() ?? new GatewayOptions();
    var apiKeyHeader = builder.Configuration["Authentication:ApiKey:HeaderName"] ?? "X-API-Key";

    // ---------- Forwarded headers: only trust known proxies (prevents X-Forwarded-For IP spoofing) ----------
    builder.Services.Configure<ForwardedHeadersOptions>(o =>
    {
        o.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto | ForwardedHeaders.XForwardedHost;
        o.ForwardLimit = gateway.ForwardedHeaders.ForwardLimit;
        foreach (var entry in gateway.ForwardedHeaders.KnownProxies)
        {
            o.KnownIPNetworks.Add(IpFilterMiddleware.ParseNetwork(entry));
        }
    });

    // ---------- Core services ----------
    builder.Services.AddProblemDetails(o => o.CustomizeProblemDetails = ctx =>
    {
        ctx.ProblemDetails.Extensions["correlationId"] = CorrelationIdMiddleware.Get(ctx.HttpContext);
        ctx.ProblemDetails.Extensions.Remove("exception"); // never leak stack traces
    });
    builder.Services.AddGatewayCompression(builder.Configuration);
    builder.Services.AddGatewayRateLimiting();
    builder.Services.AddGatewayAuthentication(builder.Configuration, builder.Environment);
    builder.Services.AddHealthChecks();

    builder.Services.AddCors(o => o.AddDefaultPolicy(p =>
    {
        var cors = gateway.Cors;
        if (cors.AllowedOrigins.Length == 0) return; // no origins configured -> cross-origin requests get no CORS grant
        p.WithOrigins(cors.AllowedOrigins)
            .WithMethods(cors.AllowedMethods)
            .WithHeaders(cors.AllowedHeaders)
            .WithExposedHeaders(cors.ExposedHeaders)
            .SetPreflightMaxAge(TimeSpan.FromSeconds(cors.PreflightMaxAgeSeconds));
        if (cors.AllowCredentials) p.AllowCredentials();
    }));

    // ---------- Reverse proxy (YARP) ----------
    builder.Services.AddReverseProxy()
        .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
        .AddTransforms(ctx => ctx.AddRequestTransform(t =>
        {
            var headers = t.ProxyRequest.Headers;

            // Gateway owns compression (zstd/br/gzip) -> ask upstream for identity encoding.
            if (gateway.Compression.Enabled && gateway.Compression.StripUpstreamAcceptEncoding)
                headers.Remove("Accept-Encoding");

            // Anti-spoofing: callers must never be able to inject identity headers.
            foreach (var name in t.HttpContext.Request.Headers.Keys)
            {
                if (name.StartsWith("X-Authenticated-", StringComparison.OrdinalIgnoreCase)) headers.Remove(name);
            }

            // Do not leak API keys to backends; pass the resolved identity instead.
            headers.Remove(apiKeyHeader);
            var user = t.HttpContext.User;
            if (user.Identity?.IsAuthenticated == true)
            {
                var clientId = user.FindFirst("client_id")?.Value ?? user.FindFirst("sub")?.Value;
                if (clientId is not null) headers.TryAddWithoutValidation("X-Authenticated-Client", clientId);
            }

            headers.Remove(CorrelationIdMiddleware.HeaderName);
            headers.TryAddWithoutValidation(CorrelationIdMiddleware.HeaderName, CorrelationIdMiddleware.Get(t.HttpContext));
            return ValueTask.CompletedTask;
        }));

    var app = builder.Build();

    // ---------- Pipeline (order matters) ----------
    app.UseForwardedHeaders();                         // real client IP before anything uses it
    app.UseMiddleware<CorrelationIdMiddleware>();      // correlation id on every log line + response
    app.UseExceptionHandler();                         // RFC 9457 problem+json, no stack traces
    app.UseGatewayRequestLogging();                    // one structured event per request
    app.UseMiddleware<SecurityHeadersMiddleware>();    // OWASP headers, strip Server/X-Powered-By
    if (gateway.Compression.Enabled) app.UseResponseCompression(); // zstd > br > gzip
    app.UseMiddleware<IpFilterMiddleware>();           // allow / deny lists
    app.UseMiddleware<RequestValidationMiddleware>();  // methods, sizes, content types
    app.UseRouting();
    app.UseCors();
    app.UseAuthentication();
    app.UseRateLimiter();                              // after auth so limits can be per client
    app.UseMiddleware<WafMiddleware>();                // SQLi / XSS / traversal / RCE signatures
    app.UseAuthorization();

    app.MapHealthChecks("/health/live", new HealthCheckOptions { Predicate = _ => false, ResponseWriter = WriteHealth })
        .AllowAnonymous().DisableRateLimiting();
    app.MapHealthChecks("/health/ready", new HealthCheckOptions { ResponseWriter = WriteHealth })
        .AllowAnonymous().DisableRateLimiting();

    app.MapReverseProxy();

    app.Run();
}
catch (Exception ex) when (ex is not HostAbortedException)
{
    Log.Fatal(ex, "Gateway terminated unexpectedly");
    throw;
}
finally
{
    Log.CloseAndFlush();
}

static Task WriteHealth(HttpContext context, HealthReport report)
{
    context.Response.ContentType = "application/json";
    context.Response.Headers.CacheControl = "no-store";
    return context.Response.WriteAsync(JsonSerializer.Serialize(new
    {
        status = report.Status.ToString(),
        totalDurationMs = report.TotalDuration.TotalMilliseconds,
        checks = report.Entries.Select(e => new { name = e.Key, status = e.Value.Status.ToString() }),
    }));
}

/// <summary>Exposed for WebApplicationFactory in integration tests.</summary>
public partial class Program;
