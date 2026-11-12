using OpenTelemetry.Metrics;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;
using Serilog;
using Serilog.Events;
using Yarp.ReverseProxy.Model;

namespace Secure.Gateway.API.Logging;

public static class LoggingExtensions
{
    /// <summary>
    /// Serilog, configured entirely from the "Serilog" config section (sinks, levels, enrichers),
    /// so ops can switch to Seq / Elastic / OTLP without a rebuild.
    /// </summary>
    public static WebApplicationBuilder AddGatewayLogging(this WebApplicationBuilder builder)
    {
        builder.Services.AddSerilog((services, lc) => lc
            .ReadFrom.Configuration(builder.Configuration)
            .ReadFrom.Services(services)
            .Enrich.FromLogContext()
            .Enrich.WithMachineName()
            .Enrich.WithEnvironmentName()
            .Enrich.WithThreadId()
            .Enrich.WithProperty("Application", builder.Environment.ApplicationName));

        return builder;
    }

    /// <summary>
    /// OpenTelemetry traces + metrics (ASP.NET Core, HttpClient, YARP). Exported via OTLP when
    /// OpenTelemetry:OtlpEndpoint (or OTEL_EXPORTER_OTLP_ENDPOINT) is set. Serilog automatically
    /// stamps TraceId/SpanId on every log event, so logs and traces correlate.
    /// </summary>
    public static WebApplicationBuilder AddGatewayTelemetry(this WebApplicationBuilder builder)
    {
        var endpoint = builder.Configuration["OpenTelemetry:OtlpEndpoint"]
                       ?? builder.Configuration["OTEL_EXPORTER_OTLP_ENDPOINT"];
        if (string.IsNullOrWhiteSpace(endpoint)) return builder;

        builder.Services.AddOpenTelemetry()
            .ConfigureResource(r => r.AddService(builder.Environment.ApplicationName))
            .WithTracing(t => t
                .AddAspNetCoreInstrumentation(o => o.Filter = ctx => !ctx.Request.Path.StartsWithSegments("/health"))
                .AddHttpClientInstrumentation()
                .AddSource("Yarp.ReverseProxy")
                .AddOtlpExporter(o => o.Endpoint = new Uri(endpoint)))
            .WithMetrics(m => m
                .AddAspNetCoreInstrumentation()
                .AddHttpClientInstrumentation()
                .AddMeter("System.Runtime", "Microsoft.AspNetCore.RateLimiting", "Microsoft.AspNetCore.Server.Kestrel", "Yarp.ReverseProxy")
                .AddOtlpExporter(o => o.Endpoint = new Uri(endpoint)));

        return builder;
    }

    /// <summary>
    /// One structured completion event per request. Only the path is logged (never the query string,
    /// Authorization, cookies or bodies) to keep secrets/PII out of logs.
    /// </summary>
    public static IApplicationBuilder UseGatewayRequestLogging(this IApplicationBuilder app) =>
        app.UseSerilogRequestLogging(o =>
        {
            o.MessageTemplate = "HTTP {RequestMethod} {RequestPath} responded {StatusCode} in {Elapsed:0.0} ms";
            o.GetLevel = (ctx, _, ex) => ex is not null || ctx.Response.StatusCode >= 500
                ? LogEventLevel.Error
                : ctx.Request.Path.StartsWithSegments("/health")
                    ? LogEventLevel.Verbose
                    : ctx.Response.StatusCode >= 400 ? LogEventLevel.Warning : LogEventLevel.Information;

            o.EnrichDiagnosticContext = (diag, ctx) =>
            {
                diag.Set("ClientIp", ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown");
                diag.Set("RequestHost", LogSanitizer.Clean(ctx.Request.Host.Value, 128));
                diag.Set("Protocol", ctx.Request.Protocol);
                diag.Set("Scheme", ctx.Request.Scheme);
                diag.Set("UserAgent", LogSanitizer.Clean(ctx.Request.Headers.UserAgent.ToString(), 200));
                diag.Set("RequestContentLength", ctx.Request.ContentLength ?? 0);
                diag.Set("ResponseContentType", ctx.Response.ContentType ?? string.Empty);
                diag.Set("ContentEncoding", ctx.Response.Headers.ContentEncoding.ToString());
                diag.Set("CorrelationId", CorrelationIdMiddleware.Get(ctx));

                if (ctx.User.Identity?.IsAuthenticated == true)
                {
                    diag.Set("ClientId", ctx.User.Identity.Name ?? ctx.User.FindFirst("sub")?.Value ?? "authenticated");
                }

                var proxy = ctx.Features.Get<IReverseProxyFeature>();
                if (proxy is not null)
                {
                    diag.Set("RouteId", proxy.Route.Config.RouteId);
                    diag.Set("ClusterId", proxy.Cluster?.Config.ClusterId ?? string.Empty);
                    diag.Set("Destination", proxy.ProxiedDestination?.DestinationId ?? string.Empty);
                }
            };
        });
}
