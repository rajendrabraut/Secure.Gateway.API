using System.Diagnostics;
using Serilog.Context;

namespace Secure.Gateway.API.Logging;

/// <summary>
/// Accepts a caller-supplied X-Correlation-ID only if it is short and safe (prevents log forging /
/// header injection); otherwise uses the W3C trace id. Echoes it on the response and pushes it into
/// every log event of the request.
/// </summary>
public sealed class CorrelationIdMiddleware(RequestDelegate next)
{
    public const string HeaderName = "X-Correlation-ID";
    public const string ItemKey = "CorrelationId";

    public async Task InvokeAsync(HttpContext context)
    {
        var correlationId = context.Request.Headers.TryGetValue(HeaderName, out var supplied) && IsValid(supplied.ToString())
            ? supplied.ToString()
            : Activity.Current?.TraceId.ToString() ?? context.TraceIdentifier;

        context.Items[ItemKey] = correlationId;
        context.TraceIdentifier = correlationId;
        Activity.Current?.SetTag("correlation.id", correlationId);

        context.Response.OnStarting(static state =>
        {
            var (ctx, id) = ((HttpContext, string))state;
            ctx.Response.Headers[HeaderName] = id;
            return Task.CompletedTask;
        }, (context, correlationId));

        using (LogContext.PushProperty(ItemKey, correlationId))
        {
            await next(context);
        }
    }

    internal static bool IsValid(string value)
    {
        if (value.Length is 0 or > 64) return false;
        foreach (var c in value)
        {
            if (!(char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.')) return false;
        }
        return true;
    }

    public static string Get(HttpContext context) =>
        context.Items.TryGetValue(ItemKey, out var id) && id is string s ? s : context.TraceIdentifier;
}
