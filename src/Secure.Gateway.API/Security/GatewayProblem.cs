using Secure.Gateway.API.Logging;

namespace Secure.Gateway.API.Security;

/// <summary>Writes RFC 9457 problem+json responses that never echo attacker input or internals.</summary>
public static class GatewayProblem
{
    public static Task WriteAsync(HttpContext context, int statusCode, string title, string? detail = null)
    {
        if (context.Response.HasStarted) return Task.CompletedTask;

        // Not Response.Clear(): that would also drop headers set by the caller (Retry-After, Allow).
        context.Response.StatusCode = statusCode;
        context.Response.Headers.CacheControl = "no-store";

        return Results.Problem(
                statusCode: statusCode,
                title: title,
                detail: detail,
                extensions: new Dictionary<string, object?> { ["correlationId"] = CorrelationIdMiddleware.Get(context) })
            .ExecuteAsync(context);
    }
}
