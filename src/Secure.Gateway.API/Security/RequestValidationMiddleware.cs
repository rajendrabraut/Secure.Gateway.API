using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;
using Secure.Gateway.API.Logging;
using Secure.Gateway.API.Options;

namespace Secure.Gateway.API.Security;

/// <summary>
/// Cheap protocol-level checks before any expensive work: HTTP method allow-list (blocks TRACE/CONNECT
/// / cross-site tracing), URL length, query-parameter flooding (HPP / hash-DoS), oversized header values,
/// control characters in the path, and request Content-Type allow-listing.
/// </summary>
public sealed class RequestValidationMiddleware(
    RequestDelegate next,
    IOptionsMonitor<GatewayOptions> options,
    ILogger<RequestValidationMiddleware> logger)
{
    public async Task InvokeAsync(HttpContext context)
    {
        var settings = options.CurrentValue.RequestValidation;
        if (!settings.Enabled)
        {
            await next(context);
            return;
        }

        var (status, reason) = Validate(context.Request, settings);
        if (status != 0)
        {
            SecurityEvents.RequestRejected(logger, "RequestValidation", status, reason,
                context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
                context.Request.Method, LogSanitizer.Clean(context.Request.Path.Value));

            if (status == StatusCodes.Status405MethodNotAllowed)
            {
                context.Response.Headers.Allow = string.Join(", ", settings.AllowedMethods);
            }

            await GatewayProblem.WriteAsync(context, status, reason);
            return;
        }

        await next(context);
    }

    private static (int Status, string Reason) Validate(HttpRequest request, RequestValidationSettings s)
    {
        if (!s.AllowedMethods.Contains(request.Method, StringComparer.OrdinalIgnoreCase))
            return (StatusCodes.Status405MethodNotAllowed, "Method not allowed");

        var urlLength = (request.PathBase.Value?.Length ?? 0) + (request.Path.Value?.Length ?? 0) + (request.QueryString.Value?.Length ?? 0);
        if (urlLength > s.MaxUrlLength)
            return (StatusCodes.Status414UriTooLong, "URI too long");

        if (request.Query.Count > s.MaxQueryParameters)
            return (StatusCodes.Status400BadRequest, "Too many query parameters");

        var path = request.Path.Value ?? string.Empty;
        foreach (var c in path)
        {
            if (char.IsControl(c)) return (StatusCodes.Status400BadRequest, "Invalid characters in path");
        }

        foreach (var header in request.Headers)
        {
            foreach (var value in header.Value)
            {
                if (value is not null && value.Length > s.MaxHeaderValueLength)
                    return (StatusCodes.Status431RequestHeaderFieldsTooLarge, "Request header too large");
            }
        }

        if (HasBody(request) && !IsAllowedContentType(request.ContentType, s.AllowedContentTypes))
            return (StatusCodes.Status415UnsupportedMediaType, "Unsupported media type");

        return (0, string.Empty);
    }

    private static bool HasBody(HttpRequest request) =>
        request.ContentLength > 0 || request.Headers.TransferEncoding.Count > 0;

    private static bool IsAllowedContentType(string? contentType, string[] allowed)
    {
        if (string.IsNullOrWhiteSpace(contentType) || !MediaTypeHeaderValue.TryParse(contentType, out var parsed))
            return false;

        var mediaType = parsed.MediaType.Value ?? string.Empty;
        if (allowed.Contains(mediaType, StringComparer.OrdinalIgnoreCase)) return true;

        // application/problem+json, application/vnd.api+json, ... are JSON.
        return parsed.Suffix.Equals("json", StringComparison.OrdinalIgnoreCase)
               && allowed.Contains("application/json", StringComparer.OrdinalIgnoreCase);
    }
}
