using System.Buffers;
using System.Collections.Frozen;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;
using Secure.Gateway.API.Logging;
using Secure.Gateway.API.Options;

namespace Secure.Gateway.API.Security.Waf;

/// <summary>
/// Lightweight Web Application Firewall. Scans path, query string, selected headers, cookies and the
/// request body (JSON values are scanned individually, so JSON syntax never causes false positives)
/// against <see cref="ThreatDetector"/> rules. In Block mode a match returns 403 without echoing input.
/// </summary>
public sealed class WafMiddleware(
    RequestDelegate next,
    IOptionsMonitor<GatewayOptions> options,
    ILogger<WafMiddleware> logger)
{
    private static readonly JsonReaderOptions JsonOptions = new() { MaxDepth = 64, CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true };

    public async Task InvokeAsync(HttpContext context)
    {
        var settings = options.CurrentValue.Waf;
        if (settings.Mode == WafMode.Off || IsExcluded(context.Request.Path, settings.ExcludedPaths))
        {
            await next(context);
            return;
        }

        var disabled = settings.DisabledRules.Length == 0 ? null : settings.DisabledRules.ToFrozenSet(StringComparer.OrdinalIgnoreCase);

        var (match, location) = ScanRequestLine(context.Request, settings, disabled);
        if (match is null && settings.InspectBody)
        {
            var body = await ScanBodyAsync(context.Request, settings, disabled, context.RequestAborted);
            if (body.Uninspectable)
            {
                SecurityEvents.RequestRejected(logger, "WafBodyUninspectable", StatusCodes.Status413PayloadTooLarge,
                    body.Reason, ClientIp(context), context.Request.Method, LogSanitizer.Clean(context.Request.Path.Value));
                await GatewayProblem.WriteAsync(context, StatusCodes.Status413PayloadTooLarge, "Request body cannot be inspected");
                return;
            }

            (match, location) = (body.Match, "body");
        }

        if (match is not null)
        {
            var block = settings.Mode == WafMode.Block;
            SecurityEvents.WafMatch(logger, "WafMatch", match.RuleId, match.Category, location, ClientIp(context),
                context.Request.Method, LogSanitizer.Clean(context.Request.Path.Value), block ? "blocked" : "detected");

            if (block)
            {
                await GatewayProblem.WriteAsync(context, StatusCodes.Status403Forbidden, "Request blocked by security policy");
                return;
            }
        }

        await next(context);
    }

    private static (ThreatMatch? Match, string Location) ScanRequestLine(HttpRequest request, WafSettings s, ISet<string>? disabled)
    {
        if (s.InspectPath && ThreatDetector.Scan(request.Path.Value, disabled) is { } pathMatch)
            return (pathMatch, "path");

        if (s.InspectQuery)
        {
            // Raw query catches encodings that model binding would decode differently.
            if (ThreatDetector.Scan(request.QueryString.Value, disabled) is { } raw) return (raw, "query");
            foreach (var (key, values) in request.Query)
            {
                if (ThreatDetector.Scan(key, disabled) is { } k) return (k, "query-key");
                foreach (var v in values)
                {
                    if (ThreatDetector.Scan(v, disabled) is { } m) return (m, "query");
                }
            }
        }

        if (s.InspectHeaders)
        {
            foreach (var name in s.HeadersToInspect)
            {
                if (request.Headers.TryGetValue(name, out var values))
                {
                    foreach (var v in values)
                    {
                        if (ThreatDetector.Scan(v, disabled) is { } m) return (m, $"header:{name}");
                    }
                }
            }
        }

        if (s.InspectCookies)
        {
            foreach (var (_, value) in request.Cookies)
            {
                if (ThreatDetector.Scan(value, disabled) is { } m) return (m, "cookie");
            }
        }

        return (null, string.Empty);
    }

    private readonly record struct BodyScanResult(ThreatMatch? Match, bool Uninspectable, string Reason);

    private static async Task<BodyScanResult> ScanBodyAsync(HttpRequest request, WafSettings s, ISet<string>? disabled, CancellationToken ct)
    {
        var hasBody = request.ContentLength > 0 || request.Headers.TransferEncoding.Count > 0;
        if (!hasBody) return default;

        var mediaType = MediaTypeHeaderValue.TryParse(request.ContentType, out var ctHeader) ? ctHeader.MediaType.Value ?? "" : "";

        // Binary / multipart uploads are not text-scanned (protect upload endpoints with ExcludedPaths + AV scanning).
        if (mediaType.Equals("application/octet-stream", StringComparison.OrdinalIgnoreCase) ||
            mediaType.StartsWith("multipart/", StringComparison.OrdinalIgnoreCase) ||
            mediaType.StartsWith("image/", StringComparison.OrdinalIgnoreCase))
            return default;

        // A compressed request body would hide its payload from inspection (and is a zip-bomb vector).
        if (request.Headers.ContentEncoding.Count > 0 && !request.Headers.ContentEncoding.ToString().Equals("identity", StringComparison.OrdinalIgnoreCase))
            return s.RejectUninspectableBodies ? new(null, true, "compressed request body") : default;

        if (request.ContentLength > s.MaxBodyInspectionBytes)
            return s.RejectUninspectableBodies ? new(null, true, "body exceeds inspection limit") : default;

        request.EnableBuffering(bufferThreshold: 64 * 1024, bufferLimit: Math.Max(s.MaxBodyInspectionBytes, 64 * 1024) + 1);

        var buffer = ArrayPool<byte>.Shared.Rent(s.MaxBodyInspectionBytes + 1);
        try
        {
            var total = 0;
            int read;
            while (total <= s.MaxBodyInspectionBytes &&
                   (read = await request.Body.ReadAsync(buffer.AsMemory(total, s.MaxBodyInspectionBytes + 1 - total), ct)) > 0)
            {
                total += read;
            }

            request.Body.Position = 0;

            if (total > s.MaxBodyInspectionBytes)
                return s.RejectUninspectableBodies ? new(null, true, "body exceeds inspection limit") : default;

            var bytes = buffer.AsSpan(0, total);
            var isJson = mediaType.Equals("application/json", StringComparison.OrdinalIgnoreCase) ||
                         (ctHeader?.Suffix.Equals("json", StringComparison.OrdinalIgnoreCase) ?? false);

            ThreatMatch? match;
            if (isJson && TryScanJson(bytes, disabled, out match))
                return new(match, false, string.Empty);

            var text = Encoding.UTF8.GetString(bytes);
            if (mediaType.Equals("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase))
            {
                foreach (var (key, values) in QueryHelpers.ParseQuery(text))
                {
                    if ((match = ThreatDetector.Scan(key, disabled)) is not null) return new(match, false, string.Empty);
                    foreach (var v in values)
                    {
                        if ((match = ThreatDetector.Scan(v, disabled)) is not null) return new(match, false, string.Empty);
                    }
                }
                return default;
            }

            return new(ThreatDetector.Scan(text, disabled), false, string.Empty);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    /// <summary>Scans every property name and string value. Returns false if the JSON is malformed (caller falls back to raw scan).</summary>
    private static bool TryScanJson(ReadOnlySpan<byte> json, ISet<string>? disabled, out ThreatMatch? match)
    {
        match = null;
        try
        {
            var reader = new Utf8JsonReader(json, JsonOptions);
            while (reader.Read())
            {
                if (reader.TokenType is JsonTokenType.String or JsonTokenType.PropertyName &&
                    ThreatDetector.Scan(reader.GetString(), disabled) is { } m)
                {
                    match = m;
                    return true;
                }
            }
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static bool IsExcluded(PathString path, string[] excluded)
    {
        foreach (var prefix in excluded)
        {
            if (path.StartsWithSegments(prefix, StringComparison.OrdinalIgnoreCase)) return true;
        }
        return false;
    }

    private static string ClientIp(HttpContext context) => context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
}
