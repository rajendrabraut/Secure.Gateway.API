namespace Secure.Gateway.API.Options;

/// <summary>Root of all gateway-specific settings (section "Gateway").</summary>
public sealed class GatewayOptions
{
    public const string SectionName = "Gateway";

    public CompressionSettings Compression { get; set; } = new();
    public SecurityHeaderSettings SecurityHeaders { get; set; } = new();
    public RequestValidationSettings RequestValidation { get; set; } = new();
    public WafSettings Waf { get; set; } = new();
    public RateLimitSettings RateLimiting { get; set; } = new();
    public IpFilterSettings IpFilter { get; set; } = new();
    public CorsSettings Cors { get; set; } = new();
    public ForwardedHeaderSettings ForwardedHeaders { get; set; } = new();
}

public sealed class CompressionSettings
{
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Compress over HTTPS. Browsers only advertise zstd over HTTPS, so this must be true to serve zstd.
    /// BREACH note: do not mix secrets and attacker-reflected input in the same compressed response.
    /// </summary>
    public bool EnableForHttps { get; set; } = true;

    /// <summary>zstd level 1-22. 3 is the zstd default and a good speed/ratio trade-off for dynamic API traffic.</summary>
    public int ZstdLevel { get; set; } = 3;

    /// <summary>Fastest | Optimal | SmallestSize | NoCompression.</summary>
    public string BrotliLevel { get; set; } = "Fastest";
    public string GzipLevel { get; set; } = "Fastest";

    /// <summary>
    /// Remove Accept-Encoding before forwarding upstream so the gateway owns compression uniformly
    /// (zstd/br/gzip) instead of passing through whatever the backend produces.
    /// </summary>
    public bool StripUpstreamAcceptEncoding { get; set; } = true;

    public string[] MimeTypes { get; set; } =
    [
        "application/json", "application/problem+json", "application/xml", "application/javascript",
        "application/graphql-response+json", "application/x-ndjson", "text/plain", "text/html",
        "text/css", "text/xml", "text/csv", "text/javascript", "image/svg+xml",
    ];
}

public sealed class SecurityHeaderSettings
{
    public bool Enabled { get; set; } = true;
    public string ContentSecurityPolicy { get; set; } = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";
    public string PermissionsPolicy { get; set; } = "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()";
    public string ReferrerPolicy { get; set; } = "no-referrer";
    public string FrameOptions { get; set; } = "DENY";
    public string CrossOriginOpenerPolicy { get; set; } = "same-origin";
    public string CrossOriginResourcePolicy { get; set; } = "same-site";
    public int HstsMaxAgeSeconds { get; set; } = 31536000;
    public bool HstsIncludeSubDomains { get; set; } = true;
    public bool HstsPreload { get; set; }

    /// <summary>Response headers that leak server/framework details; removed from every (incl. proxied) response.</summary>
    public string[] RemoveHeaders { get; set; } = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-SourceFiles"];
}

public sealed class RequestValidationSettings
{
    public bool Enabled { get; set; } = true;
    public string[] AllowedMethods { get; set; } = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];
    public int MaxUrlLength { get; set; } = 4096;
    public int MaxQueryParameters { get; set; } = 64;
    public int MaxHeaderValueLength { get; set; } = 8192;

    /// <summary>Allowed request Content-Type media types for requests carrying a body. Suffix "+json" types are allowed when application/json is.</summary>
    public string[] AllowedContentTypes { get; set; } =
    [
        "application/json", "application/x-www-form-urlencoded", "multipart/form-data",
        "text/plain", "application/xml", "text/xml", "application/octet-stream",
    ];
}

public enum WafMode { Off, Detect, Block }

public sealed class WafSettings
{
    public WafMode Mode { get; set; } = WafMode.Block;
    public bool InspectPath { get; set; } = true;
    public bool InspectQuery { get; set; } = true;
    public bool InspectHeaders { get; set; } = true;
    public bool InspectBody { get; set; } = true;
    public bool InspectCookies { get; set; } = true;

    /// <summary>Request headers whose values are scanned (Authorization/Cookie are never logged).</summary>
    public string[] HeadersToInspect { get; set; } = ["User-Agent", "Referer", "X-Forwarded-Host", "X-Original-URL", "X-Rewrite-URL"];

    /// <summary>Max bytes of request body buffered for inspection.</summary>
    public int MaxBodyInspectionBytes { get; set; } = 1024 * 1024;

    /// <summary>Reject (413) bodies larger than MaxBodyInspectionBytes instead of forwarding them uninspected.</summary>
    public bool RejectUninspectableBodies { get; set; } = true;

    /// <summary>Path prefixes skipped by the WAF (e.g. file-upload endpoints protected elsewhere).</summary>
    public string[] ExcludedPaths { get; set; } = [];

    /// <summary>Rule ids to disable when they cause false positives (e.g. "XSS-004").</summary>
    public string[] DisabledRules { get; set; } = [];
}

public sealed class RateLimitSettings
{
    public bool Enabled { get; set; } = true;

    /// <summary>Global per-client token bucket applied to every request.</summary>
    public int GlobalTokenLimit { get; set; } = 200;
    public int GlobalTokensPerPeriod { get; set; } = 100;
    public int GlobalReplenishmentSeconds { get; set; } = 1;

    /// <summary>"default" policy: sliding window per client.</summary>
    public int DefaultPermitLimit { get; set; } = 600;
    public int DefaultWindowSeconds { get; set; } = 60;
    public int DefaultSegmentsPerWindow { get; set; } = 6;

    /// <summary>"strict" policy for sensitive routes (login, password reset, OTP).</summary>
    public int StrictPermitLimit { get; set; } = 10;
    public int StrictWindowSeconds { get; set; } = 60;

    /// <summary>Concurrent in-flight requests per client.</summary>
    public int ConcurrencyLimitPerClient { get; set; } = 50;
}

public sealed class IpFilterSettings
{
    /// <summary>If non-empty, only these IPs/CIDRs may call the gateway.</summary>
    public string[] Allow { get; set; } = [];
    public string[] Deny { get; set; } = [];
}

public sealed class CorsSettings
{
    /// <summary>Exact origins allowed. Empty = no cross-origin access.</summary>
    public string[] AllowedOrigins { get; set; } = [];
    public string[] AllowedMethods { get; set; } = ["GET", "POST", "PUT", "PATCH", "DELETE"];
    public string[] AllowedHeaders { get; set; } = ["Content-Type", "Authorization", "X-API-Key", "X-Correlation-ID"];
    public string[] ExposedHeaders { get; set; } = ["X-Correlation-ID", "Retry-After"];
    public bool AllowCredentials { get; set; }
    public int PreflightMaxAgeSeconds { get; set; } = 600;
}

public sealed class ForwardedHeaderSettings
{
    /// <summary>Only honour X-Forwarded-* from these proxy IPs / CIDRs (load balancer, ingress). Empty = loopback only.</summary>
    public string[] KnownProxies { get; set; } = [];
    public int ForwardLimit { get; set; } = 1;
}
