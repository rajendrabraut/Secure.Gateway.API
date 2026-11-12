using Microsoft.Extensions.Options;
using Secure.Gateway.API.Options;

namespace Secure.Gateway.API.Security;

/// <summary>
/// Adds OWASP-recommended response headers and strips fingerprinting headers. Runs in OnStarting so it
/// also applies to responses copied from upstream services by YARP.
/// </summary>
public sealed class SecurityHeadersMiddleware(RequestDelegate next, IOptionsMonitor<GatewayOptions> options)
{
    public Task InvokeAsync(HttpContext context)
    {
        var settings = options.CurrentValue.SecurityHeaders;
        if (!settings.Enabled) return next(context);

        context.Response.OnStarting(static state =>
        {
            var (ctx, s) = ((HttpContext, SecurityHeaderSettings))state;
            var headers = ctx.Response.Headers;

            foreach (var name in s.RemoveHeaders) headers.Remove(name);

            headers.XContentTypeOptions = "nosniff";
            headers.XFrameOptions = s.FrameOptions;
            headers["Referrer-Policy"] = s.ReferrerPolicy;
            headers["Permissions-Policy"] = s.PermissionsPolicy;
            headers["Cross-Origin-Opener-Policy"] = s.CrossOriginOpenerPolicy;
            headers["Cross-Origin-Resource-Policy"] = s.CrossOriginResourcePolicy;
            headers["X-Permitted-Cross-Domain-Policies"] = "none";
            // Legacy XSS auditor is itself exploitable; OWASP recommends disabling it explicitly.
            headers.XXSSProtection = "0";

            // Let an upstream that serves HTML define its own CSP; otherwise lock everything down.
            if (!headers.ContainsKey("Content-Security-Policy"))
            {
                headers.ContentSecurityPolicy = s.ContentSecurityPolicy;
            }

            if (ctx.Request.IsHttps && s.HstsMaxAgeSeconds > 0)
            {
                var hsts = $"max-age={s.HstsMaxAgeSeconds}";
                if (s.HstsIncludeSubDomains) hsts += "; includeSubDomains";
                if (s.HstsPreload) hsts += "; preload";
                headers.StrictTransportSecurity = hsts;
            }

            return Task.CompletedTask;
        }, (context, settings));

        return next(context);
    }
}
