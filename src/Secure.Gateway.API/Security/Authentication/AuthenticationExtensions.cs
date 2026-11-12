using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using Secure.Gateway.API.Logging;

namespace Secure.Gateway.API.Security.Authentication;

public static class AuthenticationExtensions
{
    public const string SmartScheme = "GatewayAuth";
    public const string AuthenticatedPolicy = "authenticated";

    /// <summary>
    /// JWT bearer (OIDC: Entra ID, Auth0, Keycloak, ...) + API key. A policy scheme picks API key when the
    /// X-API-Key header is present, otherwise JWT. YARP routes choose with "AuthorizationPolicy":
    /// "authenticated" (require identity) or YARP's built-in "Anonymous".
    /// </summary>
    public static IServiceCollection AddGatewayAuthentication(this IServiceCollection services, IConfiguration configuration, IHostEnvironment env)
    {
        var jwt = configuration.GetSection("Authentication:Jwt");
        var apiKey = configuration.GetSection("Authentication:ApiKey");
        var apiKeyHeader = apiKey["HeaderName"] ?? "X-API-Key";

        services.AddAuthentication(SmartScheme)
            .AddPolicyScheme(SmartScheme, "API key or JWT", o =>
                o.ForwardDefaultSelector = ctx => ctx.Request.Headers.ContainsKey(apiKeyHeader)
                    ? ApiKeyAuthenticationHandler.SchemeName
                    : JwtBearerDefaults.AuthenticationScheme)
            .AddScheme<ApiKeyAuthenticationOptions, ApiKeyAuthenticationHandler>(ApiKeyAuthenticationHandler.SchemeName, o =>
            {
                o.HeaderName = apiKeyHeader;
                apiKey.GetSection("Clients").Bind(o.Clients);
            })
            .AddJwtBearer(o =>
            {
                o.Authority = jwt["Authority"];
                o.Audience = jwt["Audience"];
                o.RequireHttpsMetadata = !env.IsDevelopment();
                o.MapInboundClaims = false;
                o.SaveToken = false;
                o.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    RequireExpirationTime = true,
                    RequireSignedTokens = true,
                    ClockSkew = TimeSpan.FromSeconds(30),
                    ValidAlgorithms = ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"],
                    NameClaimType = "sub",
                    RoleClaimType = "roles",
                };
                o.Events = new JwtBearerEvents
                {
                    OnAuthenticationFailed = ctx =>
                    {
                        var logger = ctx.HttpContext.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("Secure.Gateway.Auth");
                        SecurityEvents.AuthFailed(logger, "AuthFailed", "Bearer",
                            ctx.HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown", ctx.Exception.GetType().Name);
                        return Task.CompletedTask;
                    },
                };
            });

        services.AddAuthorizationBuilder()
            .AddPolicy(AuthenticatedPolicy, p => p.RequireAuthenticatedUser())
            // "Anonymous" / "Default" are reserved by YARP, so they are not registered here.
            // Secure by default: routes that do not name a policy require an authenticated caller.
            .SetFallbackPolicy(new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build());

        return services;
    }
}
