using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using Secure.Gateway.API.Logging;

namespace Secure.Gateway.API.Security.Authentication;

public sealed class ApiKeyClient
{
    public string ClientId { get; set; } = string.Empty;

    /// <summary>Lower-case hex SHA-256 of the API key. Plain-text keys are never stored in config.</summary>
    public string KeyHash { get; set; } = string.Empty;

    public string[] Roles { get; set; } = [];
}

public sealed class ApiKeyAuthenticationOptions : AuthenticationSchemeOptions
{
    public string HeaderName { get; set; } = "X-API-Key";
    public List<ApiKeyClient> Clients { get; set; } = [];
}

/// <summary>
/// API-key authentication for machine-to-machine clients. Keys are compared as SHA-256 hashes using
/// <see cref="CryptographicOperations.FixedTimeEquals"/> to avoid timing side channels.
/// Generate a hash with: <c>dotnet run --project src/Secure.Gateway.API -- hash-key &lt;key&gt;</c>.
/// </summary>
public sealed class ApiKeyAuthenticationHandler(
    IOptionsMonitor<ApiKeyAuthenticationOptions> options,
    ILoggerFactory loggerFactory,
    UrlEncoder encoder)
    : AuthenticationHandler<ApiKeyAuthenticationOptions>(options, loggerFactory, encoder)
{
    public const string SchemeName = "ApiKey";

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Headers.TryGetValue(Options.HeaderName, out var supplied) || supplied.Count == 0)
            return Task.FromResult(AuthenticateResult.NoResult());

        var key = supplied.ToString();
        if (supplied.Count > 1 || key.Length is < 16 or > 256)
            return Fail("malformed key");

        var suppliedHash = SHA256.HashData(Encoding.UTF8.GetBytes(key));

        ApiKeyClient? matched = null;
        foreach (var client in Options.Clients)
        {
            if (client.KeyHash.Length != 64) continue;
            byte[] expected;
            try { expected = Convert.FromHexString(client.KeyHash); }
            catch (FormatException) { continue; }

            // Compare every entry (no early exit) to keep timing independent of which client matched.
            if (CryptographicOperations.FixedTimeEquals(suppliedHash, expected)) matched ??= client;
        }

        if (matched is null) return Fail("unknown key");

        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, matched.ClientId),
            new(ClaimTypes.Name, matched.ClientId),
            new("client_id", matched.ClientId),
            new("auth_method", "api_key"),
        };
        claims.AddRange(matched.Roles.Select(r => new Claim(ClaimTypes.Role, r)));

        var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, SchemeName));
        return Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(principal, SchemeName)));
    }

    private Task<AuthenticateResult> Fail(string reason)
    {
        SecurityEvents.AuthFailed(Logger, "AuthFailed", SchemeName, Context.Connection.RemoteIpAddress?.ToString() ?? "unknown", reason);
        return Task.FromResult(AuthenticateResult.Fail("Invalid API key"));
    }

    public static string HashKey(string key) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(key)));
}
