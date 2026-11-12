using System.Net;
using System.Text;
using System.Text.RegularExpressions;

namespace Secure.Gateway.API.Security.Waf;

public sealed record WafRule(string Id, string Category, Regex Pattern);

public sealed record ThreatMatch(string RuleId, string Category);

/// <summary>
/// Signature-based detection of injection payloads (OWASP Top 10 A03). Inputs are canonicalised first
/// (repeated URL-decoding, HTML-entity decoding, SQL comment removal, whitespace folding) so
/// double-encoding and comment-obfuscation tricks do not bypass the rules.
///
/// All regexes use <see cref="RegexOptions.NonBacktracking"/>: matching is linear-time, which makes the
/// WAF itself immune to ReDoS.
///
/// IMPORTANT: this is defence in depth. Backend services must still use parameterised queries / ORMs
/// for SQL, output encoding for HTML, and must validate input against their own schema.
/// </summary>
public static class ThreatDetector
{
    private const RegexOptions Opts = RegexOptions.IgnoreCase | RegexOptions.CultureInvariant |
                                      RegexOptions.NonBacktracking | RegexOptions.Singleline;

    private static readonly TimeSpan Timeout = TimeSpan.FromMilliseconds(250);

    private static WafRule R(string id, string category, string pattern) => new(id, category, new Regex(pattern, Opts, Timeout));

    public static readonly IReadOnlyList<WafRule> Rules =
    [
        // ---------------- SQL injection ----------------
        R("SQLI-001", "SqlInjection", @"['""`]\s*\)*\s*(or|and|xor|\|\||&&)\s*\(*\s*['""`]?\w*['""`]?\s*(=|<>|!=|<=?|>=?|\blike\b)"),  // ' OR 'a'='a , " or 1=1
        R("SQLI-002", "SqlInjection", @"\b(or|and)\s+\(*\d+\)*\s*(=|<>|!=|<|>)\s*\(*\d+"),                                       // or 1=1 (numeric context)
        R("SQLI-003", "SqlInjection", @"\bunion\b(\s+(all|distinct))?\s+\(*\s*select\b"),                                        // UNION SELECT
        R("SQLI-004", "SqlInjection", @";\s*(drop|truncate|alter|create|delete|insert|update|replace|merge|grant|revoke|exec|execute|declare|shutdown)\b"), // stacked queries
        R("SQLI-005", "SqlInjection", @"\b(xp_cmdshell|sp_executesql|sp_oacreate|xp_regread|xp_dirtree|sp_configure|openrowset|opendatasource)\b"),
        R("SQLI-006", "SqlInjection", @"\b(waitfor\s+delay|pg_sleep\s*\(|sleep\s*\(\s*\d|benchmark\s*\(\s*\d|dbms_pipe\.receive_message|randomblob\s*\(\s*\d{6,})"), // time-based blind
        R("SQLI-007", "SqlInjection", @"\b(information_schema|sysobjects|syscolumns|sys\.(tables|columns|objects|databases)|pg_catalog|pg_shadow|mysql\.user|sqlite_master|all_tables|user_tables)\b"),
        R("SQLI-008", "SqlInjection", @"['""`]\s*\)*\s*(--(\s|$)|/\*|#\s*$)"),                                                    // quote followed by comment: admin'--
        R("SQLI-009", "SqlInjection", @"\b(load_file\s*\(|into\s+(out|dump)file\b|@@(version|datadir|hostname)\b|\bversion\s*\(\s*\))"),
        R("SQLI-010", "SqlInjection", @"\b(extractvalue|updatexml|xmltype|utl_inaddr\.get_host_name|ctxsys\.drithsx\.sn)\s*\("),   // error-based
        R("SQLI-011", "SqlInjection", @"\b(char|nchar|chr)\s*\(\s*\d+\s*\)\s*(\+|\|\||,)\s*(char|nchar|chr)\s*\("),               // CHAR(83)+CHAR(69) obfuscation
        R("SQLI-012", "SqlInjection", @"\b(select|delete|insert|update)\b[^;]{0,120}\b(from|into|set)\b[^;]{0,120}\bwhere\b[^;]{0,120}(=|\blike\b)\s*['""`]?\s*\w*['""`]?\s*(--|#|;|\bor\b)"),
        R("SQLI-013", "SqlInjection", @"\border\s+by\s+\d+\s*(--|#|/\*)"),                                                        // column enumeration
        R("SQLI-014", "SqlInjection", @"\bhaving\s+\d+\s*=\s*\d+"),

        // ---------------- NoSQL injection (MongoDB operators) ----------------
        R("NOSQL-001", "NoSqlInjection", @"(\[\s*\$|^\$)(ne|eq|gt|gte|lt|lte|in|nin|regex|where|exists|expr|function|accumulator|elemMatch)\b"),
        R("NOSQL-002", "NoSqlInjection", @"\$where\s*[:=]|\bdb\.\w+\.(find|drop|remove|insert)\s*\("),

        // ---------------- Cross-site scripting ----------------
        R("XSS-001", "Xss", @"<\s*/?\s*script\b"),
        R("XSS-002", "Xss", @"\b(javascript|vbscript|livescript)\s*:"),
        R("XSS-003", "Xss", @"<[^>]*\bon[a-z]{3,30}\s*="),                                                                         // <img onerror=...>
        R("XSS-004", "Xss", @"<\s*(iframe|frame|frameset|object|embed|applet|svg|math|base|link|meta|style|form|isindex|template|portal)\b"),
        R("XSS-005", "Xss", @"\bdata\s*:\s*(text/html|image/svg\+xml|application/(x-)?javascript)"),
        R("XSS-006", "Xss", @"\b(document\s*\.\s*(cookie|domain|write)|window\s*\.\s*location|\.innerHTML\s*=|eval\s*\(|settimeout\s*\(\s*['""`]|new\s+function\s*\()"),
        R("XSS-007", "Xss", @"\bexpression\s*\(|-moz-binding\s*:|\bsrcdoc\s*="),

        // ---------------- Path traversal / file inclusion ----------------
        R("LFI-001", "PathTraversal", @"(^|[\\/])\.\.([\\/]|$)"),
        R("LFI-002", "PathTraversal", @"(/etc/(passwd|shadow|hosts|group)|/proc/self/|[a-z]:\\windows\\|\bboot\.ini\b|\bweb\.config\b|/\.env\b|/\.git/)"),
        R("LFI-003", "PathTraversal", @"\b(file|php|phar|zip|expect|glob|data|gopher|dict|jar)://"),

        // ---------------- OS command injection ----------------
        R("CMD-001", "CommandInjection", @"(\||\|\||&&|\$\()\s*(cat|ls|id|whoami|uname|pwd|wget|curl|nc|ncat|netcat|bash|sh|zsh|python[23]?|perl|ruby|php|powershell|pwsh|cmd(\.exe)?|certutil|bitsadmin|nslookup|ping)\b"),
        R("CMD-002", "CommandInjection", @"\$\{IFS\}|/bin/(ba)?sh\b|\bcmd(\.exe)?\s+/c\b|\bpowershell(\.exe)?\s+-(enc|e|command|c)\b"),

        // ---------------- Template / expression injection, Log4Shell ----------------
        R("SSTI-001", "TemplateInjection", @"\$\{\s*(jndi|env|sys|java|lower|upper|::-)\s*:"),                                     // ${jndi:ldap://...}
        R("SSTI-002", "TemplateInjection", @"\{\{\s*[^}]{0,60}(__class__|__globals__|__builtins__|config\.|request\.|self\.|lipsum|cycler|\d+\s*\*\s*\d+)"),
        R("SSTI-003", "TemplateInjection", @"<%\s*=|#\{\s*\d+\s*\*\s*\d+\s*\}|\$\{\s*\d+\s*\*\s*\d+\s*\}"),

        // ---------------- LDAP / XPath / XXE / CRLF ----------------
        R("LDAP-001", "LdapInjection", @"\*\)\s*\(\s*[|&!]|\)\s*\(\s*\|\s*\(\s*\w+\s*=\s*\*"),
        R("XXE-001", "Xxe", @"<!\s*(doctype|entity)\b[^>]*\b(system|public)\b"),
        R("CRLF-001", "HeaderInjection", @"[\r\n]\s*(set-cookie|location|content-type|content-length|x-[a-z-]+)\s*:"),
    ];

    /// <summary>Returns the first matching rule, or null if the value looks clean.</summary>
    public static ThreatMatch? Scan(string? value, ISet<string>? disabledRules = null)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length < 2) return null;

        var normalized = Normalize(value);
        foreach (var rule in Rules)
        {
            if (disabledRules is not null && disabledRules.Contains(rule.Id)) continue;
            try
            {
                if (rule.Pattern.IsMatch(normalized)) return new ThreatMatch(rule.Id, rule.Category);
            }
            catch (RegexMatchTimeoutException)
            {
                // Pathological input; fail closed.
                return new ThreatMatch(rule.Id + "-TIMEOUT", rule.Category);
            }
        }

        return null;
    }

    /// <summary>
    /// Canonicalises input: up to 3 rounds of URL decoding (defeats %2527-style double encoding),
    /// HTML-entity decoding, null-byte removal, SQL inline-comment stripping and whitespace folding.
    /// </summary>
    public static string Normalize(string value)
    {
        var current = value;
        for (var i = 0; i < 3; i++)
        {
            string decoded;
            try
            {
                decoded = Uri.UnescapeDataString(current.Replace('+', ' '));
            }
            catch (UriFormatException)
            {
                break;
            }

            if (decoded == current) break;
            current = decoded;
        }

        current = WebUtility.HtmlDecode(current);

        var sb = new StringBuilder(current.Length);
        var lastWasSpace = false;
        for (var i = 0; i < current.Length; i++)
        {
            var c = current[i];

            // Strip /* ... */ comments used to split keywords: UN/**/ION SEL/**/ECT
            if (c == '/' && i + 1 < current.Length && current[i + 1] == '*')
            {
                var end = current.IndexOf("*/", i + 2, StringComparison.Ordinal);
                if (end > 0)
                {
                    if (!lastWasSpace) { sb.Append(' '); lastWasSpace = true; }
                    i = end + 1;
                    continue;
                }
            }

            if (c == '\0') continue;

            if (char.IsWhiteSpace(c) && c is not '\r' and not '\n')
            {
                if (!lastWasSpace) sb.Append(' ');
                lastWasSpace = true;
                continue;
            }

            sb.Append(c);
            lastWasSpace = false;
        }

        return sb.ToString();
    }
}
