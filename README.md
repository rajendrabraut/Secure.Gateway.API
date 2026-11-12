# Secure.Gateway.API

A hardened API gateway / reverse proxy built on **.NET 10 (LTS) + ASP.NET Core + [YARP](https://github.com/dotnet/yarp)**.
It sits in front of your backend services and gives you defence-in-depth, modern compression and structured logging.

```
Client ──HTTPS──▶ Secure.Gateway.API ──▶ backend services
                  │ forwarded headers (trusted proxies only)
                  │ correlation id  ─ Serilog JSON logs + OpenTelemetry traces/metrics
                  │ security headers (HSTS, CSP, nosniff, ...) / strip Server, X-Powered-By
                  │ response compression: zstd ▸ brotli ▸ gzip
                  │ IP allow/deny ─ request validation (methods, sizes, content types)
                  │ auth: JWT (OIDC) or API key ─ rate limiting (global + per route)
                  │ WAF: SQLi, NoSQLi, XSS, path traversal, RCE, SSTI/Log4Shell, XXE, LDAP, CRLF
                  └ YARP: routing, load balancing, active + passive health checks
```

## Why .NET 10 + YARP?

Research summary (Nov 2026):

| Option | Strength | Trade-off |
|---|---|---|
| **Rust** (Cloudflare Pingora) | Highest raw throughput, memory safety | Pingora is a *framework*: you write every gateway feature yourself; slower to build; smaller hiring pool |
| **Go** (Traefik, Tyk, KrakenD) | Very fast, simple concurrency, great for infra | Fewer batteries for auth / rate limiting / WAF in the std lib |
| **.NET 10 + YARP** ✅ | Microsoft-supported reverse-proxy toolkit, top-tier Kestrel performance, *built-in* rate limiting, JWT/OIDC, response compression, health checks, OpenTelemetry; LTS until Nov 2028 | Slightly higher memory than Rust/Go |

Benchmarks show the big gap is between interpreted (Python/Lua) and compiled gateways, not between Rust, Go and .NET.
For a gateway that needs rich, auditable security logic maintained by an application team, .NET 10 + YARP gives the best
security-features-per-line-of-code while staying in the same performance class. .NET 11 (STS) shipped this month with
built-in zstd; this project stays on the **LTS** release and uses ZstdSharp for zstd until the next LTS.

## Features

### Compression (all evergreen browsers)
| Encoding | Browsers | Notes |
|---|---|---|
| `zstd` | Chrome/Edge 123+, Firefox 126+, Safari 26.3+ | **HTTPS only** (browsers don't advertise it over HTTP). Preferred when q-values tie. |
| `br` | all modern browsers | Fallback for older browsers. |
| `gzip` | everything | Universal fallback. |

* Negotiation honours `Accept-Encoding` q-values; `Vary: Accept-Encoding` is always set.
* The gateway strips `Accept-Encoding` before proxying so backends send identity and the gateway compresses uniformly.
* Compressed **request** bodies are rejected (they hide payloads from the WAF and are a zip-bomb vector).
* BREACH: don't place secrets and attacker-reflected input in the same compressed response.

### Security
| Control | Where |
|---|---|
| SQL injection, NoSQL (Mongo `$ne`...), XSS, path traversal/LFI, OS command injection, SSTI + Log4Shell `${jndi:`, XXE, LDAP, CRLF | `Security/Waf` — path, query, selected headers, cookies, JSON (per value), form and text bodies; input canonicalised (multi-round URL decode, HTML entities, SQL comment stripping) |
| ReDoS-proof WAF | all rules use `RegexOptions.NonBacktracking` (linear time) |
| Rate limiting | global per-client token bucket + concurrency limit; route policies `standard` (sliding window) and `strict` (fixed window per IP, for login/OTP); 429 + `Retry-After` |
| AuthN/AuthZ | JWT bearer (OIDC, asymmetric algs only, 30 s clock skew) or API key (SHA-256 hashed, constant-time compare). **Secure by default**: routes without a policy require authentication |
| Identity spoofing | incoming `X-Authenticated-*` headers stripped; API key never forwarded; backend receives `X-Authenticated-Client` |
| Security headers | HSTS (HTTPS), CSP, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, COOP/CORP; `Server`/`X-Powered-By` removed even from proxied responses |
| Request validation | method allow-list (TRACE/CONNECT blocked), URL length, query-param count, header size, control chars, content-type allow-list |
| Slowloris / resource limits | Kestrel limits: body size, header count/size, header timeout, connection caps, HTTP/2 stream caps |
| Host header attacks | `AllowedHosts` allow-list |
| IP spoofing | `X-Forwarded-For` honoured only from `Gateway:ForwardedHeaders:KnownProxies` |
| IP filtering | CIDR allow/deny lists (IPv4 + IPv6) |
| Errors | RFC 9457 `problem+json`, never echoes input or stack traces; includes `correlationId` |
| Supply chain | NuGet audit on every restore, Dependabot, CodeQL `security-extended`, chiseled non-root container |

> The WAF is **defence in depth**. Backends must still use parameterised queries/ORMs, output encoding and schema validation.

### Logging & observability
* **Serilog** structured JSON (compact CLEF) to console + rolling file (daily, 100 MB cap, 14 files); readable coloured template in Development.
* One completion event per request with route, cluster, destination, status, elapsed ms, content-encoding, client IP, client id, correlation id.
* Query strings, `Authorization`, cookies and bodies are **never** logged; user-controlled values are sanitised (CWE-117).
* Security events (`EventId` 4001-4005, property `SecurityEvent`) for SIEM alerting: `WafMatch`, `RateLimited`, `IpFilter`, `RequestValidation`, `AuthFailed`.
* `X-Correlation-ID` accepted (validated) or generated from the W3C trace id; forwarded upstream and returned to the client.
* **OpenTelemetry** traces + metrics (ASP.NET Core, HttpClient, YARP, rate limiting, Kestrel, runtime) via OTLP — set `OpenTelemetry:OtlpEndpoint`.

## Getting started

```bash
dotnet run --project src/Secure.Gateway.API
```

Routes (see `ReverseProxy` in `appsettings.json`):

| Route | Path | Auth | Rate limit |
|---|---|---|---|
| `auth` | `/api/auth/**` | anonymous | `strict` |
| `public-api` | `/api/public/**` | anonymous | `standard` |
| `secure-api` | `/api/**` | `authenticated` | `standard` |

Health: `GET /health/live`, `GET /health/ready`.

### API keys
```bash
dotnet run --project src/Secure.Gateway.API -- hash-key "<a long random key>"
```
Put the printed hash in `Authentication:ApiKey:Clients` (`ClientId`, `KeyHash`, `Roles`). Keep real values in user-secrets, environment variables or a vault — not in git.

### JWT / OIDC
Set `Authentication:Jwt:Authority` and `Authentication:Jwt:Audience` (Entra ID, Auth0, Keycloak, Cognito...).

### HTTP/3 + TLS (production)
```json
"Kestrel": {
  "Endpoints": {
    "Https": {
      "Url": "https://*:443",
      "Protocols": "Http1AndHttp2AndHttp3",
      "Certificate": { "Path": "/certs/gateway.pfx", "Password": "<from secret store>" }
    }
  }
}
```

### Docker
```bash
docker build -t secure-gateway-api .
docker run -p 8080:8080 -e ReverseProxy__Clusters__backend__Destinations__primary__Address=http://backend:8080/ secure-gateway-api
```

### Production checklist
- [ ] `AllowedHosts` = your public host names
- [ ] `Gateway:ForwardedHeaders:KnownProxies` = load balancer / ingress CIDRs
- [ ] TLS termination (here or at the LB) and `HstsPreload` once ready
- [ ] JWT authority/audience or API key hashes from a secret store
- [ ] `Gateway:Cors:AllowedOrigins` = exact front-end origins
- [ ] OTLP endpoint + alerts on `SecurityEvent` logs
- [ ] Multi-instance? add a distributed limiter (Redis) or LB-level rate limit — built-in limits are per instance
- [ ] Tune WAF false positives with `Gateway:Waf:DisabledRules` / `ExcludedPaths`, start with `Mode: Detect` on new routes

## Tests
```bash
dotnet test
```
89 tests: integration tests run the real pipeline against a live Kestrel upstream (proxying, header stripping,
zstd/br/gzip negotiation + round-trip decode, WAF block/allow cases, rate limiting, auth, validation) plus
unit tests for detection rules, false positives, ReDoS resistance and CIDR parsing.

## Project layout
```
src/Secure.Gateway.API
  Program.cs                      pipeline + YARP transforms
  Compression/                    zstd provider, compression registration
  Logging/                        Serilog/OTel setup, correlation id, security events, log sanitiser
  RateLimiting/                   global + route rate-limit policies
  Security/                       headers, request validation, IP filter, problem responses
  Security/Authentication/        API key handler, JWT + policy scheme
  Security/Waf/                   threat rules + WAF middleware
  Options/                        strongly typed settings
tests/Secure.Gateway.API.Tests    xUnit + WebApplicationFactory
```
