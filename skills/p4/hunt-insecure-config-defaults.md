# SKILL: hunt-insecure-config-defaults

## ⚡ BREADTH SCAN — semgrep-PRO-derived patterns, 15+ languages

Run grep, read context with `get_code_snippet` (or `read_file` for config files), submit immediately. Use at most 2 turns per step: batch all of a step's greps into ONE turn, then read the hits in the next turn.

---

## Step 1 — CORS wildcard (allow all origins)

**Python Django (django-cors-headers):**
```
grep(pattern="CORS_ALLOW_ALL_ORIGINS\s*=\s*True|CORS_ORIGIN_ALLOW_ALL\s*=\s*True", max_matches=15)
```

**Python FastAPI:**
```
grep(pattern="allow_origins\s*=\s*\[?\s*['\"]\*['\"]", max_matches=15)
```

**Python Flask (flask-cors):**
```
grep(pattern="\bCORS\s*\(\s*\w+\s*(\)|,\s*supports_credentials)|\bCORS\s*\(.*origins\s*=\s*['\"]\*['\"]|resources\s*=\s*\{.*['\"]origins['\"]\s*:\s*['\"]\*['\"]|@cross_origin\s*\(\s*\)", max_matches=15)
```

**JavaScript / TypeScript (Express cors):**
```
grep(pattern="\bcors\s*\(\s*\)|cors\s*\(\s*\{[^}]*origin\s*:\s*(['\"]\*['\"]|true)|^\s*origin\s*:\s*(true|['\"]\*['\"])\s*,?\s*$", max_matches=15)
```

**Java (Spring):**
```
grep(pattern="addAllowedOrigin(Pattern)?\s*\(\s*['\"]\*['\"]|allowedOrigin(s|Patterns)\s*\(\s*['\"]\*['\"]|setAllowedOrigin(s|Patterns)\s*\(.*['\"]\*['\"]|@CrossOrigin\s*(\(\s*(origins\s*=\s*)?['\"]\*['\"]|\(\s*\)|$)", max_matches=15)
```

**PHP:**
```
grep(pattern="header\s*\(\s*['\"]Access-Control-Allow-Origin:\s*\*['\"]", max_matches=15)
```

**Ruby (Rails):**
```
grep(pattern="\borigins\s*\(?\s*['\"]\*['\"]|\borigins\s+/\.\*/", max_matches=15)
```

**Go (gin-contrib/cors, net/http):**
```
grep(pattern="Allow(ed)?Origins\s*:\s*\[\]string\{[^}]*\"\*\"|AllowAllOrigins\s*:\s*true|Header\(\)\.Set\s*\(\s*\"Access-Control-Allow-Origin\"\s*,\s*\"\*\"", max_matches=15)
```

**Kotlin (Ktor):**
```
grep(pattern="allowHost\s*\(\s*['\"]?\*['\"]?\)|anyHost\s*\(\s*\)|allowCredentials\s*=\s*true.*anyHost", max_matches=15)
```

**Any language — Origin reflection / permissive matcher:**
```
grep(pattern="Access-Control-Allow-Origin['\"]?\s*[,:]\s*.*(req|request|r)\.(headers?|getHeader|get_header|Header\.Get|META)|HTTP_ORIGIN|allowedOriginPatterns\s*\(\s*['\"]\*['\"]|addAllowedOriginPattern\s*\(\s*['\"]\*['\"]|allow_origin_regex\s*=|CORS_ALLOWED_ORIGIN_REGEXES|AllowOriginFunc\s*:|callback\s*\(\s*null\s*,\s*true\s*\)", max_matches=15)
```

**Any language — credentials allowed:**
```
grep(pattern="allow_credentials\s*=\s*True|CORS_ALLOW_CREDENTIALS\s*=\s*True|supports_credentials\s*=\s*True|credentials\s*:\s*true|allowCredentials\s*(\(\s*true\s*\)|=\s*(true|\"true\"))|AllowCredentials\s*:\s*true|Access-Control-Allow-Credentials['\"]?\s*[,:]\s*['\"]?true", max_matches=15)
```

For each match, check whether credentials are allowed for the same policy (last grep) and how the library answers:
- Browsers refuse a literal `Access-Control-Allow-Origin: *` on credentialed requests (Spring ≥ 5.3 and rack-cors even reject the `*` + credentials combination outright). A literal wildcard alone only exposes responses that need no cookies or auth headers → severity 4.
- The account-takeover case is the request `Origin` being **reflected** together with `Access-Control-Allow-Credentials: true`: Express `origin: true` or an origin callback that always allows, `allowedOriginPatterns("*")`, a permissive `allow_origin_regex`, a header set from the request `Origin`, or a wildcard config in a library that echoes the origin when credentials are on (django-cors-headers with `CORS_ALLOW_CREDENTIALS = True`, Starlette/FastAPI `CORSMiddleware(allow_origins=["*"], allow_credentials=True)`, flask-cors with `supports_credentials=True`) → severity 9.

→ Submit: violated_invariant="CORS policy trusts arbitrary origins [reflected Origin + credentials, or literal wildcard]; attacker site reads responses [with the victim's cookies when credentials are allowed]", severity=9 (4 for a literal "*" without credentials), confidence=8, exposure="internet", cwe="CWE-942"

---

## Step 2 — Weak session cookie configuration

**Python (Django):**
```
grep(pattern="SESSION_COOKIE_SECURE\s*=\s*False|SESSION_COOKIE_HTTPONLY\s*=\s*False|SESSION_COOKIE_SAMESITE\s*=\s*['\"]?None|CSRF_COOKIE_SECURE\s*=\s*False", max_matches=20)
```

**JavaScript / TypeScript (express-session, cookie options):**
```
grep(pattern="httpOnly\s*:\s*false|cookie\s*:\s*\{[^}]*secure\s*:\s*false|sameSite\s*:\s*['\"]?(?i:none)['\"]?.*secure\s*:\s*false|(res\.cookie|cookies\.set|setCookie)\s*\(.*secure\s*:\s*false", max_matches=20)
```

**PHP (session.cookie_secure):**
```
grep(pattern="session\.cookie_(secure|httponly)['\"]?\s*[=,]\s*['\"]?(0|false|Off|off)\b|setcookie\(.*false.*false", max_matches=15)
```

**Java (Spring Boot):**
```
grep(pattern="cookie\.(http-only|secure)\s*[=:]\s*false|^\s*http-only\s*:\s*false|set(Cookie)?HttpOnly\s*\(\s*false\s*\)|set(Cookie)?Secure\s*\(\s*false\s*\)", max_matches=15)
```

**Ruby (Rails):**
```
grep(pattern="session_store.*secure\s*:\s*false|httponly\s*:\s*false|http_only\s*:\s*false|cookies(\.\w+)?\[[^\]]+\]\s*=\s*\{[^}]*secure\s*:\s*false", max_matches=15)
```

For each match: `read_file("matched_file")` to read the full config context.

**Verify**:
- File is `production.py`, `settings.py` (non-dev), `application.yml`, `application.properties`, or `.env` without a surrounding dev-guard → **SUBMIT**
- File is `settings/dev.py`, `local_settings.py`, `docker-compose.dev.yml`, `test_settings.py` → **SKIP**
- Setting is inside `if DEBUG:` or `if os.getenv('ENV') == 'development':` block → **SKIP**

→ Submit: violated_invariant="session cookie [flag] disabled; cookie exposed to [JS/plaintext/cross-site] requests", severity=7, confidence=7, exposure="internet", cwe="CWE-614" (use "CWE-1004" for HttpOnly, "CWE-1275" for SameSite)

---

## Step 3 — Missing security headers

**CSP with unsafe-inline or unsafe-eval:**
```
grep(pattern="['\"]unsafe-inline['\"]|['\"]unsafe-eval['\"]|(script|default|object)-src[^;]*\s\*(\s|;|['\"]|$)", max_matches=20)
```

**X-Frame-Options allowing framing:**
```
grep(pattern="(?i:x[-_]frame[-_]options).*ALLOW|frame-ancestors[^;]*\s\*(\s|;|['\"]|$)", max_matches=15)
```

**HSTS with short max-age or disabled:**
```
grep(pattern="Strict-Transport-Security.*max-age=0|hsts.*false|includeSubDomains.*false|SECURE_HSTS_SECONDS\s*=\s*0\b", max_matches=15)
```

For each match: `get_code_snippet("containing_function_or_middleware")` to read the context.

**Verify**:
- The `unsafe-inline`/`unsafe-eval`/`*` value is part of an actual HTTP response header assignment or middleware config (not a string constant in a comment or docs) → **CONTINUE**
- The header value is set conditionally only for dev mode → **SKIP**
- The header is set on the response object (`response.headers[...]`, `res.setHeader(...)`, middleware `app.use(helmet(...))`) → **SUBMIT**
- It is only a string constant assigned to a variable but never sent in a response → **SKIP**
- `'unsafe-inline'` only in `style-src`, or next to a nonce/hash in `script-src` (CSP2+ browsers then ignore it) → lower severity (3)

→ Submit: violated_invariant="security header [header] misconfigured; enables [clickjacking/XSS/downgrade attack]", severity=6, confidence=6, exposure="internet", cwe="CWE-693" (use "CWE-1021" for framing)

---

## Step 4 — Development server in production

**Python (Flask/FastAPI/Uvicorn):**
```
grep(pattern="app\.run\(.*debug\s*=\s*True|uvicorn\.run\(.*reload\s*=\s*True|DEBUG\s*=\s*True", max_matches=20)
```

**JavaScript / TypeScript (Node hot reload, nodemon):**
```
grep(pattern="\"start\"\s*:\s*\"[^\"]*(nodemon|webpack-dev-server|webpack serve|next dev|ng serve)|^(CMD|ENTRYPOINT).*(nodemon|npm\"?,?\s*\"?run\"?,?\s*\"?dev\b|webpack-dev-server|next\"?,?\s*\"?dev\b|ng\"?,?\s*\"?serve)", max_matches=20)
```

**Go (Gin debug mode):**
```
grep(pattern="gin\.SetMode\s*\(\s*gin\.DebugMode\s*\)|gin\.Default\s*\(\s*\).*DEBUG", max_matches=15)
```

**Java (Spring dev tools in prod):**
```
grep(pattern="spring-boot-devtools|spring\.devtools\.restart\.enabled\s*=\s*true", max_matches=15)
```

**Ruby (Rails development config loaded):**
```
grep(pattern="config\.consider_all_requests_local\s*=\s*true|config\.cache_classes\s*=\s*false|config\.enable_reloading\s*=\s*true", max_matches=15)
```

**PHP:**
```
grep(pattern="display_errors\s*=\s*(On|on|1|true)|ini_set\s*\(\s*['\"]display_errors['\"]\s*,\s*['\"]?(1|On|on|true)|APP_DEBUG\s*=\s*true", max_matches=15)
```

**.NET (web.config):**
```
grep(pattern="<compilation\b[^>]*\bdebug\s*=\s*['\"]true['\"]|<customErrors\b[^>]*\bmode\s*=\s*['\"]Off['\"]|UseDeveloperExceptionPage\s*\(", max_matches=15)
```

For each match: `read_file("matched_file")` to read the full file.

**Verify**:
- Setting is unconditional or at module level with no env-guard → **SUBMIT**
- Setting is inside `if os.environ.get('ENV') == 'development':`, `if NODE_ENV === 'development':`, or similar production-exclusive guard → **SKIP**
- Setting is in a dev-only file (`docker-compose.dev.yml`, `config/dev/`, `nodemon.json`) → **SKIP**

→ Submit: violated_invariant="development server mode enabled in production; stack traces/internals exposed to all clients", severity=7, confidence=6, exposure="internet", cwe="CWE-489"

---

## Step 5 — Rate limiting absent on auth endpoints

```
grep(pattern="\b(app|router|bp|blueprint|api|server|r|e|g)\.(post|put|route|Post|POST)\s*\(\s*['\"][^'\"]*(login|signin|sign-in|signup|register|password|reset|otp|mfa|2fa|token)|@(PostMapping|RequestMapping)\s*\(\s*((value|path)\s*=\s*)?['\"][^'\"]*(login|signin|register|password|reset|otp|token)|\bpath\s*\(\s*['\"][^'\"]*(login|register|password)", max_matches=30)
```

For each match: `get_code_snippet("containing_route_handler")` to read the full route definition.

**Verify**:
- No `@limiter.limit(...)`, no `rateLimit({...})` middleware argument, no `throttle(...)`, no `slowDown(...)`, no `express-rate-limit` applied to this route or its router group → **SUBMIT**
- Rate limiter is applied globally to all routes via `app.use(rateLimit(...))` → check if auth routes are covered; if covered → **SKIP**
- Rate limiter decorator or middleware IS present on this route → **SKIP**

→ Submit: violated_invariant="authentication endpoint [path] has no rate limiting; brute-force/credential stuffing at full request rate", severity=7, confidence=6, exposure="internet", cwe="CWE-307"

---

## Step 6 — Weak or default TLS configuration

**Python (ssl minimum version):**
```
grep(pattern="ssl\.PROTOCOL_(TLSv1|TLSv1_1|SSLv2|SSLv3)\b|SSLContext\(ssl\.PROTOCOL_TLS\b|minimum_version\s*=\s*ssl\.TLSVersion\.(SSLv3|TLSv1|TLSv1_1)\b", max_matches=15)
```

**Go (weak cipher suites):**
```
grep(pattern="tls\.TLS_RSA_WITH_RC4|tls\.TLS_RSA_WITH_3DES|tls\.TLS_ECDHE.*RC4|tls\.TLS_ECDHE.*3DES|MinVersion\s*:\s*tls\.Version(SSL30|TLS10|TLS11)\b", max_matches=15)
```

**Java (SSLv3 / TLSv1.0 enabled):**
```
grep(pattern="SSLContext\.getInstance\s*\(\s*['\"](SSL|SSLv3|TLSv1|TLSv1\.1)['\"]|setEnabledProtocols\s*\(.*['\"](SSLv3|TLSv1|TLSv1\.1)['\"]|enabled-protocols\s*[=:]\s*.*(SSLv3|TLSv1(\.1)?\s*(,|$))", max_matches=15)
```

**C# (.NET):**
```
grep(pattern="SecurityProtocolType\.(Ssl3|Tls|Tls11)\b|SslProtocols\.(Ssl2|Ssl3|Tls|Tls11)\b", max_matches=15)
```

→ Submit: violated_invariant="TLS configured with deprecated protocol [proto] or weak cipher suite; downgrade attack possible", severity=7, confidence=7, exposure="internet", cwe="CWE-327"

---

## Finish

Call `finish()` now with all hypotheses collected. Do not skip this.
