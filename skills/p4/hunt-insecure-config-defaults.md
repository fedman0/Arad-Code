# SKILL: hunt-insecure-config-defaults

## ⚡ BREADTH SCAN — semgrep-PRO-derived patterns, 15+ languages

Run grep, read context with `get_code_snippet`, submit immediately. 2 tool calls per step max.

---

## Step 1 — CORS wildcard (allow all origins)

**Python Django (django-cors-headers):**
```
grep(pattern="CORS_ALLOW_ALL_ORIGINS\s*=\s*True|CORS_ORIGIN_ALLOW_ALL\s*=\s*True", max_matches=15)
```

**Python FastAPI:**
```
grep(pattern="CORSMiddleware.*allow_origins.*\*|allow_origins\s*=\s*\[.*\*.*\]", max_matches=15)
```

**Python Flask (flask-cors):**
```
grep(pattern="CORS\(.*origins\s*=\s*['\"]?\*['\"]?\)|resources\s*=\s*\{.*\*.*origins.*\*", max_matches=15)
```

**JavaScript / TypeScript (Express cors):**
```
grep(pattern="cors\(\{[^}]*origin\s*:\s*['\"]?\*['\"]?|cors\(\{[^}]*origin\s*:\s*true", max_matches=15)
```

**Java (Spring):**
```
grep(pattern="addAllowedOrigin\s*\(\s*['\"]?\*['\"]?\)|allowedOrigins\s*\(\s*['\"]?\*['\"]?\)|@CrossOrigin\s*\(\s*\*\s*\)", max_matches=15)
```

**PHP:**
```
grep(pattern="header\s*\(\s*['\"]Access-Control-Allow-Origin:\s*\*['\"]", max_matches=15)
```

**Ruby (Rails):**
```
grep(pattern="origins\s+['\*]|origins\s*['\"]?\*['\"]?", max_matches=15)
```

**Go (gin-contrib/cors, net/http):**
```
grep(pattern="AllowOrigins\s*:\s*\[\]string\{[^}]*\*[^}]*\}|AllowAllOrigins\s*:\s*true", max_matches=15)
```

**Kotlin (Ktor):**
```
grep(pattern="allowHost\s*\(\s*['\"]?\*['\"]?\)|anyHost\s*\(\s*\)|allowCredentials\s*=\s*true.*anyHost", max_matches=15)
```

For each match: is `allowCredentials` / `allow_credentials` also set? CORS wildcard + credentials = full account takeover.

→ Submit: violated_invariant="CORS allows all origins [+credentials if set]; attacker site can make credentialed requests as any logged-in user", severity=9, confidence=8, exposure="internet"

---

## Step 2 — Weak session cookie configuration

**Python (Django):**
```
grep(pattern="SESSION_COOKIE_SECURE\s*=\s*False|SESSION_COOKIE_HTTPONLY\s*=\s*False|SESSION_COOKIE_SAMESITE\s*=\s*None|CSRF_COOKIE_SECURE\s*=\s*False", max_matches=20)
```

**JavaScript / TypeScript (express-session, cookie options):**
```
grep(pattern="httpOnly\s*:\s*false|secure\s*:\s*false.*cookie|sameSite\s*:\s*['\"]none['\"].*secure\s*:\s*false", max_matches=20)
```

**PHP (session.cookie_secure):**
```
grep(pattern="session\.cookie_secure\s*=\s*0|session\.cookie_httponly\s*=\s*0|setcookie\(.*false.*false", max_matches=15)
```

**Java (Spring Boot):**
```
grep(pattern="cookie-http-only\s*:\s*false|cookie-secure\s*:\s*false|setCookieHttpOnly\s*\(\s*false\s*\)|setCookieSecure\s*\(\s*false\s*\)", max_matches=15)
```

**Ruby (Rails):**
```
grep(pattern="config\.session_store.*httponly.*false|http_only\s*:\s*false|secure\s*:\s*false.*session", max_matches=15)
```

For each match: `sqz_read_file("matched_file")` to read the full config context.

**Verify**:
- File is `production.py`, `settings.py` (non-dev), `application.yml`, `application.properties`, or `.env` without a surrounding dev-guard → **SUBMIT**
- File is `settings/dev.py`, `local_settings.py`, `docker-compose.dev.yml`, `test_settings.py` → **SKIP**
- Setting is inside `if DEBUG:` or `if os.getenv('ENV') == 'development':` block → **SKIP**

→ Submit: violated_invariant="session cookie [flag] disabled; cookie exposed to [JS/plaintext/cross-site] requests", severity=7, confidence=7, exposure="internet"

---

## Step 3 — Missing security headers

**CSP with unsafe-inline or unsafe-eval:**
```
grep(pattern="['\"]unsafe-inline['\"]|['\"]unsafe-eval['\"]|script-src\s+['\*]|Content-Security-Policy.*\*", max_matches=20)
```

**X-Frame-Options allowing framing:**
```
grep(pattern="X-Frame-Options.*ALLOW|X-Frame-Options.*ALLOWALL|frame-ancestors\s+['\*]", max_matches=15)
```

**HSTS with short max-age or disabled:**
```
grep(pattern="Strict-Transport-Security.*max-age=0|hsts.*false|includeSubDomains.*false", max_matches=15)
```

For each match: `get_code_snippet("containing_function_or_middleware")` to read the context.

**Verify**:
- The `unsafe-inline`/`unsafe-eval`/`*` value is part of an actual HTTP response header assignment or middleware config (not a string constant in a comment or docs) → **CONTINUE**
- The header value is set conditionally only for dev mode → **SKIP**
- The header is set on the response object (`response.headers[...]`, `res.setHeader(...)`, middleware `app.use(helmet(...))`) → **SUBMIT**
- It is only a string constant assigned to a variable but never sent in a response → **SKIP**

→ Submit: violated_invariant="security header [header] misconfigured; enables [clickjacking/XSS/downgrade attack]", severity=6, confidence=6, exposure="internet"

---

## Step 4 — Development server in production

**Python (Flask/FastAPI/Uvicorn):**
```
grep(pattern="app\.run\(.*debug\s*=\s*True|uvicorn\.run\(.*reload\s*=\s*True|DEBUG\s*=\s*True", max_matches=20)
```

**JavaScript / TypeScript (Node hot reload, nodemon):**
```
grep(pattern="nodemon|webpack.*hot|HMR|__DEV__|NODE_ENV.*development.*require", max_matches=20)
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
grep(pattern="config\.consider_all_requests_local\s*=\s*true|config\.cache_classes\s*=\s*false", max_matches=15)
```

**PHP:**
```
grep(pattern="display_errors\s*=\s*(On|1)|error_reporting\s*=\s*E_ALL", max_matches=15)
```

**.NET (web.config):**
```
grep(pattern="<compilation\s+debug\s*=\s*['\"]true['\"]|<customErrors\s+mode\s*=\s*['\"]Off['\"]", max_matches=15)
```

For each match: `sqz_read_file("matched_file")` to read the full file.

**Verify**:
- Setting is unconditional or at module level with no env-guard → **SUBMIT**
- Setting is inside `if os.environ.get('ENV') == 'development':`, `if NODE_ENV === 'development':`, or similar production-exclusive guard → **SKIP**
- Setting is in a dev-only file (`docker-compose.dev.yml`, `config/dev/`, `nodemon.json`) → **SKIP**

→ Submit: violated_invariant="development server mode enabled in production; stack traces/internals exposed to all clients", severity=7, confidence=6, exposure="internet"

---

## Step 5 — Rate limiting absent on auth endpoints

```
grep(pattern="@(app|router)\.(post|get)\(.*['\"][/]?(api/)?login|@(app|router)\.(post|get)\(.*['\"][/]?(api/)?register|@(app|router)\.(post|get)\(.*['\"][/]?(api/)?password", max_matches=30)
```

For each match: `get_code_snippet("containing_route_handler")` to read the full route definition.

**Verify**:
- No `@limiter.limit(...)`, no `rateLimit({...})` middleware argument, no `throttle(...)`, no `slowDown(...)`, no `express-rate-limit` applied to this route or its router group → **SUBMIT**
- Rate limiter is applied globally to all routes via `app.use(rateLimit(...))` → check if auth routes are covered; if covered → **SKIP**
- Rate limiter decorator or middleware IS present on this route → **SKIP**

→ Submit: violated_invariant="authentication endpoint [path] has no rate limiting; brute-force/credential stuffing at full request rate", severity=7, confidence=6, exposure="internet"

---

## Step 6 — Weak or default TLS configuration

**Python (ssl minimum version):**
```
grep(pattern="ssl\.PROTOCOL_TLSv1\b|ssl\.PROTOCOL_SSLv2|ssl\.PROTOCOL_SSLv3|SSLContext\(ssl\.PROTOCOL_TLS\b", max_matches=15)
```

**Go (weak cipher suites):**
```
grep(pattern="tls\.TLS_RSA_WITH_RC4|tls\.TLS_RSA_WITH_3DES|tls\.TLS_ECDHE.*RC4|tls\.TLS_ECDHE.*3DES|MinVersion\s*:\s*tls\.VersionTLS10", max_matches=15)
```

**Java (SSLv3 / TLSv1.0 enabled):**
```
grep(pattern="SSLContext\.getInstance\(['\"]SSL['\"]|SSLContext\.getInstance\(['\"]TLSv1['\"]|setEnabledProtocols.*SSLv3|setEnabledProtocols.*TLSv1\b", max_matches=15)
```

**C# (.NET):**
```
grep(pattern="SecurityProtocolType\.Ssl3|SecurityProtocolType\.Tls\b|SslProtocols\.Tls\b|SslProtocols\.Ssl3", max_matches=15)
```

→ Submit: violated_invariant="TLS configured with deprecated protocol [proto] or weak cipher suite; downgrade attack possible", severity=7, confidence=7, exposure="internet"

---

## Finish

Call `finish()` now with all hypotheses collected. Do not skip this.
