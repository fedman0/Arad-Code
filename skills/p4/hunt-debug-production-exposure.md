# SKILL: hunt-debug-production-exposure

## ⚡ BREADTH SCAN — semgrep-PRO-derived patterns, 15+ languages

**grep = CANDIDATES only.** Read the file/config context before submitting — a debug flag in a dev config file is not a finding.

---

## CONFIG VERIFICATION PROTOCOL — run for every match before submitting

For each grep match:

**a.** `read_file("matched_file")` or `get_code_snippet("match_location")` — read the full config/handler context.

**b.** Confirm production scope:
- File is in `config/dev/`, `*test*`, `*development*`, `local_settings.py`, `test.yml`, `docker-compose.dev.yml` → **SKIP** (dev-only file)
- File is `production.py`, `application.yml`, `application.properties`, `.env`, `config.py`, `app.py`, `web.config`, or any non-environment-gated file → **CONTINUE**

**c.** Check for conditional override:
- Setting is guarded by `if env != 'production'`, `if NODE_ENV === 'development'`, `if os.getenv('ENV') == 'development'` → **SKIP**
- Setting is unconditional or defaults to unsafe value with no production override → **SUBMIT**

---

## Step 1 — Framework debug mode enabled

**Python Flask:**
```
grep(pattern="app\.run\(.*debug\s*=\s*True|app\.debug\s*=\s*True|FLASK_DEBUG\s*=\s*['\"]?(1|true|True)|FLASK_ENV\s*=\s*['\"]?development", max_matches=15)
```

**Python Django:**
```
grep(pattern="DEBUG\s*=\s*True|DEBUG\s*=.*\(\s*['\"]\w*DEBUG['\"]\s*,\s*(default\s*=\s*)?(True|['\"](True|true|1)['\"])", max_matches=15)
```

**Ruby Rails:**
```
grep(pattern="config\.consider_all_requests_local\s*=\s*true", max_matches=15)
```

**Go (Gin):**
```
grep(pattern="gin\.SetMode\s*\(\s*gin\.DebugMode\s*\)|GIN_MODE\s*[=:]\s*['\"]?debug", max_matches=15)
```

**PHP:**
```
grep(pattern="display_errors\s*=\s*(On|on|1|true)|ini_set\s*\(\s*['\"]display_errors['\"]\s*,\s*['\"]?(1|On|on|true)|APP_DEBUG\s*=\s*true|DISPLAY_ERRORS.*true", max_matches=15)
```

**Node / Express:**
```
grep(pattern="NODE_ENV\s*[=:]\s*['\"]?development|app\.use\s*\(\s*error[Hh]andler\s*\(|require\s*\(\s*['\"]errorhandler['\"]\s*\)", max_matches=15)
```

**Java Spring devtools:**
```
grep(pattern="spring-boot-devtools|spring\.devtools\.restart\.enabled\s*=\s*true|spring\.devtools\.livereload|spring\.devtools\.remote\.secret", max_matches=15)
```

**.NET (web.config / ASP.NET Core):**
```
grep(pattern="<compilation\b[^>]*\bdebug\s*=\s*['\"]true['\"]|<customErrors\b[^>]*\bmode\s*=\s*['\"]Off['\"]|UseDeveloperExceptionPage\s*\(", max_matches=15)
```

**Kotlin Ktor:**
```
grep(pattern="development\s*=\s*true|io\.ktor\.development\s*=\s*true|respond\w*\s*\(.*(stackTraceToString|printStackTrace)", max_matches=15)
```

For each match: is this in a production config file or guarded by env check? Look for `if env == 'production': DEBUG = False` overrides. Framework specifics:
- Spring devtools is disabled automatically when the app runs as a packaged jar and is normally declared `<optional>true</optional>` / `developmentOnly` → **SKIP** unless `spring.devtools.remote.secret` is set or devtools is forced on in production.
- ASP.NET Core `UseDeveloperExceptionPage()` inside `if (env.IsDevelopment())` → **SKIP**.
- Gin debug mode only adds console logging; report it only at lower severity (4) unless handlers also return error details (Step 5).

→ Submit: violated_invariant="debug mode enabled unconditionally; stack traces and internal state exposed to all HTTP clients", severity=7, confidence=7, exposure="internet", cwe="CWE-489"

---

## Step 2 — Spring Boot Actuator fully exposed

```
grep(pattern="management\.endpoints\.web\.exposure\.include\s*[=:].*(\*|\benv\b|heapdump|shutdown|jolokia|threaddump)|^\s*include:\s*['\"]?\*|management\.endpoint\.(env|heapdump|shutdown)\.(enabled\s*[=:]\s*true|access\s*[=:]\s*unrestricted)", max_matches=15)
```

```
grep(pattern="@Bean.*ManagementContextConfiguration|EndpointWebMvcAutoConfiguration", max_matches=15)
```

For each match: `read_file` the matched `application.properties` / `application.yml` (and any `application-prod.*` profile) to read the full config.

**Verify**:
- `management.server.port` set to a DIFFERENT port than main app AND that port is not internet-exposed → lower severity; if port is exposed → **SUBMIT**
- `management.server.port` absent (defaults to same port as app) → **CONTINUE**
- `spring.security.user.name` / `spring.security.user.password` or Spring Security configured with actuator auth → **SKIP**
- No auth configuration, same port as main app → **SUBMIT**

→ Submit: violated_invariant="Spring Actuator exposes all endpoints including /env, /heapdump, /shutdown with no authentication", severity=9, confidence=7, exposure="internet", cwe="CWE-200"

---

## Step 3 — Swagger / OpenAPI exposed in production

**C# (Swashbuckle):**
```
grep(pattern="app\.UseSwagger(UI)?\s*\(|[Ss]ervices\.AddSwaggerGen", max_matches=15)
```

**Python (FastAPI / drf-yasg / flasgger):**
```
grep(pattern="FastAPI\s*\(|get_schema_view\s*\(|SpectacularSwaggerView|Swagger\s*\(\s*app|swagger_ui_parameters|swagger_ui_oauth2_redirect_url", max_matches=15)
```

**Node (swagger-ui-express / @nestjs/swagger):**
```
grep(pattern="swaggerUi\.serve|swaggerUi\.setup|SwaggerModule\.setup|DocumentBuilder\(\)", max_matches=15)
```

**Java (springdoc / springfox):**
```
grep(pattern="springdoc-openapi|springdoc\.(api-docs|swagger-ui)\.enabled\s*[=:]\s*true|springfox\.documentation\.swagger-ui\.enabled\s*[=:]\s*true|@EnableSwagger2", max_matches=15)
```

For each match: is the Swagger endpoint guarded by auth middleware or restricted to `ENV != production`? FastAPI and springdoc serve docs by default once present — **SKIP** when disabled for production (`FastAPI(docs_url=None, redoc_url=None, openapi_url=None)`, `springdoc.api-docs.enabled=false` in the prod profile).

→ Submit: violated_invariant="Swagger UI accessible without authentication; enumerates all API endpoints, params, and auth schemes", severity=6, confidence=7, exposure="internet", cwe="CWE-200"

---

## Step 4 — GraphQL introspection enabled

```
grep(pattern="introspection\s*[=:]\s*true|__schema|disableIntrospection\s*[=:]\s*false|NoIntrospection.*false|GRAPHQL_INTROSPECTION\s*=\s*true", max_matches=15)
```

```
grep(pattern="graphql-playground|GraphiQL.*true|graphiql\s*[=:]\s*(True|true)|ApolloServer.*introspection.*true|makeExecutableSchema.*introspection", max_matches=15)
```

For each match: verify this runs in production (not `NODE_ENV === 'development'` guard).

→ Submit: violated_invariant="GraphQL introspection enabled in production; full schema enumeration including internal types available to unauthenticated callers", severity=5, confidence=6, exposure="internet", cwe="CWE-200"

---

## Step 5 — Stack trace / exception detail returned to clients

**Generic exception details in HTTP response:**
```
grep(pattern="return.*str\s*\(\s*(e|ex|exc|err|error)\s*\)|return.*traceback|traceback\.format_exc\s*\(|JsonResponse.*exception|res\.(status\s*\(\s*\d+\s*\)\.)?(send|json)\s*\(\s*(err|error)\s*\)|res\.(status\s*\(\s*\d+\s*\)\.)?(send|json)\s*\(.*\b(err|error|e)\.(message|stack)\b|return.*error=str\(e\)", max_matches=25)
```

**Java / Kotlin (stack trace or exception message written to the response):**
```
grep(pattern="\.printStackTrace\s*\(\s*(response|resp|res|out|writer|pw|new\s+PrintWriter)|getWriter\s*\(\s*\)\.(print|println|write)\s*\(.*(getMessage|getStackTrace|stackTraceToString)\s*\(|ResponseEntity.*\.getMessage\s*\(\s*\)|include-(stacktrace|message|exception)\s*[=:]\s*['\"]?(always|true)", max_matches=20)
```

A bare `e.printStackTrace()` writes to the server's stderr/log, not to the client — it is not a finding for this step.

For each match: `get_code_snippet("containing_handler")` to read the full exception handler.

**Verify**:
- `str(e)`, `traceback`, `err`, or `e.getMessage()` is written directly to the HTTP response body (`return JsonResponse(...)`, `res.send(err)`, `res.json({error: err})`) → **SUBMIT**
- The exception is only `logger.error(e)` or written to a log file, not the response → **SKIP**
- The response returns a generic message (`{"error": "Internal server error"}`) with details only in logs → **SKIP**

→ Submit: violated_invariant="exception detail (stack trace/message) returned in HTTP response body; leaks internal paths, library versions, SQL queries", severity=6, confidence=6, exposure="internet", cwe="CWE-209"

---

## Step 6 — Debug endpoints / admin panels without auth

```
grep(pattern="['\"]/(debug|admin|_debug|metrics)['\"/]|['\"]/?__debug__/|['\"]/(phpinfo|server-status)|\bphpinfo\s*\(\s*\)|net/http/pprof|spring\.h2\.console\.enabled\s*[=:]\s*true", max_matches=25)
```

For each match: `get_code_snippet("containing_handler_or_route_registration")` to read the route definition and handler.

**Verify**:
- No auth decorator (`@login_required`, `@Secured`, `[Authorize]`), no middleware argument (`passport.authenticate`, `requireAuth`, `authRequired`), and not inside an auth-required router group → **SUBMIT**
- Auth enforced by a global middleware (e.g., `app.before_request` always checks auth) → check if this route is excluded via an allowlist; if excluded → **SUBMIT**; if covered → **SKIP**
- Auth is present → **SKIP**
- `import _ "net/http/pprof"` registers `/debug/pprof/*` on `http.DefaultServeMux` — a finding when the default mux is served on a reachable port without auth.

→ Submit: violated_invariant="debug/admin endpoint [path] accessible without authentication", severity=8, confidence=6, exposure="internet", cwe="CWE-306"

---

## Step 7 — Django ALLOWED_HOSTS wildcard (Host header poisoning)

```
grep(pattern="ALLOWED_HOSTS\s*=.*['\"]\*['\"]", max_matches=15)
```

`ALLOWED_HOSTS = []` is Django's safe default (with `DEBUG=False` every host is rejected; with `DEBUG=True` only localhost is accepted) — it is NOT a finding. The risky value is `'*'` (directly, or as an env default such as `os.environ.get("ALLOWED_HOSTS", "*")`).

For each match: confirm it is the production settings module (protocol step b) and that `'*'` is not overridden later for production. Host header validation is then disabled, so `request.get_host()` / `build_absolute_uri()` trust the attacker's Host header (password-reset link and cache poisoning).

→ Submit: violated_invariant="Django ALLOWED_HOSTS accepts any Host header ('*'); attacker-controlled Host flows into absolute URLs such as password reset links", severity=5, confidence=6, exposure="internet", cwe="CWE-20"

---

## Finish

Call `finish()` now with all hypotheses collected. Do not skip this.
