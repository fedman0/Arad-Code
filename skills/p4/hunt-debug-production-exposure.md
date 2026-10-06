# SKILL: hunt-debug-production-exposure

## ⚡ BREADTH SCAN — semgrep-PRO-derived patterns, 15+ languages

**grep = CANDIDATES only.** Read the file/config context before submitting — a debug flag in a dev config file is not a finding.

---

## CONFIG VERIFICATION PROTOCOL — run for every match before submitting

For each grep match:

**a.** `sqz_read_file("matched_file")` or `get_code_snippet("match_location")` — read the full config/handler context.

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
grep(pattern="app\.run\(.*debug\s*=\s*True|FLASK_DEBUG\s*=\s*1|FLASK_ENV\s*=\s*['\"]development['\"]", max_matches=15)
```

**Python Django:**
```
grep(pattern="DEBUG\s*=\s*True", max_matches=15)
```

**Ruby Rails:**
```
grep(pattern="config\.consider_all_requests_local\s*=\s*true|config\.log_level\s*=\s*:debug.*production", max_matches=15)
```

**Go (Gin):**
```
grep(pattern="gin\.SetMode\s*\(\s*gin\.DebugMode\s*\)|gin\.Default\s*\(\s*\)", max_matches=15)
```

**PHP:**
```
grep(pattern="display_errors\s*=\s*(On|1)|error_reporting\s*=\s*(E_ALL|-1)|DISPLAY_ERRORS.*true", max_matches=15)
```

**Node / Express:**
```
grep(pattern="NODE_ENV\s*[=:]\s*['\"]development['\"]|app\.use\s*\(\s*errorHandler|morgan\s*\(\s*['\"]dev['\"]", max_matches=15)
```

**Java Spring devtools:**
```
grep(pattern="spring-boot-devtools|spring\.devtools\.restart\.enabled\s*=\s*true|spring\.devtools\.livereload", max_matches=15)
```

**.NET web.config:**
```
grep(pattern="<compilation\s+debug\s*=\s*['\"]true['\"]|<customErrors\s+mode\s*=\s*['\"]Off['\"]", max_matches=15)
```

**Kotlin Ktor:**
```
grep(pattern="development\s*=\s*true|install\s*\(\s*CallLogging\s*\).*DEBUG|printStackTrace\s*\(", max_matches=15)
```

For each match: is this in a production config file or guarded by env check? Look for `if env == 'production': DEBUG = False` overrides.

→ Submit: violated_invariant="debug mode enabled unconditionally; stack traces and internal state exposed to all HTTP clients", severity=7, confidence=7, exposure="internet"

---

## Step 2 — Spring Boot Actuator fully exposed

```
grep(pattern="management\.endpoints\.web\.exposure\.include\s*=\s*\*|management\.endpoint\.env\.enabled\s*=\s*true|management\.endpoint\.heapdump\.enabled\s*=\s*true", max_matches=15)
```

```
grep(pattern="@Bean.*ManagementContextConfiguration|EndpointWebMvcAutoConfiguration", max_matches=15)
```

For each match: `sqz_read_file("application.properties")` or `sqz_read_file("application.yml")` to read the full config.

**Verify**:
- `management.server.port` set to a DIFFERENT port than main app AND that port is not internet-exposed → lower severity; if port is exposed → **SUBMIT**
- `management.server.port` absent (defaults to same port as app) → **CONTINUE**
- `spring.security.user.name` / `spring.security.user.password` or Spring Security configured with actuator auth → **SKIP**
- No auth configuration, same port as main app → **SUBMIT**

→ Submit: violated_invariant="Spring Actuator exposes all endpoints including /env, /heapdump, /shutdown with no authentication", severity=9, confidence=7, exposure="internet"

---

## Step 3 — Swagger / OpenAPI exposed in production

**C# (Swashbuckle):**
```
grep(pattern="app\.UseSwagger\s*\(\s*\)|app\.UseSwaggerUI\s*\(\s*\)|services\.AddSwaggerGen", max_matches=15)
```

**Python (FastAPI / drf-yasg / flasgger):**
```
grep(pattern="swagger_ui_oauth2_redirect_url|include_in_schema\s*=\s*True|swagger_ui_parameters|Swagger\(app\)", max_matches=15)
```

**Node (swagger-ui-express / @nestjs/swagger):**
```
grep(pattern="swaggerUi\.serve|swaggerUi\.setup|SwaggerModule\.setup|DocumentBuilder\(\)", max_matches=15)
```

**Java (springdoc / springfox):**
```
grep(pattern="springdoc\.api-docs\.enabled\s*=\s*true|springfox\.documentation\.swagger-ui\.enabled\s*=\s*true|@EnableSwagger2", max_matches=15)
```

For each match: is the Swagger endpoint guarded by auth middleware or restricted to `ENV != production`?

→ Submit: violated_invariant="Swagger UI accessible without authentication; enumerates all API endpoints, params, and auth schemes", severity=6, confidence=7, exposure="internet"

---

## Step 4 — GraphQL introspection enabled

```
grep(pattern="introspection\s*[=:]\s*true|__schema|disableIntrospection\s*[=:]\s*false|NoIntrospection.*false|GRAPHQL_INTROSPECTION\s*=\s*true", max_matches=15)
```

```
grep(pattern="graphql-playground|GraphiQL.*true|ApolloServer.*introspection.*true|makeExecutableSchema.*introspection", max_matches=15)
```

For each match: verify this runs in production (not `NODE_ENV === 'development'` guard).

→ Submit: violated_invariant="GraphQL introspection enabled in production; full schema enumeration including internal types available to unauthenticated callers", severity=5, confidence=6, exposure="internet"

---

## Step 5 — Stack trace / exception detail returned to clients

**Python (Django ALLOWED_HOSTS):**
```
grep(pattern="ALLOWED_HOSTS\s*=\s*\[\s*['\"][*]['\"]|ALLOWED_HOSTS\s*=\s*\[\s*\]", max_matches=15)
```

**Generic exception details in HTTP response:**
```
grep(pattern="return.*str\s*\(\s*e\s*\)|return.*traceback|JsonResponse.*exception|res\.send\s*\(\s*err\s*\)|res\.json\s*\(\s*\{\s*error.*err\s*\}|return.*error=str\(e\)", max_matches=25)
```

**Java / Kotlin (printStackTrace in web handler):**
```
grep(pattern="e\.printStackTrace\s*\(\s*\)|\.printStackTrace\s*\(\s*response|\.fillInStackTrace", max_matches=20)
```

For each match: `get_code_snippet("containing_handler")` to read the full exception handler.

**Verify**:
- `str(e)`, `traceback`, `err`, or `e.getMessage()` is written directly to the HTTP response body (`return JsonResponse(...)`, `res.send(err)`, `res.json({error: err})`) → **SUBMIT**
- The exception is only `logger.error(e)` or written to a log file, not the response → **SKIP**
- The response returns a generic message (`{"error": "Internal server error"}`) with details only in logs → **SKIP**

→ Submit: violated_invariant="exception detail (stack trace/message) returned in HTTP response body; leaks internal paths, library versions, SQL queries", severity=6, confidence=6, exposure="internet"

---

## Step 6 — Debug endpoints / admin panels without auth

```
grep(pattern="['\"][/]debug['\"|/]|['\"][/]admin['\"|/]|['\"][/]_debug['\"|/]|['\"][/]phpinfo|['\"][/]server-status|['\"][/]metrics['\"|/]", max_matches=25)
```

For each match: `get_code_snippet("containing_handler_or_route_registration")` to read the route definition and handler.

**Verify**:
- No auth decorator (`@login_required`, `@Secured`, `[Authorize]`), no middleware argument (`passport.authenticate`, `requireAuth`, `authRequired`), and not inside an auth-required router group → **SUBMIT**
- Auth enforced by a global middleware (e.g., `app.before_request` always checks auth) → check if this route is excluded via an allowlist; if excluded → **SUBMIT**; if covered → **SKIP**
- Auth is present → **SKIP**

→ Submit: violated_invariant="debug/admin endpoint [path] accessible without authentication", severity=8, confidence=6, exposure="internet"

---

## Finish

Call `finish()` now with all hypotheses collected. Do not skip this.
