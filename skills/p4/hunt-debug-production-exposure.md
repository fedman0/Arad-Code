# SKILL: hunt-debug-production-exposure

## ⚡ BREADTH SCAN — semgrep-PRO-derived patterns, 15+ languages

Run grep, read context with `get_code_snippet`, submit immediately. 2 tool calls per step max.

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

For each match: is the actuator bound to the same port as the app with no authentication? Check for `management.server.port`, `spring.security.user.name` / `spring.security.user.password`.

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

For each match: is the exception detail returned in the HTTP body to the caller, not just logged server-side?

→ Submit: violated_invariant="exception detail (stack trace/message) returned in HTTP response body; leaks internal paths, library versions, SQL queries", severity=6, confidence=6, exposure="internet"

---

## Step 6 — Debug endpoints / admin panels without auth

```
grep(pattern="['\"][/]debug['\"|/]|['\"][/]admin['\"|/]|['\"][/]_debug['\"|/]|['\"][/]phpinfo|['\"][/]server-status|['\"][/]metrics['\"|/]", max_matches=25)
```

For each match: does this route have auth middleware applied? Check for `@login_required`, `passport.authenticate`, `[Authorize]`, `authRequired`.

→ Submit: violated_invariant="debug/admin endpoint [path] accessible without authentication", severity=8, confidence=6, exposure="internet"

---

## Finish

Call `finish()` now with all hypotheses collected. Do not skip this.
