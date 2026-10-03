# SKILL: hunt-debug-production-exposure

## ⚡ BREADTH SCAN — grep-first, semgrep-derived patterns, multi-language

Run grep, read context, submit immediately. 2 tool calls per step max.

---

## Step 1 — Debug/diagnostic route registered without environment guard

```
grep(pattern="debug|benchmark|load.test|memory.test|stress.test|diagnostic", max_matches=40)
```

For each match in a route registration file (`urls.py`, `routes.js`, `router.go`, `web.php`, `routes.rb`, `*Controller*`, `Program.cs`): is the route inside an `if` block checking `DEBUG`, `NODE_ENV`, `ENVIRONMENT`, `IS_PROD`, `APP_ENV`, `ASPNETCORE_ENVIRONMENT`? If registered unconditionally:

**A — Unconditional diagnostic route**:
→ Submit: violated_invariant="debug/diagnostic route registered without environment guard; reachable from any deployment including production", severity=7, confidence=7, exposure="internet"

---

## Step 2 — Verification code or OTP placed in HTTP response header

```
grep(pattern="setHeader.*[Cc]ode|res\.set\(.*[Cc]ode|response\.headers\[.*code\]|addHeader.*[Cc]ode|response\.header.*[Cc]ode|HttpContext.*Response.*Headers.*[Cc]ode", max_matches=20)
```

Also:
```
grep(pattern="X-.*[Cc]ode\s*=|X-.*[Oo]tp\s*=|X-.*[Vv]erif|[Cc]onfirmation.*[Cc]ode.*header|header.*otp|otp.*header|verification.*header", max_matches=20)
```

For each match: is it inside a condition checking `ENV`, `NODE_ENV`, `DEBUG`, `IS_PROD`, or similar? Even staging-only still leaks to any HTTP observer.

**B — OTP/verification code in response header**:
→ Submit: violated_invariant="verification code placed in HTTP response header; any observer reads the code and authenticates as any user without OTP delivery", severity=8, confidence=7, exposure="internet"

---

## Step 3 — API documentation served without access control

**Swagger / OpenAPI (all frameworks):**
```
grep(pattern="swagger|redoc|openapi|api.docs|api-docs|swagger_urls|swaggerUi|SwaggerUI", max_matches=30)
```

**Spring Boot (springfox / springdoc):**
```
grep(pattern="springfox|springdoc|@EnableSwagger2|SwaggerConfig|Docket|OpenApiCustomiser", max_matches=20)
```

**C# (.NET / Swashbuckle):**
```
grep(pattern="UseSwagger|UseSwaggerUI|AddSwaggerGen|app\.UseSwagger", max_matches=20)
```

For each route registration: is it gated by `ENV == 'stage'` / `NODE_ENV !== 'production'` / `DEBUG` / `APP_ENV != 'production'`? No guard at all means production exposure.

**C — API docs without access control**:
→ Submit: violated_invariant="API documentation served without authentication or environment guard; full API surface publicly enumerable", severity=5, confidence=7, exposure="internet"

---

## Step 4 — Spring Boot Actuator fully exposed

**Properties file patterns:**
```
grep(pattern="management\.endpoints\.web\.exposure\.include\s*=\s*\*|management\.endpoint\..*\.enabled\s*=\s*true|endpoints\.web\.exposure\.include=\*", max_matches=20)
```

**YAML patterns:**
```
grep(pattern="exposure:\s*\n\s*include:\s*['\"]?\*['\"]?|include:\s*['\"]?\*['\"]?", max_matches=15)
```

**C# (.NET) debug compilation flag:**
```
grep(pattern="<compilation.*debug\s*=\s*['\"]true['\"]|compilation.*debug.*true", max_matches=10)
```

For Actuator findings: does Spring Security apply authentication specifically to `/actuator/**`? If not, `/actuator/env`, `/actuator/heapdump`, `/actuator/logfile` are public.

**D — Actuator/debug endpoint fully exposed**:
→ Submit: violated_invariant="[actuator/debug endpoint] accessible without authentication; internal env vars, heap dump, and log files are publicly readable", severity=7, confidence=7, exposure="internet"

---

## Step 5 — Metrics/monitoring endpoint without authentication

**Prometheus (all languages):**
```
grep(pattern="prometheus|prom_client|promClient|django_prometheus|metrics.*router|metrics.*route|/metrics|prom\.NewRegistry|PrometheusMiddleware", max_matches=20)
```

**Spring Actuator Prometheus:**
```
grep(pattern="actuator/prometheus|micrometer|MeterRegistry|PrometheusMeterRegistry", max_matches=15)
```

**Node / Express metrics:**
```
grep(pattern="express-prom-bundle|prom-client.*collectDefaultMetrics|app\.get.*['\"/]metrics['\"]", max_matches=15)
```

For each route registration: is there `permission_classes`, `@Secured`, `passport.authenticate`, `[Authorize]`, or equivalent? Unconditional include with no auth wrapper is a finding.

**E — Unauthenticated monitoring endpoint**:
→ Submit: violated_invariant="metrics endpoint registered without authentication; internal request rates, error counts, and latency are publicly readable", severity=6, confidence=7, exposure="internet"

---

## Step 6 — Development server used as production startup command

**Python:**
```
grep(pattern="manage\.py runserver|flask run|flask.*--debug|uvicorn.*--reload", max_matches=20)
```

**JavaScript / Node:**
```
grep(pattern="npm run dev|yarn dev|nodemon|ts-node-dev|node.*--inspect", max_matches=20)
```

**Java:**
```
grep(pattern="mvn spring-boot:run|\.\/mvnw spring-boot:run|gradle.*bootRun", max_matches=15)
```

**Go:**
```
grep(pattern="go run main|go run \.", max_matches=15)
```

**PHP:**
```
grep(pattern="php -S |php artisan serve", max_matches=15)
```

**Ruby:**
```
grep(pattern="rails server|rails s|rackup|bundle exec rails s|puma.*development", max_matches=15)
```

**C# / .NET:**
```
grep(pattern="dotnet watch|dotnet run.*Development|ASPNETCORE_ENVIRONMENT.*Development", max_matches=15)
```

If found in a deployment file (Dockerfile, docker-compose.yml, Kubernetes manifest, Procfile, supervisord.conf, shell entrypoint):

**F — Dev server in production container**:
→ Submit: violated_invariant="application container starts with a development server; dev servers are single-threaded, expose debug info, and are not production-safe", severity=6, confidence=7, exposure="internet"

---

## Finish

Call `finish()` now with all hypotheses collected. Do not skip this.
