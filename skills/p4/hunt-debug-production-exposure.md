# SKILL: hunt-debug-production-exposure

## ⚡ BREADTH SCAN — grep-first, multi-language, pattern-confirmed

Patterns cover Python/Django, JavaScript/Express, Go, Java/Spring, PHP, Ruby/Rails. Run grep, read context, submit immediately. 2 tool calls per step maximum.

---

## Step 1 — Debug/diagnostic route registered without environment guard

```
grep(pattern="debug|benchmark|load.test|memory.test|stress.test|diagnostic", max_matches=40)
```

For each match in a route registration file (`urls.py`, `routes.js`, `router.go`, `web.php`, `routes.rb`, `*Controller*`): is the route inside an `if` block checking `DEBUG`, `NODE_ENV`, `ENVIRONMENT`, `IS_PROD`, `APP_ENV`, or similar? If the route is registered unconditionally:

**A — Unconditional diagnostic route**:
→ Submit: violated_invariant="debug/diagnostic route registered without environment guard; reachable from any deployment including production", severity=7, confidence=7, exposure="internet"

---

## Step 2 — Verification code or OTP placed in HTTP response header

```
grep(pattern="setHeader.*[Cc]ode|set.*header.*otp|res\\.set\\(.*[Cc]ode|response\\[.*[Cc]ode\\]|response\\.headers\\[.*code\\]|addHeader.*[Cc]ode|header.*otp.*=|otp.*header|verification.*header", max_matches=20)
```

Also:
```
grep(pattern="X-.*[Cc]ode.*=|X-.*[Oo]tp.*=|X-.*[Vv]erif|response.*header.*token.*=", max_matches=20)
```

For each match: is it inside a condition checking `ENV`, `NODE_ENV`, `DEBUG`, `IS_PROD`, or similar? Even a staging-only condition leaks the OTP to anyone who can observe HTTP responses.

**B — OTP/verification code in response header**:
→ Submit: violated_invariant="verification code placed in HTTP response header when not in production; any observer reads the code and authenticates as any user without OTP delivery", severity=8, confidence=7, exposure="internet"

---

## Step 3 — API documentation served on staging or dev environments

```
grep(pattern="swagger|redoc|openapi|api.docs|api-docs|springfox|springdoc|swaggerUi|swagger_urls", max_matches=30)
```

For each route registration match: read the condition. Is it gated by `ENV == 'stage'`, `NODE_ENV === 'development'`, `DEBUG or ENV == 'dev'`, `APP_ENV != 'production'`? If staging is included in the condition, full API schema is publicly available in staging.

**C — API docs served in non-production environments**:
→ Submit: violated_invariant="API documentation served when environment is staging/dev without access control; full API surface publicly enumerable", severity=5, confidence=7, exposure="internet"

---

## Step 4 — Unbounded computation parameter accepted from caller

```
grep(pattern="benchmark|load.test|memory.test|stress|iterations|repeat", max_matches=20)
```

For each match in a request handler: is a numeric parameter (`count`, `iterations`, `size`, `n`, `limit`) read from the request without an upper-bound cap before being used in a loop or repeated computation?

**D — Unbounded computation parameter**:
→ Submit: violated_invariant="handler accepts caller-supplied numeric parameter controlling computation with no cap; large values exhaust server CPU or memory (denial of service)", severity=4, confidence=7, exposure="internet"

---

## Step 5 — Metrics/monitoring endpoint without authentication

```
grep(pattern="prometheus|prom_client|promClient|django_prometheus|metrics.*router|metrics.*route|metrics.*path|/metrics|actuator/prometheus|micrometer", max_matches=20)
```

For each route registration match: is there an authentication middleware, `permission_classes`, `@Secured`, `passport.authenticate`, or equivalent applied? If it's an unconditional include with no auth wrapper:

**E — Unauthenticated monitoring endpoint**:
→ Submit: violated_invariant="metrics endpoint registered without authentication or environment guard; internal request rates, error counts, and latency are publicly readable", severity=6, confidence=7, exposure="internet"

---

## Step 6 — Development server used as production startup command

```
grep(pattern="manage\\.py runserver|flask run|php -S|npm run dev|go run main|nodemon|node.*server\\.js.*dev|yarn dev|rails server|rackup|puma.*development|mvn spring-boot:run", max_matches=20)
```

If found in a deployment file (docker-compose.yml, Dockerfile, Kubernetes manifest, Procfile, supervisord.conf, shell entrypoint):

**F — Dev server in production container**:
→ Submit: violated_invariant="application container starts with a development server; dev servers are single-threaded, expose debug info, and are not production-safe", severity=6, confidence=7, exposure="internet"

---

## Finish

Call `finish()` now with all hypotheses collected. Do not skip this.
