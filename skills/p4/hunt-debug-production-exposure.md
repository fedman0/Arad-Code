# SKILL: hunt-debug-production-exposure

## ⚡ BREADTH SCAN — grep-first, pattern-confirmed

Each step gives an exact grep pattern. Run it. If it matches, read the surrounding context with `get_code_snippet` or `read_file`, confirm the pattern, and submit immediately. 2 tool calls per step maximum.

---

## Step 1 — Unconditional diagnostic route registration

```
grep(pattern="urlpatterns\\s*\\+=|router\\.add.*debug|app\\.use.*debug|app\\.get.*debug|path.*debug|path.*benchmark|path.*load.test", max_matches=20)
```

For each match: look at the 5 lines before it. Is there an `if` guard checking `DEBUG`, `ENV`, `ENVIRONMENT`, `settings.DEBUG`, `IS_PROD`, `NODE_ENV` etc.? If the `+=` or route registration is NOT inside such an `if` block, the debug route is unconditional.

**A — Unconditional diagnostic route**:
→ Submit: violated_invariant="diagnostic/debug route is registered without environment guard; reachable from any deployment including production", severity=7, confidence=7, exposure="internet"

---

## Step 2 — OTP or verification code leaked in response header

```
grep(pattern="X-Test-Code|X-Otp|X-Debug|response\\[.*otp\\]|response\\[.*code\\]|headers\\[.*code\\]", max_matches=10)
```

Also try:
```
grep(pattern="response\\[\"X-|response\\.headers\\[\"X-|res\\.set.*X-Test|res\\.header.*otp", max_matches=10)
```

If found: check the condition — is it `if ENV != 'production'`, `if not IS_PROD`, `if DEBUG`, or similar? The header is still sent on staging/dev environments, leaking the OTP to any observer.

**B — OTP in response header on non-production**:
→ Submit: violated_invariant="verification code placed in HTTP response header when not in production; any observer on staging/dev reads the code and authenticates as any user", severity=8, confidence=7, exposure="internet"

---

## Step 3 — API documentation served on non-production environments

```
grep(pattern="swagger|redoc|openapi|api.docs|api-docs", max_matches=20)
```

For each route registration match: read the surrounding `if` condition. Is it gated by `ENV == 'stage'`, `ENV == 'dev'`, `DEBUG or ENV`, `NODE_ENV === 'development'`? If it includes staging in the condition, full API docs are publicly served on staging.

**C — API docs served on staging**:
→ Submit: violated_invariant="API documentation endpoint is served when ENV is 'stage'/'dev' without access control; full API surface is publicly enumerable on staging", severity=5, confidence=7, exposure="internet"

---

## Step 4 — Prometheus/metrics endpoint without authentication

```
grep(pattern="prometheus|django_prometheus|prom_client|promClient|metrics.*route|include.*metrics", max_matches=10)
```

For each match in a route registration file: is there an authentication middleware, `permission_classes`, or environment guard applied? If it's a bare unconditional include with no auth wrapper:

**E — Unauthenticated monitoring endpoint**:
→ Submit: violated_invariant="metrics endpoint registered without authentication or environment guard; internal request rates, error rates, and queue depths are publicly readable", severity=6, confidence=7, exposure="internet"

---

## Step 5 — Development server command in production container

```
grep(pattern="manage\\.py runserver|flask run|php -S|npm run dev|go run main|yarn dev|node.*server\\.js.*dev", max_matches=10)
```

If found in a deployment file (docker-compose.yml, Dockerfile, kubernetes manifest, supervisord.conf, Procfile, or shell entrypoint):

**F — Dev server in production**:
→ Submit: violated_invariant="application container starts with a development server command; dev servers are single-threaded, expose debug pages, and are not production-safe", severity=6, confidence=7, exposure="internet"

---

## Finish

Call `finish()` now with all hypotheses collected. Do not skip this.
