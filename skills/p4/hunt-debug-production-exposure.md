# SKILL: hunt-debug-production-exposure

You are a security researcher. Find debug, test, and development code reachable in production or staging. For each step: (1) locate the code, (2) read it, (3) look for the exact pattern described, (4) submit if found, (5) move on. Do not conclude early — work through every check.

---

## Step 1 — Read the routing table and find unconditional diagnostic routes

Call `search_graph` with `name_pattern="url|route|router|path|endpoint"` and `label="Module"` to find the file(s) where URL patterns are registered. Call `get_code_snippet` on the module, or use `read_file` to read the URL registration file.

In the route definitions, look for a block like:
```
urlpatterns += [
    path("debug/...", DebugView...),
    path("notification-debug/...", ...),
    path("benchmark/...", ...),
    path("test/...", ...),
]
```
where this `+=` block is OUTSIDE any `if settings.DEBUG:` or `if ENV != 'prod':` conditional.

**A — Unconditional diagnostic route**: a route appended to the URL table with a path that contains words like `debug`, `test`, `benchmark`, `memory`, `load`, `diagnostic` — registered without an environment guard.

→ Submit per route group: violated_invariant="[route paths] are registered unconditionally in the production route table with no environment guard; reachable from any deployment", severity=7, confidence=9.

---

## Step 2 — Find OTP/verification handlers and check for response-header leaks

From the route table: find handlers for SMS verification, phone registration, OTP delivery, or password reset. Call `get_code_snippet` on each.

Look for any line that sets a response header containing a verification code, OTP, or temporary secret:
```
response["X-Test-Code"] = code
response.headers["Debug-OTP"] = otp_value
headers = {"X-Test-Code": otp}
```

Check the condition: is this inside `if ENV != 'production':` or `if not IS_PROD:` or similar? If so, it fires on staging too.

**B — OTP in response header on non-production**: 
→ Submit: violated_invariant="[handler] places the OTP/verification code in HTTP response header [header name] when ENV != 'production'; any observer on staging reads the code and authenticates as any user without SMS delivery", severity=8, confidence=9.

---

## Step 3 — Find API documentation route and check its condition

In the route registration file: look for routes that serve API documentation — paths containing `swagger`, `redoc`, `openapi`, `api-docs`, `api/docs`.

Read the condition that gates them. The dangerous condition:
```
if settings.DEBUG or ENV == 'dev' or ENV == 'stage':
    urlpatterns += [path("swagger/", ...)]
```
This serves full API docs on staging.

**C — Documentation served on staging**:
→ Submit: violated_invariant="API documentation endpoint is served when ENV is 'stage' or 'dev', without access control; full API surface is publicly enumerable on staging", severity=5, confidence=9.

---

## Step 4 — Find computation/load-test handlers

From the route table: find any handler whose path contains `benchmark`, `load-test`, `memory-test`, `stress`, or similar. Call `get_code_snippet` on it.

Check: does it accept a numeric parameter (iteration count, size) from the request without an upper bound cap?

**D — Unbounded computation parameter**:
→ Submit: violated_invariant="[route] accepts a caller-supplied numeric parameter controlling computation depth/count with no cap; large values exhaust server CPU or memory", severity=4, confidence=8.

---

## Step 5 — Find monitoring route and check authentication

In the main URL file: look for an unconditional include of a metrics library's URLs:
```
path('', include('django_prometheus.urls'))
path('/metrics', metricsHandler)
app.use('/metrics', promClient.collectDefaultMetrics)
```

Check whether any authentication middleware or permission class is applied to this route.

**E — Unauthenticated monitoring endpoint**:
→ Submit: violated_invariant="metrics/monitoring endpoint is registered without authentication; internal request rates, error rates, and latency are publicly readable", severity=6, confidence=9.

---

## Finish

Call `finish()` now with all hypotheses collected. Do not skip this. Call it even if the list is empty.
