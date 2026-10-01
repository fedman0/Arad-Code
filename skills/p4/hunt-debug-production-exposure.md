# SKILL: hunt-debug-production-exposure

## Goal

Find debug, test, and development code that is reachable in production or staging environments. For each step: search, read, decide, submit immediately. Do not investigate exhaustively.

---

## Step 1 — Debug URL routes registered unconditionally

Read the main URL routing file(s) of the application (search_graph for the URL router/dispatcher; in Django: `urls.py`, Express: `routes/`, Spring: `@RequestMapping`, Laravel: `routes/`, Rails: `routes.rb`).
Look for debug/test URL registrations outside any `if DEBUG:` / `if ENV == 'development':` / `if (process.env.NODE_ENV === 'development')` guard.
**Finding condition**: any route whose name/path contains `debug`, `test`, `notification-debug`, `load-test`, `memory-test`, `dev-only` is registered unconditionally in the production routing table.
→ **submit hypothesis immediately**: violated_invariant="debug/test URL route registered unconditionally; reachable in all environments", severity=7, confidence=9.

## Step 2 — One-time code or secret returned in response header

Search for response header assignments containing test codes, OTPs, or tokens (search_code for `X-Test-Code`, `X-OTP`, `X-Debug`, `X-Token`, `X-Verification`; also search for `headers=` dicts in view/controller code near `otp`, `code`, `verification`).
Read the code that sets the header. Note the condition — is it gated on a strict debug-only flag?
**Finding condition**: OTP, verification code, or authentication token is written into a response header under a condition weaker than `DEBUG=True` (e.g., `ENV != 'prod'` includes staging, or no condition at all).
→ **submit hypothesis immediately**: violated_invariant="one-time authentication code leaked in HTTP response header; any observer on staging can read it and authenticate as any user", severity=8, confidence=9.

## Step 3 — API schema/documentation served in non-prod environments

Search for API documentation route registration (search_code for `swagger`, `openapi`, `api-docs`, `redoc`, `schema_view`).
Find the condition under which the docs are served.
**Finding condition**: condition is `ENV in ('dev', 'stage')` or similar, meaning staging users can access full API schema; OR the docs are served unconditionally.
→ **submit hypothesis immediately**: violated_invariant="API schema/documentation served in staging without access control; exposes all endpoint signatures", severity=5, confidence=9.

## Step 4 — Load or stress test endpoints with unbounded computation

Search for load-test or benchmark routes (search_code for `load-test`, `stress-test`, `fib`, `fibonacci`, `cpu-test`, `memory-test`).
Read the handler. Check if user-supplied input controls an expensive computation (iteration count, recursion depth) without an upper bound.
**Finding condition**: endpoint accepts a numeric parameter that controls unbounded CPU/memory work, and is accessible in production or behind only `DEBUG=True` (which may be set on staging).
→ **submit hypothesis immediately**: violated_invariant="load-test endpoint with unbounded computation reachable outside local dev; supplies a trivial DoS primitive", severity=4, confidence=8.

## Step 5 — Metrics/health endpoint without authentication

Search for monitoring/metrics route registration (search_code for `metrics`, `prometheus`, `actuator`, `healthz`, `/health`).
Read how the route is registered. Is there authentication middleware on the route?
**Finding condition**: metrics or internal status endpoint is accessible without authentication or IP restriction.
→ **submit hypothesis immediately**: violated_invariant="metrics/monitoring endpoint exposed without authentication; discloses request rates, error rates, latency by endpoint — aids targeted attacks", severity=6, confidence=9.

## Finish

Call finish() with all hypotheses found. Call it now even if the list is empty.
