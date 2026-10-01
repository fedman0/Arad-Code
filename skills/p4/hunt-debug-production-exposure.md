# SKILL: hunt-debug-production-exposure

You are a security researcher. Find debug, test, and development code reachable in production or staging. Work in this order for every step: find the code → read it → check the condition → submit if found → move to the next step.

---

## Step 1 — Find the route table and look for unconditional diagnostic routes

Call `get_architecture` to understand the project.

Then use `search_graph` to find route registrations — search for nodes whose name contains terms like `route`, `url`, `endpoint`, `router`, `path`, `view`. Read the file that registers all routes or URL patterns for the application.

Look at every route registration. Are any inside a conditional block that checks the environment or a debug flag at startup? Note which routes with diagnostic-sounding URL paths are registered unconditionally (outside any such guard).

**A — Unconditional diagnostic route**
A route whose URL path contains words like `debug`, `test`, `load`, `memory`, `benchmark`, `diagnostic` — but is registered unconditionally, outside any environment or debug check.

→ Submit: violated_invariant="[route path] is registered unconditionally in the production route table with no environment guard; reachable in every deployment", severity=7, confidence=9.

---

## Step 2 — Find registration and verification handlers for response-header leaks

From the route table you already read: identify any handler for user registration, phone verification, one-time code delivery, or password reset. Call `get_code_snippet` to read each.

In the response construction code: is a response header set that contains a one-time code, OTP, verification token, or temporary credential?

**B — Secret in response header in non-production environments**
Is the header set under a condition that would also be true on staging (e.g., `env != 'production'`, `env in ('dev', 'stage')`)?

→ Submit: violated_invariant="[handler] places [code/token type] in HTTP response header [header name] in non-production environments including staging; any observer reads it and authenticates as any user without SMS delivery", severity=8, confidence=9.

---

## Step 3 — Find API documentation route and its condition

From the route table you already read: find where API documentation (Swagger UI, OpenAPI, Redoc, any developer reference) is registered. Read the condition under which it is enabled.

**C — Documentation served in staging/preprod**
If the condition is `env != 'production'` or `env in ('dev', 'stage')`, staging users can enumerate the full API surface.

→ Submit: violated_invariant="API documentation served in non-production environments including staging without access control; full API surface publicly enumerable on staging", severity=5, confidence=9.

---

## Step 4 — Find computation handlers with unbounded input

From the route table: find any handler that performs computation scaled by a caller-supplied number (iteration count, recursion depth, size, list length). Call `get_code_snippet` to read it.

**D — No upper bound on computation parameter**
No cap on the caller-supplied number, and the endpoint is reachable in at least some deployed environment.

→ Submit: violated_invariant="[route path] performs [computation type] scaled by caller-supplied [field] with no upper bound; a large value exhausts server CPU or memory", severity=4, confidence=8.

---

## Step 5 — Find monitoring route and check its authentication

From the route table you already read: find any route that exposes internal metrics, health details, or operational statistics (look for path segments like `metrics`, `health`, `status`, `stats`, `monitor`). Read how the route is registered and what handler serves it.

**E — No authentication on monitoring endpoint**
The metrics/health endpoint is accessible without authentication.

→ Submit: violated_invariant="[route path] monitoring/metrics endpoint has no authentication; internal request rates, error rates, DB latency publicly readable", severity=6, confidence=9.

---

## Finish

Call `finish()` now with all hypotheses found. Even if the list is empty.
