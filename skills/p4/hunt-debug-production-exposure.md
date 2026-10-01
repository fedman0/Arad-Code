# SKILL: hunt-debug-production-exposure

You are a security researcher. Find debug, test, and development code reachable in production or staging. Navigate the code — do not use search_graph or search_code.

---

## Step 1 — Read the route/URL configuration

Call `get_architecture`. Find where routes or URL patterns are defined. Read that file.

Look at every route registration. Are any inside a conditional block that checks the environment or a debug flag at startup? Note which diagnostic-looking routes are registered unconditionally (outside any such guard).

**A — Unconditional diagnostic route**
A route that looks like it triggers background jobs for all users, generates load, dumps internal state, or is only useful for development — but is registered unconditionally.

→ Submit: violated_invariant="[route path] is registered unconditionally in the production route table with no environment guard; reachable in every deployment", severity=7, confidence=9.

---

## Step 2 — Read registration/OTP handlers for response header leaks

From the route configuration: find handlers for user registration, phone verification, one-time code delivery, and password reset. Call `get_code_snippet` to read each.

In the response construction code: is a response header set that contains a one-time code, OTP, verification token, or temporary credential?

**B — Secret in response header in non-prod environments**
Is the header set under a condition that includes staging or preprod (e.g., `env != 'production'` is true on staging too)?

→ Submit: violated_invariant="[handler] places [code/token type] in HTTP response header [header name] in non-production environments including staging; any observer reads it and authenticates as any user without SMS delivery", severity=8, confidence=9.

---

## Step 3 — Find API documentation route and its condition

From the route configuration: find where API documentation (Swagger UI, OpenAPI, Redoc, developer reference) is registered. Read the condition under which it is enabled.

**C — Documentation served in staging/preprod**
If the condition is `env != 'production'` or `env in ('dev', 'stage')`, staging users can enumerate the full API surface.

→ Submit: violated_invariant="API documentation served in non-production environments including staging without access control; full API surface publicly enumerable on staging", severity=5, confidence=9.

---

## Step 4 — Find computation handlers with unbounded input

From the route configuration: find any handler that performs computation scaled by a caller-supplied number (iteration count, recursion depth, size). Call `get_code_snippet` to read it.

**D — No upper bound on computation parameter**
No cap on the caller-supplied number, and the endpoint is reachable in at least some deployed environment.

→ Submit: violated_invariant="[route path] performs [computation type] scaled by caller-supplied [field] with no upper bound; a large value exhausts server CPU or memory", severity=4, confidence=8.

---

## Step 5 — Find monitoring route and check its authentication

From the route configuration: find any route that exposes internal metrics, health details, or operational statistics. Read how the route is registered and what handler serves it.

**E — No authentication on monitoring endpoint**
The metrics/health endpoint is accessible without authentication.

→ Submit: violated_invariant="[route path] monitoring/metrics endpoint has no authentication; internal request rates, error rates, DB latency publicly readable", severity=6, confidence=9.

---

## Finish

Call `finish()` now with all hypotheses. Even if the list is empty.
