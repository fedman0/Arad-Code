# SKILL: hunt-debug-production-exposure

## Goal

Find debug, test, and development code that is reachable in production or staging environments. Navigate from the routing/config files — do not keyword-search. Read the code, check the conditions, submit or skip immediately.

---

## Step 1 — Read the routing file for unconditionally registered diagnostic routes

Use `get_architecture` to find the project structure. Read the main URL routing/configuration file(s) completely.

Look at how routes are registered. Are any grouped inside a conditional block that checks the environment or a debug flag? Now look for routes that appear diagnostic, test-only, or development-infrastructure-like — notification triggers, load generators, memory checkers, debug interaction endpoints — that are registered OUTSIDE any such conditional guard.

**Finding condition**: A diagnostic/test route is registered unconditionally — it is part of the production routing table regardless of environment.
→ **submit immediately**: violated_invariant="[route path] debug/test endpoint registered unconditionally; reachable in all deployed environments", severity=7, confidence=9.

Also note: routes registered behind a `DEBUG` check may still reach production if the application is misconfigured with `DEBUG=True` in staging (a separate but related risk — note it, do not submit unless you confirm DEBUG=True is plausible in staging based on config you read).

## Step 2 — Find authentication or OTP codes in response headers

Navigate from the routing file to the handlers for user registration, phone verification, OTP delivery, and password reset. Read those handlers.

Look for response construction: are any response headers set that include sensitive values (one-time codes, verification tokens, authentication credentials)?

**Finding condition**: A one-time code, OTP, or authentication token is placed in a response header under a condition weaker than `ENV == 'production'` (e.g., includes staging or preprod environments).
→ **submit immediately**: violated_invariant="one-time auth code placed in response header [header name] in non-production environments including staging; any observer can read it and authenticate as any user", severity=8, confidence=9.

## Step 3 — API documentation served in non-production environments

Navigate from the routing file to where API documentation (Swagger, OpenAPI, Redoc, or similar) routes are registered. Read the condition under which they are activated.

**Finding condition**: The documentation is served when `ENV` is staging, preprod, or any value other than strict production — meaning external users on staging can enumerate all API endpoints, parameters, and response schemas.
→ **submit immediately**: violated_invariant="API documentation served in [staging/preprod environment] without access control; full API surface is publicly enumerable", severity=5, confidence=9.

## Step 4 — Load or computation endpoints with unbounded input

Navigate from the routing file to any handler that performs a computation whose work scales with a caller-supplied parameter (iteration count, recursion depth, data size). Read the handler.

**Finding condition**: A caller-supplied numeric parameter controls unbounded CPU or memory work (e.g., recursive computation with no depth limit, N iterations with no cap), and the endpoint is accessible in any deployed environment (not only a local dev setup that never runs on a server).
→ **submit immediately**: violated_invariant="[endpoint] accepts caller-supplied computation depth/count with no upper bound; trivial DoS: caller supplies a large number and exhausts server CPU/memory", severity=4, confidence=8.

## Step 5 — Monitoring/metrics endpoint without authentication

Navigate from the routing file to any monitoring, metrics export, or internal health endpoint registrations. Read whether those routes have authentication middleware, guards, or IP restrictions.

**Finding condition**: A metrics or monitoring endpoint that discloses internal operational data (request counts, error rates, latencies, DB stats) is accessible without authentication.
→ **submit immediately**: violated_invariant="[path] monitoring endpoint publicly accessible without authentication; discloses internal request patterns and error rates, aiding targeted attacks", severity=6, confidence=9.

## Finish

Call finish() with all hypotheses. Call it now even if the list is empty.
