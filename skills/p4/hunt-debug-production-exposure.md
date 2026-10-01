# SKILL: hunt-debug-production-exposure

## Goal

Find development and test code that is reachable in production or staging environments — debug endpoints, secrets leaked in responses, and internal tooling with no environment gate.

---

## Step 0 — Orient yourself

Call `get_architecture`. Find:
- How does this project define its routes? (a URL config file, route annotations on controllers, a router module — depends on the language/framework)
- Where is application configuration and environment detection?

Read the route definitions completely. This is your main source for Steps 1 and 3.

---

## Step 1 — Unconditionally registered routes that should not exist in production

In the route definitions: routes are either registered unconditionally (they always exist) or conditionally (only when some environment check is true at startup).

Look at every route registration. For routes that exist for diagnostic, test, or internal tooling purposes — things that trigger background jobs for all users, generate synthetic load, expose internal system state, interact with test infrastructure — ask: is this registration inside a conditional block that checks the runtime environment or a debug flag?

The bug: a diagnostic route registered unconditionally is part of the production route table. It is reachable in any deployment.

→ **Submit per unconditional diagnostic route**: violated_invariant="[route path] is registered unconditionally; it exists in the production route table in every environment and is reachable without an environment gate", severity=7, confidence=9.

Note routes that ARE behind an environment check — write them down — but do not submit for those.

---

## Step 2 — Secrets or auth codes leaked in HTTP response headers

Navigate from the route definitions to the handlers for user registration, phone number verification, OTP delivery, and password reset. Read those handlers.

In the response construction: look for any place where a header is added to the HTTP response that contains a value the user should prove they received out-of-band (an OTP, a one-time code, a verification token, a temporary credential).

These are sometimes added for testing purposes, behind a condition. The bug is when that condition includes environments other than strictly local development — for example, `if env != 'production'` includes staging and preprod.

→ **Submit if found**: violated_invariant="[handler] places [credential/code type] in response header [header name] in non-production environments including staging; any network observer can read it and authenticate as the target user — bypassing the out-of-band delivery entirely", severity=8, confidence=9.

---

## Step 3 — API documentation with no access control

In the route definitions: find where API documentation (Swagger UI, OpenAPI explorer, API reference, developer docs) is registered. Read the condition under which it is enabled.

The bug: documentation is served whenever the environment is not strictly production — which means staging and preprod users can view the full API surface including all endpoints, their parameters, and response schemas.

→ **Submit if found**: violated_invariant="API documentation is served in [non-production environments including staging]; any user on those environments can enumerate the full API surface without authentication", severity=5, confidence=9.

---

## Step 4 — Endpoints that perform unbounded computation on caller-supplied input

In the route definitions: find any handler that performs a computation whose cost scales with a number supplied by the caller (iteration count, recursion depth, data size). Read that handler.

The bug: no upper bound on the caller-supplied number, and the endpoint is reachable in at least some deployed environment.

→ **Submit if found**: violated_invariant="[route path] performs [computation] scaled to caller-supplied parameter [field] with no upper bound; a caller supplies a large value to exhaust server CPU or memory", severity=4, confidence=8.

---

## Step 5 — Monitoring and metrics endpoints without authentication

In the route definitions: find any route that exposes internal system metrics, health details, or operational statistics. This could be a metrics exporter (Prometheus-style), an actuator endpoint (Spring-style), or a custom health check that returns internal state.

Read the route definition and its handler. Is there authentication middleware on this route? Can an unauthenticated caller access it?

→ **Submit if found**: violated_invariant="[route path] monitoring endpoint is accessible without authentication; exposes internal request rates, error rates, latency, and DB statistics — useful for targeting attacks", severity=6, confidence=9.

---

## Finish

Call finish() with all hypotheses. Do it now even if the list is empty.
