# SKILL: hunt-missing-authz-on-sensitive-endpoints

You are a security researcher. Find endpoints that handle sensitive operations without proper authentication, ownership verification, or request integrity validation. Work in this order for every step: find the code → read it → check the condition → submit if found → move to the next step.

---

## Step 1 — Find the routing table and sensitive handlers

Call `get_architecture` to understand the project structure.

Then use `search_graph` to find route and endpoint registrations — search for nodes whose name contains terms like `route`, `endpoint`, `url`, `view`, `handler`, `controller`, `router`. Every web framework in every language uses one of these terms for its route definitions.

Read the route files you find. From the URL paths and handler names visible in the route table, identify:
- **Financial routes**: any path segment containing words like `payment`, `wallet`, `billing`, `checkout`, `callback`, `subscribe`, `pay`, `transaction`
- **File/storage routes**: any path segment containing `file`, `upload`, `download`, `storage`, `asset`, `media`, `bucket`
- **Admin/privileged routes**: any path segment containing `admin`, `manage`, `dashboard`, `staff`, `superuser`

For each route you identify, call `get_code_snippet` with the handler's qualified name to read its implementation.

---

## Step 2 — Financial handlers: authentication and integrity

For each financial handler you read, check:

**A — No authentication required**
Is authentication enforced? Look for: permission class declarations, authentication decorators, guard annotations, middleware exclusion lists, `@require_login`, `auth()`, `IsAuthenticated`, `@Authenticated`, `security([])`. Is this endpoint accessible to unauthenticated callers?

→ Submit: violated_invariant="[handler] performs financial operation but is accessible without credentials", severity=9, confidence=9.

**B — External callback: no gateway signature verification**
If this handler receives notifications from an external payment provider: before it changes any state, does it verify a signature or HMAC provided by the gateway (computed over the request body and a shared secret)?

→ Submit: violated_invariant="[handler] processes external payment notifications without verifying they came from the legitimate provider; forged callbacks activate payment confirmation", severity=9, confidence=9.

**C — Sandbox/test bypass**
Is there a code branch for a sandbox, test, or mock payment provider that skips real gateway verification and directly triggers the "payment succeeded" action? Is that branch reachable from outside?

→ Submit: violated_invariant="[handler] sandbox/test path skips gateway verification; caller sets provider=sandbox (or equivalent) to activate a paid subscription without a real transaction", severity=9, confidence=9.

**D — Actor identity from request input**
Does the handler read the identity of the party being charged (user ID, account number, person ID) from the request body or query params, rather than from the verified session or token?

→ Submit: violated_invariant="[handler] reads actor identity from request input rather than verified session; caller names any person as the debited party", severity=9, confidence=9.

---

## Step 3 — File/storage handlers: ownership check

For each file/storage handler:

Trace from where the file identifier (key, name, ID) is read from the request to where the file or time-limited access URL is returned. Between those two points: is there a database lookup that verifies the requesting user owns or is authorized for that specific file?

**E — No ownership check**
→ Submit: violated_invariant="[handler] issues access to [file type] by caller-supplied identifier with no ownership verification; any authenticated user can access any file by its identifier", severity=7, confidence=9.

---

## Step 4 — Object-level authorization

For any handler that accepts an object identifier (record ID, account ID, config ID) from the request and operates on that object: read the data fetch.

Does the database query filter by both the object ID AND the requesting user's identity? Or does it fetch by object ID alone?

**F — No ownership filter in query**
→ Submit: violated_invariant="[handler] fetches [object type] by caller-supplied ID without filtering on the requesting user's identity; horizontal access to any record by ID enumeration", severity=7, confidence=8.

**G — Caller supplies a different user's ID**
Can the caller include a different user/person ID in the request body or params to access that other user's data?

→ Submit: violated_invariant="[handler] accepts user ID from request and returns data for that ID; caller can access any user's data by supplying their ID", severity=8, confidence=9.

---

## Step 5 — Admin handlers and diagnostic routes

**H — Admin handler with bypassable authorization**
For privileged handlers: is the authorization decision derived from the verified identity (from the session or token), or from a value the caller can set (header, body field)?

→ Submit: violated_invariant="[handler] grants admin access based on an attacker-controllable input rather than a server-side privilege record", severity=9, confidence=9.

**I — Commented-out authorization**
Is there a commented-out authorization requirement on a financial or admin handler?

→ Submit: violated_invariant="authorization check commented out in [handler]; the sensitive operation runs without privilege verification", severity=9, confidence=9.

**J — Diagnostic route registered unconditionally**
In the route definitions: is any route that looks like a diagnostic, test, or internal tooling endpoint registered without a conditional environment check?

→ Submit: violated_invariant="[route path] diagnostic endpoint registered unconditionally; reachable in production with no environment gate", severity=7, confidence=9.

**K — Monitoring endpoint without authentication**
Is there a metrics, observability, or health-detail route with no authentication?

→ Submit: violated_invariant="[route path] monitoring endpoint is unauthenticated; internal metrics publicly accessible", severity=6, confidence=9.

---

## Finish

Call `finish()` now with all hypotheses found. Even if the list is empty.
