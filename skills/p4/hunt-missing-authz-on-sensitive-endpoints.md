# SKILL: hunt-missing-authz-on-sensitive-endpoints

## Goal

Find endpoints that perform sensitive operations — financial, file access, privileged actions — without properly verifying that the caller is who they claim to be, owns the resource they're accessing, or has the privilege the operation requires.

---

## Step 0 — Orient yourself

Call `get_architecture`. Understand the project structure and how routes are defined in this framework. Then read the route/URL definitions — find all the endpoints.

Identify the sensitive categories:
- **Financial**: payment processing, wallet operations, subscription, billing — anything involving money movement
- **File/media**: endpoints that return, stream, or issue time-limited access URLs for stored files
- **Privileged/admin**: endpoints that operate on data belonging to all users, or that require elevated privilege
- **External callbacks**: endpoints called by external services (payment gateways, notification providers)

Navigate to each category's handlers and read them. The findings below describe what to look for.

---

## Step 1 — Financial handlers: who can call this, and is the caller verified?

For each financial handler:

**No authentication**: can an unauthenticated caller (no credential at all) invoke this endpoint?
→ Submit: violated_invariant="[handler] performs [operation] and is accessible without credentials", severity=9, confidence=9.

**No gateway signature verification** (for external payment callbacks): the endpoint receives notifications from a payment gateway. Is the incoming request verified against a signature or HMAC provided by the gateway, before any state change? Without this, anyone can POST a fake payment confirmation.
→ Submit: violated_invariant="[handler] processes external payment notifications without verifying they came from the legitimate gateway; attacker can forge a payment confirmation", severity=9, confidence=9.

**Sandbox bypass**: is there a branch for a test or sandbox payment provider that skips real verification and goes directly to the "payment succeeded" action? Is this branch reachable from outside?
→ Submit: violated_invariant="[handler] sandbox/test path skips gateway verification; attacker requests [sandbox provider value] to trigger payment success without a real transaction", severity=9, confidence=9.

**Caller supplies the actor**: does the handler read the identity of the party being charged (employee ID, user ID, account) from the request body or params, rather than deriving it from the authenticated session?
→ Submit: violated_invariant="[handler] reads [field] from request body as the charged party; any caller can name any person as the debited party", severity=9, confidence=9.

---

## Step 2 — File/media handlers: ownership check

For each handler that returns a file or issues a time-limited access URL for stored content:

Trace from where the file identifier is read from the request to where the file or URL is returned. Between those two points, is there a lookup that confirms the requesting user is the owner or an authorized accessor of that specific file?

→ If no ownership check: Submit: violated_invariant="[handler] issues access to [file/object] using caller-supplied identifier [field] with no ownership verification; any authenticated user can access any [file type] by its identifier", severity=7, confidence=9.

---

## Step 3 — Object-level authorization (BOLA)

For endpoints that accept an identifier (record ID, object ID, account ID) from the request and perform an action on or return data about that specific object:

Read the data fetch. Does the query filter by BOTH the object ID AND the authenticated user's identity? Or does it fetch by object ID alone?

A query like `findById(caller_supplied_id)` with no co-filter on the authenticated user → any authenticated user can access any record by changing the ID.

Also: can the caller supply a different user's ID directly in the request to access that user's data?

→ Submit per instance: violated_invariant="[handler] fetches [object type] by caller-supplied [field] without binding the result to the authenticated user; horizontal access to any [object type] by ID enumeration", severity=7, confidence=8.

---

## Step 4 — Unconditionally registered diagnostic routes

Go back to the route definitions. Look at how routes are registered — are any inside a conditional block that checks the runtime environment or a debug flag?

For any route that looks like it should only exist in development or test environments (triggers background jobs for all users, generates load, interacts with test infrastructure): is it registered unconditionally — present in the production route table regardless of environment?

→ Submit: violated_invariant="[route path] diagnostic/test endpoint is registered unconditionally; it is reachable in production with no environment gate", severity=7, confidence=9.

Also look for monitoring or metrics endpoints. Are they accessible without authentication?
→ Submit: violated_invariant="[route path] monitoring endpoint has no authentication; internal operational metrics are publicly readable", severity=6, confidence=9.

---

## Step 5 — Admin handler authorization

For handlers that perform privileged operations (operating on all users' data, managing application-wide config, bulk actions):

Read the authorization check. Trace where the decision comes from — does it use:
- A property of the authenticated identity from the verified session/token (trustworthy), OR
- A value from the request (header, body, query param) that the caller controls?

Is there a commented-out authorization block?

→ Submit per issue: violated_invariant="[handler] [admin operation] uses [input source] for its authorization decision, which the caller controls; or: authorization block is commented out", severity=9, confidence=9.

---

## Finish

Call finish() with all hypotheses. Do it now even if the list is empty. Reduce confidence rather than raising blocking questions.
