# SKILL: hunt-missing-authz-on-sensitive-endpoints

## Goal

Find endpoints handling sensitive operations that lack authentication, ownership verification, or request integrity validation. Navigate from the routing file — do not keyword-search. Read the code, check the authorization conditions, submit or skip immediately.

---

## Step 1 — Read the routing file and navigate to sensitive handlers

Use `get_architecture` to find the project structure. Read the main routing/URL configuration file(s) completely.

Identify the handlers for:
- Financial operations: payment processing, wallet operations, subscription purchase, billing callbacks from external providers
- File or media access: endpoints that retrieve, stream, or issue access URLs for user-uploaded content
- Administrative or bulk operations: endpoints that operate across users' data or require elevated privilege

Navigate to each handler and read it. This is the foundation for Steps 2–5.

## Step 2 — Payment/financial handlers: authentication and integrity

For each financial handler:

**Authentication**: Can an unauthenticated caller invoke it?
→ If yes: **submit immediately**: violated_invariant="[handler] performs financial operation but accepts unauthenticated requests; any caller can invoke it without credentials", severity=9, confidence=9.

**External callback integrity**: If the handler receives notifications from an external provider — is the request verified against a provider-issued signature or shared secret before any state change?
→ If no verification: **submit immediately**: violated_invariant="[handler] accepts external financial callbacks without verifying their origin; attacker can forge a payment confirmation for any reference", severity=9, confidence=9.

**Test/sandbox bypass**: Is there a branch for sandbox/test mode that skips verification and goes directly to the success path, reachable from outside?
→ **submit immediately**: violated_invariant="[handler] sandbox path bypasses gateway verification; attacker triggers [success action] without a real transaction", severity=9, confidence=9.

**Actor from request**: Does the handler read the actor identity (employee ID, user ID, account being charged) from the request body/params rather than from the authenticated session?
→ **submit immediately**: violated_invariant="[handler] uses caller-supplied [field] as the actor; caller names any identity as the charged party", severity=9, confidence=9.

## Step 3 — File/media access: ownership check

For each file access handler:

Trace from where the file identifier is read from the request to where the file or access URL is returned.

**Ownership**: Between reading the caller-supplied ID and issuing the response, is there a lookup that confirms this user owns or is authorized for that specific file?
→ If no ownership check: **submit immediately**: violated_invariant="[handler] returns file access for caller-supplied key without ownership verification; any authenticated user can access any file by its key", severity=7, confidence=9.

## Step 4 — Object-level authorization (BOLA) on sensitive resources

For endpoints that accept an object identifier (user ID, record ID, account ID, config ID) from the request and perform an action on or return data about that specific object:

Read the handler. How does it fetch the object? Does it filter by BOTH the object ID AND the requesting user's identity (person ID, user ID, tenant ID)?

**Finding condition**: The handler fetches an object using only the caller-supplied ID, with no additional filter that binds the result to the requesting user's identity.

→ **submit immediately**: violated_invariant="[handler] fetches [object type] by caller-supplied ID [field name] without a co-filter on the requesting user's identity; any authenticated user can access any [object type] by ID", severity=7, confidence=8.

Also check: can the caller supply a different user ID or person ID as part of the request to access another user's data?

→ If yes: **submit immediately**: violated_invariant="[handler] accepts caller-supplied user/person ID and returns data for that ID without verifying it matches the authenticated session; horizontal privilege escalation", severity=8, confidence=9.

## Step 5 — Diagnostic and monitoring endpoints: authentication

Go back to the routing file. Find routes that are diagnostic, monitoring, or internal-tooling in nature — registered either unconditionally or behind a flag.

**Unconditionally registered debug route**: registered outside any environment or debug guard.
→ **submit immediately**: violated_invariant="[path] diagnostic endpoint registered unconditionally; reachable in all deployed environments", severity=7, confidence=9.

**Monitoring without auth**: An internal metrics or health detail route that exposes operational data without authentication.
→ **submit immediately**: violated_invariant="[path] monitoring endpoint has no authentication; internal metrics publicly readable", severity=6, confidence=9.

## Step 6 — Administrative handlers: authorization soundness

For each administrative handler (operating on all users' data, managing config, bulk actions):

Read the authorization check. Is the decision derived from the authenticated session/token (trustworthy) or from a request header/body field (attacker-controlled)?

**Bypassable or absent check**:
→ **submit immediately**: violated_invariant="[handler] uses [input source] for authorization rather than a cryptographically bound identity property; any caller satisfying the attacker-controlled condition gains admin access", severity=9, confidence=9.

**Commented-out authorization**: Is there a commented-out authorization block on a financial or admin handler?
→ **submit immediately**: violated_invariant="authorization check commented out on [handler]; sensitive operation executes without privilege verification", severity=9, confidence=9.

## Finish

Call finish() with all hypotheses. Call it now even if the list is empty. Set confidence lower rather than raising open questions.
