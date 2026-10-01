# SKILL: hunt-missing-authz-on-sensitive-endpoints

## Goal

Find endpoints that handle sensitive operations but lack proper authentication, ownership verification, or request integrity validation. Explore the route surface first — do not search for specific names.

---

## Step 1 — Enumerate all routes/endpoints

Use `get_architecture` to understand the project structure.
Find the routing definition files (url config, router, route table, controller map — whatever this project uses).
Read them. Build a list of all endpoints grouped by what they do:
- Payment / financial operations
- File or media access
- User data access (other users' records)
- Privileged or administrative operations
- External webhook receivers or callbacks

## Step 2 — For each sensitive endpoint: check authentication

For every endpoint in the sensitive categories from Step 1: read the handler.
Check whether the standard authentication chain from this project (as you understand it from the code) is applied. Look at:
- Is the endpoint excluded from auth middleware or marked as public/anonymous?
- Does it explicitly declare no authentication required?
- Is there a comment or annotation that suggests auth was intentionally skipped?

**Finding condition**: a sensitive endpoint is reachable without authentication.
→ **submit hypothesis immediately**: violated_invariant="[endpoint path] handles [sensitive operation] but is accessible without authentication", severity=8, confidence=9.

## Step 3 — For webhook/callback endpoints: check request integrity

For any endpoint that receives calls from an external system (payment gateway, notification provider, third-party service):
Read the handler. Check whether the incoming request is verified against a shared secret or signature from the external provider (HMAC over the request body, signature header, challenge-response).

**Finding condition**: an external callback endpoint accepts and processes requests without verifying they came from the legitimate provider.
→ **submit hypothesis immediately**: violated_invariant="external callback endpoint processes requests without integrity verification; attacker can forge provider notifications", severity=9, confidence=8.

## Step 4 — For resource access endpoints: check ownership

For endpoints that return or operate on a specific resource (file, record, object) identified by a user-supplied key or ID:
Read the handler. Trace from where the key/ID is read from the request to where the resource is fetched or operated on.

**Finding condition**: the handler fetches or operates on the resource using the user-supplied identifier without first confirming that the requesting user owns or is authorized to access that specific resource.
→ **submit hypothesis immediately**: violated_invariant="resource access endpoint uses caller-supplied ID without ownership check; any authenticated user can access any resource by ID", severity=7, confidence=8.

## Step 5 — For privileged endpoints: check if the privilege check is sound

For endpoints that require elevated access (administrative actions, bulk operations, other users' data):
Read the handler and any permission check it uses.
Understand: where does the privilege determination come from? Is it read from a tamper-proof source (DB record, verified token claim) or from somewhere the caller could influence?

**Finding condition**: the privilege check is absent, trivially bypassed, or reads from caller-controlled input rather than a trusted source.
→ **submit hypothesis immediately**: violated_invariant="privileged endpoint relies on a bypassable or absent access check", severity=9, confidence=8.

## Finish

Call finish() with all hypotheses. Call it now even if the list is empty. Set confidence lower rather than raising blocking open questions.
