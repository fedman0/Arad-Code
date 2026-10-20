# SKILL: understand-authorization-and-access

## Goal

Read and understand how this application decides what each authenticated identity
is allowed to do and access. Find every place that decision can be influenced by
attacker-controlled input, is missing, or is applied incorrectly.

Do NOT search for specific function names or URL patterns.
Derive the authorization model from the code itself.

---

## Phase 1 — Understand the permission model

1. Call `get_architecture`. Find how roles, permissions, and privilege are modeled.
   Read the actual implementation — not the framework docs.
2. What object carries the authenticated identity at runtime?
   What fields on that object determine privilege? (e.g. `is_superuser`, claims, roles)
3. These privilege fields are your trust anchors. Authorization decisions are only sound
   when they derive exclusively from these trust anchors.

---

## Phase 2 — Find every authorization decision point

Do not search by name. Instead:

1. Use `trace_path(mode="calls", direction="outbound")` from HTTP handlers to find every function whose
   return value determines whether a request is allowed or denied.
2. For each authorization function, use `get_code_snippet` to read it completely.
3. Answer: what data does this function use to make its decision?
   - Data from the validated token/session → trusted
   - Data from `request.headers`, `request.GET`, `request.data`, `request.META` → attacker-controlled
   - Data from a database lookup → depends on what key is used for the lookup
4. If ANY path through the function returns "allowed" based on attacker-controlled data
   without cryptographic binding to the authenticated identity → that is a vulnerability.

**Specifically look for:**
- Functions that check a header value and return True before checking the user's actual role
- Short-circuit conditions: "if X in header: return True" that bypass the real check
- Commented-out checks: lines beginning with `#` that look like authorization conditions

---

## Phase 3 — Trace every HTTP entry point end to end

For each significant endpoint (prioritize: admin operations, privileged mutations, resource access):

1. Use `trace_path(mode="calls", direction="outbound")` from the view handler through the full call chain.
2. At what point is authorization enforced? At the view? At the service? At the repository?
3. Is it enforced at EVERY step that matters, or only at the outermost layer?
4. For endpoints that operate on a resource identified by an ID (URL param, body field):
   - Does the code verify the requesting user is authorized to access THAT SPECIFIC resource?
   - Or does it only check "is the user authenticated"?
   - Read the actual query/fetch that retrieves the resource — does it filter by owner/user?

---

## Phase 4 — Find privilege escalation paths

1. For every operation that requires elevated privilege: can a normal user reach it?
2. Can a user supply a parameter (header, body field, query param) that the application
   interprets as granting them elevated access?
3. Are there any operations that accept an actor ID from the request body instead of
   deriving it from the authenticated session? (e.g. `employee_id` in payment body)
4. For role assignment or status change operations: who can perform them? Can a user
   change their own role or another user's role?

---

## Phase 5 — Multi-tenancy isolation

For SaaS applications or any system with multiple organizations, workspaces, or tenants:

1. Find how tenancy is modeled. Every data record should be scoped to a tenant.
2. For every database query that returns user data: are there TWO filters — one for the
   tenant and one for the user? A query filtered only by user ID may return data from any
   tenant if the user ID is shared across tenants.
3. For admin operations within a tenant: can a user from tenant A perform operations on
   tenant B's resources by supplying tenant B's IDs?
4. Find tenant ID extraction: does it come from the authenticated token (trusted), or from
   a request parameter (attacker-controlled)?

---

## Phase 6 — URL path normalization bypass

The dangerous pattern: authorization middleware checks the raw path against an allowlist or
denylist, but the router normalizes the path differently before routing.

- Does the authorization check use the raw request path?
- Does the router normalize paths? (strip trailing slashes, decode percent-encoding,
  handle case, collapse `//`, resolve `./` or `../`, strip path parameters like `;foo`)
- If the two use different representations of the path:
  - Case: `/Admin/` may pass a check for `/admin` on a case-insensitive match
  - Double slash: `//admin/` may not match a denylist pattern for `/admin/`
  - Encoded chars: `/%61dmin/` decodes to `/admin/` — does the check run before or after decode?
  - Semicolon params (Java): `/admin;foo=bar` routes to `/admin` but may not match `/admin`
  - Null byte: `/admin%00.jpg` — some systems strip trailing content after the null byte
- Read what path representation the authorization check uses vs. what the router receives.

---

## What to produce

A hypothesis for each:
- Authorization function that accepts attacker-controlled input to make its decision
- Endpoint where object-level ownership is not verified
- Privileged operation reachable without the required privilege
- Authorization check that is commented out or conditionally disabled
- Multi-tenant isolation failure: tenant A user accessing tenant B data
- Tenant ID sourced from request parameter instead of authenticated token
- URL path normalization bypass: auth check and router disagree on path representation

Include the complete call chain: HTTP entry → middleware → gate function → operation,
with file:line for every step. Mark reachability as `proven` only if you have read every link.

Set `cwe` on each hypothesis (e.g. CWE-807 authorization decided from attacker-controlled input, CWE-639
object-level or cross-tenant access, CWE-862 missing or commented-out check, CWE-269 privilege escalation,
CWE-647 path-normalization bypass).

## Forbidden

- Do not search for `/admin/` or specific URL substrings as a proxy for privilege
- Do not assume a function named `is_admin` or `check_permission` is the only gate
- Do not report without tracing the actual call chain
- Do not report path normalization bypass without verifying the auth check and router
  use different representations of the same path
