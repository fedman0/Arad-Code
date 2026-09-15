# SKILL: model-authorization

## Contract

**Trigger:** After model-identities.
**Phase:** 2 — Identity & Ownership
**Preconditions:** Identity model, DI map, middleware map
**Escalates to:** review-object-authorization, review-function-authorization

## Inputs
- repo_path
- identity model from model-identities

## Procedure
1. Find the authorization model: RBAC (role-based), ABAC (attribute-based), ACL, policy-based, object-level.
2. Get code snippets for: IAuthorizationHandler<TRequirement>, policy definitions, permission enums.
3. Map roles to permissions: what can each role do?
4. Find object-level authorization (IDOR check): does the code verify ownership before operating on a resource?
5. For each sensitive operation, find the authorization check: where in the call chain does it occur?
6. Find authorization that happens AFTER data is loaded (vs. before) — loading then checking is a data leakage pattern.
7. Find policy aggregation: can multiple partial policies combine to grant more than intended?
8. Find the permission check for: read, write, delete, admin operations on each resource type.
9. Find any admin bypass or backdoor: super-admin that skips all checks.
10. Identify claims used for authorization: are they from the token or re-fetched from the database?

## Required evidence
- Role → permission matrix
- Object-level authorization: how ownership is verified per resource type
- Authorization check placement: before or after data load
- Claims source: token vs. database
- Admin bypass paths

## Counterchecks
- Load-then-check is a pattern; it only leaks data if the response includes data before the check fails.
- Claims from token may be stale — but this is only exploitable if the token lifetime is long and roles change frequently.
- Admin bypass is only a finding if there is a path to obtain admin privileges or if admin operations affect other tenants.

## Output schema
Standard FINDINGS_SCHEMA. Hypotheses for: missing object-level check, load-then-check with data leakage, policy aggregation granting excess privilege, stale claims exploitable.

## Stop condition
When every resource type has a documented ownership check and every sensitive operation has a documented authorization gate.

## Forbidden inferences
- Do not conclude authorization is missing because there is no [Authorize] attribute — policies and middleware must be checked.
- Do not report stale claims as exploitable without confirming token lifetime and a scenario where privilege changes matter.
