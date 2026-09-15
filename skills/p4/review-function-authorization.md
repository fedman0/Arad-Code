# SKILL: review-function-authorization

## Contract

**Trigger:** After model-authorization, for admin and privileged operations.
**Phase:** 4 — Security Analysis
**Preconditions:** Role/permission model, entry point map, middleware map
**Escalates to:** trace-effect-to-callers

## Inputs
- repo_path
- privileged_operations: list of operations requiring elevated role

## Procedure
1. Find all admin/management entry points: routes with /admin/, /manage/, /internal/, /ops/.
2. For each privileged entry point: what role/permission is required?
3. Check: is the required role enforced at the entry point (attribute/policy) AND in the service layer?
4. Find privilege-separated operations: some fields updateable by user, some only by admin — is field-level auth enforced?
5. Find role assignment endpoints: who can assign roles to users? Can a user assign themselves a role?
6. Find privilege escalation via feature: can normal operations accumulate to achieve admin-level effect?
7. Find API versioning: does an older API version skip authorization that a newer version enforces?
8. Find undocumented/hidden endpoints: routes not in Swagger/OpenAPI but present in the router.
9. Find debug endpoints: /debug/, /actuator/ (Spring), /.well-known/ admin paths — are they protected?
10. Find operations that change the identity of the caller: password reset, email change, phone change — authorization before and after the change?

## Required evidence
- Per privileged operation: required role, where enforced, whether service layer also checks
- Role assignment path: who can grant which roles
- Field-level auth for mixed-privilege entities
- Hidden/undocumented endpoints found

## Counterchecks
- Defense-in-depth: check in both middleware AND service is better than either alone.
- Role assignment restricted to superadmin with no path for normal users to reach it is sufficient.
- Debug endpoints accessible only from localhost/cluster network may be acceptable depending on threat model.

## Output schema
Standard FINDINGS_SCHEMA. Hypotheses for: admin endpoint reachable without required role, role self-assignment, field-level privilege bypass, debug endpoint reachable from internet.

## Stop condition
When every privileged operation has a documented and confirmed authorization check.

## Forbidden inferences
- Do not report a missing [Authorize(Roles="Admin")] attribute without checking global policy and middleware.
- Do not assume /actuator/ endpoints are exposed externally without checking ingress/network config.
