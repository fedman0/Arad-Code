# SKILL: review-object-authorization

## Contract

**Trigger:** After model-authorization and model-resource-ownership. Run for each resource type.
**Phase:** 4 — Security Analysis
**Preconditions:** Resource ownership model, authorization model, entry point map
**Escalates to:** trace-input-to-effect

## Inputs
- repo_path
- resource_type: entity name
- operations: [read, update, delete, share, transfer]

## Procedure
1. For each entry point that operates on resource_type: get code snippet.
2. Check: is the resource ID taken from user input (URL param, body)?
3. Check: before loading or operating on the resource, is ownership verified?
4. Check: is the ownership check done on the ID (before loading) or on the loaded object (after loading)?
5. If after loading: does the response include any resource data before the check runs?
6. Check: is the ownership check against the SAME user making the request (not a header-injected user)?
7. Find batch operations: /resources?ids[]=1&ids[]=2 — does each ID get ownership-checked?
8. Find search/filter: can a user search for resources by ID range and infer existence of other users' resources?
9. Find indirect object reference: resource is referenced via a child object — does the check follow the chain?
10. Find admin override: an admin can access any resource — is the admin check tight or broad?

## Required evidence
- For each operation: ownership check location (before/after load), check fields, check against correct identity
- Batch operations: per-item or batch-level check
- Indirect reference chain: fully traced
- Admin path: check tightness

## Counterchecks
- EF Core global query filter on ownership may enforce it at DB level, preventing loading of other users' data.
- Repository pattern that always appends WHERE userId = currentUser may be sufficient.
- 404 vs. 403 response doesn't fix IDOR — the operation must not execute.

## Output schema
Standard FINDINGS_SCHEMA. Hypotheses require: confirmed path from user input to resource operation WITHOUT ownership check, confirmed different user's resource is accessible.

## Stop condition
When every operation on every resource type has a confirmed ownership check or explicit justification for its absence.

## Forbidden inferences
- Do not report IDOR without confirming the ownership check is absent — not just that no [Authorize] attribute is on the method.
- Do not assume EF Core global query filter is present without confirming it's registered in OnModelCreating.
