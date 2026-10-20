---
order: 30
---

# SKILL: model-resource-ownership

## Contract

**Trigger:** After model-authorization.
**Phase:** 2 — Identity & Ownership
**Preconditions:** Identity model and authorization model (Threat Model in Known Context), DB schema
**Escalates to:** hunt-privilege-escalation-bola, model-tenant-boundaries

## Inputs
- repo_path
- resource types (entities, tables, documents)

## Procedure
1. Find all resource entities with foreign keys to user or tenant: get_code_snippet for each entity class.
2. Identify direct ownership: UserId on the resource matches the requesting user.
3. Identify indirect ownership: resource → order → user, resource → organization → member → user.
4. Identify shared resources: resources owned by organization/team/tenant (not individual user).
5. For shared resources: who can access them? All members? Members with a role? Only owners?
6. Find resources with no ownership column — these are either global (intentional) or a missing ownership bug.
7. For each operation (read, update, delete): trace where the ownership check occurs.
8. Find transfer of ownership operations: what happens when a resource is transferred? Are child resources updated?
9. Find deletion cascades: when a user is deleted, what resources remain and who can access them?

## Required evidence
- Per resource type: ownership type (direct/indirect/shared/global), ownership field, check location
- Operations on each resource: which operations check ownership, which don't
- Resources with no ownership column and their justification
- Ownership transfer and deletion cascade behavior

## Counterchecks
- A global resource is only a finding if it contains user-specific data or allows writes that affect other users.
- Indirect ownership is harder to verify — trace the full chain (resource → parent → owner) in code.
- EF Core global query filters may enforce ownership at the ORM level — check before concluding the check is missing.

## Output schema
Standard FINDINGS_SCHEMA. Hypotheses for: operation without ownership check, indirect chain not verified, global resource with user data.
Set `cwe` on each hypothesis (e.g. CWE-639 missing or unverified ownership check, CWE-862 operation with no authorization at all).

Persist the resource ownership model (per resource type: ownership type, ownership field, check location per operation) with `amend_threat_model` as a short `## Resource Ownership` section (if no threat model exists yet,
call `save_threat_model` with `## Overview`, `## Trust Boundaries`, `## Attack Surface`, `## Severity Calibration`
and this section). Later skills read it from the Threat Model in Known Context.

## Stop condition
When every resource type has a documented ownership model and every write/delete operation has a traced authorization check.

## Forbidden inferences
- Do not assume a missing ownership column means no ownership check — the check may be done via query filter.
- Do not report a shared resource access as IDOR if the access is intentional for all organization members.
