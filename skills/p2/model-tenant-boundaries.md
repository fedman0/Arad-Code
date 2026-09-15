# SKILL: model-tenant-boundaries

## Contract

**Trigger:** After model-resource-ownership. Run for any multi-tenant application.
**Phase:** 2 — Identity & Ownership
**Preconditions:** Resource ownership model, DI map, DB schema
**Escalates to:** review-tenant-isolation

## Inputs
- repo_path
- multi-tenant: yes/no, tenancy model (schema-per-tenant / row-per-tenant / DB-per-tenant)

## Procedure
1. Find the ICurrentTenant / ITenantContext / TenantProvider service — get code snippet.
2. Determine how TenantId is resolved at request time: from JWT claim, subdomain, header, URL path.
3. Find how TenantId is injected into queries: global query filter in EF Core, row-level security in DB, explicit .Where(x => x.TenantId == currentTenant).
4. Find the TenantId column on each entity — is it present on ALL entities? Are any missing?
5. For EF Core global filters: check if they can be disabled via IgnoreQueryFilters() and where that is called.
6. Find cache keys that include TenantId — and cache lookups that don't.
7. Find message queue consumers — is TenantId present in the message envelope? How is it restored?
8. Find export/report generation: does the query apply tenant filter before aggregating data?
9. Find admin/ops endpoints that query across tenants — are they protected by an admin role and not reachable by normal users?
10. Find tenant creation and deletion: can a user create a tenant that overlaps with another? Can a deleted tenant's ID be reused?

## Required evidence
- Tenant resolution mechanism and trust level of the source
- Query filter mechanism and coverage across entity types
- Entities missing TenantId column
- Cache key patterns
- Message consumer tenant restoration
- Cross-tenant queries and their access controls

## Counterchecks
- IgnoreQueryFilters() may be intentional for admin operations — check if those are protected.
- Schema-per-tenant isolation is stronger than row-per-tenant, but connection string selection must still be verified.
- A missing TenantId on a join/lookup table may be intentional if the parent entity has TenantId.

## Output schema
Standard FINDINGS_SCHEMA. Hypotheses for: TenantId not in query filter, cache miss on tenant key, message consumer not restoring tenant, cross-tenant query reachable by non-admin.

## Stop condition
When every data access path has a confirmed TenantId filter or explicit justification for its absence.

## Forbidden inferences
- Do not report an entity without TenantId as a finding if it's a global lookup table (countries, languages).
- Do not conclude schema-per-tenant is bypassed without confirming the connection string selection logic.
