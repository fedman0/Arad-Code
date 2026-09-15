# SKILL: review-tenant-isolation

## Contract

**Trigger:** After model-tenant-boundaries. Run for every cross-tenant data access pattern.
**Phase:** 4 — Security Analysis
**Preconditions:** Tenant boundary model, DB schema, cache key patterns
**Escalates to:** trace-input-to-effect, review-query-construction

## Inputs
- repo_path
- tenancy_model: row-per-tenant | schema-per-tenant | db-per-tenant

## Procedure
1. For row-per-tenant: check every DB query that touches a tenant-scoped entity. Is TenantId in the WHERE clause?
2. Find IgnoreQueryFilters() calls: what is the context? Is the caller protected by admin-only auth?
3. Check aggregate queries (COUNT, SUM, AVG): do they filter by TenantId before aggregating?
4. Check cache: for every cached value, is the cache key tenant-scoped (includes TenantId)?
5. Check message consumers: does the consumer restore TenantId from the message, and is it validated?
6. Check export/report jobs: does the job accept a tenantId parameter and filter all queries by it?
7. Find cross-tenant comparison: search, deduplication, or suggestion features that query multiple tenants' data.
8. Find tenant discovery: can a user enumerate tenant IDs or tenant names they don't belong to?
9. Find shared resources between tenants: templates, categories, lookup tables — are writes to shared resources restricted?
10. For schema-per-tenant: is the connection string or schema name derived from a trusted source (server-side) or user-provided value?

## Required evidence
- Per entity: tenant filter presence in each query type (read, aggregate, export)
- IgnoreQueryFilters usage map
- Cache key tenant scoping
- Consumer tenant restoration and validation
- Schema/connection selection source for schema-per-tenant

## Counterchecks
- EF Core global query filter auto-applies TenantId — but IgnoreQueryFilters() can disable it.
- Schema-per-tenant is stronger than row-per-tenant unless the schema name is derived from user input.
- Shared lookup tables (countries, currencies) need no tenant filter — only mutable tenant data does.

## Output schema
Standard FINDINGS_SCHEMA. Hypotheses require: a concrete data path where tenant filter is absent AND the operation affects data from multiple tenants.

## Stop condition
When every entity type in every query type has confirmed tenant isolation or explicit justification.

## Forbidden inferences
- Do not report a missing TenantId on a global lookup table as a cross-tenant leak.
- Do not assume schema-per-tenant is bypassed without confirming the schema selection logic accepts user input.
