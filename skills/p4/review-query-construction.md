# SKILL: review-query-construction

## Contract

**Trigger:** Phase 4. Run for any service with DB access.
**Phase:** 4 — Security Analysis
**Preconditions:** Entry point map, ORM/DB library identified
**Escalates to:** trace-input-to-effect

## Inputs
- repo_path
- db_library: EF Core | Dapper | JDBC | SQLAlchemy | Mongoose | Prisma | raw SQL

## Procedure
1. search_code(pattern="ExecuteRawSql|FromSqlRaw|ExecuteQuery|QueryAsync|query\(|execute\(") to find raw query calls.
2. For each raw query call: get_code_snippet and check if parameters are interpolated vs. passed separately.
3. search_code(pattern="\\$\"|string.Format|\\+.*sql|concat.*sql") to find string-built queries.
4. For each string-built query: trace which parts come from user input via trace-input-to-effect.
5. Check NoSQL: MongoDB filter construction — are field names from user input (operator injection)?
6. Check LDAP: filter string construction from user input.
7. Check ORM raw fragments: LINQ .Where($"column = {value}") or equivalent — are these interpolated?
8. Check ORDER BY from user input: column name cannot be parameterized — is there a whitelist?
9. Check LIKE queries: is the wildcard character (%) escaped in the search term?
10. Find query builder patterns: does the builder ever append raw user input without escaping?
11. Check second-order: is any stored value later used in a raw query construction?

## Required evidence
- All raw query locations: file:line, parameterized or interpolated
- String concatenation query patterns with input source
- NoSQL operator injection candidates
- ORDER BY from user input: whitelist confirmed or absent
- Second-order SQLi candidates from trace-persisted-data-reuse

## Counterchecks
- Parameterized queries (? or @param) are safe regardless of input content.
- ORM-generated queries are safe unless raw fragments are injected.
- Dapper with @param syntax is parameterized.
- LIKE wildcard must be escaped to prevent over-matching, but this is correctness, not injection.

## Output schema
Standard FINDINGS_SCHEMA. Hypotheses require: confirmed string-built query AND confirmed user-controlled value in the built portion AND confirmed execution path.

## Stop condition
When all raw query locations are classified as parameterized-safe or interpolated-vulnerable.

## Forbidden inferences
- Do not report Dapper usage as SQLi without checking the specific query's parameter syntax.
- Do not report string interpolation as SQLi without confirming the interpolated value traces to user input.
- LIKE wildcard escape issue is not SQLi.
