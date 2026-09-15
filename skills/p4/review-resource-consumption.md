# SKILL: review-resource-consumption

## Contract

**Trigger:** Phase 4. Run for public-facing or high-load services.
**Phase:** 4 — Security Analysis
**Preconditions:** Entry point map, middleware map
**Escalates to:** review-financial-operations

## Inputs
- repo_path

## Procedure
1. Find endpoints that accept large payloads: file upload size limits, JSON body size limits — are they configured?
2. Find endpoints that trigger expensive operations: DB full-table scans, N+1 query chains, large aggregations.
3. Find pagination: do list endpoints have mandatory page size limits? Can a client request 1,000,000 records?
4. Find unbounded recursion: tree traversal, nested includes (GraphQL depth, EF Core Include chains).
5. Find regex operations on user input: catastrophic backtracking (ReDoS) patterns.
6. Find async fan-out: one user action that triggers N downstream requests or tasks — what is the max N?
7. Find rate limiting: is it per-user, per-IP, per-tenant? Is it on computationally expensive endpoints specifically?
8. Find CPU-intensive operations on user-supplied data: image processing, document conversion, compression.
9. Find queue depth: message producers without consumers — can a user flood the queue?
10. Find memory allocation based on user-supplied size: allocation of byte[userInput] without limit.

## Required evidence
- Payload size limits: configured or absent per endpoint
- Mandatory pagination limits: max page size enforced or absent
- Rate limiting coverage: which endpoints are rate-limited
- Fan-out cap: maximum N for any fan-out operation
- ReDoS-vulnerable regex patterns

## Counterchecks
- Rate limiting at the reverse proxy/CDN layer may protect even if application-level rate limiting is absent.
- Pagination limits enforced by the ORM (EF Core MaxResultsPerPage) are effective even if the application doesn't check.
- Async fan-out of N requests is only a DoS if N is large enough and the server resources are limited.

## Output schema
Standard FINDINGS_SCHEMA. Hypotheses for: unbounded list endpoint, ReDoS in user-controlled regex, uncapped fan-out, allocation from user-supplied size.

## Stop condition
When all expensive or unbounded operations have documented limits.

## Forbidden inferences
- Do not report missing pagination as a finding if the dataset is inherently small (e.g., a list of 2-3 static values).
- Do not report ReDoS without confirming the regex pattern is actually susceptible to catastrophic backtracking.
