# SKILL: trace-identity-propagation

## Contract

**Trigger:** When identity-based findings involve cross-service or async boundaries.
**Phase:** 3 — Path Analysis
**Preconditions:** Identity model, trust boundary map, service communication graph
**Escalates to:** review-tenant-isolation, review-object-authorization

## Inputs
- repo_path
- identity_field: the claim or field carrying user/tenant identity (userId, tenantId, actorId)
- boundary_type: http | message | job | cache

## Procedure
1. Find where the identity_field is established at the entry point.
2. Trace how it is passed to downstream services: HTTP header, message body field, JWT forwarding.
3. At each boundary: does the receiving side re-establish identity from its own auth source, or accept the forwarded value?
4. For message boundaries: is tenantId/userId in the message envelope? Is it validated against the producer's allowed scope?
5. For job/background workers: where does identity come from? Is it the original user's identity or a service identity?
6. Find places where identity is lost: a service call that drops the user context and uses ambient service account.
7. Find places where identity can be spoofed: a header or message field that callers can set arbitrarily.
8. Find privilege amplification: user identity enters a queue, message is processed by a service with higher privilege, and the user context is not re-checked.

## Required evidence
- Identity value at each boundary crossing: confirmed present vs. absent vs. spoofable
- Re-validation at each receiving side
- Privilege amplification paths (user triggers → service account executes)
- Loss of user context in async processing

## Counterchecks
- A service that generates its own token from forwarded claims re-validates the original source.
- Message schema validation can prevent spoofed identity fields if the schema enforces type/format but NOT content authorization.
- A service account executing a background job may legitimately not carry user identity.

## Output schema
Standard FINDINGS_SCHEMA. Hypotheses for: spoofable identity header, privilege amplification via queue, user context lost causing authorization bypass.

## Stop condition
When identity flow is documented for every inter-service boundary in the scope of the current hypothesis.

## Forbidden inferences
- Do not conclude identity is spoofable without confirming the receiving service reads that header without validation.
- Do not report privilege amplification if the background service re-fetches and re-validates user identity from the DB.
