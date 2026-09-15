# SKILL: review-error-and-logging

## Contract

**Trigger:** Phase 4, after map-sensitive-data.
**Phase:** 4 — Security Analysis
**Preconditions:** Sensitive data map, exception handling middleware map
**Escalates to:** trace-persisted-data-reuse

## Inputs
- repo_path

## Procedure
1. Find global exception handler: what does it return to the client? Stack trace? Exception message? Internal error details?
2. Find development vs. production error handling: is UseDeveloperExceptionPage() gated on environment?
3. search_code(pattern="logger\\.Log|log\\.Info|Console\\.Write|Serilog|NLog|Microsoft\\.Extensions\\.Logging") to find logging calls.
4. For each log statement near sensitive operations: does it log passwords, tokens, PII, or full request bodies?
5. Find structured logging destructuring: does @object logging serialize all fields including sensitive ones?
6. Find exception serialization: do exception messages include sensitive field values?
7. Find verbose error responses: does a 400/422 response reveal which field failed and why in a way that aids enumeration?
8. Find timing-based information leakage: does "username not found" respond differently (timing or message) than "wrong password"?
9. Find log injection: is user input included in log messages without encoding? (can inject fake log entries)
10. Find audit logs: are security-relevant events (login, role change, data access) logged with sufficient context?

## Required evidence
- Global error handler behavior in production: confirmed stack trace exposure or confirmed safe generic message
- Log statements containing sensitive fields: file:line
- Exception messages reaching the API response
- Username enumeration via timing or distinct error messages

## Counterchecks
- A generic 500 error message is safe even if the exception contains sensitive detail.
- Structured logging with explicit destructuring policies may mask sensitive fields automatically.
- Username enumeration via timing is only exploitable if the timing difference is consistent and measurable.

## Output schema
Standard FINDINGS_SCHEMA. Hypotheses for: stack trace in production error response, PII in log, username enumeration, log injection enabling log forgery.

## Stop condition
When global exception handling and all sensitive-operation log statements are reviewed.

## Forbidden inferences
- Do not report verbose validation errors as information disclosure without confirming they reveal non-public data.
- Do not report username enumeration timing attack without confirming a consistent measurable timing difference.
