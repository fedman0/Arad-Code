# SKILL: map-sensitive-data

## Contract

**Trigger:** Phase 2, alongside other identity/ownership skills.
**Phase:** 2 — Identity & Ownership
**Preconditions:** Entity schema, service list, config map
**Escalates to:** review-error-and-logging, review-cryptographic-usage

## Inputs
- repo_path

## Procedure
1. search_code(pattern="password|secret|token|ssn|credit_card|cvv|dob|salary|pii") to find data fields.
2. For each sensitive field: where is it stored (DB column, cache, log, file)?
3. Find serialization: does the sensitive field appear in JSON responses? Check AutoMapper, Serializer configs.
4. Find logging: does the field appear in log.Info(), logger.LogInformation(), Serilog enrichers?
5. Find error messages: are sensitive values included in exception messages?
6. Find export/report generation: are sensitive fields exported to CSV, Excel, PDF?
7. Find masked/redacted output: does the API return a masked version (last4 of card) or full value?
8. Find encryption at rest: are sensitive DB columns encrypted? Where is the key stored?
9. Find transit exposure: are sensitive values in URL query parameters, HTTP headers, or request bodies?
10. Find data retention: how long is sensitive data kept, and is old data purged?

## Required evidence
- Sensitive field inventory: field, location, masking status, encryption status
- Serialization exposure: fields that appear in API responses
- Logging exposure: sensitive fields logged anywhere in the call chain
- URL parameter exposure (sensitive data in query strings is logged by proxies/CDN)

## Counterchecks
- [JsonIgnore] or equivalent serialization exclusion may prevent API exposure even if the field is in the model.
- Structured logging with destructuring policies may mask sensitive fields automatically.
- Encryption at rest doesn't prevent application-level leakage via logs or API responses.

## Output schema
Standard FINDINGS_SCHEMA. Hypotheses for: password/token in API response, PII in log output, sensitive data in URL parameter, unencrypted sensitive column with logging exposure.

## Stop condition
When every sensitive data field has a documented flow from storage to all possible output channels.

## Forbidden inferences
- Do not report a field as exposed in logs without finding an actual log statement that includes it.
- Do not assume AutoMapper maps all fields — check profile configuration and ignored members.
