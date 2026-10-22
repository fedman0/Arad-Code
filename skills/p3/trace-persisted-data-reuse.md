---
parallel: true
max_turns: 40
---

# SKILL: trace-persisted-data-reuse

## Contract

**Trigger:** When investigating second-order injection or stored payload attacks.
**Phase:** 3 — Path Analysis
**Preconditions:** Sensitive data map (Threat Model in Known Context), entry point map (Known entry points), DB schema
**Escalates to:** hunt-injection-sqli-cmdi, hunt-xss, understand-data-flows

## Procedure
1. Find all locations where user-controlled data is persisted to DB, file system, or cache.
2. For each persisted field: find all places where that field is later READ and USED.
3. For each read-then-use pattern: trace_path(read_function, mode="data_flow", direction="outbound") to find where the value goes.
4. Check: is the value re-sanitized/validated when it is read for later use, or only validated at write time?
5. Find dangerous reuse sinks: HTML template rendering (stored XSS), SQL construction (second-order SQLi), shell execution, file path construction, LDAP query.
6. Find the consumer context: when the data is reused, what identity/privilege level is executing the code?
7. Find batch/export jobs that read stored data and produce output — are outputs sanitized for the output format?
8. Find webhook/notification systems that include stored user data in outbound payloads.
9. Find audit log reads that may re-render dangerous stored content.

## Required evidence
- Write site: where user data is stored (field, table, cache key)
- Read sites: all code locations that read that field later
- Sink at each read site: what happens to the value
- Consumer privilege level at each read site
- Sanitization status at read time (not write time)

## Counterchecks
- Write-time sanitization is only sufficient if the sanitization is appropriate for ALL future read contexts (HTML encoding may not be appropriate for CSV export).
- Context-sensitive encoding at render time is the correct defense for XSS, not write-time sanitization.
- A background job reading user data with service-level privilege is a finding only if the job performs a dangerous operation on that data.

## Output schema
Standard FINDINGS_SCHEMA. Hypotheses for: stored XSS (data persisted, later rendered unsanitized into HTML), second-order SQLi (data persisted, later interpolated into SQL), stored payload in webhook/export.
Set `cwe` from the reuse sink (e.g. CWE-79 stored XSS, CWE-89 second-order SQLi, CWE-78 command, CWE-1236 formula injection in CSV export).

## Stop condition
When every identified stored field has a complete map of its read sites and each site's sanitization status.

## Forbidden inferences
- Do not report second-order SQLi without confirming the stored value is interpolated into SQL at the read site (not parameterized).
- Do not report stored XSS without confirming the rendering context uses the stored value without encoding.
