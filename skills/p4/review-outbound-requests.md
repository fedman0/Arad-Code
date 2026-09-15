# SKILL: review-outbound-requests

## Contract

**Trigger:** Phase 4. Run for any service making outbound HTTP calls with user-supplied URLs.
**Phase:** 4 — Security Analysis
**Preconditions:** Entry point map, HTTP client usage
**Escalates to:** trace-input-to-effect

## Inputs
- repo_path

## Procedure
1. search_code(pattern="HttpClient|WebClient|fetch\(|axios\.|requests.get|urllib|curl") to find HTTP client usage.
2. For each HTTP client call: does the URL come from user input, a stored value, or a redirect parameter?
3. Check URL validation: is there a scheme allowlist (https only)? A host allowlist? A hostname resolution check?
4. Check redirects: does the HTTP client follow redirects? Can a redirect lead to an internal host?
5. Check SSRF to internal metadata: is access to 169.254.169.254 (AWS/Azure/GCP metadata) or 100.100.100.200 blocked?
6. Check DNS rebinding: is the URL validated before or after DNS resolution?
7. Check Webhook registration: users can register webhook URLs — are they validated against a blocklist?
8. Check file:// and other non-HTTP schemes: are non-HTTP schemes blocked?
9. Check URL parsing inconsistencies: are there two parsers used for the same URL (validation vs. execution)?
10. Find request forgery via redirect: does the application follow a user-supplied redirect URL without validation?

## Required evidence
- User-controlled URL sources: entry point, field name
- URL validation: scheme check, host allowlist/blocklist, confirmed present or absent
- Redirect following: enabled or disabled
- Internal metadata IP in blocklist: confirmed present or absent

## Counterchecks
- An allowlist of allowed host suffixes (e.g., *.example.com) is strong if DNS resolution is done after allowlist check.
- Disabling redirect following prevents redirect-based SSRF but not direct SSRF.
- A blocklist of internal IPs is weak because it can be bypassed via DNS rebinding, IPv6, or alternate representations.

## Output schema
Standard FINDINGS_SCHEMA. Hypotheses for: SSRF via user-controlled URL without allowlist, webhook URL without blocklist reaching internal services, redirect-based SSRF.

## Stop condition
When all outbound HTTP calls with user-controlled URLs have a documented validation mechanism.

## Forbidden inferences
- Do not report SSRF without confirming the URL or a portion of it is user-controlled.
- Do not report a blocklist as safe against DNS rebinding without confirming re-validation after resolution.
