# SKILL: review-browser-data-flows

## Contract

**Trigger:** Phase 4. Run for any web application generating HTML or handling browser messages.
**Phase:** 4 — Security Analysis
**Preconditions:** Entry point map, template engine, front-end framework
**Escalates to:** trace-persisted-data-reuse

## Inputs
- repo_path
- template_engine: Razor | Jinja2 | Handlebars | React | Vue | Angular | EJS

## Procedure
1. search_code(pattern="@Html.Raw|innerHTML|dangerouslySetInnerHTML|v-html|outerHTML|document.write|bypassSecurityTrust") to find raw HTML injection points.
2. For each raw HTML injection: trace where the value comes from — is it user-controlled?
3. For server-side rendering: find template syntax for unescaped output ({{ raw }}, <%- %>, @Html.Raw).
4. Check CSP header: is Content-Security-Policy set? Does it allow unsafe-inline or data: URIs?
5. Check DOM sinks from URL: location.hash, location.search, location.href — are they used in innerHTML or eval?
6. Check postMessage handlers: does the app receive postMessages? Is the origin validated?
7. Check javascript: URI schemes in href or redirect URLs.
8. Check open redirect: is a user-supplied URL used in a redirect without validation?
9. Check JSONP endpoints: are there legacy JSONP endpoints with callback parameter?
10. Check Subresource Integrity: are third-party scripts loaded with SRI hashes?

## Required evidence
- All raw HTML injection sinks with data source
- DOM-based XSS sources (URL parts fed to DOM sinks)
- CSP header configuration and bypasses
- postMessage origin validation
- Open redirect sinks

## Counterchecks
- Trusted Types browser API prevents DOM XSS if enforced via CSP require-trusted-types-for.
- Angular's DomSanitizer.bypassSecurityTrust* is intentional — check if it's necessary.
- JSONP is only exploitable if the callback name is reflected unescaped and attacker can control the script load.

## Output schema
Standard FINDINGS_SCHEMA. Hypotheses for: reflected/stored XSS via raw HTML sink, DOM XSS from URL fragment, open redirect, missing postMessage origin validation.

## Stop condition
When all raw HTML output and DOM manipulation sites are classified with their input source.

## Forbidden inferences
- Do not report React JSX as XSS — JSX escapes by default; only dangerouslySetInnerHTML is a risk.
- Do not report open redirect as stored XSS — they are different findings.
