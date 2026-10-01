# SKILL: hunt-auth-bypass-patterns

## Goal

Find specific authentication and authorization bypass vulnerabilities. Each step targets a specific bug class. Find the relevant code, check the condition, submit or skip immediately — do not explore broadly.

---

## Step 1 — Find the auth middleware and read it

Use `get_architecture` to identify the project structure. Find the authentication middleware, filter, or decorator that runs before HTTP handlers. Read its complete implementation.

Check for:

**A — Header short-circuit**: Does any code grant an authenticated or elevated identity based on a request header value without verifying against a database record or signed token?
→ **submit immediately**: violated_invariant="authentication/authorization grants elevated access based on attacker-controlled HTTP header [name the header]; any caller can bypass identity verification", severity=10, confidence=8.

**B — Algorithm confusion**: Does the token decode call read the signing algorithm from the token itself rather than an explicit allowlist in the verifier?
→ **submit immediately**: violated_invariant="token verifier reads algorithm from attacker-controlled token header; alg:none or RS256→HS256 confusion allows signature bypass", severity=10, confidence=8.

**C — Fail-open on error**: Does any exception handler in the auth pipeline catch validation errors silently and allow the request through (pass, continue, return default user)?
→ **submit immediately**: violated_invariant="auth validation exception handler fails open; crafted tokens that trigger exceptions are treated as authenticated", severity=10, confidence=9.

## Step 2 — Check token claim validation

From the auth code found in Step 1, find where JWT/token claims are validated (expiry, issuer, audience, signature). Read that code.

**A — Audience skipped**: Is audience (`aud`) validation absent, disabled, or using a non-exact match (substring, prefix)?
→ **submit immediately**: violated_invariant="token audience not validated or validated loosely; tokens issued for service A are accepted by service B", severity=9, confidence=8.

**B — Revocation order**: If there is a token blacklist or revocation list — is it checked BEFORE or AFTER signature verification? Blacklist after signature means a forged token (never issued, never in the list) bypasses revocation entirely.
→ If after: **submit immediately**: violated_invariant="token revocation check runs after signature validation; a token forged with a leaked key is never in the blacklist and bypasses revocation", severity=7, confidence=8.

## Step 3 — Find signing secrets

Find the config/settings file where signing keys, session secrets, and HMAC keys are defined. Read the value assignments.

**A — Hardcoded fallback in application code**:
```
os.environ.get('KEY', 'some-literal-value')
process.env.KEY || 'some-literal-value'
```
→ **submit immediately**: violated_invariant="signing/session secret has non-empty hardcoded fallback in application code; anyone with source access can forge tokens or sessions", severity=10, confidence=9.

**B — Literal value in deployment config** (docker-compose, helm, k8s manifest): is the key set as a literal string rather than a secret manager reference like `${VAR}` or `secretKeyRef`?
→ **submit immediately**: violated_invariant="signing secret committed as literal string in deployment config; any developer with repo access has the production secret", severity=9, confidence=9.

## Step 4 — Find commented-out security checks

Read the payment, billing, and financial operation handlers — the views or controllers that handle money movement, wallet operations, or subscription purchases. Do not search by name; navigate from the routing file to the payment-related handlers.

**Commented-out auth/authz**: Is there any commented-out block (`#`, `//`, `/* */`) that looks like an authentication requirement, identity check, or authorization guard?
→ **submit immediately**: violated_invariant="authentication/authorization check is commented out in [handler name]; the endpoint executes the sensitive operation without verifying the caller's identity or ownership", severity=9, confidence=9.

**Caller-supplied identity**: Does the handler accept an identity field (user ID, employee ID, account ID) from the request body and use it as the actor for a financial operation, instead of reading the actor from the authenticated session?
→ **submit immediately**: violated_invariant="[operation] uses caller-supplied actor ID from request body rather than authenticated session; caller can operate as any identity by supplying their ID", severity=9, confidence=9.

## Step 5 — Find TLS-disabled key fetches and dev auth injection

**A — TLS off for key fetch**: Find any HTTP call that fetches signing keys or auth configuration from an external service. Read the TLS/SSL verification parameter.
- `verify=False`, `ssl=false`, `InsecureSkipVerify: true`, or `verify = not DEBUG`
→ **submit immediately**: violated_invariant="signing key or auth config fetched with TLS verification disabled [or conditionally disabled]; MITM can inject forged key material", severity=7, confidence=8.

**B — Dev auth injection**: Find any middleware that creates or injects an authenticated identity for requests that would otherwise be unauthenticated. Read the activation condition.
- Activates on a non-standard env var (not DEBUG itself) → could be set on staging accidentally
→ **submit immediately**: violated_invariant="dev/test auth injection middleware activates on env var [name]; if accidentally set on staging, all unauthenticated requests are treated as authenticated", severity=8, confidence=7.

## Finish

Call finish() with all hypotheses. Call it now even if the list is empty.
