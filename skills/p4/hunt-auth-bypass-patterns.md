# SKILL: hunt-auth-bypass-patterns

You are a security researcher auditing this codebase for authentication and authorization bypass vulnerabilities. Navigate the code — do not use search_graph or search_code. Use get_architecture, read_file, get_code_snippet, and trace_path only.

---

## Step 1 — Locate the middleware/filter chain

Call `get_architecture`. From the result, identify:
- Where is the application configuration or settings file?
- How does this framework register request-processing middleware, filters, interceptors, or guards?

Read that configuration file. Find the list of middleware/filters registered for all requests. Copy the class names of every middleware that is related to authentication, authorization, or session handling.

For each of those class names: call `get_code_snippet` with the qualified class name to read its implementation completely.

---

## Step 2 — Analyze the auth middleware for bypass conditions

In the middleware code you just read, look for:

**A — Request field trusted for auth decision**
Is there any branch that reads a value from the request (header, query param, body field, cookie other than the session) and uses it to grant access or elevated privilege — without the server having cryptographically issued that value?

Pattern: `if request.header("X") contains "something" → return authorized`

→ Submit immediately: violated_invariant="auth/authorization grants access based on attacker-controlled [describe the field]; no cryptographic binding to actual identity", severity=10, confidence=8.

**B — Token algorithm read from token itself**
Does the JWT/token decoder accept the signing algorithm from the token's own header rather than an explicit allowlist in the verify call?

→ Submit immediately: violated_invariant="token verifier reads algorithm from attacker-controlled token header; enables alg:none bypass or RS256→HS256 confusion with public key", severity=10, confidence=8.

**C — Validation exception swallowed**
Does any exception handler in the validation chain catch errors silently and allow the request to continue?

→ Submit immediately: violated_invariant="auth validation exception is caught and swallowed; a malformed credential that triggers an exception passes as authenticated", severity=10, confidence=9.

**D — Token audience not strictly checked**
For JWT or OIDC tokens: is the audience (`aud`) claim validated with strict equality? If it is absent, disabled, or uses a prefix/substring match, tokens issued for other services are accepted.

→ Submit immediately: violated_invariant="token audience check absent or uses loose match; token issued for service A is accepted by service B", severity=9, confidence=8.

**E — Revocation checked after signature**
If a token blacklist or revocation store exists: does the blacklist query run BEFORE or AFTER signature verification? A blacklist only catches tokens the server issued — if checked after signature, a token forged with a leaked key is not in the blacklist.

→ Submit immediately: violated_invariant="token blacklist checked after signature verification; a token forged with a compromised key is not in the blacklist and bypasses revocation", severity=7, confidence=8.

---

## Step 3 — Find the signing key source

From the middleware code you read: identify what configuration key or environment variable provides the signing secret (the key used to sign or verify tokens/sessions). Navigate to the configuration code that supplies it — read the assignment.

**F — Hardcoded fallback value**
The signing key is loaded with a fallback:
```
get_env('KEY', 'hardcoded-value')
os.environ.get('KEY', 'fallback')
process.env.KEY || 'fallback'
config.getOrDefault('KEY', 'literal')
```
→ Submit immediately: violated_invariant="signing/session secret has a non-empty hardcoded fallback; anyone with source code access has a working signing key to forge tokens", severity=10, confidence=9.

**G — Secret as literal string in deployment config**
Navigate to the infrastructure/deployment configuration (container definitions, orchestration manifests, environment files). Find where the signing key environment variable is set. Is it a literal string value, rather than a reference to an external secret store?

→ Submit immediately: violated_invariant="signing secret is a literal string in the deployment configuration; any developer with repository access has the production key", severity=9, confidence=9.

---

## Step 4 — Read payment and billing handlers

From the `get_architecture` result: find where URL routes or API endpoints are defined. Read the route configuration. Identify routes for financial operations: payment initiation, wallet operations, subscription purchase, payment provider callbacks.

For each: call `get_code_snippet` with the handler class name to read its implementation.

**H — Commented-out security check**
Is there any commented-out block (lines starting with `#`, `//`, or inside `/* */`) that looks like it was or should be an authentication requirement, identity check, or authorization guard?

→ Submit immediately: violated_invariant="authentication/authorization check is commented out in [handler name]; financial operation executes without verifying caller's identity or ownership", severity=9, confidence=9.

**I — Actor identity from request body**
Does the handler read the identity of the party being charged (employee ID, user ID, account ID) from the request body or query params rather than from the authenticated session/token?

→ Submit immediately: violated_invariant="[handler] reads actor identity [field name] from request input; caller can specify any person as the party for the financial operation", severity=9, confidence=9.

---

## Step 5 — TLS for external key fetch and dev auth injection

**J — TLS disabled for external key fetch**
From the auth middleware code (already read): find any HTTP call that fetches signing keys or auth configuration from an external service. Read the TLS verification option on that call.

If TLS is disabled (`verify=False`, `ssl=false`, `InsecureSkipVerify`) or conditionally disabled when a debug flag is set:
→ Submit immediately: violated_invariant="signing key or auth config fetched from [endpoint] with TLS verification disabled; a network-positioned attacker can substitute forged key material", severity=7, confidence=8.

**K — Dev/test auth injection middleware**
Return to the middleware list from Step 1. Is there any middleware that auto-authenticates requests (creates or injects a user identity for requests that would otherwise be unauthenticated)? Read its activation condition.

If it activates on an environment variable that is not the main debug flag (something that could be accidentally set on a staging server):
→ Submit immediately: violated_invariant="dev/test auth-injection middleware activates on env var [name] rather than the main debug flag; if accidentally set on staging, all requests without credentials become authenticated", severity=8, confidence=7.

---

## Finish

Call `finish()` with all hypotheses. Call it now even if the list is empty.
