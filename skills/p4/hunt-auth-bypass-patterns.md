# SKILL: hunt-auth-bypass-patterns

You are a security researcher. Find authentication and authorization bypass vulnerabilities. Work in this order for every step: find the code → read it → check the condition → submit if found → move to the next step.

---

## Step 1 — Find and read the authentication layer

Call `get_architecture` to understand the project.

Use `search_graph` to find the code that handles authentication — search for nodes whose name or qualified name contains terms like `auth`, `middleware`, `token`, `jwt`, `permission`, `filter`, `guard`, `interceptor`. These are the standard terms every framework uses regardless of language. Read every result.

Then use `trace_path` from the authentication entry point to follow the full validation chain: credential extraction → cryptographic verification → identity construction.

Read every function in that chain.

---

## Step 2 — Check: is a request field trusted for the access decision?

In the code you read: does any branch read a value directly from the HTTP request (a header, query parameter, body field, or cookie) and use that value to decide that the caller is authenticated or has elevated privilege — **without** verifying it against a server-side record or cryptographically signed credential?

This is the pattern: caller sends field X → code checks if X equals some expected value → if yes, grants access. The caller controls X.

→ If found: `finish` with hypothesis — violated_invariant="access granted based on attacker-controlled request field [describe it] without cryptographic binding; any caller sets that field to bypass the check", severity=10, confidence=8.

---

## Step 3 — Check: is the token/credential validated correctly?

In the token validation code:

**A — Algorithm not pinned:** Does the decoder accept the signing algorithm from inside the token rather than an explicit allowlist? If so, an attacker sets `alg:none` or swaps RS256 for HS256.
→ Submit: violated_invariant="signing algorithm read from attacker-controlled token header; algorithm confusion or none bypass possible", severity=10, confidence=8.

**B — Audience not strictly checked:** Is the `aud` claim absent from validation, disabled, or checked with a non-exact match?
→ Submit: violated_invariant="token audience not strictly validated; token issued for one service accepted by another", severity=9, confidence=8.

**C — Revocation after signature:** Is there a token blacklist or revocation store? Is it queried BEFORE or AFTER signature verification? After means a forged token (never issued, never in the list) bypasses revocation.
→ Submit: violated_invariant="revocation check runs after signature verification; a token forged with a leaked key is not in the blacklist", severity=7, confidence=8.

**D — Exception swallowed:** Does any exception handler in the validation chain catch failures silently and let the request continue?
→ Submit: violated_invariant="credential validation exception caught and swallowed; a malformed credential that causes an error passes as authenticated", severity=10, confidence=9.

---

## Step 4 — Check: is the signing secret strong and private?

From the authentication code: find where the signing key or session secret is loaded. Navigate to that configuration code and read it.

**E — Hardcoded fallback:** Is the secret loaded with a default literal value if the environment variable is absent?
```
getenv('KEY', 'some-literal')   # any language variant
process.env.KEY || 'literal'
config.get('key', 'literal')
```
→ Submit: violated_invariant="signing/session secret has a non-empty hardcoded fallback; anyone with source code forges tokens", severity=10, confidence=9.

**F — Literal in deployment config:** Find the infrastructure/deployment configuration (container definitions, orchestration files, environment files). Is the signing secret written as a literal string rather than a secrets manager reference?
→ Submit: violated_invariant="signing secret committed as literal string in deployment config; any developer with repo access has the key", severity=9, confidence=9.

---

## Step 5 — Check: financial handlers and dev auth injection

**G — Commented-out security check:** Navigate from the route definitions to handlers for financial operations (payment, wallet, billing). Read them. Is any authentication or authorization check commented out?
→ Submit: violated_invariant="auth/authz check commented out in [handler]; financial operation runs without verifying caller identity", severity=9, confidence=9.

**H — Actor identity from request:** Does a financial handler read the identity of the party being charged from the request body/params rather than from the authenticated session?
→ Submit: violated_invariant="[handler] uses caller-supplied identity field as the debited party; caller charges any person", severity=9, confidence=9.

**I — TLS disabled for external key fetch:** In the authentication code: find any HTTP call to an external endpoint that provides signing keys or auth configuration. Is TLS verification disabled or conditionally disabled when a debug flag is set?
→ Submit: violated_invariant="signing key fetched from external endpoint with TLS disabled; MITM substitutes forged key material", severity=7, confidence=8.

**J — Dev auth injection on non-debug env var:** Use `search_graph` to find middleware that auto-authenticates requests without credentials. Read its activation condition. Does it activate on an env var that could be accidentally set on staging (not the main debug flag)?
→ Submit: violated_invariant="dev auth injection middleware activates on [env var]; if set on staging, all requests become authenticated without credentials", severity=8, confidence=7.

---

## Finish

Call `finish()` now with all hypotheses found. Even if the list is empty.
