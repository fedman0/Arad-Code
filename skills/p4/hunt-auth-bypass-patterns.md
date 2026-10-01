# SKILL: hunt-auth-bypass-patterns

## Goal

Find bugs that let a caller authenticate as someone they are not, or gain privileges they don't have. You will read the actual code of this specific application — do not assume how its auth works.

---

## Step 0 — Orient yourself

Call `get_architecture`. From the result, understand:
- What language and framework is this?
- Where does an HTTP request enter the application?
- Where is the authentication layer? (middleware, filter, guard, interceptor — whatever the framework calls it)

Read the authentication layer completely. Then proceed through the steps below. Each step is a single class of bug to look for in what you just read (and in code you navigate to from it).

---

## Step 1 — Does anything from the request short-circuit the identity check?

Read the authentication and authorization decision code. Look for any branch where a value from the incoming request — a header, a query parameter, a field in the request body, a cookie other than the session — determines whether the caller is treated as authenticated or elevated-privilege, BEFORE or INSTEAD OF verifying a cryptographically-backed identity.

The pattern: "if request contains X → grant access" where X is something the caller can set freely, not something the server issued.

**Submit if found**: violated_invariant="caller-supplied [field type] [field name] is trusted to grant [access level] without cryptographic binding to the authenticated identity; any caller can satisfy the check by setting that field", severity=10, confidence=8.

---

## Step 2 — Is any authentication requirement commented out?

Read the payment, billing, wallet, and financial operation handlers. Navigate to them from the route definitions — read the route table, find the routes that handle financial operations, read those handlers.

Look for commented-out lines that look like they were (or should be) an authentication requirement, ownership check, or identity verification. A block of code beginning with `#`, `//`, or `/*` that reads like a security check is a high-value signal.

Also look for: does the handler accept an actor identity (the person being charged, the employee being billed) from the request body/params rather than reading it from the authenticated session/token?

**Submit if found (commented-out check)**: violated_invariant="authentication/authorization check is commented out in [handler]; the financial operation executes without verifying the caller's identity or ownership", severity=9, confidence=9.

**Submit if found (caller-supplied actor)**: violated_invariant="[handler] reads actor identity [field name] from request input; caller names any identity as the party for the financial operation", severity=9, confidence=9.

---

## Step 3 — Is the credential validation correct?

From the authentication code you read in Step 0: find where the credential (JWT, session token, signed cookie, API key — whatever this app uses) is validated. Read the validation logic completely.

Look for:
- **Algorithm confusion**: does the validator read the signing algorithm from the credential itself, rather than checking against an explicit allowlist? If so, an attacker can set `alg: none` or swap RS256 for HS256.
- **Missing claim validation**: for JWT-style tokens — is the audience (`aud`) validated with strict equality? Is expiry checked before other logic runs?
- **Revocation order**: if there is a token blacklist or revocation store — is the revocation check performed BEFORE or AFTER the signature is verified? A blacklist checked after signature validation cannot catch a token forged with a leaked key.

**Submit per issue found**: describe the specific validation step that is absent or in wrong order.

---

## Step 4 — Is the signing secret strong and external?

Find where the application's signing secret (the key used to sign/verify tokens or sessions) is configured. This is typically loaded from an environment variable or config system at startup.

Look for:
- A **hardcoded fallback**: `get_env('KEY', 'some-literal-string')` — if the env var is absent, the fallback is used. Anyone with the source code can forge tokens.
- A **literal value in deployment config**: the key is written as a plain string in infrastructure configuration (container config, orchestration manifests, environment files) rather than referenced from a secrets manager.

**Submit per issue**: violated_invariant="signing secret [description] has hardcoded fallback / is committed as literal; source code or repo access gives an attacker a working signing key", severity=10, confidence=9.

---

## Step 5 — Are external keys fetched securely? Is there debug auth injection?

**TLS for key fetch**: if the application fetches signing keys or auth configuration from an external service (JWKS endpoint, OIDC discovery, key server) — find that HTTP call and read its TLS verification setting. Is verification disabled, or disabled conditionally when a debug flag is set?
→ Submit: violated_invariant="signing key fetched from [endpoint] with TLS verification disabled [or disabled when debug=true]; MITM can substitute forged key material", severity=7, confidence=8.

**Debug auth injection**: is there any middleware or code path that automatically authenticates a request (injects a user identity, bypasses credential check) based on an environment variable? Read the activation condition — is it something that could be accidentally set on a staging or production server?
→ Submit: violated_invariant="auth injection code activates on env var [name]; if set on staging, all requests are auto-authenticated without credentials", severity=8, confidence=7.

---

## Finish

Call finish() with all hypotheses. Do it now even if the list is empty.
