# SKILL: hunt-auth-bypass-patterns

## ⚡ BREADTH SCAN — grep-first, pattern-confirmed

Each step below gives you an exact grep pattern to run. If the pattern matches, read the surrounding code with `get_code_snippet` or `read_file`, confirm the pattern is present, and immediately submit a finding. Budget: 2 tool calls per step maximum.

---

## Step 1 — Header-based privilege check

```
grep(pattern="headers\\.get.*return True|in.*headers.*return True|\\.META\\.get.*return True|getHeader.*return true|r\\.Header\\.Get.*return nil", max_matches=10)
```

Also run:
```
grep(pattern="request\\.headers|request\\.META\\.get|req\\.headers\\[|r\\.Header\\.Get|request\\.getHeader", max_matches=20)
```
Then call `get_code_snippet` on any function that reads a header. Check: does it return `True`/`true`/`authorized` based solely on the header value, without checking a database or cryptographic proof?

→ Submit: violated_invariant="privilege granted based on caller-controlled request header without cryptographic binding; any caller adds that header to bypass the check", severity=10, confidence=7, exposure="internet"

---

## Step 2 — Token audience validation disabled in fallback

```
grep(pattern="verify_aud.*False|\"verify_aud\":\\s*False|verify_aud=False", max_matches=10)
```

If found inside an `except` block (the line is inside a try/except where the first decode attempt fails and the except clause retries with audience disabled):

→ Submit: violated_invariant="token audience validation disabled in error fallback path; a token issued for a different service is accepted", severity=9, confidence=7, exposure="internet"

---

## Step 3 — TLS verification disabled when debug flag is set

```
grep(pattern="verify_ssl.*not.*[Dd]ebug|verify.*=.*not.*DEBUG|ssl_verify.*not.*debug", max_matches=10)
```

If found: the TLS verification flag for an external HTTP request (to fetch signing keys or JWT issuer config) is disabled when the debug flag is true.

→ Submit: violated_invariant="TLS verification for signing key fetch disabled when debug flag is set; MITM substitutes attacker-controlled signing key material", severity=7, confidence=7, exposure="internet"

---

## Step 4 — Signing key has hardcoded fallback in deployment config

```
grep(pattern="SECRET_KEY:-|JWT_SECRET.*:-|SIGNING_KEY:-|jwt.*secret.*:-", max_matches=10)
```

If found in a deployment file (docker-compose.yml, .env.example, Helm values): the secret has a non-empty literal fallback value after `:-`.

→ Submit per secret: violated_invariant="signing/session secret has a non-empty hardcoded fallback literal; any deployment without explicit env vars uses this known secret", severity=10, confidence=7, exposure="internet"

---

## Step 5 — Authentication check commented out in financial handler

```
grep(pattern="#.*is_authenticated|#.*UnauthorizedException|#.*raise.*Auth|#.*active_employee", max_matches=10)
```

If found in a payment, billing, or wallet handler file:

→ Submit: violated_invariant="authorization check commented out in payment handler; financial operation runs without verifying caller's identity", severity=9, confidence=7, exposure="authenticated"

---

## Step 6 — Token revocation checked after signature verification

```
grep(pattern="get_validated_token|validate.*token|verify.*token", max_matches=10)
```

For each match, call `get_code_snippet` on the containing class. Check whether the blacklist or revocation store lookup happens AFTER `super().get_validated_token()` or equivalent. The dangerous order: signature check → then blacklist check.

→ If revocation is after signature: Submit: violated_invariant="token revocation check runs after signature verification; a token forged with a compromised key is never in the revocation list and bypasses it", severity=7, confidence=7, exposure="authenticated"

---

## Step 7 — Dev auth injection middleware

```
grep(pattern="LOCAL_TESTING|TestUserAuth|auth.*inject|inject.*auth|X-Test-User|test.*middleware.*auth", max_matches=10)
```

If found: a middleware class that sets or overrides the Authorization header or authenticated user based on a non-production environment variable.

→ Submit: violated_invariant="dev auth injection middleware activates on an environment variable that could be set on staging; all requests become pre-authenticated without credentials", severity=8, confidence=7, exposure="internet"

---

## Finish

Call `finish()` now with all hypotheses collected. Do not skip this.
