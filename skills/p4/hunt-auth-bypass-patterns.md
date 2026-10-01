# SKILL: hunt-auth-bypass-patterns

You are a security researcher. Find authentication and authorization bypass vulnerabilities. For each step: (1) locate the code with search_graph, (2) read it with get_code_snippet, (3) look for the exact pattern described, (4) submit if found, (5) move on. Do not summarize or conclude early — work through every check.

---

## Step 1 — Find the authentication layer

Call `search_graph` with `name_pattern="auth|middleware|token|jwt|permission|filter|guard|interceptor"` and `label="Class"`. Read the results. Identify which classes handle authentication (classes in files whose path contains "auth", "middleware", or "authentication"). Call `get_code_snippet` on each.

Also call `search_graph` with `name_pattern="authenticate|validate_token|verify_token|get_validated_token"`. Call `get_code_snippet` on any result that looks like it validates credentials.

---

## Step 2 — Check: header used as authorization decision

In the code you read: does any function read an HTTP header (using `.get("Header-Name")`, `request.headers.get(...)`, `request.META.get(...)`, or equivalent) and then use that value to return `True` for an admin/privilege check — WITHOUT verifying it against a database record or cryptographic proof?

The dangerous pattern looks like:
```
header_value = request.headers.get("SomeName")
if "some-literal" in header_value:
    return True   ← grants access based solely on a header the caller controls
```

→ If found: submit — violated_invariant="privilege granted based on caller-controlled request header without cryptographic binding; any caller adds that header to bypass the check", severity=10, confidence=9.

---

## Step 3 — Check: token audience validation disabled

In the token validation code, look for any `decode(...)` call that has `"verify_aud": False` or `verify_aud=False` or an equivalent option that disables audience checking. Pay special attention to try-except blocks where the first decode attempt validates audience but the except clause re-decodes with audience disabled — this is a silent fallback that accepts any token regardless of audience.

The dangerous pattern:
```
try:
    payload = decode(token, ..., options={"verify_aud": True})
except SomeError:
    payload = decode(token, ..., options={"verify_aud": False})  ← fallback accepts all tokens
```

→ If found: submit — violated_invariant="token audience validation disabled in error fallback path; a token issued for a different service is accepted", severity=9, confidence=9.

---

## Step 4 — Check: TLS disabled for external key fetch

In the authentication code, find any HTTP request to an external URL (calls like `requests.get(url, ...)`, `httpx.get(...)`, `fetch(url)`, or equivalent). Look at the SSL/TLS verification argument:

The dangerous pattern: `verify = not DEBUG` or `verify_ssl = not debug_flag` — when the debug flag is True, TLS verification is off.

→ If found: submit — violated_invariant="TLS verification for signing key fetch disabled when debug flag is set; MITM substitutes attacker-controlled signing key material", severity=7, confidence=9.

---

## Step 5 — Check: signing key has hardcoded fallback

In the authentication code, find where the signing secret or JWT key is loaded. Look for environment variable reads with a non-empty default literal:

```
getenv("KEY", "some-literal-string")          # Python
process.env.KEY || "literal"                   # Node
config.get("signing_key", "literal")           # any
```

Also read the deployment configuration file (docker-compose, Helm values, .env.example, or similar). Look for lines where a secret is defined with a literal value as the fallback:
```
SECRET_KEY: ${SECRET_KEY:-actual-literal-value-here}
JWT_SECRET: ${JWT_SECRET:-MLC+KgPZpHX$2.6R6s79N}
```

→ If found: submit — violated_invariant="signing/session secret has a non-empty hardcoded fallback literal; anyone with source or config access can forge tokens", severity=10, confidence=9.

---

## Step 6 — Check: financial handler with commented-out auth

Call `search_graph` with `name_pattern="payment|wallet|billing|checkout|subscribe|pay"` and `label="Class"`. Call `get_code_snippet` on each. Look for lines where an authentication or authorization check is commented out — lines starting with `//`, `#`, or `/*` that would otherwise raise an auth exception or verify identity.

The dangerous pattern:
```
# if not user.is_authenticated:
#     raise UnauthorizedException(...)
```

Also check whether the handler reads the actor's identity (which account to charge) from the request body/params (`request.data.get("user_id")`, `body["account_id"]`, etc.) rather than from the verified session token.

→ If commented-out auth found: submit — violated_invariant="authorization check commented out in payment handler; financial operation runs without verifying caller's identity", severity=9, confidence=9.
→ If actor ID from request body: submit — violated_invariant="payment handler reads actor identity from caller-controlled request field; caller can charge any account by supplying its ID", severity=9, confidence=9.

---

## Step 7 — Check: revocation after signature

In the token validation code, find where the blacklist or revocation store is checked. Is this check BEFORE or AFTER the cryptographic signature verification call?

The dangerous order:
```
validated_token = parent_class.validate(raw_token)    ← signature check first
if blacklist.contains(token_hash):                     ← revocation check after
    raise Expired()
```

A token never issued (forged with a leaked key) would pass signature AND not appear in the blacklist.

→ If found in this order: submit — violated_invariant="token revocation check runs after signature verification; a token forged with a compromised key is never in the revocation list and bypasses it", severity=7, confidence=8.

---

## Step 8 — Check: dev auth injection middleware

Call `search_graph` with `name_pattern="inject|test.*auth|auth.*inject|dev.*auth"` and `label="Class"`. Also look in the middleware you already read for any class that sets or overrides the `Authorization` header unconditionally. Find its activation condition. Does it activate on an environment variable that is NOT the main production guard (i.e., could accidentally be set in staging)?

→ If found: submit — violated_invariant="dev auth injection middleware activates on an environment variable that could be set on staging; all requests become pre-authenticated without credentials", severity=8, confidence=8.

---

## Finish

Call `finish()` now with all hypotheses collected. Do not skip this. Call it even if the list is empty.
