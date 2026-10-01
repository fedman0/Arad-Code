# SKILL: hunt-auth-bypass-patterns

## Goal

Hunt for every way an attacker can bypass, short-circuit, or forge authentication in
this codebase. This is an active hunt — you are looking for bugs, not documenting
correct behavior. Assume every auth check is broken until you verify it is not.

---

## Step 1 — Find every authentication function and middleware

Use `search_graph` to find:
- Functions named `is_admin`, `is_superuser`, `check_admin`, `has_permission`, `is_staff`
- Middleware classes (anything with `process_request`, `__call__`, or registered in MIDDLEWARE)
- Authentication classes (anything subclassing `BaseAuthentication`, `JWTAuthentication`,
  `TokenAuthentication`, or anything listed in `DEFAULT_AUTHENTICATION_CLASSES`)

Read EVERY function you find. Do not sample. Read the complete body.

---

## Step 2 — Audit every auth function for header-based shortcuts

For each function found in Step 1, look for this pattern:
```python
request.headers.get("SomeName")  # or request.META.get("HTTP_SOMENAME")
```
used to make an **authorization decision** (return True, skip further checks, grant admin).

**This is always a critical finding** if:
- The header value controls whether an admin/elevated check passes
- The header is not cryptographically signed (no HMAC, no signature)
- Any authenticated (or unauthenticated) user can set the header

Write down: the function name, the header name, what the check grants, what the fallback is.

---

## Step 3 — Audit JWT/token validation order

Find the complete JWT validation pipeline. Trace from the raw token string to the
authenticated user object. Write down every step in order.

Specifically check:
1. Is the token signature verified? With what algorithm?
2. Is the algorithm read from the token header, or hardcoded to an allowlist?
   (If the verifier calls `jwt.decode(token, key, algorithms=jwt.get_unverified_header(token)["alg"])`,
   an attacker can set `alg: "none"` in the token header.)
3. Is the audience (`aud`) claim verified? Search for `verify_aud`, `options=`, `audience=`.
   If you see `options={"verify_aud": False}` or the audience parameter is omitted, that is a finding.
4. Is the issuer (`iss`) verified? Is it an exact string match or a prefix/startswith check?
   (`token_issuer.startswith(authority)` is a bypass — an attacker can register `authority.evil.com`)
5. Is there a token blacklist or revocation check? What line does it appear on relative to
   the signature verification call? **If the blacklist check comes AFTER signature verification**,
   a forged token (signed with a leaked/weak key) will never be in the blacklist and bypasses it.

---

## Step 4 — Find the signing key source

Find where the JWT signing key is defined. Typical locations: `settings.py`, `SIMPLE_JWT` dict,
`JWT_SECRET_KEY` env var, any `SECRET_KEY` usage.

**Critical pattern to find:**
```python
'SIGNING_KEY': os.environ.get('JWT_SECRET_KEY', 'some-fallback-string')
```
If there is a fallback value (second argument to `os.environ.get` or `os.getenv`), that is
a **token forgery** finding — anyone with read access to the source code can forge tokens.

Also check `docker-compose.yml` and any `.env*` files — are signing keys committed in plaintext?

---

## Step 5 — Audit OIDC/JWKS key fetching

Find where the OIDC configuration or JWKS endpoint is fetched. Look for:
```python
requests.get(url, verify=False)
requests.get(url, verify=verify_ssl)  # follow verify_ssl to find its value
```
If `verify=False` or if `verify_ssl` is computed as `not settings.DEBUG` (False when DEBUG is True),
that is a **MITM-allows-forged-tokens** finding for any environment where DEBUG might be True
(staging, preprod, CI).

---

## Step 6 — Find test/debug auth injection middleware

Search for middleware that:
- Reads `request.META.get("HTTP_AUTHORIZATION")` and injects a token when absent
- Reads `LOCAL_TESTING`, `TESTING`, `TEST_MODE` environment variables
- Auto-authenticates requests for convenience

For each found: under what condition does it activate? Can that condition be True in staging?
(`if os.environ.get('LOCAL_TESTING') == 'True'` can be accidentally set on a server.)

---

## Step 7 — Find unauthenticated endpoints that handle sensitive operations

Find every view class or function where **no** `permission_classes` is set (defaults to
`AllowAny` in DRF if `DEFAULT_PERMISSION_CLASSES` is not set). Cross-reference against:
- Payment callbacks (`callback`, `webhook`, `notify`, `return`)
- Admin operations
- Any endpoint that writes to the database

For payment callbacks specifically: is there an HMAC or signature verification against
the payment gateway's published secret? Search for the gateway name + "signature" or "hmac".
If a callback endpoint accepts `provider=sandbox` and takes different code paths based on it,
verify that the sandbox path cannot be invoked in production.

---

## What to produce

A hypothesis for EACH of:
- Header used to make an authorization decision (header controllable by any user)
- JWT `alg` read from token header (algorithm confusion attack possible)
- JWT audience (`aud`) not verified (`verify_aud: False` or parameter omitted)
- JWT issuer checked with prefix/startswith instead of exact equality
- Token blacklist checked AFTER signature verification (forged tokens bypass revocation)
- Signing key has a hardcoded fallback value in source code
- Signing key committed in plaintext to repository (docker-compose, .env file)
- OIDC JWKS fetched with `verify=False` or SSL disabled in staging
- Test/debug auth injection middleware that can activate in non-local deployment
- Payment/webhook callback accepts requests without gateway signature verification
- Payment callback accepts a `provider=sandbox` parameter that bypasses real verification

For each hypothesis, populate `violated_invariant` with the exact security property violated,
`entry_point` with the specific file:line or endpoint, and `execution_path` with the
exact call sequence from attacker input to the vulnerable point.

## Forbidden

- Do not report "JWT is used" without reading how it is validated
- Do not skip reading the actual signing key default value
- Do not assume `DEBUG=False` in staging without checking deployment config
- Do not report a finding based on reading headers that are sent TO the OIDC provider
  (those are outgoing, not incoming — the attacker doesn't control them)
