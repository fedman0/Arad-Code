# SKILL: understand-auth-and-session

## Goal

Read and understand the complete authentication and session system in this codebase.
Do NOT assume how any framework works — read how THIS application implements it.
This skill is language-agnostic: apply to any web stack.

Find any place where authentication can be bypassed, weakened, or subverted.

---

## Phase 1 — Trace the authentication pipeline

**How does a raw HTTP request become an authenticated identity?**
1. Call `get_architecture` to find the authentication layer.
2. Find the code that runs on every request before the handler (middleware, filter, interceptor,
   guard, decorator — whatever this framework calls it).
3. Use `trace_path(mode="calls", direction="outbound")` from the request entry point to find it — do not search by name.
4. Read the complete implementation of every step:
   token extraction → parsing → cryptographic validation → identity construction.

---

## Phase 2 — Verify credential validation

For token-based authentication (JWT, PASETO, signed cookies, HMAC tokens, etc.):

**Cryptographic checks:**
- Is the signature verified? With what algorithm?
- Can the algorithm be controlled by the caller? (JWT `alg` field: if the verifier reads the
  algorithm from the token header, an attacker can set `alg: "none"` or switch from RS256 to HS256
  using the public key as the HMAC secret)
- Is there an explicit allowlist of accepted algorithms, or does the library accept whatever
  the token claims?

**Claims and metadata:**
- Is expiry (`exp`) checked? Before or after other checks?
- Is the issuer (`iss`) verified? Exact string match, or prefix/substring?
- Is the audience (`aud`) verified? Or skipped?
- Are there any other security-relevant claims (scope, permissions, roles embedded in token)?
  Read what happens if they are absent or malformed.

**Key source:**
- Is the signing key fetched from an external source (JWKS endpoint, key server)?
- Is SSL verified when fetching the key? What happens if key fetching fails — does the
  system fail open (skip validation) or fail closed (reject)?

**Error handling:**
- What happens when any validation step fails?
- Is the request immediately rejected with no further processing?
- Or does partial state persist (partial token parse, partial identity object)?

---

## Phase 3 — Order of checks

Write down the actual order of operations in the auth pipeline. Specifically:
- Does any cache, allowlist or revocation lookup run before signature validation? A lookup that
  returns an identity on a hit (e.g. "token seen before → authenticated") lets a token skip
  cryptographic validation entirely. A revocation check that some path skips (early return,
  exception handler) lets revoked tokens through.
- Are there any early-return paths that skip later checks?
- Is there a "shortcut" condition that returns an authenticated identity before the full
  validation completes?

---

## Phase 4 — Bypass conditions

Read every conditional in the authentication pipeline:
- Is auth skipped based on a feature flag, environment variable, configuration value?
- Is there middleware or test code that injects an identity for unauthenticated requests?
  (common in test environments — does it run in staging/production too?)
- Are any endpoints explicitly exempted from authentication? Read the exemption list.
  Is every exempted endpoint intentionally public, or was it forgotten?

---

## Phase 5 — Session lifecycle

- After logout: can the credential still be used? How is revocation stored and checked?
- For single-use tokens (password reset, email verification, OTP): are they invalidated
  before or after the action succeeds? Check-then-invalidate-after is a race condition.
- After a security-sensitive event (password change, phone change, role change): are ALL
  existing sessions for that user invalidated?

**Session fixation:**
- Is a new session ID generated immediately after successful authentication?
  If the pre-authentication session ID is kept after login, an attacker who can set the
  victim's session ID (via subdomain cookie, URL parameter, or earlier XSS) can pre-set it
  and take control once the victim logs in.
- Can a session ID be provided via URL parameter?
  (Java: `;jsessionid=X`, PHP: `?PHPSESSID=X`) — these enable session fixation trivially.
- Can a session cookie be set for a parent domain by the application or a related subdomain?

**Cookie security flags:**
- Find the session cookie creation. Read all three flag settings:
- `HttpOnly`: without it, JavaScript can read the cookie → XSS becomes session hijack.
- `Secure`: without it, the cookie is sent over unencrypted HTTP if available.
- `SameSite`: already covered in http-security skill; confirm all three flags together.

**MFA bypass:**
- If MFA is implemented (TOTP, SMS OTP, hardware key): find the post-first-factor handler.
- Can the MFA step be skipped by directly accessing the post-authentication endpoint
  without completing MFA? (forced browsing: authenticate step 1 → access `/dashboard` directly)
- Read the session/token state at each step: does step 1 create a partially-authenticated
  token that only becomes fully valid after MFA? Or does a fully-authenticated session
  exist after step 1 with MFA as a separate check?
- Are backup codes single-use? Are they rate-limited?
- Does a phone number change invalidate existing MFA enrollment?

---

## Phase 6 — Cryptographic and randomness weaknesses

**Token generation (any type — session ID, password reset token, OTP, API key):**
- How is the token value generated? Read the actual generation call.
- Is it generated from a cryptographically secure random source?
  (OS-level randomness: /dev/urandom, CryptGenRandom, etc.)
- Or from a weak source: current time, sequential counter, predictable seed?
- What is the entropy? How many bits? A 6-digit OTP has ~20 bits — sufficient only if
  rate-limited and single-use.

**Token/secret comparison:**
- How are tokens compared during validation? Read the comparison code exactly.
- Constant-time comparison (timing-safe): purpose-built comparison functions in the
  language's standard library (e.g. functions specifically named for HMAC/digest comparison).
- Variable-time comparison (timing attack risk): `==`, `!=`, standard string equality,
  any comparison that short-circuits on the first differing byte.
- This matters for: API keys, HMAC signatures, password reset tokens, webhook secrets.
  It does NOT matter for public values like usernames.

**Password storage:**
- How are passwords stored? Find and read the password hashing call.
- Safe: adaptive hashing algorithms designed for passwords (bcrypt, Argon2, scrypt, PBKDF2
  with sufficient iterations). These are intentionally slow.
- Unsafe: general-purpose hash functions (MD5, SHA-1, SHA-256, SHA-512) even with salt —
  these are too fast and can be brute-forced.
- Is a per-user salt used? Is it unique and random per user?

**Signing key strength:**
- For symmetric signing: what is the secret key? Is it long and random, or a short string?
  A key shorter than the hash output size (e.g. less than 32 bytes for HS256) weakens the scheme.
- Where does the key come from? Is it from an environment variable (acceptable) or hardcoded?

**Symmetric encryption cipher modes (if app encrypts data, not just hashes):**
- Find where the application encrypts and decrypts data (not hashing — actual encrypt/decrypt).
- Is AES-ECB used? ECB: identical plaintext blocks → identical ciphertext → patterns visible.
- Is AES-CBC used with a static or predictable IV? A reused IV leaks which messages share a common prefix;
  a predictable IV enables chosen-plaintext guessing. For CTR/GCM, a reused nonce with the same key is worse:
  XORing two ciphertexts yields the XOR of the plaintexts, and GCM nonce reuse also exposes the authentication key.
- Is authenticated encryption used (AES-GCM, ChaCha20-Poly1305)?
  Without authentication tag: ciphertext can be tampered and the decryptor won't detect it
  (padding oracle, bit-flipping).

**Account and user enumeration:**
- For login: does the error response differ between "user does not exist" and "wrong password"?
- For registration: does "email already taken" differ from a successful registration flow?
- For password reset: does the response reveal whether the submitted email is registered?
- Is there a timing difference between valid and invalid accounts?
  Read the code path for each case — does a valid username trigger a database lookup + hash
  comparison while an invalid one returns early?

---

## Phase 7 — Race conditions in auth operations

**Single-use token redemption:**
- For password reset links, email confirmation links, OTP codes:
  1. Find the code that validates the token.
  2. Find the code that invalidates/deletes the token.
  3. Which happens FIRST?
  - Safe: invalidate atomically before executing the action (atomic compare-and-delete).
  - Unsafe: validate → execute action → invalidate (two concurrent requests both pass).

---

## What to produce

A hypothesis for each:
- Validation step absent, in wrong order, or bypassable
- Algorithm confusion: caller controls which algorithm is used to verify their own token
- Cache/allowlist shortcut that returns an identity before signature validation, or a revocation check skipped on some path
- Auth conditioned on an environment variable that is set incorrectly in staging
- Token generated from a predictable or low-entropy source
- Variable-time comparison used on a secret value
- Password stored with a fast hash algorithm (not designed for password storage)
- Single-use token redeemable twice via concurrent requests
- Sessions not invalidated after security event (password change, role change)
- Session fixation: pre-authentication session ID kept after login
- Cookie missing HttpOnly or Secure flag
- MFA bypass via forced browsing to post-MFA endpoint
- Account enumeration: distinguishable responses for valid vs invalid accounts
- Symmetric encryption using ECB mode, CBC with static/predictable IV, or a reused CTR/GCM nonce
- Encryption without authentication tag (malleable ciphertext)

Include the full execution path from HTTP request to identity object, with file:line for every step.

Set `cwe` on each hypothesis (e.g. CWE-287 missing or bypassable validation step, CWE-347 algorithm confusion or
unverified signature, CWE-330 predictable token, CWE-208 variable-time secret comparison, CWE-916 fast password hash,
CWE-367 single-use token race, CWE-613 sessions not invalidated, CWE-384 session fixation, CWE-1004 / CWE-614 missing
HttpOnly / Secure, CWE-288 MFA bypass, CWE-204 account enumeration, CWE-327 ECB, CWE-329 predictable CBC IV,
CWE-323 reused nonce, CWE-353 missing integrity tag).

## Forbidden

- Do not assume any library or framework validates audience, algorithm, or issuer correctly
  without reading the code
- Do not report "JWT is used" as a finding — read how it is validated
- Do not skip the middleware/filter/interceptor stack — read every class that runs before the handler
- Do not report timing attack risk on a comparison of a public value (username, user ID, etc.)
