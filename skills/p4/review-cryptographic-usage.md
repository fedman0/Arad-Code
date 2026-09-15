# SKILL: review-cryptographic-usage

## Contract

**Trigger:** Phase 4, after map-sensitive-data and review-session-lifecycle.
**Phase:** 4 — Security Analysis
**Preconditions:** Sensitive data map, auth mechanism
**Escalates to:** review-session-lifecycle

## Inputs
- repo_path

## Procedure
1. search_code(pattern="MD5|SHA1|DES|3DES|ECB|RSA\.Encrypt|new Random\(|Math.random\(\)") to find weak/broken crypto.
2. Find password hashing: is bcrypt/scrypt/Argon2/PBKDF2 used? Is MD5/SHA1/SHA256 used without salt or iterations?
3. Find symmetric encryption: what cipher? What mode? Is IV/nonce random and unique per encryption? Is it authenticated (AES-GCM vs. AES-CBC)?
4. Find random number generation: cryptographic operations must use CSPRNG (RNGCryptoServiceProvider, secrets.token_bytes, crypto.randomBytes).
5. Find key management: where are encryption keys stored? Are they hardcoded? Are they rotated?
6. Find signature verification: RSA/ECDSA — is the signature verified before the data is processed?
7. Find token generation: reset tokens, CSRF tokens, API keys — are they generated with sufficient entropy?
8. Check TLS configuration: minimum TLS version, cipher suites (only for server-side config in code).
9. Find homegrown crypto: any custom encryption implementation that isn't using a standard library.
10. Find constant-time comparison: for timing-sensitive operations (HMAC verification, token comparison), is bytes.Equal or constant-time compare used?

## Required evidence
- Password hashing algorithm and parameters (iterations, salt)
- Symmetric cipher mode and IV/nonce generation
- CSPRNG vs. PRNG usage for secrets
- Key storage mechanism
- Token entropy bits
- Constant-time comparison for security tokens

## Counterchecks
- SHA256 without PBKDF2 for passwords is weak but not same severity as MD5.
- AES-CBC without authentication is vulnerable to padding oracle; AES-GCM provides both.
- Hardcoded IV is weaker than random IV but doesn't allow full decryption unless IV is also predictable for future messages.

## Output schema
Standard FINDINGS_SCHEMA. Hypotheses for: MD5/SHA1 password hash, ECB mode, predictable token, PRNG for security-sensitive secret, timing attack on token comparison.

## Stop condition
When all cryptographic operations are classified by algorithm, mode, and key/IV management.

## Forbidden inferences
- Do not report SHA256 for integrity checking (not passwords) as a vulnerability.
- Do not report weak TLS cipher suites without confirming the code actually configures them (many use OS defaults).
