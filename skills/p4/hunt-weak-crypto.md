# SKILL: hunt-weak-crypto

## ⚡ BREADTH SCAN — semgrep-PRO-derived patterns, 15+ languages

Run grep, read context with `get_code_snippet`, submit immediately. 2 tool calls per step max.

---

## Step 1 — Broken hash algorithms (MD5 / SHA-1)

**Python:**
```
grep(pattern="hashlib\.md5\s*\(|hashlib\.sha1\s*\(|hashlib\.new\s*\(['\"]md5['\"]|hashlib\.new\s*\(['\"]sha1['\"]", max_matches=20)
```

**JavaScript / TypeScript (Node crypto):**
```
grep(pattern="createHash\s*\(['\"]md5['\"]|createHash\s*\(['\"]sha1['\"]|createHmac\s*\(['\"]md5['\"]|createHmac\s*\(['\"]sha1['\"]", max_matches=20)
```

**Java:**
```
grep(pattern="MessageDigest\.getInstance\s*\(['\"]MD5['\"]|MessageDigest\.getInstance\s*\(['\"]SHA-1['\"]|MessageDigest\.getInstance\s*\(['\"]SHA1['\"]", max_matches=20)
```

**Go:**
```
grep(pattern="md5\.New\s*\(\s*\)|md5\.Sum\s*\(|sha1\.New\s*\(\s*\)|sha1\.Sum\s*\(", max_matches=20)
```

**C#:**
```
grep(pattern="MD5\.Create\s*\(\s*\)|MD5CryptoServiceProvider\s*\(\s*\)|SHA1\.Create\s*\(\s*\)|SHA1CryptoServiceProvider\s*\(\s*\)", max_matches=20)
```

**PHP:**
```
grep(pattern="hash\s*\(\s*['\"]md5['\"]|hash\s*\(\s*['\"]sha1['\"]|md5\s*\(\s*\\\$|sha1\s*\(\s*\\\$|hash_hmac\s*\(\s*['\"]md5['\"]|hash_hmac\s*\(\s*['\"]sha1['\"]", max_matches=20)
```

**Ruby:**
```
grep(pattern="Digest::MD5\.|OpenSSL::Digest::MD5\.|OpenSSL::Digest::SHA1\.|Digest::SHA1\.", max_matches=20)
```

**Kotlin / Java (commons-codec):**
```
grep(pattern="DigestUtils\.getMd5Digest\s*\(\s*\)|DigestUtils\.md5\s*\(|org\.apache\.commons\.codec\.digest\.DigestUtils\.md5", max_matches=15)
```

**Swift:**
```
grep(pattern="CC_MD5\s*\(|CC_SHA1\s*\(|kCCHmacAlgMD5|kCCHmacAlgSHA1", max_matches=15)
```

**Rust:**
```
grep(pattern="md5::compute\s*\(|sha1::Sha1::new\s*\(\s*\)|sha1::digest", max_matches=15)
```

For each match: `get_code_snippet("containing_function")` to read the full function body and identify what the hash result is used for.

**Verify**:
- Hash output used to compare against a stored password, sign a token, check file integrity for security purposes, generate a CSRF token, or derive a key → **SUBMIT** (severity=8–9 depending on purpose; password hashing = critical severity=9)
- Hash output used only for content-addressable storage, non-security deduplication, ETag generation, or cache keys → **SKIP** (not a security finding)
- Unclear → `trace_path("function_name", mode="data_flow")` downstream to see where the digest value is consumed

→ Submit: violated_invariant="[MD5/SHA-1] used for [purpose]; collision attacks produce forged data / rainbow tables crack passwords in seconds", severity=8, confidence=7, exposure="internet"

---

## Step 2 — Broken symmetric encryption (DES / 3DES / RC4 / Blowfish / ECB mode)

**Python (cryptography library):**
```
grep(pattern="algorithms\.DES\s*\(|algorithms\.TripleDES\s*\(|algorithms\.Blowfish\s*\(|algorithms\.ARC4\s*\(|algorithms\.IDEA\s*\(|modes\.ECB\s*\(", max_matches=20)
```

**JavaScript / TypeScript (Node crypto):**
```
grep(pattern="createCipheriv\s*\(['\"]des|createDecipheriv\s*\(['\"]des|createCipheriv\s*\(['\"]rc4|createCipheriv\s*\(['\"]aes-\d+-ecb", max_matches=20)
```

**Java:**
```
grep(pattern="Cipher\.getInstance\s*\(['\"]DES['\"]|Cipher\.getInstance\s*\(['\"]DESede|Cipher\.getInstance\s*\(['\"]RC2|Cipher\.getInstance\s*\(['\"]RC4|Cipher\.getInstance\s*\(['\"]Blowfish|Cipher\.getInstance\s*\(['\"]AES/ECB", max_matches=20)
```

**Go (weak cipher suites in TLS config):**
```
grep(pattern="tls\.TLS_RSA_WITH_RC4_128|tls\.TLS_RSA_WITH_3DES_EDE|tls\.TLS_ECDHE_RSA_WITH_RC4|tls\.TLS_ECDHE_ECDSA_WITH_RC4", max_matches=15)
```

**C#:**
```
grep(pattern="new DESCryptoServiceProvider\s*\(\s*\)|new RC2CryptoServiceProvider\s*\(\s*\)|new TripleDESCryptoServiceProvider\s*\(\s*\)|CipherMode\.ECB", max_matches=20)
```

**PHP:**
```
grep(pattern="openssl_encrypt\s*\(.*['\"]des-|openssl_decrypt\s*\(.*['\"]des-|mcrypt_encrypt\s*\(.*MCRYPT_DES", max_matches=15)
```

**Ruby:**
```
grep(pattern="OpenSSL::Cipher\.new\s*\(['\"]DES|OpenSSL::Cipher\.new\s*\(['\"]des|OpenSSL::Cipher\.new\s*\(['\"]rc4", max_matches=15)
```

**Kotlin:**
```
grep(pattern="Cipher\.getInstance\s*\(['\"]DES|Cipher\.getInstance\s*\(['\"]des|Cipher\.getInstance\s*\(['\"]RC4|KeyGenerator\.getInstance\s*\(['\"]DES", max_matches=15)
```

**Swift:**
```
grep(pattern="kCCAlgorithmDES\b|kCCAlgorithmRC4\b|kCCAlgorithm3DES\b", max_matches=15)
```

For each match: is this encrypting session tokens, passwords, PII, or keys? DES key = 56-bit (brute-forceable in hours). ECB mode leaks patterns.

→ Submit: violated_invariant="[DES/3DES/RC4/ECB] used to encrypt [data]; brute-force or pattern analysis recovers plaintext", severity=8, confidence=8, exposure="internet"

---

## Step 3 — Insecure random for security-sensitive use

**Python (random module — not cryptographically secure):**
```
grep(pattern="random\.random\s*\(\s*\)|random\.randint\s*\(|random\.choice\s*\(|random\.shuffle\s*\(|random\.sample\s*\(", max_matches=20)
```

For each match: `get_code_snippet("containing_function")` to read the full function body and trace where the random value goes.

**Verify** — the random value must reach a security-sensitive destination:
- Assigned to a session token, password reset link, OTP, CSRF token, nonce, API key, UUID used as a secret → **SUBMIT**
- Used only for load balancing, random delays, test data generation, non-security shuffling → **SKIP**
- Unclear → `trace_path("function_name", mode="data_flow")` downstream to find the consumer

**JavaScript (Math.random for tokens):**
```
grep(pattern="Math\.random\s*\(\s*\)", max_matches=20)
```

For each match: `get_code_snippet("containing_function")` — is the output used to generate tokens, nonces, UUIDs, or secrets? → **SUBMIT** if yes, **SKIP** if used for UI randomness or non-security purposes.

**PHP (rand / mt_rand):**
```
grep(pattern="rand\s*\(\s*\)|mt_rand\s*\(|shuffle\s*\(", max_matches=20)
```

For each match: `get_code_snippet("containing_function")` — is the value used in a security context? → **SUBMIT** if yes.

Safe signal: `secrets.token_hex`, `crypto.randomBytes`, `openssl_random_pseudo_bytes`, `SecureRandom`.

→ Submit: violated_invariant="Non-cryptographic PRNG [function] generates security-sensitive [token/nonce/session ID]; predictable from seed", severity=8, confidence=7, exposure="internet"

---

## Step 4 — Hardcoded encryption key / IV

**Python:**
```
grep(pattern="AES\.new\s*\(['\"][^'\"]{16,}['\"]|Fernet\s*\(['\"][^'\"]{16,}['\"]", max_matches=15)
```

**JavaScript / TypeScript:**
```
grep(pattern="createCipheriv\s*\([^,]+,\s*['\"][^'\"]{16,}['\"]|createDecipheriv\s*\([^,]+,\s*['\"][^'\"]{16,}['\"]", max_matches=15)
```

**Java:**
```
grep(pattern="SecretKeySpec\s*\(['\"][^'\"]{8,}['\"]\.getBytes|new IvParameterSpec\s*\(['\"][^'\"]{8,}['\"]\.getBytes", max_matches=15)
```

**Go:**
```
grep(pattern="aes\.NewCipher\s*\(\s*\[\]byte\s*\{[0-9a-fx, ]+\}\)|cipher\.NewCFBEncrypter\s*\(.*\[\]byte\s*['\"][^'\"]{8,}['\"]", max_matches=15)
```

**C#:**
```
grep(pattern="new AesCryptoServiceProvider\s*\(\s*\).*Key\s*=\s*new byte|Encoding\.[^.]+\.GetBytes\s*\(['\"][^'\"]{8,}['\"]", max_matches=15)
```

→ Submit: violated_invariant="Encryption key/IV hardcoded as string literal; key recovery by code inspection breaks all encrypted data", severity=9, confidence=8, exposure="internet"

---

## Step 5 — Password stored with weak / unsalted hash

**Python:**
```
grep(pattern="hashlib\.md5\s*\(\s*password|hashlib\.sha1\s*\(\s*password|hashlib\.sha256\s*\(\s*password\s*\)\.hexdigest", max_matches=15)
```

**PHP:**
```
grep(pattern="md5\s*\(\s*\\\$password|sha1\s*\(\s*\\\$password|hash\s*\(\s*['\"]sha256['\"],\s*\\\$password\s*\)", max_matches=15)
```

**Node:**
```
grep(pattern="createHash\s*\(['\"]md5['\"].*password|createHash\s*\(['\"]sha1['\"].*password|createHash\s*\(['\"]sha256['\"].*password.*hexdigest", max_matches=15)
```

**Java:**
```
grep(pattern="MessageDigest\.getInstance\s*\(['\"]SHA-256['\"].*password|MessageDigest\.getInstance\s*\(['\"]MD5['\"].*password", max_matches=15)
```

For each match: `get_code_snippet("containing_function")` to read the full password hashing call.

**Verify**:
- Hash is a raw `hexdigest()` / `digest()` with no salt argument and no KDF wrapping → **SUBMIT** (severity=9)
- Hash is wrapped in PBKDF2, bcrypt, scrypt, or argon2 → **SKIP**
- A salt is manually prepended/appended (e.g., `md5(salt + password)`) → still **SUBMIT** — unsalted KDF schemes are offline-crackable with precomputed tables

→ Submit: violated_invariant="Password hashed with [MD5/SHA-1/SHA-256 without KDF]; rainbow table / GPU cracking trivially recovers passwords", severity=9, confidence=8, exposure="internet"

---

## Finish

Call `finish()` now with all hypotheses collected. Do not skip this.
