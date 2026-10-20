---
parallel: true
---

# SKILL: hunt-weak-crypto

## ⚡ BREADTH SCAN — semgrep-PRO-derived patterns, 15+ languages

Run grep, read context with `get_code_snippet`, submit immediately. Use at most 2 turns per step: batch all of a step's greps into ONE turn, then read the hits in the next turn.

---

## Step 1 — Broken hash algorithms (MD5 / SHA-1)

**Python:**
```
grep(pattern="hashlib\.(md5|sha1)\s*\(|hashlib\.new\s*\(\s*['\"](md5|sha1|MD5|SHA1)['\"]", max_matches=20)
```

**JavaScript / TypeScript (Node crypto):**
```
grep(pattern="create(Hash|Hmac)\s*\(\s*['\"](md5|sha1|MD5|SHA1)['\"]", max_matches=20)
```

**Java:**
```
grep(pattern="MessageDigest\.getInstance\s*\(\s*['\"](MD5|MD2|SHA-1|SHA1|SHA)['\"]", max_matches=20)
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
grep(pattern="\bhash\s*\(\s*['\"](md5|sha1)['\"]|\bmd5\s*\(\s*\$|\bsha1\s*\(\s*\$|hash_hmac\s*\(\s*['\"](md5|sha1)['\"]", max_matches=20)
```

**Ruby:**
```
grep(pattern="Digest::(MD5|SHA1)\.|OpenSSL::Digest::(MD5|SHA1)\b|OpenSSL::Digest\.new\s*\(\s*['\"](MD5|SHA1|md5|sha1)['\"]", max_matches=20)
```

**Kotlin / Java (commons-codec):**
```
grep(pattern="DigestUtils\.(md5|sha1|sha)(Hex|DigestAsHex)?\s*\(|DigestUtils\.get(Md5|Sha1)Digest\s*\(", max_matches=15)
```

**Swift:**
```
grep(pattern="CC_MD5\s*\(|CC_SHA1\s*\(|kCCHmacAlgMD5|kCCHmacAlgSHA1|Insecure\.(MD5|SHA1)\b", max_matches=15)
```

**Rust:**
```
grep(pattern="md5::compute\s*\(|\bMd5::(new|digest)\s*\(|\bSha1::(new|digest)\s*\(|sha1::digest", max_matches=15)
```

For each match: `get_code_snippet("containing_function")` to read the full function body and identify what the hash result is used for.

**Verify**:
- Hash output used to compare against a stored password, sign a token, check file integrity for security purposes, generate a CSRF token, or derive a key → **SUBMIT** (severity=8–9 depending on purpose; password hashing = critical severity=9)
- Hash output used only for content-addressable storage, non-security deduplication, ETag generation, or cache keys → **SKIP** (not a security finding)
- Python `hashlib.md5(..., usedforsecurity=False)` declares non-security use → **SKIP** unless the value is clearly used for security anyway
- HMAC-MD5 / HMAC-SHA1 (`createHmac('sha1')`, `hash_hmac('sha1')`, `kCCHmacAlgSHA1`) are not broken by collision attacks — report only as deprecated, severity 3
- Unclear → `trace_path("function_name", mode="data_flow")` downstream to see where the digest value is consumed; if still unclear, **submit with confidence=5** (uncertain is not safe)

→ Submit: violated_invariant="[MD5/SHA-1] used for [purpose]; collision attacks produce forged data / rainbow tables crack passwords in seconds", severity=8, confidence=7, exposure="internet", cwe="CWE-328"

---

## Step 2 — Broken symmetric encryption (DES / 3DES / RC4 / Blowfish / ECB mode)

**Python (cryptography / PyCryptodome):**
```
grep(pattern="algorithms\.(DES|TripleDES|Blowfish|ARC4|IDEA|CAST5|SEED)\s*\(|modes\.ECB\s*\(|\b(DES|DES3|ARC4|ARC2|Blowfish|CAST)\.new\s*\(|\bMODE_ECB\b", max_matches=20)
```

**JavaScript / TypeScript (Node crypto):**
```
grep(pattern="create(Cipher|Decipher)(iv)?\s*\(\s*['\"](?i:des|rc2|rc4|bf|blowfish|aes-\d+-ecb)|\bcreateCipher\s*\(", max_matches=20)
```

**Java:**
```
grep(pattern="Cipher\.getInstance\s*\(\s*['\"](DES|DESede|TripleDES|RC2|RC4|ARCFOUR|Blowfish)\b|Cipher\.getInstance\s*\(\s*['\"]AES(/ECB/[^'\"]*)?['\"]", max_matches=20)
```

**Go (crypto/des, crypto/rc4, weak cipher suites in TLS config):**
```
grep(pattern="tls\.TLS_RSA_WITH_RC4_128|tls\.TLS_RSA_WITH_3DES_EDE|tls\.TLS_ECDHE_RSA_WITH_RC4|tls\.TLS_ECDHE_ECDSA_WITH_RC4|des\.New(TripleDES)?Cipher\s*\(|rc4\.NewCipher\s*\(", max_matches=15)
```

**C#:**
```
grep(pattern="new\s+(DES|RC2|TripleDES)CryptoServiceProvider\s*\(\s*\)|\b(DES|RC2|TripleDES)\.Create\s*\(|CipherMode\.ECB", max_matches=20)
```

**PHP:**
```
grep(pattern="openssl_(en|de)crypt\s*\(.*['\"](?i:des-|des3|des['\"]|rc2|rc4|bf-|blowfish|aes-\d+-ecb)|mcrypt_(en|de)crypt\s*\(.*MCRYPT_(DES|3DES|TRIPLEDES|BLOWFISH|RC2)|MCRYPT_MODE_ECB", max_matches=15)
```

**Ruby:**
```
grep(pattern="OpenSSL::Cipher\.new\s*\(\s*['\"](?i:des|rc2|rc4|bf-|blowfish|aes-\d+-ecb)|OpenSSL::Cipher::(DES|RC4|RC2|BF)\b", max_matches=15)
```

**Kotlin:**
```
grep(pattern="Cipher\.getInstance\s*\(\s*\"(?i:des|rc2|rc4|blowfish)|Cipher\.getInstance\s*\(\s*\"AES(/ECB/[^\"]*)?\"|KeyGenerator\.getInstance\s*\(\s*\"(DES|DESede)", max_matches=15)
```

**Swift:**
```
grep(pattern="kCCAlgorithmDES\b|kCCAlgorithmRC4\b|kCCAlgorithm3DES\b|kCCOptionECBMode", max_matches=15)
```

For each match: is this encrypting session tokens, passwords, PII, or keys? DES key = 56-bit (brute-forceable in hours). ECB mode leaks patterns. Java/Kotlin `Cipher.getInstance("AES")` with no mode defaults to `AES/ECB/PKCS5Padding` on the standard providers, so it counts as ECB.

→ Submit: violated_invariant="[DES/3DES/RC4/ECB] used to encrypt [data]; brute-force or pattern analysis recovers plaintext", severity=8, confidence=8, exposure="internet", cwe="CWE-327"

---

## Step 3 — Insecure random for security-sensitive use

**Python (random module — not cryptographically secure):**
```
grep(pattern="random\.(random|randint|randrange|choice|choices|shuffle|sample|getrandbits)\s*\(", max_matches=20)
```

For each match: `get_code_snippet("containing_function")` to read the full function body and trace where the random value goes.

**Verify** — the random value must reach a security-sensitive destination:
- Assigned to a session token, password reset link, OTP, CSRF token, nonce, API key, UUID used as a secret → **SUBMIT**
- Used only for load balancing, random delays, test data generation, non-security shuffling → **SKIP**
- Unclear → `trace_path("function_name", mode="data_flow")` downstream to find the consumer; if still unclear, **submit with confidence=5** (uncertain is not safe)

**JavaScript (Math.random for tokens):**
```
grep(pattern="Math\.random\s*\(\s*\)", max_matches=20)
```

For each match: `get_code_snippet("containing_function")` — is the output used to generate tokens, nonces, UUIDs, or secrets? → **SUBMIT** if yes, **SKIP** if used for UI randomness or non-security purposes.

**PHP (rand / mt_rand):**
```
grep(pattern="\b(rand|mt_rand|lcg_value|uniqid|array_rand)\s*\(|\b(str_)?shuffle\s*\(", max_matches=20)
```

For each match: `get_code_snippet("containing_function")` — is the value used in a security context? → **SUBMIT** if yes.

**Java / Kotlin / C# / Go (non-cryptographic PRNG):**
```
grep(pattern="new\s+(java\.util\.)?Random\s*\(|ThreadLocalRandom\.current\s*\(|\"math/rand(/v2)?\"|\bRandom\.next(Int|Long|Bytes)\s*\(", max_matches=20)
```

For each match: `get_code_snippet("containing_function")` — is the value used in a security context? → **SUBMIT** if yes.

Safe signal: `secrets.token_hex`, `crypto.randomBytes`, `random_bytes` / `random_int`, `openssl_random_pseudo_bytes`, `SecureRandom`, `crypto/rand`, `RandomNumberGenerator`.

→ Submit: violated_invariant="Non-cryptographic PRNG [function] generates security-sensitive [token/nonce/session ID]; predictable from seed", severity=8, confidence=7, exposure="internet", cwe="CWE-338"

---

## Step 4 — Hardcoded encryption key / IV

**Python:**
```
grep(pattern="AES\.new\s*\(\s*b?['\"][^'\"]{16,}['\"]|Fernet\s*\(\s*b?['\"][^'\"]{16,}['\"]", max_matches=15)
```

**JavaScript / TypeScript:**
```
grep(pattern="create(Cipher|Decipher)iv\s*\([^,]+,\s*(Buffer\.from\s*\(\s*)?['\"][^'\"]{16,}['\"]", max_matches=15)
```

**Java:**
```
grep(pattern="SecretKeySpec\s*\(\s*['\"][^'\"]{8,}['\"]\.getBytes|new\s+IvParameterSpec\s*\(\s*['\"][^'\"]{8,}['\"]\.getBytes", max_matches=15)
```

**Go:**
```
grep(pattern="aes\.NewCipher\s*\(\s*\[\]byte\s*(\{[0-9a-fA-Fx, ]+\}|\(\s*\")|cipher\.New\w+\s*\(.*\[\]byte\s*\(\s*\"[^\"]{8,}\"", max_matches=15)
```

**C#:**
```
grep(pattern="\.(Key|IV)\s*=\s*(Encoding\.\w+\.GetBytes\s*\(\s*\"|new\s+byte\s*\[\s*\]\s*\{|Convert\.FromBase64String\s*\(\s*\")|Create(En|De)cryptor\s*\(\s*Encoding\.\w+\.GetBytes\s*\(\s*\"", max_matches=15)
```

→ Submit: violated_invariant="Encryption key/IV hardcoded as string literal; key recovery by code inspection breaks all encrypted data", severity=9, confidence=8, exposure="internet", cwe="CWE-321"

---

## Step 5 — Password stored with weak / unsalted hash

**Python:**
```
grep(pattern="hashlib\.(md5|sha1|sha224|sha256|sha384|sha512)\s*\([^)]*(?i:passw|pwd)|hashlib\.new\s*\(\s*['\"]\w+['\"]\s*,[^)]*(?i:passw|pwd)", max_matches=15)
```

**PHP:**
```
grep(pattern="\b(md5|sha1)\s*\([^)]*(?i:passw|pwd)|\bhash\s*\(\s*['\"](md5|sha1|sha256|sha512)['\"]\s*,[^)]*(?i:passw|pwd)", max_matches=15)
```

**Node:**
```
grep(pattern="createHash\s*\(\s*['\"](md5|sha1|sha256|sha512)['\"]\s*\).*(?i:passw|pwd)", max_matches=15)
```

**Java:**
```
grep(pattern="MessageDigest\.getInstance\s*\(\s*\"(MD5|SHA-?1|SHA-?256|SHA-?512)\".*(?i:passw)|\.(digest|update)\s*\(\s*\w*(?i:passw)\w*\.getBytes|DigestUtils\.(md5|sha1|sha256|sha512|sha)(Hex)?\s*\(\s*\w*(?i:passw)", max_matches=15)
```

For each match: `get_code_snippet("containing_function")` to read the full password hashing call.

**Verify**:
- Hash is a raw `hexdigest()` / `digest()` with no salt argument and no KDF wrapping → **SUBMIT** (severity=9)
- Hash is wrapped in PBKDF2, bcrypt, scrypt, or argon2 → **SKIP**
- A salt is manually prepended/appended (e.g., `md5(salt + password)`) → still **SUBMIT** — the salt defeats precomputed tables, but a single fast hash is still GPU-crackable at billions of guesses per second

→ Submit: violated_invariant="Password hashed with [MD5/SHA-1/SHA-256 without KDF]; rainbow table / GPU cracking trivially recovers passwords", severity=9, confidence=8, exposure="internet", cwe="CWE-916"

---

## Finish

Call `finish()` now with all hypotheses collected. Do not skip this.
