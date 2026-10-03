# SKILL: hunt-auth-bypass-patterns

## ⚡ BREADTH SCAN — semgrep-PRO-derived patterns, 15+ languages

Run grep, read context with `get_code_snippet`, submit immediately. 2 tool calls per step max.

---

## Step 1 — JWT algorithm=none

**Python (PyJWT):**
```
grep(pattern="jwt\.decode\(.*algorithms=\[.*[\"']none[\"'].*\]|jwt\.decode\(.*options=\{.*verify_signature.*False", max_matches=20)
```

**JavaScript / TypeScript (jsonwebtoken, jose):**
```
grep(pattern="\.verify\(.*algorithms.*['\"]none['\"]|JWT\.verify\(.*algorithms.*none|JWK\.None|jwt\.sign\(.*algorithm.*['\"]none['\"]", max_matches=20)
```

**Java (auth0 java-jwt):**
```
grep(pattern="Algorithm\.none\(\)|com\.auth0\.jwt\.algorithms\.Algorithm\.none\(\)|\.sign\(Algorithm\.none\(\)\)", max_matches=15)
```

**Go (golang-jwt):**
```
grep(pattern="jwt\.UnsafeAllowNoneSignatureType|jwt\.SigningMethodNone", max_matches=15)
```

**Ruby:**
```
grep(pattern="JWT\.encode\(.*['\"]none['\"]|JWT\.decode\(.*algorithms.*none", max_matches=15)
```

**Kotlin:**
```
grep(pattern="algorithms\.Algorithm\.none\(\)|Algorithm\.none\(\)", max_matches=15)
```

For each match: is this in production code or a test file? Does the decode call run on user-supplied tokens?

→ Submit: violated_invariant="JWT algorithm=none accepted; attacker strips signature, self-signs any payload", severity=10, confidence=8, exposure="internet"

---

## Step 2 — JWT validation options disabled

**Python (PyJWT options dict):**
```
grep(pattern="options\s*=\s*\{[^}]*verify_signature[^}]*False|options\s*=\s*\{[^}]*verify_exp[^}]*False|options\s*=\s*\{[^}]*verify_aud[^}]*False", max_matches=20)
```

**JavaScript (jsonwebtoken ignoreExpiration):**
```
grep(pattern="ignoreExpiration\s*:\s*true|verify_aud.*false|verify_signature.*false|ignoreNotBefore\s*:\s*true", max_matches=20)
```

**C# (TokenValidationParameters):**
```
grep(pattern="ValidateLifetime\s*=\s*false|ValidateIssuerSigningKey\s*=\s*false|ValidateIssuer\s*=\s*false|ValidateAudience\s*=\s*false|RequireExpirationTime\s*=\s*false", max_matches=20)
```

For each match: read the full TokenValidationParameters block or decode call. Is ANY of the critical flags (signature, expiry, issuer, audience) disabled unconditionally?

Safe signal: options disabled only inside tests (`test_`, `spec_`, `_test.py`, `*.test.js`).

→ Submit: violated_invariant="JWT validation flag [flag] disabled unconditionally; expired/forged tokens accepted", severity=9, confidence=7, exposure="internet"

---

## Step 3 — TLS certificate verification disabled

**Python (requests):**
```
grep(pattern="requests\.(get|post|put|patch|delete|head|options|request)\(.*verify\s*=\s*False", max_matches=25)
```

**Python (ssl module):**
```
grep(pattern="ssl\._create_unverified_context\(\)|_create_default_https_context\s*=\s*ssl\._create_unverified|check_hostname\s*=\s*False|CERT_NONE", max_matches=15)
```

**JavaScript / TypeScript (Node https / axios / node-postgres):**
```
grep(pattern="rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*[=:]\s*['\"]0['\"]", max_matches=20)
```

**Go:**
```
grep(pattern="InsecureSkipVerify\s*:\s*true|grpc\.WithInsecure\(\)|tls\.Config\{[^}]*InsecureSkipVerify", max_matches=20)
```

**PHP (cURL):**
```
grep(pattern="curl_setopt\(.*CURLOPT_SSL_VERIFYPEER.*[,\s](0|false)|CURLOPT_SSL_VERIFYHOST.*[,\s](0|1)", max_matches=15)
```

**C# (.NET):**
```
grep(pattern="ServerCertificateValidationCallback\s*[+\-]?=|X509CertificateValidationMode\.None|ServicePointManager\.ServerCertificate", max_matches=15)
```

**Ruby (OpenSSL):**
```
grep(pattern="OpenSSL::SSL::VERIFY_NONE|verify_mode\s*=\s*OpenSSL::SSL::VERIFY_NONE|:verify_ssl\s*=>\s*false", max_matches=15)
```

**Swift:**
```
grep(pattern="kCFStreamSSLValidatesCertificateChain.*false|willSendRequestForAuthenticationChallenge|NSURLAuthenticationMethodServerTrust", max_matches=15)
```

**Kotlin / Java (OkHttp, HttpClient):**
```
grep(pattern="hostnameVerifier.*true|ALLOW_ALL_HOSTNAME_VERIFIER|TrustAllX509TrustManager|trustAll", max_matches=15)
```

For each match: is it scoped to tests, a dev-only code path, or truly unconditional in production paths?

→ Submit: violated_invariant="TLS certificate verification disabled; MITM substitutes attacker-controlled content", severity=7, confidence=7, exposure="internet"

---

## Step 4 — Hardcoded JWT / signing secrets

**Python (PyJWT literal):**
```
grep(pattern="jwt\.encode\([^,]+,\s*['\"][^'\"]{8,}['\"]|jwt\.decode\([^,]+,\s*['\"][^'\"]{8,}['\"]", max_matches=15)
```

**Django SECRET_KEY:**
```
grep(pattern="SECRET_KEY\s*=\s*['\"][^'\"]{8,}['\"]", max_matches=15)
```

**JavaScript / TypeScript (jsonwebtoken / jose):**
```
grep(pattern="jwt\.sign\([^,]+,\s*['\"][^'\"]{8,}['\"]|jwt\.verify\([^,]+,\s*['\"][^'\"]{8,}['\"]", max_matches=15)
```

**Java (auth0 java-jwt HMAC literal):**
```
grep(pattern="Algorithm\.HMAC(256|384|512)\(['\"][^'\"]{8,}['\"]|HMAC256\(['\"][^'\"]{8,}['\"]", max_matches=15)
```

**Java (SecretKeySpec with literal string):**
```
grep(pattern="new SecretKeySpec\(['\"][^'\"]{8,}['\"]\.getBytes\(\)", max_matches=15)
```

**Kotlin (SecretKeySpec literal):**
```
grep(pattern="SecretKeySpec\(['\"][^'\"]{8,}['\"]\.toByteArray\(\)|SecretKeySpec\(['\"][^'\"]{8,}['\"]\.getBytes\(\)", max_matches=15)
```

**Go:**
```
grep(pattern="hmac\.New\(.*['\"][^'\"]{8,}['\"]|jwt\.NewWithClaims\(.*['\"][^'\"]{8,}['\"]", max_matches=15)
```

**C# (SymmetricSecurityKey literal):**
```
grep(pattern="SymmetricSecurityKey\(Encoding\.[^.]+\.GetBytes\(['\"][^'\"]{8,}['\"]", max_matches=15)
```

**Ruby (Rails secret_key_base hardcoded):**
```
grep(pattern="secret_key_base\s*[=:]\s*['\"][^'\"]{8,}['\"]|config\.secret_key_base\s*=\s*['\"]", max_matches=15)
```

**Shell/Docker fallback defaults:**
```
grep(pattern="SECRET_KEY\s*:-\s*[a-zA-Z0-9+/=@#!_-]{8,}|JWT_SECRET\s*:-\s*[a-zA-Z0-9+/=@#!_-]{8,}|SIGNING_KEY\s*:-", max_matches=15)
```

For each match: is this in a real config/main file, not a test fixture?

→ Submit per secret: violated_invariant="signing secret [name] hardcoded; attacker forges tokens in any deployment without explicit env override", severity=10, confidence=8, exposure="internet"

---

## Step 5 — Authorization decision from request header alone

```
grep(pattern="request\.headers\.get\(['\"]X-|req\.headers\[['\"]X-|request\.META\.get\(['\"]HTTP_X_|r\.Header\.Get\(['\"]X-|request\.getHeader\(['\"]X-|\$_SERVER\[['\"]HTTP_X_", max_matches=30)
```

For each match: does the function return `True`/`authorized`/`nil` based ONLY on the header value, with no cryptographic check or DB lookup?

```
if header_value == "secret": return True         # instant bypass
if header is not None: return True               # presence-only
if (req.headers["X-Internal"] != null) allow()  # Java presence
```

→ Submit: violated_invariant="authorization decision made from caller-controlled request header alone; any caller sets the header to gain access", severity=10, confidence=7, exposure="internet"

---

## Step 6 — Auth check commented out

```
grep(pattern="#\s*(if|raise|assert).*[Aa]uth|#\s*verify|#\s*@login_required|#\s*@require|//\s*isAuthenticated|//\s*auth\.required|//\s*passport\.authenticate|//\s*@Secured|//\s*@PreAuthorize|/\*.*[Aa]uth.*\*/", max_matches=20)
```

For each match in a sensitive handler (payment, admin, transfer, account): is the commented line the only place an auth check would be enforced?

→ Submit: violated_invariant="authorization check commented out; handler runs without verifying caller identity", severity=9, confidence=7, exposure="authenticated"

---

## Step 7 — Dev/test authentication injection middleware

```
grep(pattern="inject.*[Aa]uth|[Aa]uth.*[Ii]nject|bypass.*[Aa]uth|skip.*[Aa]uth|TEST.*AUTH|TESTING.*=.*true.*auth|set.*Authorization.*header.*test|mock.*user.*auth", max_matches=20)
```

For each match: what env var activates it? Can `TESTING=true`, `LOCAL=1`, or `NODE_ENV=test` be set on staging?

→ Submit: violated_invariant="auth injection middleware activates on non-production-exclusive env var; all requests become pre-authenticated when variable is set", severity=8, confidence=7, exposure="internet"

---

## Finish

Call `finish()` now with all hypotheses collected. Do not skip this.
