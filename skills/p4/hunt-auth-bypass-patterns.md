# SKILL: hunt-auth-bypass-patterns

## ⚡ BREADTH SCAN — semgrep-PRO-derived, per-library, all supported languages

Run grep, read context with get_code_snippet, submit immediately. Use at most 2 turns per step: batch all greps of a step into one turn, then read the hits in the next.

---

## Step 1 — JWT algorithm=none: Python / JavaScript / Java / Go / Ruby / Kotlin / Scala

**Python (PyJWT):**
```
grep(pattern="jwt\.encode\(.*algorithm\s*=\s*[\"']none[\"']|jwt\.decode\(.*algorithms\s*=\s*\[[^\]]*[\"']none[\"']", max_matches=20)
```

**JavaScript / TypeScript (jsonwebtoken):**
```
grep(pattern="\.verify\(.*algorithms\s*:\s*\[[^\]]*['\"]none['\"]|\.sign\(.*algorithm\s*:\s*['\"]none['\"]", max_matches=20)
```

**JavaScript / TypeScript (jose library):**
```
grep(pattern="JWT\.verify\([^,]+,\s*JWK\.None|UnsecuredJWT\.decode\(", max_matches=15)
```

**JavaScript / TypeScript (jwt-simple — 3rd arg = noVerify):**
```
grep(pattern="require\(\s*['\"]jwt-simple['\"]\s*\)|from\s+['\"]jwt-simple['\"]", max_matches=10)
```
For each: read the `.decode(token, secret, true)` call — 3rd param `true` disables verification.

**Java (auth0 java-jwt):**
```
grep(pattern="com\.auth0\.jwt\.algorithms\.Algorithm\.none\(\)|Algorithm\.none\(\)|\.sign\(Algorithm\.none\(\)\)", max_matches=15)
```

**Java (JJWT — io.jsonwebtoken):**
```
grep(pattern="SignatureAlgorithm\.NONE|\.parseClaimsJwt\(|\.parseUnsecuredClaims\(|\.unsecured\(\)", max_matches=15)
```

**Go (golang-jwt / dgrijalva/jwt-go):**
```
grep(pattern="jwt\.UnsafeAllowNoneSignatureType|jwt\.SigningMethodNone", max_matches=15)
```

**Ruby (ruby-jwt):**
```
grep(pattern="JWT\.encode\(.*,\s*['\"]none['\"]|JWT\.decode\(.*algorithms?['\"]?\s*(:|=>)\s*\[?\s*['\"]none['\"]", max_matches=15)
```

**Kotlin (auth0 java-jwt):**
```
grep(pattern="Algorithm\.none\(\)|algorithms\.Algorithm\.none\(\)", max_matches=15)
```

**Scala (auth0 java-jwt):**
```
grep(pattern="com\.auth0\.jwt\.algorithms\.Algorithm\.none\(\)|Algorithm\.none\(\)", max_matches=15)
```

Confirm each match actually signs, parses, or verifies with `none` — a comparison that rejects it (e.g. `if token.Method == jwt.SigningMethodNone { return err }`) is the safe form. A confirmed use outside a test file is a vulnerability.

→ Submit: violated_invariant="JWT algorithm=none accepted; attacker strips and self-signs any payload", severity=10, confidence=9, exposure="internet", cwe="CWE-347"

---

## Step 2 — JWT decoded without signature verification

**Python (PyJWT — verify_signature=False / legacy verify=False):**
```
grep(pattern="jwt\.decode\(.*options\s*=\s*\{[^}]*[\"']verify_signature[\"']\s*:\s*False|jwt\.decode\(.*verify\s*=\s*False", max_matches=20)
```

**Python (PyJWT — individual options):**
```
grep(pattern="\{[^}]*[\"']verify_(exp|aud|iat|nbf|iss)[\"']\s*:\s*False", max_matches=20)
```

**JavaScript / TypeScript (jsonwebtoken):**
```
grep(pattern="ignoreExpiration\s*:\s*true|ignoreNotBefore\s*:\s*true", max_matches=20)
```

**JavaScript / TypeScript (jwt-simple — noVerify mode):**
```
grep(pattern="\.decode\([^,]+,\s*[^,]+,\s*true\s*[,)]", file_glob="*.{js,jsx,ts,tsx,mjs,cjs}", max_matches=20)
```

**Ruby (ruby-jwt — verify=false):**
```
grep(pattern="JWT\.decode\([^,]+,\s*[^,]+,\s*false\b", max_matches=15)
```

**Java (auth0 java-jwt — decode without verify):**
```
grep(pattern="\bJWT\.decode\(", file_glob="*.{java,kt,kts,scala}", max_matches=20)
```
For each: call `get_code_snippet` — is `.verify(` ever called on the result in the same function? If not, token integrity is unchecked.

**Go (ParseUnverified):**
```
grep(pattern="\.ParseUnverified\(|jwt\.ParseUnverified\(", max_matches=15)
```

**C# (jwt-dotnet — verify:false):**
```
grep(pattern="\.Decode\(.*verify\s*:\s*false|\.Decode\([^,]+,\s*[^,]+,\s*false\s*\)|IJwtDecoder.*Decode.*verify.*false|DoNotVerifySignature\(\)", max_matches=15)
```

**C# (System.IdentityModel TokenValidationParameters):**
```
grep(pattern="RequireSignedTokens\s*=\s*false|SignatureValidator\s*=|ValidateLifetime\s*=\s*false|ValidateIssuer\s*=\s*false|ValidateAudience\s*=\s*false|RequireExpirationTime\s*=\s*false", max_matches=20)
```
`ValidateIssuerSigningKey = false` is the default and does not skip signature validation — not a finding on its own. A custom `SignatureValidator` is a finding only when it returns the token without checking the signature.

Safe signal: flags disabled only inside `*_test.go`, `*.test.ts`, `test_*.py`, `*spec.rb`.

→ Submit: violated_invariant="JWT decoded without cryptographic verification; forged/expired tokens accepted", severity=9, confidence=8, exposure="internet", cwe="CWE-347"

---

## Step 3 — TLS certificate verification disabled

**Python (requests / sessions):**
```
grep(pattern="\.(get|post|put|patch|delete|head|options|request)\(.*verify\s*=\s*False|\.verify\s*=\s*False", max_matches=25)
```

**Python (httpx / aiohttp):**
```
grep(pattern="httpx\.(get|post|put|patch|delete|head|request|stream)\(.*verify\s*=\s*False|httpx\.(Async)?Client\(.*verify\s*=\s*False|TCPConnector\(.*(ssl|verify_ssl)\s*=\s*False|\.(get|post|put|patch|delete|request)\(.*\bssl\s*=\s*False", max_matches=20)
```

**Python (ssl / urllib):**
```
grep(pattern="ssl\._create_unverified_context\(\)|ssl\.CERT_NONE|check_hostname\s*=\s*False", max_matches=15)
```

**JavaScript / TypeScript (Node https / axios):**
```
grep(pattern="rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED[\"']?\]?\s*[=:]\s*[\"']?0", max_matches=20)
```

**Go (crypto/tls / grpc):**
```
grep(pattern="InsecureSkipVerify\s*[:=]\s*true|grpc\.WithInsecure\(\)|insecure\.NewCredentials\(\)", max_matches=20)
```

**PHP (cURL / Guzzle):**
```
grep(pattern="CURLOPT_SSL_VERIFY(PEER|HOST)\s*(,|=>)\s*(0|false|FALSE|False)\b|['\"]verify['\"]\s*=>\s*false", max_matches=15)
```

**Ruby (OpenSSL / Net::HTTP / RestClient / Faraday):**
```
grep(pattern="OpenSSL::SSL::VERIFY_NONE|verify_ssl\s*(=>|:)\s*(false|OpenSSL::SSL::VERIFY_NONE)|ssl:\s*\{[^}]*verify:\s*false", max_matches=15)
```

**Rust (openssl / reqwest):**
```
grep(pattern="SslVerifyMode::NONE|danger_accept_invalid_(certs|hostnames)\(\s*true\s*\)", max_matches=15)
```

**C# (.NET):**
```
grep(pattern="(ServerCertificateValidationCallback|ServerCertificateCustomValidationCallback|RemoteCertificateValidationCallback)\s*[+-]?=.*=>\s*true|DangerousAcceptAnyServerCertificateValidator|X509CertificateValidationMode\.None|ServicePointManager\.ServerCertificateValidationCallback", max_matches=15)
```

**Java (RestTemplate / HttpClient — TrustAll):**
```
grep(pattern="TrustStrategy.*->\s*true|TrustAllStrategy|TrustSelfSignedStrategy|\.trustAll\(\)|AllowAllHostnameVerifier|NoopHostnameVerifier|HostnameVerifier.*true|new X509TrustManager\s*\(", max_matches=15)
```

**Kotlin (OkHttp / Ktor):**
```
grep(pattern="hostnameVerifier\b.*->\s*true|checkServerTrusted\([^)]*\)(\s*throws\s+[\w.]+)?\s*\{\s*\}|trustAll|ALLOW_ALL_HOSTNAME_VERIFIER", max_matches=15)
```
For `new X509TrustManager(` / `checkServerTrusted`: SUBMIT only when `checkServerTrusted` has an empty body or never throws.

**Swift:**
```
grep(pattern="kCFStreamSSLValidatesCertificateChain.*false|URLCredential\(\s*trust:|DisabledTrustEvaluator|DisabledEvaluator|\.disableEvaluation", max_matches=15)
```
For `URLCredential(trust:)`: SUBMIT only when the challenge handler accepts the server trust without `SecTrustEvaluateWithError` or a pinning comparison.

**Connection strings (any language — MongoDB):**
```
grep(pattern="mongodb(\+srv)?://.*(tlsAllowInvalidCertificates|tlsAllowInvalidHostnames|tlsInsecure|sslAllowInvalidCertificates|sslAllowInvalidHostnames)=true|(tlsAllowInvalidCertificates|tlsAllowInvalidHostnames|tlsInsecure)\s*:\s*true", max_matches=15)
```

→ Submit: violated_invariant="TLS certificate verification disabled; MITM substitutes content or key material", severity=7, confidence=8, exposure="internet", cwe="CWE-295"

---

## Step 4 — Hardcoded JWT / signing secrets

**Python (PyJWT literal):**
```
grep(pattern="jwt\.encode\(.*,\s*[\"'][^\"']{8,}[\"']\s*[,)]|jwt\.decode\(.*,\s*[\"'][^\"']{8,}[\"']\s*[,)]", max_matches=15)
```

**Django SECRET_KEY / env fallback:**
```
grep(pattern="SECRET_KEY\s*=\s*[\"'][^\"']{8,}[\"']|(environ\.get|getenv)\(\s*[\"']\w*(SECRET|KEY)\w*[\"']\s*,\s*[\"'][^\"']{8,}[\"']", max_matches=15)
```

**Node.js (jsonwebtoken / env fallback):**
```
grep(pattern="jwt\.(sign|verify)\(.*,\s*[\"'`][^\"'`]{8,}[\"'`]\s*[,)]|(JWT|TOKEN|SESSION|COOKIE)_?SECRET\w*\s*(\|\||\?\?)\s*[\"'`][^\"'`]{8,}[\"'`]", max_matches=15)
```

**Node.js (passport-jwt):**
```
grep(pattern="secretOrKey\s*:\s*[\"'][^\"']{8,}[\"']", max_matches=15)
```

**Java (auth0 java-jwt HMAC literal):**
```
grep(pattern="Algorithm\.HMAC(256|384|512)\([\"'][^\"']{8,}[\"']", max_matches=15)
```

**Java (SecretKeySpec / JJWT literal):**
```
grep(pattern="new SecretKeySpec\(\s*[\"'][^\"']{8,}[\"']\.getBytes\(|hmacShaKeyFor\(\s*\"[^\"]{8,}\"|setSigningKey\(\s*\"[^\"]{8,}\"|signWith\(.*,\s*\"[^\"]{8,}\"\s*\)", max_matches=15)
```

**Kotlin:**
```
grep(pattern="SecretKeySpec\(\s*[\"'][^\"']{8,}[\"']\.toByteArray\(|Algorithm\.HMAC(256|384|512)\(\s*[\"'][^\"']{8,}[\"']", max_matches=15)
```

**Scala (auth0):**
```
grep(pattern="Algorithm\.HMAC256\([\"'][^\"']{8,}[\"']", max_matches=15)
```

**C# (jwt-dotnet / SymmetricSecurityKey):**
```
grep(pattern="\.Encode\(.*,\s*\"[^\"]{8,}\"\s*\)|SymmetricSecurityKey\(\s*Encoding\.\w+\.GetBytes\(\s*\"[^\"]{8,}\"|WithSecret\(\s*\"[^\"]{8,}\"", max_matches=15)
```

**Go (JWT literal key):**
```
grep(pattern="\[\]byte\([\"'][^\"']{8,}[\"']\)|hmac\.New\(.*,\s*\[\]byte\([\"']", max_matches=15)
```

**Ruby (Rails secret_key_base):**
```
grep(pattern="secret_key_base\s*[=:]\s*[\"'][^\"']{8,}[\"']|config\.secret_key_base\s*=\s*[\"']|secret_key_base:\s*[0-9a-fA-F]{32,}", max_matches=15)
```

**Shell / Docker default fallback:**
```
grep(pattern="SECRET_KEY\s*:-\s*[a-zA-Z0-9+/=$@#!_-]{8,}|JWT_SECRET\s*:-\s*[a-zA-Z0-9+/=$@#!_-]{8,}|SESSION_SECRET\s*:-", max_matches=15)
```

For each match: is this in a real config/main file, not a test fixture or example?

→ Submit per secret: violated_invariant="signing secret [name] hardcoded; attacker forges tokens in any deployment without explicit env override", severity=10, confidence=8, exposure="internet", cwe="CWE-321"

---

## Step 5 — Authorization decision from request header alone

```
grep(pattern="[Rr]eq(uest)?\.[Hh]eaders(\.get\(|\[)\s*['\"][Xx]-|req\.(get|header)\(\s*['\"][Xx]-|request\.META(\.get\(|\[)\s*['\"]HTTP_X_|r\.Header\.Get\(\s*['\"][Xx]-|request\.getHeader\(\s*['\"][Xx]-|\$_SERVER\[\s*['\"]HTTP_X_", max_matches=30)
```

For each match: `get_code_snippet("containing_function")` to read the full function body.

**Verify**:
- Function returns `True`/`authorized`/`nil` based ONLY on the header value — no HMAC check, no DB lookup, no cryptographic comparison? → **SUBMIT**
- Header value is verified against a DB record or a cryptographic secret (HMAC, signed token) → **SKIP**

```
if header_value == "secret": return True         # instant bypass — SUBMIT
if header is not None: return True               # presence-only — SUBMIT
if (req.headers["X-Internal"] != null) allow()  # Java presence — SUBMIT
if HMAC(header, secret_key) == expected: allow()  # cryptographic check — SKIP
```

→ Submit: violated_invariant="authorization decision made from caller-controlled request header alone; any caller sets the header to gain access", severity=10, confidence=7, exposure="internet", cwe="CWE-290"

---

## Step 6 — Auth check commented out

```
grep(pattern="#\s*(if|raise|assert).*[Aa]uth|#\s*(self\.)?verify\w*\(|#\s*@login_required|#\s*@require|#\s*@permission_classes|#\s*before_action\s*:authenticate|//\s*isAuthenticated|//\s*auth\.required|//\s*passport\.authenticate|//\s*@Secured|//\s*@PreAuthorize|//\s*\[Authorize|//\s*\w+\.use\(\s*\w*[Aa]uth|/\*.*[Aa]uth.*\*/", max_matches=20)
```

For each match: `get_code_snippet("containing_function_or_handler")` to read the full handler and its surrounding context.

**Verify**:
1. Is this handler for a sensitive operation (payment, admin, transfer, account, delete, update)? → **CONTINUE**
2. Is the commented line the ONLY auth check? No decorator (`@login_required`, `@Secured`), no middleware call, no `request.user.is_authenticated` guard anywhere in the function → **SUBMIT**
3. Auth is enforced by a decorator on the function or a middleware group in route registration → **SKIP**

→ Submit: violated_invariant="authorization check commented out with no other enforcement; handler runs without verifying caller identity", severity=9, confidence=7, exposure="internet" (use "authenticated" when login is still enforced and only a role/permission check is commented out), cwe="CWE-306"

---

## Step 7 — Dev/test authentication injection middleware

```
grep(pattern="(?i)(inject|bypass|skip|disable|mock|fake)_?\w{0,20}auth|auth\w{0,20}(bypass|disabled|skip)|(testing|test_mode|dev_mode)\s*[=:].*auth|set.*authorization.*header.*test", max_matches=20)
```

For each match: `get_code_snippet("containing_function_or_module")` to read the full activation logic.

**Verify**:
- What env var activates it? Is it `TESTING=true`, `LOCAL=1`, `NODE_ENV=test`, `DEBUG=True`, or similar non-exclusive flag? These CAN be set in staging/prod environments → **SUBMIT**
- Activation gated by a deploy-time secret or a production-exclusive mechanism (e.g., a cryptographic service account check) → **SKIP**
- Env var is explicitly blocked in production deploy configs (checked against deploy scripts/IaC) → **SKIP**

→ Submit: violated_invariant="auth injection middleware activates on non-production-exclusive env var; all requests become pre-authenticated when variable is set", severity=8, confidence=7, exposure="internet", cwe="CWE-489"

---

## Finish

Call `finish()` now with all hypotheses collected. Do not skip this.
