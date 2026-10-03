# SKILL: hunt-auth-bypass-patterns

## ⚡ BREADTH SCAN — semgrep-PRO-derived, per-library, all supported languages

Run grep, read context with get_code_snippet, submit immediately. 2 tool calls per step max.

---

## Step 1 — JWT algorithm=none: Python / JavaScript / Java / Go / Ruby / Kotlin / Scala

**Python (PyJWT):**
```
grep(pattern="jwt\\.encode\\([^,]+,\\s*[^,]+,\\s*algorithm\\s*=\\s*[\"']none[\"']|jwt\\.decode\\(.*algorithms\\s*=\\s*\\[.*[\"']none[\"']", max_matches=20)
```

**JavaScript / TypeScript (jsonwebtoken):**
```
grep(pattern="\\.verify\\(.*,\\s*[^,]+,\\s*\\{[^}]*algorithms\\s*:\\s*\\[.*['\"]none['\"]|\\.sign\\(.*,\\s*[^,]+,\\s*\\{[^}]*algorithm\\s*:\\s*['\"]none['\"]", max_matches=20)
```

**JavaScript / TypeScript (jose library):**
```
grep(pattern="JWT\\.verify\\([^,]+,\\s*JWK\\.None", max_matches=15)
```

**JavaScript / TypeScript (jwt-simple — 3rd arg = noVerify):**
```
grep(pattern="require\\(['\"]jwt-simple['\"]\\)", max_matches=10)
```
For each: read the `.decode(token, secret, true)` call — 3rd param `true` disables verification.

**Java (auth0 java-jwt):**
```
grep(pattern="com\\.auth0\\.jwt\\.algorithms\\.Algorithm\\.none\\(\\)|Algorithm\\.none\\(\\)|\\.sign\\(Algorithm\\.none\\(\\)\\)", max_matches=15)
```

**Java (JJWT — io.jsonwebtoken):**
```
grep(pattern="SignatureAlgorithm\\.NONE|\\.signWith\\(SignatureAlgorithm\\.NONE", max_matches=15)
```

**Go (golang-jwt / dgrijalva/jwt-go):**
```
grep(pattern="jwt\\.UnsafeAllowNoneSignatureType|jwt\\.SigningMethodNone", max_matches=15)
```

**Ruby (ruby-jwt):**
```
grep(pattern="JWT\\.encode\\([^,]+,\\s*[^,]+,\\s*['\"]none['\"]|JWT\\.decode\\([^,]+,\\s*[^,]+,\\s*\\{.*algorithms.*none", max_matches=15)
```

**Kotlin (auth0 java-jwt):**
```
grep(pattern="Algorithm\\.none\\(\\)|algorithms\\.Algorithm\\.none\\(\\)", max_matches=15)
```

**Scala (auth0 java-jwt):**
```
grep(pattern="com\\.auth0\\.jwt\\.algorithms\\.Algorithm\\.none\\(\\)|Algorithm\\.none\\(\\)", max_matches=15)
```

These are all DEFINITIVE — any match outside a test file is a vulnerability.

→ Submit: violated_invariant="JWT algorithm=none accepted; attacker strips and self-signs any payload", severity=10, confidence=9, exposure="internet"

---

## Step 2 — JWT decoded without signature verification

**Python (PyJWT — verify_signature=False):**
```
grep(pattern="jwt\\.decode\\(.*options\\s*=\\s*\\{[^}]*[\"']verify_signature[\"']\\s*:\\s*False", max_matches=20)
```

**Python (PyJWT — individual options):**
```
grep(pattern="options\\s*=\\s*\\{[^}]*verify_exp[^}]*False|options\\s*=\\s*\\{[^}]*verify_aud[^}]*False|options\\s*=\\s*\\{[^}]*verify_iat[^}]*False", max_matches=20)
```

**JavaScript / TypeScript (jsonwebtoken):**
```
grep(pattern="ignoreExpiration\\s*:\\s*true|ignoreNotBefore\\s*:\\s*true", max_matches=20)
```

**JavaScript / TypeScript (jwt-simple — noVerify mode):**
```
grep(pattern="\\.decode\\([^,]+,\\s*[^,]+,\\s*true\\s*[,)]", max_matches=20)
```

**Java (auth0 java-jwt — decode without verify):**
```
grep(pattern="com\\.auth0\\.jwt\\.JWT\\.decode\\(", max_matches=20)
```
For each: call `get_code_snippet` — is `.verify(` ever called on the result in the same function? If not, token integrity is unchecked.

**Go (ParseUnverified):**
```
grep(pattern="\\.ParseUnverified\\(|jwt\\.ParseUnverified\\(", max_matches=15)
```

**C# (jwt-dotnet — verify:false):**
```
grep(pattern="\\.Decode\\([^,]+,\\s*[^,]+,\\s*verify\\s*:\\s*false|IJwtDecoder.*Decode.*verify.*false", max_matches=15)
```

**C# (System.IdentityModel TokenValidationParameters):**
```
grep(pattern="ValidateLifetime\\s*=\\s*false|ValidateIssuerSigningKey\\s*=\\s*false|ValidateIssuer\\s*=\\s*false|ValidateAudience\\s*=\\s*false|RequireExpirationTime\\s*=\\s*false", max_matches=20)
```

Safe signal: flags disabled only inside `*_test.go`, `*.test.ts`, `test_*.py`, `*spec.rb`.

→ Submit: violated_invariant="JWT decoded without cryptographic verification; forged/expired tokens accepted", severity=9, confidence=8, exposure="internet"

---

## Step 3 — TLS certificate verification disabled

**Python (requests):**
```
grep(pattern="requests\\.(get|post|put|patch|delete|head|options|request)\\(.*verify\\s*=\\s*False", max_matches=25)
```

**Python (httpx):**
```
grep(pattern="httpx\\.(get|post|put|patch|delete|head|request)\\(.*verify\\s*=\\s*False|httpx\\.Client\\(.*verify\\s*=\\s*False|httpx\\.AsyncClient\\(.*verify\\s*=\\s*False", max_matches=20)
```

**Python (ssl / urllib):**
```
grep(pattern="ssl\\._create_unverified_context\\(\\)|ssl\\.CERT_NONE|check_hostname\\s*=\\s*False", max_matches=15)
```

**JavaScript / TypeScript (Node https / axios):**
```
grep(pattern="rejectUnauthorized\\s*:\\s*false|process\\.env\\[[\"']NODE_TLS_REJECT_UNAUTHORIZED[\"']\\]\\s*=\\s*[\"']?0[\"']?", max_matches=20)
```

**Go (crypto/tls):**
```
grep(pattern="InsecureSkipVerify\\s*:\\s*true|grpc\\.WithInsecure\\(\\)|tls\\.Config\\{[^}]*InsecureSkipVerify\\s*:\\s*true", max_matches=20)
```

**PHP (cURL):**
```
grep(pattern="curl_setopt\\(.*CURLOPT_SSL_VERIFYPEER.*,\\s*(0|false|FALSE)|curl_setopt\\(.*CURLOPT_SSL_VERIFYHOST.*,\\s*(0|1)\\b", max_matches=15)
```

**Ruby (OpenSSL / Net::HTTP / RestClient):**
```
grep(pattern="OpenSSL::SSL::VERIFY_NONE|verify_mode\\s*=\\s*OpenSSL::SSL::VERIFY_NONE|:verify_ssl\\s*=>\\s*(false|FALSE|OpenSSL::SSL::VERIFY_NONE)", max_matches=15)
```

**Rust (openssl crate):**
```
grep(pattern="set_verify\\(openssl::ssl::SslVerifyMode::NONE\\)|SslVerifyMode::NONE", max_matches=15)
```

**C# (.NET):**
```
grep(pattern="ServerCertificateValidationCallback\\s*[+\\-]?=.*=>\\s*true|X509CertificateValidationMode\\.None|ServicePointManager\\.ServerCertificateValidationCallback", max_matches=15)
```

**Java (RestTemplate / HttpClient — TrustAll):**
```
grep(pattern="TrustStrategy.*->\\s*true|\\.trustAll\\(\\)|AllowAllHostnameVerifier|HostnameVerifier.*true", max_matches=15)
```

**Kotlin (OkHttp / Ktor):**
```
grep(pattern="hostnameVerifier\\s*=\\s*HostnameVerifier\\s*\\{[^}]*true|trustAll|ALLOW_ALL_HOSTNAME_VERIFIER", max_matches=15)
```

**Swift:**
```
grep(pattern="kCFStreamSSLValidatesCertificateChain.*false|SecTrustEvaluate|didReceive.*challenge.*ServerTrust", max_matches=15)
```

**Connection strings (any language — MongoDB):**
```
grep(pattern="mongodb://.*tlsAllowInvalidCertificates=true|mongodb://.*tlsInsecure=true|mongodb://.*tlsAllowInvalidHostnames=true", max_matches=15)
```

→ Submit: violated_invariant="TLS certificate verification disabled; MITM substitutes content or key material", severity=7, confidence=8, exposure="internet"

---

## Step 4 — Hardcoded JWT / signing secrets

**Python (PyJWT literal):**
```
grep(pattern="jwt\\.encode\\([^,]+,\\s*[\"'][^\"']{8,}[\"']|jwt\\.decode\\([^,]+,\\s*[\"'][^\"']{8,}[\"']", max_matches=15)
```

**Django SECRET_KEY:**
```
grep(pattern="SECRET_KEY\\s*=\\s*[\"'][^\"']{8,}[\"']", max_matches=15)
```

**Node.js (jsonwebtoken):**
```
grep(pattern="jwt\\.sign\\([^,]+,\\s*[\"'][^\"']{8,}[\"']|jwt\\.verify\\([^,]+,\\s*[\"'][^\"']{8,}[\"']", max_matches=15)
```

**Node.js (passport-jwt):**
```
grep(pattern="secretOrKey\\s*:\\s*[\"'][^\"']{8,}[\"']", max_matches=15)
```

**Java (auth0 java-jwt HMAC literal):**
```
grep(pattern="Algorithm\\.HMAC(256|384|512)\\([\"'][^\"']{8,}[\"']", max_matches=15)
```

**Java (SecretKeySpec literal):**
```
grep(pattern="new SecretKeySpec\\([\"'][^\"']{8,}[\"']\\.getBytes\\(\\)", max_matches=15)
```

**Kotlin:**
```
grep(pattern="SecretKeySpec\\([\"'][^\"']{8,}[\"']\\.toByteArray\\(\\)|Algorithm\\.HMAC256\\([\"'][^\"']{8,}[\"']", max_matches=15)
```

**Scala (auth0):**
```
grep(pattern="Algorithm\\.HMAC256\\([\"'][^\"']{8,}[\"']", max_matches=15)
```

**C# (jwt-dotnet / SymmetricSecurityKey):**
```
grep(pattern="(IJwtEncoder|JwtEncoder)\\s*\\.\\s*Encode\\([^,]+,\\s*[\"'][^\"']{8,}[\"']|SymmetricSecurityKey\\(Encoding\\.[^.]+\\.GetBytes\\([\"'][^\"']{8,}[\"']", max_matches=15)
```

**Go (JWT literal key):**
```
grep(pattern="\\[\\]byte\\([\"'][^\"']{8,}[\"']\\)|hmac\\.New\\(.*,\\s*\\[\\]byte\\([\"']", max_matches=15)
```

**Ruby (Rails secret_key_base):**
```
grep(pattern="secret_key_base\\s*[=:]\\s*[\"'][^\"']{8,}[\"']|config\\.secret_key_base\\s*=\\s*[\"']", max_matches=15)
```

**Shell / Docker default fallback:**
```
grep(pattern="SECRET_KEY\\s*:-\\s*[a-zA-Z0-9+/=$@#!_-]{8,}|JWT_SECRET\\s*:-\\s*[a-zA-Z0-9+/=$@#!_-]{8,}|SESSION_SECRET\\s*:-", max_matches=15)
```

For each match: is this in a real config/main file, not a test fixture or example?

→ Submit per secret: violated_invariant="signing secret [name] hardcoded; attacker forges tokens in any deployment without explicit env override", severity=10, confidence=8, exposure="internet"

---

## Step 5 — Authorization decision from request header alone

```
grep(pattern="request\\.headers\\.get\\(['\"]X-|req\\.headers\\[['\"]X-|request\\.META\\.get\\(['\"]HTTP_X_|r\\.Header\\.Get\\(['\"]X-|request\\.getHeader\\(['\"]X-|\\$_SERVER\\[['\"]HTTP_X_", max_matches=30)
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
grep(pattern="#\\s*(if|raise|assert).*[Aa]uth|#\\s*verify|#\\s*@login_required|#\\s*@require|//\\s*isAuthenticated|//\\s*auth\\.required|//\\s*passport\\.authenticate|//\\s*@Secured|//\\s*@PreAuthorize|/\\*.*[Aa]uth.*\\*/", max_matches=20)
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
