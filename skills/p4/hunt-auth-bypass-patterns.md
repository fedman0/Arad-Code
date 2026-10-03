# SKILL: hunt-auth-bypass-patterns

## ⚡ BREADTH SCAN — grep-first, semgrep-derived patterns, multi-language

Run grep, read context with `get_code_snippet`, submit immediately. 2 tool calls per step max.

---

## Step 1 — Authorization decision made from a request header value

```
grep(pattern="request\.headers\.get|req\.headers\[|request\.META\.get|r\.Header\.Get|request\.getHeader|HttpServletRequest.*getHeader|\$_SERVER\[.HTTP_", max_matches=30)
```

For each result: does the function return authorized/true/nil **solely** on the header string, without DB lookup or crypto verification?

```
if "literal" in header_value: return True       # Python
if (header === "literal") return true;           # JS
if header == "literal" { return nil }            # Go
if (request.getHeader("X-Internal") != null)    # Java — presence only
```

**A — Header-only authorization**:
→ Submit: violated_invariant="authorization decision made from caller-controlled request header; any caller adds the header to gain access", severity=10, confidence=7, exposure="internet"

---

## Step 2 — JWT algorithm=none or validation disabled

**Python (PyJWT):**
```
grep(pattern="jwt\.decode.*algorithms.*none|jwt\.encode.*algorithm.*none|algorithms=\[.*none|algorithm=\"none\"", max_matches=20)
```

**JavaScript (jsonwebtoken):**
```
grep(pattern="\.verify\(.*algorithms.*none|\.decode\(.*complete.*true|jwt\.verify.*\{.*algorithms.*none", max_matches=20)
```

**Java (auth0 java-jwt):**
```
grep(pattern="Algorithm\.none\(\)|\.withAlgorithm\(Algorithm\.none|algorithm.*none.*sign", max_matches=15)
```

**C# (.NET / System.IdentityModel):**
```
grep(pattern="RequireExpirationTime\s*=\s*false|ValidateLifetime\s*=\s*false|ValidateIssuerSigningKey\s*=\s*false|ValidateIssuer\s*=\s*false|ValidateAudience\s*=\s*false", max_matches=20)
```

**All fallback / option-object patterns:**
```
grep(pattern="verify_aud.*[Ff]alse|ignoreExpiration.*true|validateIssuer.*false|verify_signature.*[Ff]alse|options.*verify.*false", max_matches=20)
```

For each match: is validation disabled unconditionally or only in a catch/fallback path where the primary validation failed?

→ Submit: violated_invariant="JWT validation option [option] disabled; tokens failing normal validation are accepted", severity=9, confidence=7, exposure="internet"

---

## Step 3 — TLS certificate verification disabled

**Python (requests library):**
```
grep(pattern="requests\.(get|post|put|patch|delete|head|request)\(.*verify=False|verify\s*=\s*False", max_matches=20)
```

**Python (ssl module):**
```
grep(pattern="ssl\._create_unverified_context|_create_default_https_context\s*=\s*ssl\._create_unverified|check_hostname\s*=\s*False", max_matches=15)
```

**JavaScript (Node.js):**
```
grep(pattern="rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED.*[\"']0[\"']|https\.request.*rejectUnauthorized.*false", max_matches=20)
```

**Go:**
```
grep(pattern="InsecureSkipVerify\s*:\s*true|tls\.Config\{.*InsecureSkipVerify|grpc\.WithInsecure\(\)", max_matches=20)
```

**PHP (cURL):**
```
grep(pattern="curl_setopt.*CURLOPT_SSL_VERIFYPEER.*0|CURLOPT_SSL_VERIFYPEER.*false|CURLOPT_SSL_VERIFYHOST.*0", max_matches=15)
```

**C# (.NET):**
```
grep(pattern="ServerCertificateValidationCallback.*true|X509CertificateValidationMode\.None|SslCertificateTrust\.CreateFor.*true", max_matches=15)
```

→ Submit: violated_invariant="TLS certificate verification disabled [unconditionally/when debug flag set]; MITM substitutes attacker-controlled content or signing key material", severity=7, confidence=7, exposure="internet"

---

## Step 4 — Signing key or session secret hardcoded

**Python (PyJWT literal string as secret):**
```
grep(pattern="jwt\.encode\([^,]+,\s*['\"][^'\"]{8,}['\"]|jwt\.decode\([^,]+,\s*['\"][^'\"]{8,}['\"]", max_matches=15)
```

**JavaScript (jsonwebtoken / jose):**
```
grep(pattern="jwt\.sign\([^,]+,\s*['\"][^'\"]{8,}['\"]|jwt\.verify\([^,]+,\s*['\"][^'\"]{8,}['\"]|new TextEncoder.*encode\(['\"][^'\"]{8,}['\"]", max_matches=15)
```

**Java (auth0 java-jwt — HMAC with literal):**
```
grep(pattern="Algorithm\.HMAC(256|384|512)\(['\"][^'\"]{8,}['\"]|HMAC256\(['\"][^'\"]{8,}['\"]|\.withSecret\(['\"][^'\"]{8,}['\"]", max_matches=15)
```

**C# (SymmetricSecurityKey with literal bytes):**
```
grep(pattern="SymmetricSecurityKey\(Encoding\.[^.]+\.GetBytes\(['\"][^'\"]{8,}['\"]|IssuerSigningKey.*SymmetricSecurityKey.*GetBytes\(['\"]", max_matches=15)
```

**Shell-variable fallback (docker-compose, Helm, k8s):**
```
grep(pattern=":-[a-zA-Z0-9+/=$@#!_-]{8,}", max_matches=30)
```

Also:
```
grep(pattern="SECRET_KEY\s*:-|JWT_SECRET\s*:-|SIGNING_KEY\s*:-|SESSION_SECRET\s*:-|APP_SECRET\s*:-", max_matches=10)
```

→ Submit per secret: violated_invariant="signing/session secret [name] hardcoded; any deployment without explicit env vars uses this known value to forge tokens", severity=10, confidence=7, exposure="internet"

---

## Step 5 — Authentication or authorization check commented out

```
grep(pattern="#\s*(if|raise).*[Aa]uth|#\s*verify|//\s*isAuthenticated|//\s*auth\.required|//\s*passport\.authenticate|//\s*@Secured|//\s*@PreAuthorize|/\*.*[Aa]uth.*\*/", max_matches=20)
```

For each match in a handler (payment, transfer, admin, account): is the commented line the only place an auth check would be enforced?

→ Submit: violated_invariant="authorization check commented out; handler runs without verifying caller identity", severity=9, confidence=7, exposure="authenticated"

---

## Step 6 — Token blacklist or revocation checked after signature verification

```
grep(pattern="blacklist|revoke|blocklist|token_revoke|invalidate.*token|token.*invalid|denylist", max_matches=20)
```

For each match: call `get_code_snippet`. Is the revocation store lookup done AFTER `jwt.verify` / `get_validated_token` / `parseClaimsJws` / `TokenHandler.ValidateToken`?

→ Submit: violated_invariant="token revocation check runs after cryptographic signature verification; a token forged with a compromised key bypasses the revocation list", severity=7, confidence=7, exposure="authenticated"

---

## Step 7 — Development authentication injection middleware

```
grep(pattern="inject.*[Aa]uth|[Aa]uth.*[Ii]nject|bypass.*[Aa]uth|skip.*[Aa]uth|[Tt]est.*[Aa]uth.*[Mm]iddleware|[Dd]ev.*[Aa]uth|set.*[Aa]uthorization.*header|override.*[Aa]uth|TESTING.*=.*true|LOCAL.*=.*1", max_matches=20)
```

For each match: what condition activates it? Could `TESTING=true`, `LOCAL=1`, or `NODE_ENV=test` be accidentally set on staging?

→ Submit: violated_invariant="authentication injection middleware activates on a non-production-exclusive env var; all requests become pre-authenticated wherever the variable is set", severity=8, confidence=7, exposure="internet"

---

## Finish

Call `finish()` now with all hypotheses collected. Do not skip this.
