# SKILL: hunt-auth-bypass-patterns

## ⚡ BREADTH SCAN — grep-first, multi-language, pattern-confirmed

Each step gives grep patterns that work across Python, JavaScript/TypeScript, Go, Java, PHP, and Ruby. Run the grep, read context with `get_code_snippet` or `read_file`, confirm the pattern, submit immediately. 2 tool calls per step maximum.

---

## Step 1 — Authorization decision made from a request header value

```
grep(pattern="request\\.headers\\.get|req\\.headers\\[|request\\.META\\.get|r\\.Header\\.Get|request\\.getHeader|HttpServletRequest.*getHeader|\\$_SERVER\\[.HTTP_", max_matches=30)
```

For each result: call `get_code_snippet` on the surrounding function. Check: does the function return `True` / `true` / `authorized` / `nil` (allowed) **solely** based on the header string value, without checking a database record or verifying a cryptographic token?

Dangerous pattern (any language):
```
if "literal" in header_value: return True       # Python
if (header === "literal") return true;           # JS
if header == "literal" { return nil }            # Go
```

→ Submit: violated_invariant="authorization decision made from caller-controlled request header value; any caller adds the header to gain access", severity=10, confidence=7, exposure="internet"

---

## Step 2 — Token validation options that disable security checks

```
grep(pattern="verify_aud.*[Ff]alse|\"verify_aud\".*false|algorithms.*['\"]none['\"]|algorithm.*['\"]none['\"]|ignoreExpiration.*true|validateIssuer.*false|verify.*=.*[Ff]alse|options.*verify.*false", max_matches=20)
```

Also:
```
grep(pattern="decode.*options|jwt\\.verify.*\\{|PyJWT.*options|verify_signature.*[Ff]alse", max_matches=20)
```

Look for any `decode`/`verify` call that disables audience, signature, or expiry checking — especially inside an `except`/`catch` block where the first attempt failed with full validation and the fallback re-decodes with reduced validation.

→ Submit: violated_invariant="token validation option [option name] disabled [in fallback path / unconditionally]; tokens failing normal validation are accepted", severity=9, confidence=7, exposure="internet"

---

## Step 3 — TLS certificate verification disabled

```
grep(pattern="verify_ssl.*[Ff]alse|rejectUnauthorized.*false|NODE_TLS_REJECT_UNAUTHORIZED.*0|ssl_verify.*[Ff]alse|verify=False|InsecureRequestWarning|InsecureSkipVerify.*true|curl_setopt.*CURLOPT_SSL_VERIFYPEER.*0", max_matches=20)
```

Check the condition: is it `if DEBUG`, `if not IS_PROD`, `if NODE_ENV !== 'production'`, or similar? TLS disabled even conditionally allows MITM on dev/staging.

→ Submit: violated_invariant="TLS certificate verification disabled [unconditionally / when debug flag is set]; MITM substitutes attacker-controlled content or signing key material", severity=7, confidence=7, exposure="internet"

---

## Step 4 — Signing key or session secret with hardcoded fallback

```
grep(pattern=":-[a-zA-Z0-9+/=$@#!_-]{8,}", max_matches=20)
```

Also:
```
grep(pattern="SECRET_KEY.*:-|JWT_SECRET.*:-|SIGNING_KEY.*:-|APP_SECRET.*:-|SESSION_SECRET.*:-", max_matches=10)
```

Also check for hardcoded literals in code:
```
grep(pattern="jwtSecret\\s*=\\s*['\"][^'\"]{8,}['\"]|jwt\\.sign.*secret.*['\"][^'\"]{8,}['\"]|SECRET_KEY\\s*=\\s*['\"][^'\"]{8,}['\"]", max_matches=10)
```

Any non-empty literal after `:-` in a deployment config means the secret is used as-is when the env var is unset.

→ Submit per secret: violated_invariant="signing/session secret has a non-empty hardcoded fallback; any deployment without explicit env vars uses this known value to forge tokens", severity=10, confidence=7, exposure="internet"

---

## Step 5 — Authentication or authorization check commented out

```
grep(pattern="#\\s*(if|raise).*[Aa]uth|#\\s*verify|//\\s*isAuthenticated|//\\s*auth\\.required|//\\s*passport\\.authenticate|/\\*.*[Aa]uth.*\\*/|<!--.*[Aa]uth", max_matches=20)
```

For each match in a handler file (payment, transfer, admin, account): is the commented line the only place an authorization check would be enforced?

→ Submit: violated_invariant="authorization check commented out; handler runs without verifying caller identity", severity=9, confidence=7, exposure="authenticated"

---

## Step 6 — Token blacklist or revocation checked after signature verification

```
grep(pattern="blacklist|revoke|blocklist|token_revoke|invalidate.*token|token.*invalid", max_matches=20)
```

For each match: call `get_code_snippet`. Is the revocation store lookup done AFTER the cryptographic signature check (`jwt.verify`, `get_validated_token`, `parseClaimsJws`, etc.)? A forged token with a leaked key passes signature but is not in the revocation list.

→ Submit: violated_invariant="token revocation check runs after cryptographic signature verification; a token forged with a compromised key bypasses the revocation list", severity=7, confidence=7, exposure="authenticated"

---

## Step 7 — Development authentication injection middleware

```
grep(pattern="inject.*[Aa]uth|[Aa]uth.*[Ii]nject|bypass.*[Aa]uth|skip.*[Aa]uth|[Tt]est.*[Aa]uth.*[Mm]iddleware|[Dd]ev.*[Aa]uth|set.*[Aa]uthorization.*header|override.*[Aa]uth", max_matches=20)
```

For each match: what environment variable or condition activates it? Could it be accidentally true on staging (e.g., `TESTING=true`, `LOCAL=1`, `NODE_ENV=test`)?

→ Submit: violated_invariant="authentication injection middleware activates on a non-production-exclusive environment variable; all requests become pre-authenticated on any environment where the variable is set", severity=8, confidence=7, exposure="internet"

---

## Finish

Call `finish()` now with all hypotheses collected. Do not skip this.
