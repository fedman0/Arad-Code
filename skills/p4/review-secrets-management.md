# review-secrets-management

Audit hardcoded credentials, secret leakage through logs/errors, insecure storage, and missing secret rotation.

## Scope

- Hardcoded secrets: API keys, DB passwords, JWT signing keys, private keys in source
- Secrets in environment: `.env` files committed, insecure defaults, fallback to insecure value
- Secret leakage: secrets echoed in logs, error responses, stack traces, debug endpoints
- Storage: secrets in version control, build artifacts, Docker image layers
- Rotation: long-lived tokens with no expiry, no rotation mechanism

## Methodology

1. Scan for hardcoded credentials:
   - `grep(pattern="password\s*=\s*['\"]|secret\s*=\s*['\"]|api_key\s*=\s*['\"]|token\s*=\s*['\"]")`
   - `grep(pattern="BEGIN (RSA|EC|OPENSSH|PGP) PRIVATE KEY")`
   - `shell(command="git log --all --oneline --diff-filter=A -- '*.env' '*.pem' '*.key'")`
2. For each hit: read the file context to confirm it is a real credential, not a placeholder.
3. Check environment variable fallbacks: `os.getenv("SECRET", "default_insecure")` patterns.
4. Search for debug/admin endpoints that expose config:
   - `grep(pattern="/debug|/health|/env|/config|/actuator")`
   - Read the handler: does it include secrets in the response?
5. Check log statements near auth operations for secret material:
   - `grep(pattern="logger\.(info|debug|warn).*password|logger.*token")`
6. Inspect Dockerfile and CI config for secrets in ENV or ARG:
   - `read_file("Dockerfile")`, `read_file(".github/workflows/")`

## Required proof_obligations

- `reachability`: is the secret reachable by an attacker (in a response, log, artifact)?
- `impact`: what does compromise of this secret enable?

## anchor_text requirement

Point anchor_text to the exact line with the hardcoded value or the leaking log statement.

## Reject criteria

- Placeholder values (e.g. `"your-api-key-here"`, `"changeme"`) — note them as a risk but not a confirmed finding.
- Secret only in test fixtures, not production config — document scope.

Call `finish()` when complete.
