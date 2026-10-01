# SKILL: hunt-auth-bypass-patterns

## Goal

Find authentication bypass bugs. For each step: use search_graph or search_code to locate the code, read it, decide immediately, and submit a hypothesis if the pattern is present. Do not investigate exhaustively — submit and move on.

---

## Step 1 — HTTP header used in authorization decision

Search for the authorization/admin check function (search_graph for `is_admin`, `checkAdmin`, `isAdmin`, `hasAdminRole`, `isStaff`, or whatever name the project uses for elevated privilege checks).
Read the complete function body.
**Finding condition**: the function grants elevated access (returns True, grants admin role, skips further checks) based on the value of any HTTP request header (e.g., `request.headers.get(...)`, `req.header(...)`, `getHeader(...)`, `ctx.GetHeader(...)`) before checking a database-backed identity property (like `is_superuser`, `admin=true` in a DB record, or a cryptographically verified claim).
→ **submit hypothesis immediately**: violated_invariant="admin/elevated privilege check short-circuits on attacker-controlled HTTP header before verifying identity in the trusted store", severity=10, confidence=8.

## Step 2 — JWT audience not verified

Search for JWT decode calls (search_code for `verify_aud`, `audience=`, `decode(token`, `jwt.decode`, `jwtlib.decode`, `verifyToken`, `parseJWT`, or the project's JWT library).
Read the decode options/parameters.
**Finding condition**: audience verification is explicitly disabled (`verify_aud: false`, `options={"verify_aud": False}`, audience parameter omitted when the library defaults to no-verify) OR the audience is validated with a loose match (substring, prefix) rather than exact equality.
→ **submit hypothesis immediately**: violated_invariant="JWT tokens issued to a different audience are accepted; cross-service token replay possible", severity=9, confidence=8.

## Step 3 — Signing key hardcoded fallback

Search for JWT or session signing key configuration (search_code for `SIGNING_KEY`, `JWT_SECRET`, `SECRET_KEY`, `jwt_secret`, `signing_key`).
Find where the key value is assigned at startup. Read the assignment.
**Finding condition**: the key source uses a "get with default" pattern (`os.environ.get('X', 'hardcoded-string')`, `process.env.X || 'fallback'`, `ENV['X'] || 'fallback'`, `config.GetString("x", "default")`) where the fallback is a non-empty string literal.
→ **submit hypothesis immediately**: violated_invariant="JWT signing key falls back to hardcoded string when env var absent; anyone with source code access can forge tokens", severity=10, confidence=9.

## Step 4 — TLS verification disabled for external key fetch

Search for HTTP client calls that fetch OAuth2/OIDC discovery or JWKS documents (search_code for `jwks_uri`, `openid-configuration`, `well-known`, `discovery`, `JWKS`).
Read the HTTP call including the `verify`, `ssl`, `tls`, or equivalent parameter.
**Finding condition**: TLS verification is disabled (`verify=False`, `ssl=false`, `InsecureSkipVerify: true`) OR disabled conditionally based on a debug flag (`verify = not DEBUG`, `if (isDev) { rejectUnauthorized: false }`).
→ **submit hypothesis immediately**: violated_invariant="OIDC/JWKS key material fetched with TLS verification disabled; MITM can inject forged signing keys", severity=7, confidence=8.

## Step 5 — Revocation check after signature validation

Search for token revocation/blacklist logic (search_code for `blacklist`, `revoke`, `BlacklistedToken`, `invalidated_token`, `token_blacklist`).
Find where the revocation check executes relative to signature verification. Trace the call order.
**Finding condition**: the revocation/blacklist query executes AFTER the signature verification call (e.g., `super().get_validated_token()` followed later by a DB query to a blacklist table).
→ **submit hypothesis immediately**: violated_invariant="token blacklist checked after signature validation; a token forged with a leaked key is never in the blacklist and bypasses revocation", severity=7, confidence=8.

## Step 6 — Test/debug authentication injection

Search for middleware that injects authentication for unauthenticated requests (search_code for `LOCAL_TESTING`, `TEST_USER`, `inject.*token`, `inject.*auth`, `bypass.*auth`, `TestUser`).
Read the activation condition.
**Finding condition**: the middleware activates based on an environment variable (not `DEBUG` itself) that could be accidentally set on a staging/production server.
→ **submit hypothesis immediately**: violated_invariant="development auth injection middleware can activate on staging via misset env var; unauthenticated requests become authenticated", severity=8, confidence=7.

## Finish

Call finish() with all hypotheses found. Call it now even if the list is empty.
