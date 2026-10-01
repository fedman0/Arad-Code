# SKILL: hunt-auth-bypass-patterns

## Goal

Find authentication bypass bugs. Read the listed files directly. For each pattern found, submit a hypothesis immediately — do not wait.

---

## Step 1 — Header-based auth bypass

Read `coreapi/application/utilities/AdminCheck.py` (or search_graph for `is_admin`).
Check: does any path return True based on `request.headers.get(...)` before checking `is_superuser`?
If yes → **submit hypothesis**: actor=any authenticated user, violated_invariant="admin check short-circuits on attacker-controlled HTTP header", severity=10, confidence=8.

## Step 2 — JWT audience not verified

Search for `verify_aud` in the codebase (search_code or grep).
If you find `"verify_aud": False` or `options={"verify_aud": False}` in JWT decode calls → **submit hypothesis**: violated_invariant="OIDC tokens from other audiences accepted", severity=9, confidence=8.

## Step 3 — JWT signing key hardcoded fallback

Read `hesaboai/settings.py` section for `SIMPLE_JWT` or `JWT_SECRET_KEY`.
If `os.environ.get('JWT_SECRET_KEY', 'some-string')` has a non-empty default → **submit hypothesis**: violated_invariant="JWT signing key falls back to hardcoded string; attacker with repo access can forge tokens", severity=10, confidence=9.

## Step 4 — OIDC JWKS SSL disabled

Search for `verify=False` or `verify=verify_ssl` near `requests.get` in authentication files.
If JWKS/discovery endpoint is fetched with SSL disabled (even conditionally on DEBUG) → **submit hypothesis**: violated_invariant="OIDC key material fetched without TLS verification; MITM can inject forged keys", severity=7, confidence=7.

## Step 5 — Token blacklist ordering

Find `CustomJWTAuthentication.get_validated_token` (search_graph or search_code for `BlacklistedAccessToken`).
Check: is the blacklist query AFTER `super().get_validated_token()` (signature check)?
If yes → **submit hypothesis**: violated_invariant="blacklist checked after signature validation; forged tokens never in blacklist", severity=7, confidence=8.

## Step 6 — Test auth injection middleware

Search for `LOCAL_TESTING` or `TestUserAuthInjectionMiddleware` in the codebase.
If middleware injects a token for unauthenticated requests and is gated on an env var (not `DEBUG`) → **submit hypothesis**: violated_invariant="test middleware injects authentication when env var set; can activate on staging", severity=8, confidence=7.

## Finish

Call finish() with whatever hypotheses you found. Call it even if you found zero — pass an empty list.
