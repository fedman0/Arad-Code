# review-authentication-flows

Audit OAuth 2.0 / OIDC / SAML flows, JWT validation, password reset, MFA, and session fixation paths for authentication bypass.

## Scope

- OAuth/OIDC: state parameter, redirect_uri validation, PKCE, token binding
- SAML: signature verification, assertion replay, XML canonicalization
- JWT: algorithm confusion (none/RS→HS), missing aud/iss/exp validation, weak secret
- Password reset: predictable tokens, token reuse, account enumeration
- MFA: bypass via fallback flow, race condition on OTP window, SIM swap vector
- Session: fixation, insufficient rotation on privilege escalation, concurrent session handling

## Methodology

1. Call `get_architecture()` to identify the auth framework and IdP.
2. Call `get_open_questions()` for prior unresolved auth findings.
3. Call `get_return_contracts()` for documented auth-check return values.
4. Use `search_graph` to find all custom permission/authorization helper functions (e.g. `is_admin`, `check_permission`, `require_auth`, `has_access`). For each one found, call `trace_path` to discover every caller — the bug may be in how the function is used, not defined.
5. Use `search_graph` to find all middleware classes. Read each one end-to-end: middleware can inject identity, strip headers, or bypass authentication for entire request paths.
6. For each authentication endpoint:
   a. Read the token validation logic end-to-end via `trace_path` + `read_file`.
   b. Verify the algorithm is explicitly allowlisted (never accept "alg": "none").
   c. Verify `aud`, `iss`, `exp`, `nbf` are validated before trusting claims.
   d. Verify redirect_uri is exact-match against a static allowlist.
   e. Verify the state parameter is cryptographically random and tied to session.
   f. Verify password-reset tokens are single-use, time-limited, and invalidated on use.
7. For each `proof_obligation` of type `guard`, read the guard function directly — do not trust its name.
8. For Django/DRF apps specifically: find `REST_FRAMEWORK` settings and read every custom `DEFAULT_AUTHENTICATION_CLASSES` and `DEFAULT_PERMISSION_CLASSES`. Read the `SIMPLE_JWT` config. Check if token blacklisting is verified before or after signature validation.

## Required proof_obligations per finding

- `reachability`: is this endpoint exposed without prior authentication?
- `input_control`: can the attacker supply the manipulated token/parameter?
- `guard`: is there no validation that stops the bypass?
- `impact`: what account or privilege does successful bypass yield?

## Finding template

```json
{
  "actor": "unauthenticated attacker",
  "capability": "send crafted JWT / OAuth request",
  "entry_point": "POST /oauth/token or equivalent",
  "exposure": "internet",
  "anchor_text": "exact code substring proving the bypass"
}
```

## Common false positives to reject

- Validation present but behind a feature flag: check the flag's default and deployment config.
- Library handles it: read the library version and its changelog for the specific CVE.
- Only affects non-production endpoints: verify the routing condition.

Call `reject_hypothesis` with `rejection_condition` when a guard is effective.
Call `finish()` when complete.
