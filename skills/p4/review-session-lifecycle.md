# SKILL: review-session-lifecycle

## Contract

**Trigger:** Phase 4, for any application using sessions or tokens.
**Phase:** 4 — Security Analysis
**Preconditions:** Identity model, auth library
**Escalates to:** review-cryptographic-usage

## Inputs
- repo_path
- auth_mechanism: JWT | session-cookie | refresh-token | opaque-token

## Procedure
1. Find token/session issuance: where are tokens created? What claims are included?
2. Check signing: what algorithm? Where is the signing key? Is it environment-specific?
3. Check validation on each request: signature, expiry, issuer, audience — all four checked?
4. Find refresh token flow: is the refresh token single-use? Is it rotated on use?
5. Find revocation: when a user logs out or changes password, are existing tokens/sessions invalidated?
6. Find privilege change: when a user's role changes, does their active session reflect the change?
7. Find session fixation: is a new session ID issued after successful authentication?
8. Find concurrent session: are multiple sessions allowed? Is there a limit?
9. Find session data storage: server-side (DB/Redis) or client-side (cookie)?
10. For client-side session: is the data authenticated (signed/encrypted) and does the app verify signature before use?
11. Find account recovery: password reset tokens — are they single-use, time-limited, and tied to the account?
12. Find "remember me": what's the lifetime? Is the persistent token stored with the same privileges as the session token?

## Required evidence
- Token validation checklist: signature, expiry, issuer, audience — each confirmed present or absent
- Revocation mechanism and its coverage (logout, password change, role change)
- Refresh token: single-use confirmed or denied
- Session fixation: new session ID on auth confirmed or denied
- Password reset token: single-use, time-limited, account-bound confirmed or denied

## Counterchecks
- Short-lived tokens (< 5 min) reduce the window for stolen token replay even without revocation.
- Audience validation prevents token confusion attacks between services.
- A revocation list (database or Redis) is sufficient even for JWTs if checked on every request.

## Output schema
Standard FINDINGS_SCHEMA. Hypotheses for: missing audience validation enabling token confusion, refresh token reuse attack, no revocation on password change, session fixation.

## Stop condition
When the complete token/session lifecycle is documented from issuance to expiry/revocation.

## Forbidden inferences
- Do not report JWT algorithm=none as a finding without testing — most libraries reject it by default.
- Do not report missing revocation without confirming token lifetime is long enough to matter.
