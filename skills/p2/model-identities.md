# SKILL: model-identities

## Contract

**Trigger:** After Phase 1 completes. First skill in Phase 2.
**Phase:** 2 — Identity & Ownership
**Preconditions:** Service list, DI map, middleware map (Threat Model in Known Context)
**Escalates to:** model-authorization, model-resource-ownership

## Inputs
- repo_path
- auth library (JWT, OAuth2, SAML, Session, API key)

## Procedure
1. Find the user/identity entity: ApplicationUser, UserEntity, ClaimsPrincipal, ICurrentUser.
2. Get code snippet for the identity type — what fields does it carry? (id, tenantId, roles, email, isAdmin).
3. Find how identity is established at the entry point: JWT decode, session read, API key lookup, certificate.
4. Identify identity types: human user, service account, operator, external system (webhook), anonymous.
5. For each identity type, find: what they are allowed to do, what claims/roles they carry, how the identity is propagated across async boundaries.
6. Find impersonation: any mechanism that allows acting as another user or switching identity.
7. Find external identity providers: OIDC, SAML — what claims are trusted from the provider, and are they validated?
8. Find anonymous/guest identity: what operations are available without authentication?
9. Find admin/super-admin escalation paths: how does a user become an admin?

## Required evidence
- Identity entity schema (fields, types)
- Identity establishment mechanism per entry point type
- Identity types and their capabilities
- Admin escalation path
- Impersonation mechanism (if any)
- External IdP claims validation

## Counterchecks
- A claim present in the JWT does not mean it's trusted — check if the JWT is validated (signature, expiry, issuer).
- Roles in the token may be stale if not refreshed — check token lifetime and revocation mechanism.
- External IdP claims need audience and issuer validation.

## Output schema
Standard FINDINGS_SCHEMA. Hypotheses for: JWT not validated, stale role without revocation, trusted external claim without validation.
Set `cwe` on each hypothesis (e.g. CWE-347 token signature not verified, CWE-287 other token validation gaps, CWE-613 stale role without revocation, CWE-345 external IdP claim trusted without validation).

Persist the identity model (identity types, entity fields, establishment mechanism per entry point type, propagation, admin escalation, impersonation) with `amend_threat_model` as a short `## Identity Model` section (if no threat model exists yet,
call `save_threat_model` with `## Overview`, `## Trust Boundaries`, `## Attack Surface`, `## Severity Calibration`
and this section). Later skills read it from the Threat Model in Known Context.

## Stop condition
When every identity type is documented with its establishment mechanism and propagation model.

## Forbidden inferences
- Do not conclude JWT validation is absent because the validation code isn't in the handler — check middleware.
- Do not assume all admin operations require the same level of admin role.
