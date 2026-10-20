---
order: 70
---

# SKILL: map-trust-boundaries

## Contract

**Trigger:** Phase 2, after model-identities and map-service-boundaries.
**Phase:** 2 — Identity & Ownership
**Preconditions:** Identity model, service communication map, deployment context (Identity Model, Service Communication Graph and Deployment Context sections of the Threat Model in Known Context)
**Escalates to:** trace-identity-propagation, understand-authorization-and-access

## Inputs
- repo_path
- service communication graph (Service Communication Graph section of the Threat Model)

## Procedure
1. Define trust levels: anonymous (0), authenticated user (1), service account (2), internal admin (3), superadmin (4).
2. For each service boundary (HTTP, message, RPC, shared DB): what trust level does the consumer assign to incoming data?
3. Find points where trust INCREASES: where does the system accept a lower-trust claim and act with higher-trust authority?
4. Find inter-service calls: ServiceA (user-trusted) → ServiceB — does ServiceB re-validate the user identity or trust ServiceA's claim?
5. Find message consumers: consumer receives message from queue — trust level of message data?
6. Find user-controlled fields that reach privileged code paths: can a user set a field that later is used to determine privilege?
7. Find ambient authority: operations that use service account identity when they should use user identity.
8. Find trust escalation via configuration: is there a config value that promotes a user claim to admin?
9. Find third-party webhooks: does the system verify webhook origin/signature before processing payload?

## Required evidence
- Trust level map: every inter-service edge with caller trust level and recipient trust assumption
- Boundary crossings where trust increases without re-validation
- User-controlled fields that reach privileged operations
- Webhook signature verification (or absence)

## Counterchecks
- A service-to-service call with mTLS proves ServiceA's identity but not the user's — this is correct if ServiceB does its own user validation.
- Ambient authority (service account) is only a finding if the operation should be scoped to user identity.
- Trust via shared secret header (API key) is weaker than mTLS but may be acceptable for internal traffic with network policy.

## Output schema
Standard FINDINGS_SCHEMA. Hypotheses for: trust elevation without re-validation, user field reaching admin operation, webhook processed without signature verification.
Set `cwe` on each hypothesis (e.g. CWE-290 forwarded claim accepted without re-validation, CWE-269 user-controlled field deciding privilege, CWE-345 webhook processed without signature verification).

Persist the trust boundary map (each boundary crossing with caller trust level, recipient assumption, re-validation status) with `amend_threat_model` as a short `## Trust Boundary Map` section (if no threat model exists yet,
call `save_threat_model` with `## Overview`, `## Trust Boundaries`, `## Attack Surface`, `## Severity Calibration`
and this section). Later skills read it from the Threat Model in Known Context.

## Stop condition
When every boundary crossing has a documented trust level and re-validation status.

## Forbidden inferences
- Do not conclude forwarded user claims are trusted without reading the receiving service's validation code.
- Do not report ambient authority as a finding if the operation is explicitly meant to run as the service (e.g., a background cleanup job).
