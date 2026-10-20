# SKILL: extract-business-invariants

## Contract

**Trigger:** Phase 2, after extract-state-machines.
**Phase:** 2 — Identity & Ownership
**Preconditions:** Entity schema, state machines, service list (State Machines and Repository Inventory sections of the Threat Model in Known Context)
**Escalates to:** understand-business-logic, trace-state-transitions

## Inputs
- repo_path
- domain type (financial / e-commerce / healthcare / SaaS / etc.)

## Procedure
1. Find quota and limit enforcement: MaxRequests, DailyLimit, StorageQuota — where are they checked?
2. Find financial invariants: balance cannot go negative, total debit = total credit, refund <= original charge.
3. Find uniqueness constraints: unique order IDs, idempotency keys, email uniqueness — at DB level or application level?
4. Find rate limiting: is it enforced per-user, per-IP, per-tenant? Can it be bypassed via different endpoints?
5. Find authorization scope boundaries: a token scoped to read:invoices cannot write:invoices.
6. Find maximum/minimum value constraints: price > 0, quantity integer, discount <= 100%.
7. Find temporal constraints: subscription active before accessing features, payment due date enforcement.
8. Find referential integrity: deleting a parent when children exist — is it prevented or cascaded?
9. For each invariant, determine: enforced at DB level (CONSTRAINT), ORM level (validation), application level (service), or only in the UI.

## Required evidence
- Invariant list with source (DB constraint / ORM / service / UI-only)
- Invariants enforced only at UI or client level (potentially bypassable via API)
- Financial invariants and their enforcement layer
- Uniqueness constraints: DB UNIQUE vs. application check (race condition if application-only)

## Counterchecks
- UI-only enforcement is bypassed by direct API access — only report if the API endpoint doesn't also enforce it.
- DB constraints are stronger than application checks but may be bypassed by raw SQL or a different ORM context.
- Rate limiting at application level can be bypassed if multiple pods don't share state (no distributed rate limiter).

## Output schema
Standard FINDINGS_SCHEMA. Hypotheses for: UI-only invariant bypassable via API, uniqueness race (application check without DB constraint), rate limit bypass via multiple pods without shared state.
Set `cwe` on each hypothesis (e.g. CWE-602 client-side-only enforcement, CWE-362 uniqueness race, CWE-799 rate limit not enforced across instances).

Persist the invariant list (rule, enforcement layer, weakest layer) with `amend_threat_model` as a short `## Business Invariants` section (if no threat model exists yet,
call `save_threat_model` with `## Overview`, `## Trust Boundaries`, `## Attack Surface`, `## Severity Calibration`
and this section). Later skills read it from the Threat Model in Known Context.

## Stop condition
When every identified invariant has a documented enforcement layer and the weakest layer is assessed.

## Forbidden inferences
- Do not report a DB UNIQUE constraint as a race without confirming the application also checks for duplicates before insert in a non-atomic way.
- Do not assume a validation in a ViewModel applies to the API endpoint without checking the API layer.
