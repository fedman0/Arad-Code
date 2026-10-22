---
order: 50
max_turns: 40
---

# SKILL: extract-state-machines

## Contract

**Trigger:** Phase 2, after model-resource-ownership.
**Phase:** 2 — Identity & Ownership
**Preconditions:** Resource list (Resource Ownership section of the Threat Model in Known Context), entity schema
**Escalates to:** trace-state-transitions, understand-business-logic

## Inputs
- repo_path
- entity types with status/state fields

## Procedure
1. search_graph(name_pattern="Status|State|Phase|Stage") to find enum types representing states.
2. For each state-bearing entity: get its state enum values and find all transitions (where the state field is written).
3. Map transitions: from state → to state, triggered by which operation, authorized for which role.
4. Find transitions that skip states (e.g., Draft → Published, bypassing Review).
5. Find reverse transitions that should be prohibited (e.g., Completed → Draft for a financial transaction).
6. Find concurrent transition risk: is the transition atomic (DB update with WHERE status=expected)?
7. Find state-gated operations: operations that are valid only in specific states — does the code check the state before proceeding?
8. Find state changes in distributed transactions: is the state update and the message publication atomic?
9. Find state transitions triggered by consumer messages — can replaying the message transition the same entity twice?

## Required evidence
- State machine diagram per entity (states, transitions, guards, triggers)
- Transitions that bypass required intermediate states
- Prohibited reverse transitions and whether they are enforced
- Concurrent transition safety (atomic WHERE clause)
- State-gated operations with their state check location

## Counterchecks
- DB-level constraints may enforce state transitions even if application code doesn't check.
- Optimistic concurrency (RowVersion, ETag) prevents concurrent transitions even without explicit state check.
- An event log / audit trail doesn't prevent bad transitions — only a state guard does.

## Output schema
Standard FINDINGS_SCHEMA. Hypotheses for: state-bypassing transition, prohibited reverse transition reachable, concurrent transition race, message replay causing double transition.
Set `cwe` on each hypothesis (e.g. CWE-841 skipped or reversed workflow state, CWE-362 concurrent transition race, CWE-837 replayed message applying a single-use transition twice).

Persist the state-machine map (per entity: states, transitions with handler QN, guards, triggers, atomicity) with `amend_threat_model` as a short `## State Machines` section (if no threat model exists yet,
call `save_threat_model` with `## Overview`, `## Trust Boundaries`, `## Attack Surface`, `## Severity Calibration`
and this section). Later skills read it from the Threat Model in Known Context.

## Stop condition
When every state-bearing entity has a complete state graph with transition guards documented.

## Forbidden inferences
- Do not conclude a skipped state is a vulnerability without confirming it violates a business rule.
- Do not report concurrent transition as exploitable without confirming the atomicity check is absent.
