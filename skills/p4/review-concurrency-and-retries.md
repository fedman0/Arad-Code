# SKILL: review-concurrency-and-retries

## Contract

**Trigger:** Phase 4. Run for state changes, quota checks, and financial operations.
**Phase:** 4 — Security Analysis
**Preconditions:** State machine map, business invariant model, DB transaction model
**Escalates to:** trace-state-transitions, review-financial-operations

## Inputs
- repo_path

## Procedure
1. Find check-then-act patterns: read a value, make a decision based on it, then write — are these atomic?
2. Check transaction isolation: is the read inside the same transaction as the write? What isolation level?
3. Find SELECT FOR UPDATE / UPDLOCK / advisory locks: are they used for critical sections?
4. Find optimistic concurrency: RowVersion, ETag, version column — is it checked on write?
5. Find counter operations: balance check + deduct, quota check + increment — done atomically or separately?
6. Find retry-on-failure patterns: does the retry re-read state or re-use cached state from first attempt?
7. Find message delivery guarantees: at-least-once delivery — is the consumer idempotent?
8. Find partial failure compensation: if step 2 of 3 fails, is step 1 rolled back or compensated?
9. Find TOCTOU patterns: validate, then use — with a gap that can be exploited (e.g., file check then file use).
10. Find distributed lock usage: what happens if the lock-holding process dies? Is there a timeout/TTL?

## Required evidence
- Check-then-act patterns: atomic or non-atomic, isolation level
- Optimistic locking: present and checked on write, or absent
- Idempotency mechanism for message consumers
- Retry state: re-read or stale, confirmed
- Distributed lock: TTL present or absent

## Counterchecks
- SERIALIZABLE isolation prevents phantom reads that enable certain races, but may cause performance issues.
- Atomic increments (INCR in Redis, atomic column update with WHERE) prevent most counter races.
- Saga pattern with compensation is correct as long as compensation is itself idempotent.

## Output schema
Standard FINDINGS_SCHEMA. Hypotheses require: confirmed non-atomic check-then-act with confirmed concurrent access path, OR confirmed non-idempotent consumer with at-least-once delivery.

## Stop condition
When all critical state mutations and quota operations have a documented atomicity and idempotency model.

## Forbidden inferences
- Do not report a race condition without confirming two concurrent requests can actually execute the race window simultaneously.
- Do not report non-idempotency as a finding if the message broker guarantees exactly-once delivery AND the consumer doesn't have side effects that bypass that guarantee.
