# SKILL: trace-state-transitions

## Contract

**Trigger:** When investigating state machine bypass or race condition hypotheses.
**Phase:** 3 — Path Analysis
**Preconditions:** State machine map from extract-state-machines
**Escalates to:** review-financial-operations, review-concurrency-and-retries

## Inputs
- repo_path
- entity: the state-bearing entity name
- target_transition: the transition under investigation (e.g., Pending → Completed)

## Procedure
1. get_code_snippet for the transition handler (the function that writes the new state value).
2. Check: is there a WHERE clause that asserts the current state before updating? (e.g., UPDATE ... WHERE status = 'Pending')
3. Check: does the code read current state, check it, then update? If so, is this atomic (inside a transaction with appropriate isolation)?
4. trace_path(transition_handler, mode="calls") to find all callers.
5. For each caller: what guards them? Is there an authorization check? Is the entry point authenticated?
6. Find concurrent call paths: can two concurrent requests both pass the state check and both execute the transition?
7. Find message-triggered transitions: can replaying the message trigger the transition twice?
8. Check idempotency: if the transition handler is called twice with the same input, what happens?
9. Find compensation logic for failed transitions: does partial success leave the entity in an inconsistent state?

## Required evidence
- Atomicity proof: WHERE-clause update vs. read-then-update
- Isolation level of the enclosing transaction
- Concurrent execution risk: evidence of missing atomic check
- Idempotency mechanism (or absence)
- Authorization chain for every path to the transition handler

## Counterchecks
- Optimistic concurrency (RowVersion) prevents duplicate state transitions even without WHERE clause.
- SERIALIZABLE isolation eliminates phantom reads that enable certain races.
- A DB UNIQUE constraint on (entityId, targetState) prevents duplicate transition records.
- Message deduplication at the broker level (exactly-once delivery) prevents replay.

## Output schema
Standard FINDINGS_SCHEMA. Hypotheses require: confirmed non-atomic read-modify-write pattern AND confirmed concurrent access path, OR confirmed message replay path without deduplication.

## Stop condition
When atomicity and idempotency are confirmed or denied with code evidence for each transition path.

## Forbidden inferences
- Do not report a race condition without confirming two concurrent requests can both pass the state check.
- Do not assume message replay is possible without checking broker delivery guarantees and consumer deduplication.
