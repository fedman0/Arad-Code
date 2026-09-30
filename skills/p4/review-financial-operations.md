# SKILL: review-financial-operations

## Contract

**Trigger:** Phase 4. Run for any service handling money, credits, points, or subscriptions.
**Phase:** 4 — Security Analysis
**Preconditions:** Business invariant model, state machine map, entry point map
**Escalates to:** review-concurrency-and-retries, trace-state-transitions

## Inputs
- repo_path

## Procedure
1. Use `search_graph` to find all monetary operations: charge, refund, transfer, credit, debit, withdraw, deposit, payment, wallet. Then use `trace_path` from each to understand the full call chain — auth checks may be bypassed several hops deep.
2. For each payment endpoint: use `find_all_usages` on any permission/auth check it calls. Verify the check actually runs and cannot be bypassed by a request parameter or header.
2. For each operation: is the amount taken from user input? What type (decimal, float, integer cents)?
3. Check float arithmetic: is floating-point used for money calculations? (should be decimal or integer cents)
4. Check rounding: is rounding applied? In which direction? Can rounding errors accumulate?
5. Check sign: can a user submit a negative amount to reverse a charge direction (charge → credit)?
6. Check zero: is a zero-amount transaction allowed? What are its side effects?
7. Check refund amount: is the refund amount validated against the original charge? Can refund > charge?
8. Check transfer: is the balance sufficient check and the debit atomic?
9. Check quota/limit: can a user exceed their spending limit via concurrent requests?
10. Check idempotency: if a charge request is sent twice, does it charge twice?
11. Check webhook confirmation: is a payment confirmed before fulfillment, or does the server act on user claim?
12. Check currency: is currency code validated? Can a user submit a cheaper currency?

## Required evidence
- Amount type: float vs. decimal vs. cents integer
- Sign and zero validation: confirmed present or absent
- Refund cap against original: confirmed present or absent
- Atomic balance check + debit: confirmed present or absent
- Idempotency key: present and server-enforced or absent
- Payment webhook verification: server-verified or user-claimed

## Counterchecks
- Float money is a correctness issue that may or may not be exploitable depending on rounding direction.
- Atomic balance-sufficient + debit can be achieved via DB transaction with SELECT FOR UPDATE or optimistic locking.
- Idempotency keys are only effective if stored and checked before processing, not after.

## Output schema
Standard FINDINGS_SCHEMA. Hypotheses for: float money enabling rounding exploit, negative amount reversing direction, refund exceeding original, double-charge via no idempotency, payment fulfillment without webhook verification.

## Stop condition
When every monetary operation has a documented amount validation, atomicity mechanism, and idempotency approach.

## Forbidden inferences
- Do not report float arithmetic as exploitable without confirming a concrete rounding scenario with financial impact.
- Do not report missing idempotency without confirming the payment provider can actually send duplicate webhooks.
