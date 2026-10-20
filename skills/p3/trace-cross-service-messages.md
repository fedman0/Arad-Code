---
parallel: true
requires: [messaging, multiservice]
---

# SKILL: trace-cross-service-messages

## Contract

**Trigger:** When investigating inter-service communication vulnerabilities or second-order effects.
**Phase:** 3 — Path Analysis
**Preconditions:** Service boundary map (Service Communication Graph section of the Threat Model in Known Context), message schema definitions
**Escalates to:** trace-identity-propagation, hunt-privilege-escalation-bola, understand-business-logic

## Inputs
- repo_path
- message_type: the message class/event being traced
- producer_service: which service publishes this message
- consumer_service: which service consumes it

If no message_type was supplied, pick the highest-priority message flows from Known Context (consumer entry points,
the Service Communication Graph in the Threat Model, existing hypotheses via `list_hypotheses`) and process up to 3 of them.

## Procedure
1. get_code_snippet for the message class/schema — what fields does it contain?
2. Find the producer: trace_path(producer_handler, mode="data_flow") to find what fields come from user input.
3. Find the consumer: get_code_snippet for the consumer handler.
4. Check: which fields does the consumer trust without re-validation? Does it re-fetch data from DB vs. trusting message fields?
5. Check: is there a schema/contract validation at the consumer boundary?
6. Find: does the consumer re-check authorization for the requested operation?
7. Check ordering: does the consumer assume messages arrive in a specific order? What happens with out-of-order delivery?
8. Check duplicate delivery: what happens if the message is delivered twice? Is the operation idempotent?
9. Find correlation: does the consumer correlate a message to a DB entity and then operate on that entity using the message's userId/tenantId or re-fetching from DB?
10. Find retry logic: after a partial success (e.g., DB written, downstream message not sent), what does the retry do?

## Required evidence
- Message field trust: which fields are re-validated vs. accepted as-is from the message
- Authorization re-check at consumer
- Idempotency mechanism for the consumer operation
- Ordering assumption (if any) and what breaks if violated
- Retry behavior after partial success

## Counterchecks
- A consumer that re-fetches all business data from DB (using only message ID as a key) is much harder to exploit via message manipulation.
- Schema validation at consumer prevents type-confusion attacks but not authorization attacks.
- Exactly-once delivery semantics at broker level reduce but do not eliminate duplicate processing risk.

## Output schema
Standard FINDINGS_SCHEMA. Hypotheses for: message field manipulation causing unauthorized operation, consumer skipping auth check, duplicate delivery with non-idempotent consumer, out-of-order messages causing inconsistent state.
Set `cwe` on each hypothesis (e.g. CWE-345 trusted message field, CWE-862 consumer skipping authorization, CWE-837 non-idempotent duplicate processing, CWE-362 out-of-order processing).

## Stop condition
When producer-to-consumer flow is fully documented including trust model, idempotency, and re-validation.

## Forbidden inferences
- Do not report message field manipulation without confirming the consumer actually trusts that field for a security decision.
- Do not report duplicate delivery risk without confirming the consumer operation is non-idempotent.
