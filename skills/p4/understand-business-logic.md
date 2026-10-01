# SKILL: understand-business-logic

## Goal

Read and understand every operation with real-world financial, contractual, or
security-significant effect. Find where the intended security properties of those
operations are violated in the actual implementation — regardless of what
vulnerability class that violation belongs to.

---

## Phase 1 — Find all consequential operations

Use `get_architecture` to understand the business domain. Then:

1. Find every operation that has financial effect: payments, subscriptions, wallet debits,
   refunds, charges. Use `search_graph` on the service/use-case layer.
2. Find every operation that changes security-relevant state: account creation, password
   change, phone change, role change, account activation/deactivation.
3. Find every operation that produces effects beyond the requesting user's own data:
   notifications to other users, operations on behalf of another user, admin operations.

For each: read the complete implementation using `get_code_snippet` and `trace_path`.

---

## Phase 2 — Verify every precondition is enforced

For each consequential operation, answer from the actual code:

**Who is authorized to trigger this operation?**
- What does the code check to determine the actor is authorized?
- Is the actor's identity derived from the authenticated session, or accepted from request input?
- A `person_id` or `employee_id` taken from the request body instead of from the token
  means an attacker can act as any person.

**Are all preconditions verified before the operation executes?**
- Read every line before the state-changing call.
- Look for commented-out checks: lines beginning with `#` that appear to be conditions
  (`# if not 'role' in request.auth:`, `# raise UnauthorizedException`, `# employee_id = request.auth.get(...)`)
- A commented-out check is an absent check.

**Idempotency:**
- Can the operation be triggered multiple times with the same effect?
- For payments and state transitions: is there a guard against double-processing?
- Read the guard — is it atomic (database-level lock or unique constraint)?
  A check-then-act pattern without a lock can be bypassed by concurrent requests.

---

## Phase 3 — Verify state machine correctness

For entities with lifecycle states (subscription: pending → active → cancelled,
payment: pending → processing → success/failed):

1. Read the code that handles state transitions.
2. For each transition: is the current state verified before the transition is applied?
3. Can an external event (callback, message) trigger an invalid transition?
4. Can events arrive out of order and produce incorrect final state?

---

## Phase 4 — Examine async and background operations

For operations that execute in the background (task queues, message consumers, scheduled jobs):
- Do they re-verify authorization when they execute, or do they trust data from when the
  task was enqueued?
- Can an attacker enqueue a task with forged parameters?
- Is the task's effect correctly scoped to the user who originally authorized it?

---

## Phase 5 — Race conditions in consequential operations

The dangerous pattern: check a condition, then act based on the result, without an
atomic lock between the two steps (TOCTOU — Time Of Check Time Of Use).

This applies in every language and framework. The pattern is always:
1. Read a value from shared state (balance, count, status, flag, token)
2. Make a decision based on that value
3. Modify the shared state

If steps 1 and 3 are not atomic, two concurrent requests can both pass step 2 with the
same value and both execute step 3.

**For each consequential operation, ask:**
- Is there a database-level lock (SELECT FOR UPDATE, pessimistic lock) between read and write?
- Is the write operation atomic and conditional?
  (e.g. `UPDATE wallet SET balance = balance - :amount WHERE id = :id AND balance >= :amount`
  — this fails atomically if balance is insufficient; no race)
- Or is it a read-modify-write in application code?
  (read object → check → modify field → save/update — NOT atomic)

**Specific scenarios to check:**
- **Wallet / balance deduction**: two concurrent withdrawals both reading the same balance
  and both succeeding even if the combined amount exceeds the balance.
- **Coupon / voucher redemption**: two concurrent requests both seeing `used=false` and
  both applying the discount.
- **Subscription state transitions**: concurrent upgrades or activations producing duplicate
  charges or duplicate records.
- **Quantity-limited resources**: two concurrent reservations of the last available slot.
- **Single-use token redemption**: two concurrent requests both validating the same
  password-reset or confirmation token before either invalidates it.

Read the actual database operations, not just the application logic. An application-level
check is not protection against a race if the database write is not conditional.

**Numeric edge cases:**
- Are there arithmetic operations on financial values where integer overflow, underflow,
  or floating-point precision loss could produce incorrect results?
- What happens when a quantity is zero or negative? Is this checked?
- What happens when an amount exceeds the representable range of the stored type?

---

## What to produce

A hypothesis for each:
- Operation that accepts an actor identifier from request input instead of from the session
- Precondition that is commented out or missing
- State transition that can be triggered by an unauthorized caller or out of sequence
- Payment/subscription operation that can be replayed or double-triggered
- Background operation that re-trusts attacker-supplied data
- Check-then-act sequence without a database-level atomic guard (race condition)
- Numeric edge case: overflow, underflow, or precision loss in financial arithmetic

Include the exact file:line of the missing check and the call chain from HTTP request to
the consequential action.

## Forbidden

- Do not skip reading commented-out code — a commented-out security check IS a finding
- Do not assume idempotency is guaranteed without reading the actual guard mechanism
- Do not report a race condition without identifying the specific non-atomic sequence —
  read the database call and confirm there is no lock or conditional write
- Do not report a finding based on "this looks like it might accept user input" —
  read the actual code and confirm what happens to each field
