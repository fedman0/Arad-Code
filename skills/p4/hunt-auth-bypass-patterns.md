# SKILL: hunt-auth-bypass-patterns

## Goal

Understand how this application authenticates requests and enforces access control, then reason about whether those controls can be bypassed. Do not search for known names or patterns — explore the codebase to discover what actually exists.

---

## Step 1 — Orient: find the request entry point and middleware chain

Use `get_architecture` to see the project layout.
Find the main entry point for HTTP requests: the router, the server startup file, or the base application class.
Read it. Follow the chain: what runs for every request before it reaches a handler? Find the middleware or filter stack and read the relevant parts.

Your goal: understand what auth-related work happens before a handler runs, and how a handler signals what access it requires.

## Step 2 — Trace how identity is established

From Step 1, find the specific code that turns an incoming request into a known identity (user, service, etc.).
Read that code completely. Understand:
- What does it read from the request? (Which header, cookie, or field?)
- What does it verify? (Signature, expiry, revocation status?)
- What can go wrong? Is there any branch that produces a valid identity without full verification, or defaults to a privileged identity on error?

If the token is a JWT or structured credential: find where it is decoded and where each claim is validated. Are there claims the caller can influence that affect the identity or role?

## Step 3 — Trace how access decisions are made

Find the code that decides whether the established identity may perform the requested action.
Read it completely. Understand:
- Does the decision rely solely on the resolved identity from Step 2, or does it also read anything directly from the request?
- Is there any short-circuit path (fallback, exception handler, debug mode) that grants access without a complete check?
- If the system has privilege levels (admin, staff, operator, owner, etc.) — how are they represented, and is the representation stored in a tamper-proof place (signed token claim, DB column) or somewhere a caller can influence?

## Step 4 — Check credential security

Find where signing secrets, session keys, and API credentials used by the auth system are configured.
Read those values.
**Finding condition**: any secret has a hardcoded non-empty fallback value that activates when the environment variable is absent.
→ **submit hypothesis immediately**: violated_invariant="auth secret has hardcoded fallback; source code access lets an attacker forge tokens or sessions", severity=10, confidence=9.

## Step 5 — Reason about bypass paths

Based on what you read in Steps 2 and 3, answer: can an attacker reach a handler that requires elevated access without legitimately having that access? Consider:
- Controlling an input that is trusted in the identity or permission decision
- Triggering an exception or fallback that grants access
- Replaying a token from a different context (different service, different audience)
- Finding any code path that skips the standard auth chain

For each bypass path you find: submit a hypothesis.

## Finish

Call finish() with all hypotheses. Call it now even if the list is empty.
