# SKILL: trace-effect-to-callers

## Contract

**Trigger:** When a sensitive function is found and we need to know who can reach it.
**Phase:** 3 — Path Analysis
**Preconditions:** Symbol graph indexed, entry point map
**Escalates to:** review-object-authorization, review-function-authorization

## Inputs
- repo_path
- sensitive_function: qualified name of the function performing a sensitive operation

## Procedure
1. trace_path(sensitive_function, mode="calls") to find all callers at every depth.
2. For each caller chain: which entry point does it originate from?
3. For each entry point → sensitive function path: what authorization checks exist along the chain?
4. Identify paths with no authorization check before the sensitive function.
5. For paths with authorization checks: are the checks enforced for ALL callers, or only some?
6. Find internal callers (same service) vs. external callers (different service via HTTP/RPC).
7. For internal callers: can a lower-privilege path call the same service that reaches the sensitive function?
8. Check if the sensitive function itself has an authorization assertion (defensive programming) or relies entirely on callers.

## Required evidence
- Complete caller tree with entry points for each chain
- Authorization check presence and location for each path
- Paths with no authorization check
- Internal vs. external caller classification
- Self-authorization in the sensitive function (if any)

## Counterchecks
- A seemingly unprotected internal path may only be reachable from other protected entry points.
- Authorization in the sensitive function itself (not just callers) provides defense-in-depth.
- An internal caller from a background job may run under a service account with the appropriate authority.

## Output schema
Standard FINDINGS_SCHEMA. Hypotheses for: entry point reaching sensitive function without auth check, lower-privilege path sharing a code path with higher-privilege operation.

## Stop condition
When all paths from all entry points to the sensitive function are documented with their auth status.

## Forbidden inferences
- Do not conclude a path is unprotected because the sensitive function has no auth check — callers may have it.
- Do not report an internal-only path as externally exploitable without confirming an external path to that internal caller.
