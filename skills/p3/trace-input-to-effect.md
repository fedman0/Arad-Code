# SKILL: trace-input-to-effect

## Contract

**Trigger:** For any hypothesis where the data flow from user input to a sensitive effect needs tracing.
**Phase:** 3 — Path Analysis
**Preconditions:** Entry point map, symbol graph indexed
**Escalates to:** review-query-construction, review-code-execution, review-file-boundaries

## Inputs
- repo_path
- entry_point: qualified name or route
- field: the specific input field to trace
- target_effect: what kind of effect to find (DB write, shell exec, HTTP call, file write)

## Procedure
1. get_code_snippet(entry_point handler) — read the handler fully.
2. Identify the specific field: how is it deserialized? What type? Any binding restrictions?
3. trace_path(handler_qn, mode="data_flow") to follow the field through the call chain.
4. For each function in the chain: does it transform, validate, or constrain the value?
5. Record all transformations: sanitization, encoding, parsing, type coercion.
6. Find the sink: the function that performs the effect (ExecuteRawSql, Process.Start, File.WriteAll, HttpClient.Send).
7. At the sink: is the field value still attacker-controlled after all transformations?
8. Check: is there a parameterized/safe API that should have been used instead of the raw sink?
9. Check: are there validations that occur AFTER the sink that would have caught a malicious value?

## Required evidence
- Full call chain from entry point to sink with each function's QN and file:line
- Per-function transformation inventory
- Sink function signature and whether it's parameterized or raw
- Remaining control over field value at the sink
- Any validation between field and sink that could stop the attack

## Counterchecks
- Type binding may restrict the field to safe values (e.g., int cannot be SQL injection).
- Parameterized queries at the sink prevent SQL injection regardless of input content.
- HTML encoding at the rendering layer prevents XSS even if raw HTML is stored.
- An intermediate step that whitelists values eliminates the attack surface.

## Output schema
Standard FINDINGS_SCHEMA. A hypothesis requires: proven or probable reachability, full chain documented, sink confirmed raw (not parameterized).

## Stop condition
When the value at the sink is confirmed attacker-controlled and the sink is confirmed raw, or when a definitive sanitization/constraint is found that eliminates the path.

## Forbidden inferences
- Do not report a sink as vulnerable without confirming the field reaches it.
- Do not assume parameterized queries are absent because the code looks like string concatenation — check the API being called.
- Do not conclude a sanitization is present just because a sanitization function exists somewhere in the file.
