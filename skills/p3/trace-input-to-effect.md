---
parallel: true
max_turns: 45
fanout: entry_points
batch: 6
---

# SKILL: trace-input-to-effect

## Contract

**Trigger:** For any hypothesis where the data flow from user input to a sensitive effect needs tracing.
**Phase:** 3 — Path Analysis
**Preconditions:** Entry point map (Known entry points), symbol graph indexed
**Escalates to:** hunt-injection-sqli-cmdi, hunt-path-traversal, understand-data-flows

## Inputs
- repo_path
- entry_point: qualified name or route
- field: the specific input field to trace
- target_effect: what kind of effect to find (DB write, shell exec, HTTP call, file write)

When the prompt lists Assigned entry points, trace each of them: every input it accepts, through every
function it calls, to every effect it reaches. Record one coverage decision per assigned entry point as
that list asks, and spread the turns across all of them.

If no entry_point was supplied, pick the highest-priority targets from Known Context (existing hypotheses via
`list_hypotheses` that still need a data-flow trace, then unauthenticated entry points that accept input) and process
up to 3 of them, deriving field and target_effect from each.

## Procedure
1. get_code_snippet(entry_point handler) — read the handler fully.
2. Identify the specific field: how is it deserialized? What type? Any binding restrictions?
3. trace_path(handler_qn, mode="data_flow", direction="outbound") to follow the field through the call chain.
4. For each function in the chain: does it transform, validate, or constrain the value?
5. Record all transformations: sanitization, encoding, parsing, type coercion.
6. Find the sink: the function that performs the effect (ExecuteRawSql, Process.Start, File.WriteAll, HttpClient.Send).
7. At the sink: is the field value still attacker-controlled after all transformations?
8. Check: is there a parameterized/safe API that should have been used instead of the raw sink?
9. Check: are there validations that run only AFTER the sink? They do not protect it — record them so they are not mistaken for guards.

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
Standard FINDINGS_SCHEMA. A hypothesis requires: full chain documented, sink confirmed raw (not parameterized).
Set `reachability: "proven"` only when you read every link of the chain. `probable` reachability (like
`input_control: "unknown"` or `guard_coverage` `some_paths`/`unknown`) adds an unresolved required obligation that
holds the finding back unless confidence >= 7 with structural/semantic evidence and >= 60% of required obligations
verified — report it anyway with that obligation honestly `unresolved` rather than upgrading to `proven` without
reading the missing link. Set `cwe` from the sink (e.g. CWE-89 SQL, CWE-78 OS command, CWE-22 file path, CWE-918 outbound HTTP).

## Stop condition
When the value at the sink is confirmed attacker-controlled and the sink is confirmed raw, or when a definitive sanitization/constraint is found that eliminates the path.

## Forbidden inferences
- Do not report a sink as vulnerable without confirming the field reaches it.
- Do not assume parameterized queries are absent because the code looks like string concatenation — check the API being called.
- Do not conclude a sanitization is present just because a sanitization function exists somewhere in the file.
