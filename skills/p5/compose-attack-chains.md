---
max_turns: 40
---

# compose-attack-chains

Phase 5 skill. Starts from hypotheses already in the evidence store and re-reads only the code at each link point
(where one step's effect reaches the next step's input) — not whole call chains.

Identifies multi-step attack chains where a sequence of individually low-severity findings combines into a high-severity exploit.

## When a chain exists

A chain is worth reporting when ALL of:
1. Step A enables step B: the output or effect of A is a required input or precondition for B.
2. Combined severity > max(individual severities): the chain achieves something neither step alone could.
3. Each step is independently reachable by the same actor, or by a feasible escalation from it.
4. At least one step is `evidence_supported` or `reproduced`.

## Procedure

1. `get_open_questions()` — note any unresolved question that would invalidate a chain.
2. `list_hypotheses(status="evidence_supported")`, `list_hypotheses(status="reproduced")` and `list_hypotheses(status="human_confirmed")`.
   Also `list_hypotheses(status="initial", min_priority=15)` for strong unconfirmed candidates.
   These calls are the ONLY source of hypothesis IDs. Never write an ID that did
   not come back from one of them.
3. For every candidate pair, call `get_hypothesis(id)` on both and compare the full
   detail: does A's `observable_impact` supply something B's `preconditions` or
   `entry_point` requires?
4. For each candidate link, read the code where A's effect reaches B's input:
   `get_code_snippet(qualified_name)` for the function, or `parse_file_structure(file_path)`
   followed by `read_file` for the exact lines. This read is the chain's evidence — the
   evidence already recorded on the steps does not establish the link.
5. For each chain you confirm, call `amend_hypothesis` on each contributing step with
   `enables=[<the other step ids>]` and a `reason` naming the chain. This is how the
   link is recorded — you cannot edit a prior hypothesis any other way.
6. Emit one new hypothesis per chain via `finish()`.

## Common chain patterns

- IDOR on upload + unrestricted file type + predictable serve path → RCE
- Weak token + account enumeration + no brute-force limit → account takeover
- SSRF to metadata + extracted IAM credentials + permissive IAM policy → cloud privilege escalation
- Read-only SQL injection + log injection + log parsing eval → RCE
- Reflected XSS + CSRF token readable in DOM + state-changing mutation → CSRF bypass

## Scoring the chain hypothesis

- `severity` = min(10, highest step severity + bonus); bonus is +2 when the chain reaches
  RCE or account takeover, +1 when it escalates privilege.
- `confidence` = the LOWEST confidence among the steps. A chain is never more certain
  than its weakest link.
- `reachability` / `input_control` / `guard_coverage` = the worst value among the steps (for
  `guard_coverage`, `unknown` is worse than `some_paths`, which is worse than `no_paths`).
- `exposure` = the exposure of the FIRST step, since that is where the attacker starts.
- `composed_of` = the step hypothesis IDs, in order.
- `cwe` = the CWE of the step that delivers the final impact.

## Output

The chain hypothesis follows the standard output contract. Specific to chains:

- `execution_path` — one entry per step, naming the step's ID and what it contributes.
- `evidence` — cite the code that establishes the LINK between steps (where A's output
  reaches B's input), not the evidence already recorded on the individual steps.
  Set `hypothesis_index` on each item and supply `anchor_text` (>= 12 characters copied
  verbatim from the cited lines). Set `analysis_quality.method` to `structural` only for a
  link you read with `get_code_snippet` or `parse_file_structure`; a link read only with
  `read_file` is `textual` (confidence cap 4). `list_hypotheses` / `get_hypothesis` output
  is not code evidence.
- `proof_obligations` — always include the linkage claim:
  `{"question": "Does step A's output reach step B's input unmodified?",
    "claim_type": "reachability", "required_for_finding": true}`
  Mark it `verified` only when your evidence shows that specific connection, and cite
  it in `evidence_ref`. If you cannot show it, leave it `unresolved` — the chain will
  be held back rather than reported, which is the correct outcome.

## Rejection criteria

Do not emit a chain when:
- The steps need actor capabilities that cannot realistically co-exist.
- Any step is `rejected` or `refuted`.
- The chain requires the attacker to already control the target system.
- The link between steps is assumed rather than shown in code.

If no valid chain exists, call `finish()` with an empty hypotheses list and a coverage
entry `{kind: "trust_boundary", name: "attack_chain_analysis", status: "no_issue_found"}`.
