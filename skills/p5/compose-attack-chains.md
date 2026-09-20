# compose-attack-chains

Phase 5 skill. Operates on existing hypotheses in the evidence store — does NOT re-read application code.

Identifies multi-step attack chains where a sequence of individually low-severity findings combines into a high-severity exploit. Documents chain hypotheses with `composed_of` and `enables` links.

## When a chain exists

A chain H_chain is worth reporting when ALL of:
1. Step A enables step B: the output/effect of A is required input/precondition for B.
2. Combined severity > max(individual severities): the chain achieves something neither step alone could.
3. Each step is independently reachable by the same actor (or a feasible escalation).
4. At least one step is evidence_supported or reproduced.

## Methodology

1. Call `get_open_questions()` for unresolved questions that might block chain formation.
2. Call `finish()` with existing hypotheses data:
   - Read every hypothesis whose status is `evidence_supported`, `reproduced`, or `initial` (with high priority).
   - For each pair (A, B): does A produce output that B requires as input?
3. Common chain patterns:
   - IDOR on upload + unrestricted file type + predictable serve path → RCE
   - Weak token + account enumeration + no brute-force limit → account takeover
   - SSRF to metadata + extracted IAM credentials + permissive IAM policy → cloud privilege escalation
   - SQL injection read-only + log injection + log parsing eval → RCE
   - Reflected XSS + CSRF token in DOM + state-changing mutation → CSRF bypass
4. For each confirmed chain:
   - Compute `combined_severity` = min(10, max_step_severity + chain_bonus)
     - chain_bonus: +2 if chain enables RCE/account-takeover; +1 if it escalates privilege
   - Set `composed_of` = list of hypothesis IDs that form the chain steps
   - Set `enables` on each contributing hypothesis pointing to chain hypothesis ID

## Output format

In `finish()`, emit one hypothesis per chain:
```json
{
  "actor": "<same actor as step 1>",
  "capability": "<combined capability>",
  "entry_point": "<step 1 entry point>",
  "execution_path": ["Step 1: <H1 entry_point> → <H1 impact>", "Step 2: <H2 entry_point> → <H2 impact>"],
  "security_boundary": "<the ultimate boundary crossed>",
  "violated_invariant": "<the combined invariant violated>",
  "observable_impact": "<combined impact>",
  "severity": <combined_severity>,
  "confidence": <min confidence of component steps>,
  "reachability": "<worst reachability of steps>",
  "input_control": "<worst input_control of steps>",
  "composed_of": ["<H1_id>", "<H2_id>"],
  "exposure": "<exposure of step 1>",
  "proof_obligations": [
    {"question": "Does step A output feed directly into step B input?", "status": "unresolved", "claim_type": "reachability", "required_for_finding": true}
  ]
}
```

## Rejection criteria

Do not emit a chain if:
- The steps require different actor capabilities that can't realistically co-exist.
- A step is `rejected` or `refuted`.
- The chain requires the attacker to already control the target system.

Call `finish()` with the chain hypotheses. If no valid chains exist, emit an empty hypotheses list with a coverage entry `{kind: "trust_boundary", name: "attack_chain_analysis", status: "no_issue_found"}`.
