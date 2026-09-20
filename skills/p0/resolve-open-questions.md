# SKILL: resolve-open-questions

## Contract

**Trigger:** Before every phase, and after any phase that raised blocking questions.
**Phase:** 0 — Maintenance
**Preconditions:** An evidence store with at least one prior skill run.
**Produces:** Resolved open questions. Findings are NOT the goal of this skill.

## Why this exists

An open question with `impact: blocks_finding` suppresses the hypotheses it names
until someone answers it. Nothing expires them. Without a pass that closes them,
they accumulate and quietly hold back real findings — a scan can end reporting
nothing while the answer sat one file read away.

Your job is to close questions, not to open new ones.

## Procedure

1. `get_open_questions()` to list everything still unresolved.
2. Work `blocks_finding` questions first, then `affects_confidence`, then
   `informational`. Within each group, start with questions naming the most
   hypotheses.
3. For each question:
   a. Read `resolution_hint` — the skill that raised it usually recorded where to look.
   b. If it names hypotheses, `get_hypothesis(id)` on each to see what the answer
      would change.
   c. Answer it from the code. Use `parse_file_structure`, `get_code_snippet` and
      `trace_path` rather than grep where you can — a question resolved from a parsed
      call graph is worth more than one resolved from a text match.
   d. `resolve_open_question(question_id, resolution)` with the answer and the
      `file:line` that establishes it.
4. When the answer changes what a hypothesis should claim, call `amend_hypothesis`
   with the corrected `confidence` or `exposure` and a `reason` citing the question.
5. When a question is genuinely unanswerable from the code — it needs deployment
   config, a human, or a running system — resolve it stating exactly that, and say
   what would be needed. An unanswerable question left open blocks findings forever;
   recording why it cannot be answered is the resolution.

## What counts as resolved

- **Answered:** you can point to the code that settles it.
- **Not applicable:** the assumption behind the question turned out to be wrong.
- **Needs external input:** cannot be settled from the repository; state what is missing.

Do NOT resolve a question by guessing. If you cannot establish the answer, say so in
the resolution rather than asserting one — a wrong resolution promotes a finding that
has not actually been proven.

## Counterchecks

- A question naming no hypotheses no longer blocks anything, but it is still a real
  gap. Resolve it, and if it should have been scoped, say which hypotheses it affects.
- Resolving a question does not by itself promote a finding — the hypothesis still has
  to satisfy its own proof obligations.

## Output schema

Standard FINDINGS_SCHEMA. Normally an empty `hypotheses` list.

Emit a hypothesis only if answering a question uncovers a genuine vulnerability that no
existing hypothesis covers; then follow the full output contract for it.

Record coverage as `{kind: "trust_boundary", name: "open_questions", status: ...}`:
`no_issue_found` when everything resolvable was resolved, `needs_follow_up` when
questions remain that need external input.

## Stop condition

When every open question has been resolved, or the remaining ones each have a recorded
reason why they cannot be answered from the repository.
