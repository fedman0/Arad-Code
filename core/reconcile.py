from __future__ import annotations
from pathlib import Path
from typing import Optional
from .models import Evidence, ConflictRecord, NegativeEvidence
from .evidence_gate import (
    _gate_hypothesis_status, _MIN_ANCHOR_LEN, _apply_quality_caps, _inject_minimum_obligations,
    _apply_profile,
)


class EvidenceReconciler:
    def _verify_evidence_items(
        self, repo_path: str, items: list[Evidence]
    ) -> tuple[list[Evidence], list[ConflictRecord]]:
        """Verify evidence file paths, line ranges, and anchor text.

        Shared by run_skill and submit_workflow_finding so workflow findings
        get the same integrity checks as skill findings.
        Returns (verified_items, conflict_records).
        """
        def _norm(t: str) -> str:
            return " ".join(t.split())

        verified: list[Evidence] = []
        conflicts: list[ConflictRecord] = []
        for ev in items:
            target = self._resolve_path(repo_path, ev.file_path)
            if target is None or not target.is_file():
                conflicts.append(ConflictRecord(
                    kind="stale_reference",
                    description=f"Evidence file does not exist: {ev.file_path}",
                    left=f"evidence/{ev.id}",
                    right=ev.file_path,
                    severity="blocks_finding",
                ))
                ev.analysis_quality.limitations.append(f"file not found: {ev.file_path}")
                ev.stale = True
                verified.append(ev)
                continue
            ev.file_path = target.relative_to(Path(repo_path).resolve()).as_posix()
            try:
                lines = target.read_text(errors="replace").splitlines()
                total = len(lines)
                if (ev.line_start < 1 or ev.line_start > total
                        or ev.line_end < ev.line_start or ev.line_end > total):
                    conflicts.append(ConflictRecord(
                        kind="stale_reference",
                        description=(
                            f"Evidence line {ev.line_start} out of range "
                            f"(file has {total} lines): {ev.file_path}"
                        ),
                        left=f"evidence/{ev.id}",
                        right=f"{ev.file_path}:{ev.line_start}",
                        severity="blocks_finding",
                    ))
                    ev.analysis_quality.limitations.append(
                        f"line {ev.line_start} out of range (file has {total} lines)"
                    )
                    ev.stale = True
                else:
                    s = ev.line_start - 1
                    e = min(total, max(ev.line_end, ev.line_start))
                    ev.snippet = "\n".join(lines[s:e])
                    anchor_norm = _norm(ev.anchor_text or "")
                    if anchor_norm and len(anchor_norm) < _MIN_ANCHOR_LEN:
                        ev.analysis_quality.limitations.append(
                            f"anchor_text {ev.anchor_text!r:.30} too short to verify "
                            f"(<{_MIN_ANCHOR_LEN} chars); treated as absent"
                        )
                        anchor_norm = ""
                    if not anchor_norm:
                        ev.analysis_quality.limitations.append(
                            "no usable anchor_text; line range verified but content unverified"
                        )
                        if ev.analysis_quality.confidence == "high":
                            ev.analysis_quality.confidence = "medium"
                    elif anchor_norm in _norm(ev.snippet):
                        pass
                    else:
                        lo = max(0, s - 10)
                        hi = min(total, e + 10)
                        hits = []
                        for li in range(lo + 1, hi + 1):
                            for j in range(li, hi + 1):
                                if anchor_norm in _norm("\n".join(lines[li - 1:j])):
                                    if anchor_norm not in _norm("\n".join(lines[li:j])):
                                        hits.append(li)
                                    break
                        if len(hits) == 1:
                            li = hits[0]
                            span = max(1, ev.line_end - ev.line_start + 1)
                            ev.line_start = li
                            ev.line_end = min(total, li + span - 1)
                            ev.snippet = "\n".join(lines[li - 1:ev.line_end])
                            ev.analysis_quality.confidence = "medium"
                            ev.analysis_quality.limitations.append(
                                "anchor_text found outside claimed range; line numbers corrected"
                            )
                        elif hits:
                            conflicts.append(ConflictRecord(
                                kind="stale_reference",
                                description=(
                                    f"Evidence anchor_text is absent from the claimed range and "
                                    f"ambiguous nearby ({len(hits)} matches) in {ev.file_path}"
                                ),
                                left=f"evidence/{ev.id}",
                                right=f"{ev.file_path}:{ev.line_start}",
                                severity="blocks_finding",
                            ))
                            ev.analysis_quality.limitations.append(
                                f"anchor_text ambiguous ({len(hits)} matches within ±10 lines); "
                                "citation unverified"
                            )
                            ev.stale = True
                        else:
                            conflicts.append(ConflictRecord(
                                kind="stale_reference",
                                description=(
                                    f"Evidence anchor_text not found at or near claimed lines "
                                    f"in {ev.file_path}:{ev.line_start}"
                                ),
                                left=f"evidence/{ev.id}",
                                right=f"{ev.file_path}:{ev.line_start}",
                                severity="blocks_finding",
                            ))
                            ev.analysis_quality.limitations.append(
                                f"anchor_text {ev.anchor_text!r:.40} not found in ±10 lines"
                            )
                            ev.stale = True
            except Exception as ex:
                conflicts.append(ConflictRecord(
                    kind="stale_reference",
                    description=f"Evidence could not be read and stays unverified: {ev.file_path} ({ex})",
                    left=f"evidence/{ev.id}",
                    right=ev.file_path,
                    severity="blocks_finding",
                ))
                ev.analysis_quality.limitations.append(f"read error, content unverified: {ex}")
                ev.stale = True
            verified.append(ev)
        return verified, conflicts

    def _verify_negative_evidence(
        self, repo_path: str, items: list[NegativeEvidence]
    ) -> list[NegativeEvidence]:
        """Verify NE anchor_text exists at or near anchor_line. Bidirectional: sets stale=True/False."""
        def _norm(t: str) -> str:
            return " ".join(t.split())

        for ne in items:
            target = self._resolve_path(repo_path, ne.anchor_file)
            if target is None or not target.is_file():
                ne.anchor_stale = True
                continue
            ne.anchor_file = target.relative_to(Path(repo_path).resolve()).as_posix()
            try:
                lines = target.read_text(errors="replace").splitlines()
                total = len(lines)
                anchor_norm = _norm(ne.anchor_text)
                if len(anchor_norm) < _MIN_ANCHOR_LEN:
                    ne.anchor_stale = True
                    continue
                s = max(0, ne.anchor_line - 1)
                lo, hi = max(0, s - 10), min(total, s + 11)
                window = _norm("\n".join(lines[lo:hi]))
                ne.anchor_stale = anchor_norm not in window
            except Exception:
                ne.anchor_stale = True
        return items

    def check_negative_evidence_staleness(self, repo_path: str) -> list[NegativeEvidence]:
        """Re-verify all stored NE anchors without LLM. Bidirectional. Returns items that went stale."""
        existing = self._db.list_negative_evidence(repo_path)
        if not existing:
            return []
        was_stale = {ne.id: ne.anchor_stale for ne in existing}
        self._verify_negative_evidence(repo_path, existing)
        newly_stale: list[NegativeEvidence] = []
        for ne in existing:
            if ne.anchor_stale and not was_stale[ne.id]:
                self._db.mark_negative_evidence_stale(repo_path, ne.id)
                newly_stale.append(ne)
            elif not ne.anchor_stale and was_stale[ne.id]:
                self._db.mark_negative_evidence_fresh(repo_path, ne.id)
        return newly_stale

    def _check_anchor_present(self, repo_path: str, ev: "Evidence") -> Optional[bool]:
        """None = unverifiable (no usable anchor); True/False = anchor present/absent."""
        def _norm(t: str) -> str:
            return " ".join(t.split())
        target = self._resolve_path(repo_path, ev.file_path)
        if target is None or not target.is_file():
            return False
        try:
            anchor_norm = _norm(ev.anchor_text or "")
            anchor_usable = len(anchor_norm) >= _MIN_ANCHOR_LEN
            if not anchor_usable and ev.line_start < 1:
                return None
            lines = target.read_text(errors="replace").splitlines()
            total = len(lines)
            if ev.line_start < 1 or ev.line_start > total:
                return False
            if not anchor_usable:
                return None
            s = ev.line_start - 1
            e = min(total, max(ev.line_end, ev.line_start))
            lo, hi = max(0, s - 10), min(total, e + 10)
            window = _norm("\n".join(lines[lo:hi]))
            return anchor_norm in window
        except Exception:
            return False

    def reconcile(self, repo_path: str) -> dict:
        """Reconcile DB state without LLM.

        1. Re-verify all evidence bidirectionally (stale ↔ fresh)
        2. Re-verify all NE anchors bidirectionally
        3. Recompute hypothesis status from gate:
           - rejected_by=human → terminal
           - human_confirmed + all evidence stale → needs_recheck
        4. Detect NE/finding contradictions → ConflictRecord
        5. Rebuild coverage from facts
        6. Terminal status → priority 0
        """
        from .peer_analysis import _normalize_path as _norm_ep
        from .sarif import _normalise_cwe

        summary = {
            "evidence_refreshed": 0, "evidence_staled": 0,
            "ne_refreshed": 0, "ne_staled": 0,
            "hypotheses_updated": 0, "coverage_updated": 0,
            "contradictions_found": 0,
        }

        current_commit = self._get_commit(repo_path)

        # Fix 5: skip evidence without usable anchor (return None = unverifiable)
        all_ev = self._db.list_all_evidence_for_repo(repo_path)
        for ev in all_ev:
            was_stale = ev.stale
            now_present = self._check_anchor_present(repo_path, ev)
            if now_present is None:
                continue
            if was_stale and now_present:
                ev.stale = False
                self._db.save_evidence(repo_path, ev)
                summary["evidence_refreshed"] += 1
            elif not was_stale and not now_present:
                ev.stale = True
                self._db.save_evidence(repo_path, ev)
                summary["evidence_staled"] += 1

        ne_items = self._db.list_negative_evidence(repo_path)
        was_stale_map = {ne.id: ne.anchor_stale for ne in ne_items}
        self._verify_negative_evidence(repo_path, ne_items)
        for ne in ne_items:
            if ne.anchor_stale and not was_stale_map[ne.id]:
                self._db.mark_negative_evidence_stale(repo_path, ne.id)
                summary["ne_staled"] += 1
            elif not ne.anchor_stale and was_stale_map[ne.id]:
                self._db.mark_negative_evidence_fresh(repo_path, ne.id)
                summary["ne_refreshed"] += 1

        hypotheses = self._db.list_hypotheses(repo_path)
        all_open_questions = self._db.list_open_questions(repo_path, "open")
        profile = self._profile(repo_path)

        for h in hypotheses:
            if h.rejected_by == "human":
                old_p = h.priority
                h.priority = 0
                if h.priority != old_p:
                    self._db.save_hypothesis(repo_path, h)
                continue

            all_h_ev = self._db.get_all_evidence_for_hypothesis(h.id)
            valid_ev = [e for e in all_h_ev if not e.stale]

            # Fix 4: needs_recheck keeps the original priority (don't zero it)
            if h.status == "human_confirmed" and all_h_ev and all(e.stale for e in all_h_ev):
                h.status = "needs_recheck"
                summary["hypotheses_updated"] += 1
                self._db.save_hypothesis(repo_path, h)
                continue

            old_status = h.status

            # Fix 1: commit-gated re-open — only unlock model/profile rejections and
            # refuted verdicts when new evidence from a different commit is present.
            if h.status in ("rejected", "refuted") and h.rejected_by != "human":
                if current_commit and h.rejected_at_commit == current_commit:
                    # rejection is from this very commit — nothing new has arrived
                    pass
                else:
                    ev_from_current = [
                        e for e in all_h_ev
                        if e.commit == current_commit and not e.stale
                    ]
                    if ev_from_current:
                        h.status = "initial"

            conflicts = self._db.get_conflicts_for_hypothesis(h.id, repo_path)
            _apply_quality_caps(h, valid_ev)
            _inject_minimum_obligations(h)
            # Fix 7: profile suppression must not override a human confirmation
            if h.status != "human_confirmed":
                _apply_profile(h, valid_ev, profile, commit=current_commit)
            h.status = _gate_hypothesis_status(h, valid_ev, conflicts, all_open_questions)
            h.priority = h.compute_priority()
            if h.status in ("rejected", "refuted", "blocked"):
                h.priority = 0
            if h.status != old_status:
                summary["hypotheses_updated"] += 1
            self._db.save_hypothesis(repo_path, h)

        hypotheses = self._db.list_hypotheses(repo_path)
        ne_fresh = [ne for ne in self._db.list_negative_evidence(repo_path) if not ne.anchor_stale]

        # Fix 2d: dedupe on (ne.id, h.id) across ALL conflicts (including resolved)
        existing_contradiction_pairs: set[tuple[str, str]] = set()
        for c in self._db.list_all_conflicts(repo_path):
            if c.kind == "contradicting_claims" and c.left.startswith("ne/"):
                existing_contradiction_pairs.add((c.left, c.right))

        for ne in ne_fresh:
            ne_ep = _norm_ep(ne.entry_point)
            ne_cwe = _normalise_cwe(ne.safe_from)
            ne_left = f"ne/{ne.id}"
            for h in hypotheses:
                if h.status in ("rejected", "refuted", "blocked", "needs_recheck"):
                    continue
                if (ne_left, h.id) in existing_contradiction_pairs:
                    continue
                h_ep = _norm_ep(h.entry_point.split("->")[0].strip().split(" (")[0].strip())
                h_cwe = _normalise_cwe(h.cwe)
                if h_ep != ne_ep:
                    continue
                # Fix 2c: both CWEs must be non-null and equal; empty CWE = no match
                if not (ne_cwe and h_cwe and ne_cwe == h_cwe):
                    continue
                # Fix 2e: degrades_confidence, mark NE disputed
                cf = ConflictRecord(
                    kind="contradicting_claims",
                    description=(
                        f"NE says {ne.entry_point!r} is safe from {ne.safe_from}"
                        f" ({ne.because}) — contradicts finding {h.id}"
                    ),
                    left=ne_left,
                    right=h.id,
                    severity="degrades_confidence",
                )
                self._db.save_conflict(repo_path, cf)
                self._db.mark_negative_evidence_disputed(repo_path, ne.id)
                existing_contradiction_pairs.add((ne_left, h.id))
                summary["contradictions_found"] += 1

        coverage_items = self._db.coverage_detail(repo_path)
        hypotheses = self._db.list_hypotheses(repo_path)
        ne_fresh = [ne for ne in self._db.list_negative_evidence(repo_path) if not ne.anchor_stale]

        h_by_ep: dict[str, list] = {}
        for h in hypotheses:
            k = _norm_ep(h.entry_point.split("->")[0].strip().split(" (")[0].strip())
            h_by_ep.setdefault(k, []).append(h)

        ne_by_ep: dict[str, list] = {}
        for ne in ne_fresh:
            ne_by_ep.setdefault(_norm_ep(ne.entry_point), []).append(ne)

        for item in coverage_items:
            item_ep = _norm_ep(item["name"])
            # Fix 3: initial → needs_follow_up (not reported); only evidence-backed ≥ reported
            active_supported = [h for h in h_by_ep.get(item_ep, [])
                                 if h.status in ("evidence_supported", "reproduced", "human_confirmed")]
            active_initial = [h for h in h_by_ep.get(item_ep, []) if h.status == "initial"]
            fresh_ne = ne_by_ep.get(item_ep, [])
            new_status = item["status"]
            if active_supported:
                new_status = "reported"
            elif active_initial:
                new_status = "needs_follow_up"
            elif fresh_ne:
                new_status = "provably_safe"
            if new_status != item["status"]:
                from .models import CoverageItem as _CI
                cov = _CI(
                    kind=item["kind"], name=item["name"], status=new_status,
                    blocker=item["blocker"], exclusion_reason=item["exclusion_reason"],
                )
                self._db.upsert_coverage(repo_path, cov, force=True)
                summary["coverage_updated"] += 1

        return summary
