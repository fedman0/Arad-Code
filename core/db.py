from __future__ import annotations
import re
import sqlite3
import json
from pathlib import Path
from typing import Optional
from .models import (
    Hypothesis, Evidence, CoverageItem, ValidationRun,
    EntryPoint, Guard, SkillResult, ThreatModel,
    FunctionSummary, OpenQuestion, ConflictRecord, ReturnValueContract,
    NegativeEvidence,
)


class EvidenceStore:
    def __init__(self, db_path: Path):
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(db_path))
        self.conn.row_factory = sqlite3.Row
        # two concurrent pentest invocations on one store lost updates
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.execute("PRAGMA busy_timeout=5000")
        self._init_schema()

    def _init_schema(self):
        self.conn.executescript("""
        CREATE TABLE IF NOT EXISTS repositories (
            path TEXT PRIMARY KEY,
            commit_sha TEXT,
            indexed_at TEXT,
            languages TEXT,
            notes TEXT
        );

        CREATE TABLE IF NOT EXISTS hypotheses (
            id TEXT PRIMARY KEY,
            repo_path TEXT,
            data TEXT NOT NULL,
            created_at TEXT,
            status TEXT,
            severity INTEGER,
            confidence INTEGER,
            priority INTEGER,
            skill_source TEXT,
            commit_sha TEXT,
            FOREIGN KEY(repo_path) REFERENCES repositories(path)
        );

        CREATE TABLE IF NOT EXISTS evidence (
            id TEXT PRIMARY KEY,
            hypothesis_id TEXT,
            repo_path TEXT,
            data TEXT NOT NULL,
            stale INTEGER DEFAULT 0,
            commit_sha TEXT,
            FOREIGN KEY(hypothesis_id) REFERENCES hypotheses(id)
        );

        CREATE TABLE IF NOT EXISTS coverage (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            repo_path TEXT,
            kind TEXT,
            name TEXT,
            status TEXT,
            blocker TEXT,
            exclusion_reason TEXT,
            UNIQUE(repo_path, kind, name)
        );

        CREATE TABLE IF NOT EXISTS validation_runs (
            id TEXT PRIMARY KEY,
            hypothesis_id TEXT,
            data TEXT NOT NULL,
            ran_at TEXT,
            FOREIGN KEY(hypothesis_id) REFERENCES hypotheses(id)
        );

        CREATE TABLE IF NOT EXISTS entry_points (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            repo_path TEXT,
            data TEXT NOT NULL,
            commit_sha TEXT,
            handler_qn TEXT,
            path TEXT,
            UNIQUE(repo_path, handler_qn, path)
        );

        CREATE TABLE IF NOT EXISTS guards (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            repo_path TEXT,
            data TEXT NOT NULL,
            commit_sha TEXT,
            location_qn TEXT,
            line INTEGER,
            UNIQUE(repo_path, location_qn, line)
        );

        CREATE TABLE IF NOT EXISTS threat_models (
            target TEXT PRIMARY KEY,
            content TEXT NOT NULL,
            amendments TEXT NOT NULL DEFAULT '[]',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            created_by_skill TEXT NOT NULL DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS function_summaries (
            id TEXT PRIMARY KEY,
            repo_path TEXT,
            qualified_name TEXT,
            data TEXT NOT NULL,
            created_at TEXT,
            commit_sha TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_fnsummary_repo_qn ON function_summaries(repo_path, qualified_name);

        CREATE TABLE IF NOT EXISTS open_questions (
            id TEXT PRIMARY KEY,
            repo_path TEXT,
            data TEXT NOT NULL,
            raised_at TEXT,
            status TEXT,
            impact TEXT,
            raised_by_skill TEXT
        );

        CREATE TABLE IF NOT EXISTS conflicts (
            id TEXT PRIMARY KEY,
            repo_path TEXT,
            data TEXT NOT NULL,
            created_at TEXT,
            kind TEXT,
            severity TEXT,
            status TEXT
        );

        CREATE TABLE IF NOT EXISTS return_value_contracts (
            id TEXT PRIMARY KEY,
            repo_path TEXT,
            function_qualified_name TEXT,
            data TEXT NOT NULL,
            created_at TEXT,
            security_relevance TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_rvc_repo_fn ON return_value_contracts(repo_path, function_qualified_name);

        CREATE TABLE IF NOT EXISTS triage_decisions (
            hypothesis_id TEXT PRIMARY KEY,
            repo_path TEXT,
            decision TEXT NOT NULL,
            reason TEXT NOT NULL DEFAULT '',
            confidence_at_decision INTEGER,
            severity_at_decision INTEGER,
            skill_source TEXT,
            decided_at TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_triage_repo ON triage_decisions(repo_path);

        CREATE TABLE IF NOT EXISTS negative_evidence (
            id TEXT PRIMARY KEY,
            repo_path TEXT NOT NULL,
            entry_point TEXT NOT NULL,
            safe_from TEXT NOT NULL,
            because TEXT NOT NULL,
            anchor_file TEXT NOT NULL,
            anchor_line INTEGER NOT NULL,
            anchor_text TEXT NOT NULL,
            anchor_stale INTEGER DEFAULT 0,
            commit_sha TEXT DEFAULT '',
            created_at REAL
        );
        CREATE INDEX IF NOT EXISTS idx_ne_repo ON negative_evidence(repo_path);
        CREATE UNIQUE INDEX IF NOT EXISTS idx_ne_ep_safe
            ON negative_evidence(repo_path, entry_point, safe_from);
        """)
        cols = {r["name"] for r in self.conn.execute("PRAGMA table_info(triage_decisions)")}
        if "fingerprint" not in cols:
            self.conn.execute("ALTER TABLE triage_decisions ADD COLUMN fingerprint TEXT")
            self.conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_triage_fp ON triage_decisions(fingerprint)")
        hyp_cols = {r["name"] for r in self.conn.execute("PRAGMA table_info(hypotheses)")}
        if "fingerprint" not in hyp_cols:
            self.conn.execute("ALTER TABLE hypotheses ADD COLUMN fingerprint TEXT")
            self.conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_hyp_fp ON hypotheses(repo_path, fingerprint)")
        if "rejected_at_commit" not in hyp_cols:
            self.conn.execute("ALTER TABLE hypotheses ADD COLUMN rejected_at_commit TEXT DEFAULT ''")

        ep_cols = {r["name"] for r in self.conn.execute("PRAGMA table_info(entry_points)")}
        if "handler_qn" not in ep_cols:
            self.conn.execute("DROP TABLE entry_points")
            self.conn.execute("""
                CREATE TABLE entry_points (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    repo_path TEXT,
                    data TEXT NOT NULL,
                    commit_sha TEXT,
                    handler_qn TEXT,
                    path TEXT,
                    UNIQUE(repo_path, handler_qn, path)
                )""")

        g_cols = {r["name"] for r in self.conn.execute("PRAGMA table_info(guards)")}
        if "location_qn" not in g_cols:
            self.conn.execute("DROP TABLE guards")
            self.conn.execute("""
                CREATE TABLE guards (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    repo_path TEXT,
                    data TEXT NOT NULL,
                    commit_sha TEXT,
                    location_qn TEXT,
                    line INTEGER,
                    UNIQUE(repo_path, location_qn, line)
                )""")

        ne_cols = {r["name"] for r in self.conn.execute("PRAGMA table_info(negative_evidence)")}
        if "disputed" not in ne_cols:
            self.conn.execute("ALTER TABLE negative_evidence ADD COLUMN disputed INTEGER DEFAULT 0")

        self.conn.commit()

    def upsert_repo(self, path: str, commit: str, languages: list[str], notes: str = ""):
        from datetime import datetime
        self.conn.execute(
            "INSERT OR REPLACE INTO repositories (path, commit_sha, indexed_at, languages, notes) VALUES (?,?,?,?,?)",
            (path, commit, datetime.utcnow().isoformat(), json.dumps(languages), notes)
        )
        self.conn.commit()

    def get_commit(self, repo_path: str) -> Optional[str]:
        row = self.conn.execute("SELECT commit_sha FROM repositories WHERE path=?", (repo_path,)).fetchone()
        return row["commit_sha"] if row else None

    def save_hypothesis(self, repo_path: str, h: Hypothesis):
        fp = h.fingerprint()
        existing = self.conn.execute(
            "SELECT id FROM hypotheses WHERE repo_path=? AND fingerprint=?",
            (repo_path, fp),
        ).fetchone()
        if existing and existing["id"] != h.id:
            old_id = h.id
            h.id = existing["id"]
            self.conn.execute(
                "UPDATE evidence SET hypothesis_id=? WHERE hypothesis_id=?",
                (h.id, old_id),
            )
            prior = self.get_hypothesis(repo_path, h.id)
            if prior:
                if prior.status == "human_confirmed":
                    h.status = prior.status
                elif prior.status == "rejected" and prior.rejected_by == "human":
                    h.status = prior.status
                    h.rejection_reason = prior.rejection_reason
                    h.rejected_by = "human"
                elif prior.status == "refuted":
                    h.status = prior.status
                    h.rejected_at_commit = prior.rejected_at_commit
                h.uncertainty = prior.uncertainty + [u for u in h.uncertainty
                                                     if u not in prior.uncertainty]
        h.priority = h.compute_priority()
        self.conn.execute(
            """INSERT OR REPLACE INTO hypotheses
               (id, repo_path, data, created_at, status, severity, confidence, priority, skill_source, commit_sha, fingerprint)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (h.id, repo_path, h.model_dump_json(), h.created_at,
             h.status, h.severity, h.confidence, h.priority, h.skill_source, h.commit, fp)
        )
        self.conn.commit()

    def save_evidence(self, repo_path: str, e: Evidence):
        self.conn.execute(
            "INSERT OR REPLACE INTO evidence (id, hypothesis_id, repo_path, data, stale, commit_sha) VALUES (?,?,?,?,?,?)",
            (e.id, e.hypothesis_id, repo_path, e.model_dump_json(), int(e.stale), e.commit)
        )
        self.conn.commit()

    def save_validation_run(self, repo_path: str, run: ValidationRun):
        self.conn.execute(
            "INSERT OR REPLACE INTO validation_runs (id, hypothesis_id, data, ran_at) VALUES (?,?,?,?)",
            (run.id, run.hypothesis_id, run.model_dump_json(), run.ran_at)
        )
        self.conn.commit()

    _COV_RANK: dict = {
        "reported": 7, "provably_safe": 6, "needs_follow_up": 5,
        "blocked": 4, "no_issue_found": 3, "ruled_out": 2,
        "not_applicable": 1, "unseen": 0, "excluded": 0,
    }

    def upsert_coverage(self, repo_path: str, item: CoverageItem, force: bool = False):
        if not force:
            row = self.conn.execute(
                "SELECT status FROM coverage WHERE repo_path=? AND kind=? AND name=?",
                (repo_path, item.kind, item.name),
            ).fetchone()
            if row:
                old_rank = self._COV_RANK.get(row["status"], 0)
                new_rank = self._COV_RANK.get(item.status, 0)
                if new_rank <= old_rank:
                    return
        self.conn.execute(
            """INSERT INTO coverage (repo_path, kind, name, status, blocker, exclusion_reason)
               VALUES (?,?,?,?,?,?)
               ON CONFLICT(repo_path, kind, name) DO UPDATE SET
                 status=excluded.status, blocker=excluded.blocker,
                 exclusion_reason=excluded.exclusion_reason""",
            (repo_path, item.kind, item.name, item.status, item.blocker, item.exclusion_reason)
        )
        self.conn.commit()

    def save_entry_point(self, repo_path: str, ep: EntryPoint, commit: str):
        # without the conflict clause a second p1 run duplicated every row, which
        # inflated peer cluster sizes and dragged conformity toward the cutoff
        self.conn.execute(
            """INSERT INTO entry_points (repo_path, data, commit_sha, handler_qn, path)
               VALUES (?,?,?,?,?)
               ON CONFLICT(repo_path, handler_qn, path) DO UPDATE SET
                 data=excluded.data, commit_sha=excluded.commit_sha""",
            (repo_path, ep.model_dump_json(), commit, ep.handler_qn, ep.path)
        )
        self.conn.commit()

    def save_guard(self, repo_path: str, g: Guard, commit: str):
        self.conn.execute(
            """INSERT INTO guards (repo_path, data, commit_sha, location_qn, line)
               VALUES (?,?,?,?,?)
               ON CONFLICT(repo_path, location_qn, line) DO UPDATE SET
                 data=excluded.data, commit_sha=excluded.commit_sha""",
            (repo_path, g.model_dump_json(), commit, g.location_qn, g.line)
        )
        self.conn.commit()

    def list_hypotheses(self, repo_path: str) -> list[Hypothesis]:
        rows = self.conn.execute(
            "SELECT data FROM hypotheses WHERE repo_path=? ORDER BY priority DESC", (repo_path,)
        ).fetchall()
        return [Hypothesis.model_validate_json(r["data"]) for r in rows]

    def list_entry_points(self, repo_path: str) -> list[EntryPoint]:
        rows = self.conn.execute(
            "SELECT data FROM entry_points WHERE repo_path=?", (repo_path,)
        ).fetchall()
        return [EntryPoint.model_validate_json(r["data"]) for r in rows]

    def list_guards(self, repo_path: str) -> list[Guard]:
        rows = self.conn.execute(
            "SELECT data FROM guards WHERE repo_path=?", (repo_path,)
        ).fetchall()
        return [Guard.model_validate_json(r["data"]) for r in rows]

    def coverage_summary(self, repo_path: str) -> dict:
        rows = self.conn.execute(
            "SELECT status, COUNT(*) as cnt FROM coverage WHERE repo_path=? GROUP BY status", (repo_path,)
        ).fetchall()
        return {r["status"]: r["cnt"] for r in rows}

    def save_threat_model(self, repo_path: str, content: str, skill: str = "") -> None:
        from datetime import datetime
        now = datetime.utcnow().isoformat()
        self.conn.execute(
            """INSERT INTO threat_models (target, content, amendments, created_at, updated_at, created_by_skill)
               VALUES (?,?,'[]',?,?,?)
               ON CONFLICT(target) DO UPDATE SET
                 content=excluded.content,
                 amendments='[]',
                 updated_at=excluded.updated_at,
                 created_by_skill=excluded.created_by_skill""",
            (repo_path, content, now, now, skill)
        )
        self.conn.commit()

    def get_threat_model(self, repo_path: str) -> Optional[str]:
        row = self.conn.execute(
            "SELECT content, amendments FROM threat_models WHERE target=?", (repo_path,)
        ).fetchone()
        if row is None:
            return None
        content = row["content"]
        amendments = json.loads(row["amendments"] or "[]")
        if amendments:
            addenda = "\n\n".join(
                f"### Amendment {i+1} (by {a.get('added_by_skill', '?')})\n{a['content']}"
                for i, a in enumerate(amendments)
            )
            return content + "\n\n---\n\n" + addenda
        return content

    def amend_threat_model(self, repo_path: str, addendum: str, skill: str = "") -> bool:
        from datetime import datetime
        row = self.conn.execute(
            "SELECT amendments FROM threat_models WHERE target=?", (repo_path,)
        ).fetchone()
        if row is None:
            return False
        amendments = json.loads(row["amendments"] or "[]")
        amendments.append({
            "content": addendum,
            "added_at": datetime.utcnow().isoformat(),
            "added_by_skill": skill,
        })
        self.conn.execute(
            "UPDATE threat_models SET amendments=?, updated_at=? WHERE target=?",
            (json.dumps(amendments), datetime.utcnow().isoformat(), repo_path)
        )
        self.conn.commit()
        return True

    def save_function_summary(self, repo_path: str, summary: FunctionSummary, commit: str = "") -> None:
        self.conn.execute(
            """INSERT OR REPLACE INTO function_summaries
               (id, repo_path, qualified_name, data, created_at, commit_sha)
               VALUES (?,?,?,?,?,?)""",
            (summary.id, repo_path, summary.qualified_name,
             summary.model_dump_json(), summary.created_at, commit or summary.commit)
        )
        self.conn.commit()

    def get_function_summary(self, repo_path: str, qualified_name: str, current_commit: str = "") -> Optional[FunctionSummary]:
        row = self.conn.execute(
            "SELECT data FROM function_summaries WHERE repo_path=? AND qualified_name=? ORDER BY created_at DESC LIMIT 1",
            (repo_path, qualified_name)
        ).fetchone()
        if row is None:
            return None
        fs = FunctionSummary.model_validate_json(row["data"])
        if current_commit and fs.commit and fs.commit != current_commit:
            fs.quality.limitations.append(
                f"summary from commit {fs.commit!r}; current is {current_commit!r} — re-analyze if guards changed"
            )
            fs.quality.confidence = "low"
        return fs

    def list_function_summaries(self, repo_path: str, limit: int = 50) -> list[FunctionSummary]:
        rows = self.conn.execute(
            "SELECT data FROM function_summaries WHERE repo_path=? ORDER BY created_at DESC LIMIT ?",
            (repo_path, limit)
        ).fetchall()
        return [FunctionSummary.model_validate_json(r["data"]) for r in rows]

    def save_open_question(self, repo_path: str, q: OpenQuestion) -> None:
        self.conn.execute(
            """INSERT OR REPLACE INTO open_questions
               (id, repo_path, data, raised_at, status, impact, raised_by_skill)
               VALUES (?,?,?,?,?,?,?)""",
            (q.id, repo_path, q.model_dump_json(), q.raised_at, q.status, q.impact, q.raised_by_skill)
        )
        self.conn.commit()

    def list_open_questions(self, repo_path: str, status: str = "open") -> list[OpenQuestion]:
        rows = self.conn.execute(
            "SELECT data FROM open_questions WHERE repo_path=? AND status=? ORDER BY raised_at DESC",
            (repo_path, status)
        ).fetchall()
        return [OpenQuestion.model_validate_json(r["data"]) for r in rows]

    def resolve_open_question(self, repo_path: str, question_id: str,
                              resolution: str, resolved_by: str = "") -> bool:
        row = self.conn.execute(
            "SELECT data FROM open_questions WHERE id=? AND repo_path=?",
            (question_id, repo_path)
        ).fetchone()
        if row is None:
            return False
        q = OpenQuestion.model_validate_json(row["data"])
        q.status = "resolved"
        q.resolved_by = resolved_by
        q.resolution_hint = resolution
        self.conn.execute(
            "UPDATE open_questions SET data=?, status=? WHERE id=? AND repo_path=?",
            (q.model_dump_json(), q.status, question_id, repo_path)
        )
        self.conn.commit()
        return True

    def get_hypothesis(self, repo_path: str, hypothesis_id: str) -> Optional[Hypothesis]:
        row = self.conn.execute(
            "SELECT data FROM hypotheses WHERE id=? AND repo_path=?",
            (hypothesis_id, repo_path)
        ).fetchone()
        return Hypothesis.model_validate_json(row["data"]) if row else None

    def save_conflict(self, repo_path: str, c: ConflictRecord) -> None:
        self.conn.execute(
            """INSERT OR REPLACE INTO conflicts
               (id, repo_path, data, created_at, kind, severity, status)
               VALUES (?,?,?,?,?,?,?)""",
            (c.id, repo_path, c.model_dump_json(), c.created_at, c.kind, c.severity, c.status)
        )
        self.conn.commit()

    def list_all_conflicts(self, repo_path: str) -> list[ConflictRecord]:
        rows = self.conn.execute(
            "SELECT data FROM conflicts WHERE repo_path=? ORDER BY created_at DESC",
            (repo_path,),
        ).fetchall()
        return [ConflictRecord.model_validate_json(r["data"]) for r in rows]

    def mark_negative_evidence_disputed(self, repo_path: str, ne_id: str) -> None:
        self.conn.execute(
            "UPDATE negative_evidence SET disputed=1 WHERE id=? AND repo_path=?",
            (ne_id, repo_path),
        )
        self.conn.commit()

    def list_conflicts(self, repo_path: str, status: str = "open") -> list[ConflictRecord]:
        rows = self.conn.execute(
            "SELECT data FROM conflicts WHERE repo_path=? AND status=? ORDER BY created_at DESC",
            (repo_path, status)
        ).fetchall()
        return [ConflictRecord.model_validate_json(r["data"]) for r in rows]

    def save_return_contract(self, repo_path: str, c: ReturnValueContract) -> None:
        self.conn.execute(
            """INSERT OR REPLACE INTO return_value_contracts
               (id, repo_path, function_qualified_name, data, created_at, security_relevance)
               VALUES (?,?,?,?,?,?)""",
            (c.id, repo_path, c.function_qualified_name, c.model_dump_json(), c.created_at, c.security_relevance)
        )
        self.conn.commit()

    def get_return_contract(self, repo_path: str, function_qualified_name: str) -> Optional[ReturnValueContract]:
        row = self.conn.execute(
            "SELECT data FROM return_value_contracts WHERE repo_path=? AND function_qualified_name=? ORDER BY created_at DESC LIMIT 1",
            (repo_path, function_qualified_name)
        ).fetchone()
        if row is None:
            return None
        return ReturnValueContract.model_validate_json(row["data"])

    def list_return_contracts(self, repo_path: str) -> list[ReturnValueContract]:
        rows = self.conn.execute(
            "SELECT data FROM return_value_contracts WHERE repo_path=? ORDER BY security_relevance, created_at DESC",
            (repo_path,)
        ).fetchall()
        return [ReturnValueContract.model_validate_json(r["data"]) for r in rows]

    def list_all_evidence_for_repo(self, repo_path: str) -> list[Evidence]:
        rows = self.conn.execute(
            "SELECT data FROM evidence WHERE repo_path=?", (repo_path,)
        ).fetchall()
        return [Evidence.model_validate_json(r["data"]) for r in rows]

    def get_all_evidence_for_hypothesis(self, hypothesis_id: str) -> list[Evidence]:
        rows = self.conn.execute(
            "SELECT data FROM evidence WHERE hypothesis_id=?", (hypothesis_id,)
        ).fetchall()
        return [Evidence.model_validate_json(r["data"]) for r in rows]

    def list_evidence_for_repo(self, repo_path: str) -> list[Evidence]:
        rows = self.conn.execute(
            "SELECT data FROM evidence WHERE repo_path=? AND stale=0",
            (repo_path,)
        ).fetchall()
        return [Evidence.model_validate_json(r["data"]) for r in rows]

    def get_evidence_for_hypothesis(self, hypothesis_id: str) -> list[Evidence]:
        rows = self.conn.execute(
            "SELECT data FROM evidence WHERE hypothesis_id=? AND stale=0",
            (hypothesis_id,)
        ).fetchall()
        return [Evidence.model_validate_json(r["data"]) for r in rows]

    def get_conflicts_for_hypothesis(self, hypothesis_id: str,
                                     repo_path: Optional[str] = None) -> list[ConflictRecord]:
        # the old LIKE over the whole blob had no repo filter and matched an
        # 8-hex id inside longer hex tokens, letting one repo's conflict block
        # an unrelated finding in another
        if repo_path:
            rows = self.conn.execute(
                "SELECT data FROM conflicts WHERE repo_path=? AND status='open'",
                (repo_path,)
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT data FROM conflicts WHERE status='open'"
            ).fetchall()
        pattern = re.compile(rf"\b{re.escape(hypothesis_id)}\b")
        out = []
        for r in rows:
            c = ConflictRecord.model_validate_json(r["data"])
            if (hypothesis_id in (c.left, c.right)) or pattern.search(c.description):
                out.append(c)
        return out

    def mark_stale_by_commit(self, repo_path: str, old_commit: str):
        self.conn.execute(
            "UPDATE evidence SET stale=1 WHERE repo_path=? AND commit_sha=? AND commit_sha != ''",
            (repo_path, old_commit)
        )
        rows = self.conn.execute(
            "SELECT id, data FROM evidence WHERE repo_path=? AND commit_sha=? AND commit_sha != '' AND stale=1",
            (repo_path, old_commit)
        ).fetchall()
        for row in rows:
            d = json.loads(row["data"])
            d["stale"] = True
            self.conn.execute("UPDATE evidence SET data=? WHERE id=?", (json.dumps(d), row["id"]))
        self.conn.commit()

    def save_triage_decision(self, repo_path: str, h: Hypothesis,
                             decision: str, reason: str = "") -> None:
        from datetime import datetime
        self.conn.execute(
            """INSERT OR REPLACE INTO triage_decisions
               (hypothesis_id, repo_path, decision, reason, confidence_at_decision,
                severity_at_decision, skill_source, decided_at, fingerprint)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (h.id, repo_path, decision, reason, h.confidence, h.severity,
             h.skill_source, datetime.utcnow().isoformat(), h.fingerprint())
        )
        self.conn.commit()

    def get_triage_decision(self, hypothesis: "Hypothesis | str",
                            repo_path: Optional[str] = None) -> Optional[dict]:
        """Look up by fingerprint so a decision survives the next scan's new uuid."""
        repo_clause = " AND repo_path=?" if repo_path else ""
        repo_args: tuple = (repo_path,) if repo_path else ()
        if isinstance(hypothesis, str):
            row = self.conn.execute(
                "SELECT * FROM triage_decisions WHERE hypothesis_id=?" + repo_clause,
                (hypothesis, *repo_args)
            ).fetchone()
            return dict(row) if row else None
        row = self.conn.execute(
            "SELECT * FROM triage_decisions WHERE fingerprint=?" + repo_clause
            + " ORDER BY decided_at DESC LIMIT 1",
            (hypothesis.fingerprint(), *repo_args)
        ).fetchone()
        return dict(row) if row else None

    def list_triage_decisions(self, repo_path: Optional[str] = None) -> list[dict]:
        if repo_path:
            rows = self.conn.execute(
                "SELECT * FROM triage_decisions WHERE repo_path=? ORDER BY decided_at DESC",
                (repo_path,)
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM triage_decisions ORDER BY decided_at DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    def calibration_buckets(self, repo_path: Optional[str] = None) -> dict[int, dict]:
        """Empirical accuracy per raw confidence score, from triage decisions.

        A confidence number means nothing until it is measured against outcomes;
        this is the table that makes "anything above 7" a claim rather than a guess.
        """
        decisions = [d for d in self.list_triage_decisions(repo_path)
                     if d["decision"] in ("accept", "reject")]
        buckets: dict[int, dict] = {}
        for d in decisions:
            conf = d["confidence_at_decision"]
            if conf is None:
                continue
            b = buckets.setdefault(conf, {"accepted": 0, "rejected": 0})
            b["accepted" if d["decision"] == "accept" else "rejected"] += 1
        for conf, b in buckets.items():
            total = b["accepted"] + b["rejected"]
            b["total"] = total
            b["empirical"] = b["accepted"] / total if total else 0.0
        return dict(sorted(buckets.items()))

    def coverage_detail(self, repo_path: str) -> list[dict]:
        rows = self.conn.execute(
            """SELECT kind, name, status, blocker, exclusion_reason FROM coverage
               WHERE repo_path=? ORDER BY kind, status, name""",
            (repo_path,)
        ).fetchall()
        return [dict(r) for r in rows]

    def save_skill_result(self, repo_path: str, result: SkillResult):
        id_map: dict[str, str] = {}
        for h in result.hypotheses:
            original_id = h.id
            self.save_hypothesis(repo_path, h)
            if h.id != original_id:
                id_map[original_id] = h.id
        for e in result.evidence:
            if e.hypothesis_id in id_map:
                e.hypothesis_id = id_map[e.hypothesis_id]
            self.save_evidence(repo_path, e)
        if id_map:
            for cf in result.conflicts:
                for old_id, new_id in id_map.items():
                    pattern = rf"\b{re.escape(old_id)}\b"
                    cf.left = re.sub(pattern, new_id, cf.left)
                    cf.right = re.sub(pattern, new_id, cf.right)
                    cf.description = re.sub(pattern, new_id, cf.description)
        for c in result.coverage:
            self.upsert_coverage(repo_path, c)
        for ep in result.entry_points_found:
            self.save_entry_point(repo_path, ep, result.commit)
        for g in result.guards_found:
            self.save_guard(repo_path, g, result.commit)
        for sq in result.structured_questions:
            sq.raised_by_skill = sq.raised_by_skill or result.skill_name
            self.save_open_question(repo_path, sq)
        for fs in result.function_summaries:
            fs.created_by_skill = fs.created_by_skill or result.skill_name
            self.save_function_summary(repo_path, fs, result.commit)
        for cf in result.conflicts:
            self.save_conflict(repo_path, cf)
        for rc in result.ignored_returns:
            rc.created_by_skill = rc.created_by_skill or result.skill_name
            self.save_return_contract(repo_path, rc)
        for oq_text in result.open_questions:
            if isinstance(oq_text, str) and oq_text.strip():
                oq = OpenQuestion(
                    question=oq_text,
                    raised_by_skill=result.skill_name,
                    impact="informational",
                )
                self.save_open_question(repo_path, oq)

    def save_negative_evidence(self, repo_path: str, ne: NegativeEvidence) -> None:
        import time
        self.conn.execute(
            """INSERT INTO negative_evidence
               (id, repo_path, entry_point, safe_from, because,
                anchor_file, anchor_line, anchor_text, anchor_stale, commit_sha, created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(repo_path, entry_point, safe_from) DO UPDATE SET
                 id=excluded.id,
                 because=excluded.because,
                 anchor_file=excluded.anchor_file,
                 anchor_line=excluded.anchor_line,
                 anchor_text=excluded.anchor_text,
                 anchor_stale=excluded.anchor_stale,
                 commit_sha=excluded.commit_sha""",
            (ne.id, repo_path, ne.entry_point, ne.safe_from, ne.because,
             ne.anchor_file, ne.anchor_line, ne.anchor_text,
             int(ne.anchor_stale), ne.commit, time.time()),
        )
        self.conn.commit()

    def list_negative_evidence(self, repo_path: str) -> list[NegativeEvidence]:
        rows = self.conn.execute(
            "SELECT * FROM negative_evidence WHERE repo_path=? ORDER BY entry_point, safe_from",
            (repo_path,),
        ).fetchall()
        return [NegativeEvidence(
            id=r["id"], entry_point=r["entry_point"], safe_from=r["safe_from"],
            because=r["because"], anchor_file=r["anchor_file"],
            anchor_line=r["anchor_line"], anchor_text=r["anchor_text"],
            anchor_stale=bool(r["anchor_stale"]), disputed=bool(r["disputed"]),
            commit=r["commit_sha"] or "",
        ) for r in rows]

    def mark_negative_evidence_stale(self, repo_path: str, ne_id: str) -> None:
        self.conn.execute(
            "UPDATE negative_evidence SET anchor_stale=1 WHERE id=? AND repo_path=?",
            (ne_id, repo_path),
        )
        self.conn.commit()

    def mark_negative_evidence_fresh(self, repo_path: str, ne_id: str) -> None:
        self.conn.execute(
            "UPDATE negative_evidence SET anchor_stale=0 WHERE id=? AND repo_path=?",
            (ne_id, repo_path),
        )
        self.conn.commit()

    def close(self):
        self.conn.close()
