from __future__ import annotations
import sqlite3
import json
from pathlib import Path
from typing import Optional
from .models import (
    Hypothesis, Evidence, CoverageItem, ValidationRun,
    EntryPoint, Guard, SkillResult, ThreatModel,
    FunctionSummary, OpenQuestion, ConflictRecord,
)


class EvidenceStore:
    def __init__(self, db_path: Path):
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(db_path))
        self.conn.row_factory = sqlite3.Row
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
            commit_sha TEXT
        );

        CREATE TABLE IF NOT EXISTS guards (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            repo_path TEXT,
            data TEXT NOT NULL,
            commit_sha TEXT
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
        """)
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
        h.priority = h.compute_priority()
        self.conn.execute(
            """INSERT OR REPLACE INTO hypotheses
               (id, repo_path, data, created_at, status, severity, confidence, priority, skill_source, commit_sha)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (h.id, repo_path, h.model_dump_json(), h.created_at,
             h.status, h.severity, h.confidence, h.priority, h.skill_source, h.commit)
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

    def upsert_coverage(self, repo_path: str, item: CoverageItem):
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
        self.conn.execute(
            "INSERT INTO entry_points (repo_path, data, commit_sha) VALUES (?,?,?)",
            (repo_path, ep.model_dump_json(), commit)
        )
        self.conn.commit()

    def save_guard(self, repo_path: str, g: Guard, commit: str):
        self.conn.execute(
            "INSERT INTO guards (repo_path, data, commit_sha) VALUES (?,?,?)",
            (repo_path, g.model_dump_json(), commit)
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

    def get_function_summary(self, repo_path: str, qualified_name: str) -> Optional[FunctionSummary]:
        row = self.conn.execute(
            "SELECT data FROM function_summaries WHERE repo_path=? AND qualified_name=? ORDER BY created_at DESC LIMIT 1",
            (repo_path, qualified_name)
        ).fetchone()
        if row is None:
            return None
        return FunctionSummary.model_validate_json(row["data"])

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

    def save_conflict(self, repo_path: str, c: ConflictRecord) -> None:
        self.conn.execute(
            """INSERT OR REPLACE INTO conflicts
               (id, repo_path, data, created_at, kind, severity, status)
               VALUES (?,?,?,?,?,?,?)""",
            (c.id, repo_path, c.model_dump_json(), c.created_at, c.kind, c.severity, c.status)
        )
        self.conn.commit()

    def list_conflicts(self, repo_path: str, status: str = "open") -> list[ConflictRecord]:
        rows = self.conn.execute(
            "SELECT data FROM conflicts WHERE repo_path=? AND status=? ORDER BY created_at DESC",
            (repo_path, status)
        ).fetchall()
        return [ConflictRecord.model_validate_json(r["data"]) for r in rows]

    def mark_stale_by_commit(self, repo_path: str, old_commit: str):
        self.conn.execute(
            "UPDATE evidence SET stale=1 WHERE repo_path=? AND commit_sha=? AND commit_sha != ''",
            (repo_path, old_commit)
        )
        self.conn.commit()

    def save_skill_result(self, repo_path: str, result: SkillResult):
        for h in result.hypotheses:
            self.save_hypothesis(repo_path, h)
        for e in result.evidence:
            self.save_evidence(repo_path, e)
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

    def close(self):
        self.conn.close()
