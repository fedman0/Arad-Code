import sqlite3
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.config import Config
from core.db import SCHEMA_VERSION, EvidenceStore, SchemaVersionError
from core.reconcile import EvidenceReconciler
from core.runner import SkillRunner
from core.skills import DEFAULT_ORDER, SkillCatalog, SkillFormatError, split_frontmatter
from core.tool_exec import ToolExecutor

SKILLS = Path(__file__).resolve().parent.parent / "skills"


def write_skill(root, phase, name, text):
    d = root / phase
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{name}.md").write_text(text)


def test_text_without_frontmatter_is_untouched():
    meta, body = split_frontmatter("# SKILL: x\n\nbody\n")
    assert meta == {} and body == "# SKILL: x\n\nbody\n"


def test_frontmatter_is_parsed_and_stripped():
    meta, body = split_frontmatter("---\norder: 20\nparallel: true\n---\n\n# SKILL: x\n")
    assert meta == {"order": 20, "parallel": True}
    assert body == "# SKILL: x\n"


def test_invalid_frontmatter_is_an_error():
    with pytest.raises(SkillFormatError):
        split_frontmatter("---\norder: [1\n---\nbody\n", "bad.md")
    with pytest.raises(SkillFormatError):
        split_frontmatter("---\norder: 1\nbody without closing line\n", "bad.md")
    with pytest.raises(SkillFormatError):
        split_frontmatter("---\n- a\n- b\n---\nbody\n", "bad.md")


def test_catalog_orders_by_order_then_name(tmp_path):
    write_skill(tmp_path, "p1", "zeta", "---\norder: 10\n---\nz\n")
    write_skill(tmp_path, "p1", "alpha", "a\n")
    write_skill(tmp_path, "p1", "beta", "---\norder: 10\n---\nb\n")
    cat = SkillCatalog(tmp_path)
    infos = cat.phase_skills("p1")
    assert [s.name for s in infos] == ["beta", "zeta", "alpha"]
    assert infos[-1].order == DEFAULT_ORDER


def test_catalog_reads_parallel_and_requires(tmp_path):
    write_skill(tmp_path, "p4", "hunt-x", "---\nparallel: yes\nrequires: [Web, iac]\n---\nx\n")
    write_skill(tmp_path, "p4", "hunt-y", "---\nrequires: llm\n---\ny\n")
    cat = SkillCatalog(tmp_path)
    x = cat.find("hunt-x")
    y = cat.find("hunt-y")
    assert x.phase == "p4" and x.parallel is True and x.requires == ("web", "iac")
    assert y.parallel is False and y.requires == ("llm",)
    assert cat.body("hunt-x") == "x\n"
    assert cat.find("missing") is None
    with pytest.raises(FileNotFoundError):
        cat.body("missing")


def test_catalog_reads_optional_and_the_understand_skills_use_it(tmp_path):
    write_skill(tmp_path, "p4", "deep-x", "---\noptional: true\n---\nx\n")
    write_skill(tmp_path, "p4", "deep-y", "---\nparallel: true\n---\ny\n")
    cat = SkillCatalog(tmp_path)
    assert cat.find("deep-x").optional is True and cat.find("deep-y").optional is False
    shipped = SkillCatalog(Path(__file__).resolve().parent.parent / "skills").phase_skills("p4")
    assert {s.name for s in shipped if s.optional} == {s.name for s in shipped
                                                        if s.name.startswith("understand-")}


def test_bad_order_value_is_reported_with_the_file(tmp_path):
    write_skill(tmp_path, "p1", "broken", "---\norder: soon\n---\nx\n")
    with pytest.raises(SkillFormatError, match="broken.md"):
        SkillCatalog(tmp_path).phase_skills("p1")


def test_shipped_skills_all_parse_and_keep_their_order():
    cat = SkillCatalog(SKILLS)
    seen = 0
    for phase in cat.phases():
        for info in cat.phase_skills(phase):
            body = cat.body(info.name)
            assert not body.startswith("---"), info.name
            assert body.lstrip().startswith("#"), info.name
            seen += 1
    assert seen >= 40
    assert [s.name for s in cat.phase_skills("p1")][:4] == [
        "inventory-repository", "resolve-build-context", "resolve-configuration", "map-entry-points",
    ]
    assert [s.name for s in cat.phase_skills("p2")][:2] == ["model-identities", "model-authorization"]


def test_runner_loads_skill_bodies_without_frontmatter(tmp_path):
    db = EvidenceStore(tmp_path / "t.db")
    runner = SkillRunner(Config(api_key="x", db_path=str(tmp_path / "t.db")), db, None)
    text = runner._load_skill("inventory-repository")
    assert text.startswith("# SKILL: inventory-repository")
    assert runner._get_skill_phase("inventory-repository") == "p1"
    assert runner._get_skill_phase("does-not-exist") == ""
    assert isinstance(runner, ToolExecutor) and isinstance(runner, EvidenceReconciler)


def test_fresh_database_gets_the_current_schema_version(tmp_path):
    EvidenceStore(tmp_path / "fresh.db")
    conn = sqlite3.connect(tmp_path / "fresh.db")
    assert conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION


def test_legacy_database_is_migrated(tmp_path):
    path = tmp_path / "legacy.db"
    conn = sqlite3.connect(path)
    conn.executescript("""
        CREATE TABLE hypotheses (id TEXT PRIMARY KEY, repo_path TEXT, data TEXT NOT NULL,
            created_at TEXT, status TEXT, severity INTEGER, confidence INTEGER, priority INTEGER,
            skill_source TEXT, commit_sha TEXT);
        CREATE TABLE negative_evidence (id TEXT PRIMARY KEY, repo_path TEXT NOT NULL,
            entry_point TEXT NOT NULL, safe_from TEXT NOT NULL, because TEXT NOT NULL,
            anchor_file TEXT NOT NULL, anchor_line INTEGER NOT NULL, anchor_text TEXT NOT NULL,
            anchor_stale INTEGER DEFAULT 0, commit_sha TEXT DEFAULT '', created_at REAL);
        INSERT INTO hypotheses (id, repo_path, data) VALUES ('h1', '/r', '{}');
    """)
    conn.commit()
    conn.close()
    EvidenceStore(path)
    conn = sqlite3.connect(path)
    cols = {r[1] for r in conn.execute("PRAGMA table_info(hypotheses)")}
    assert {"fingerprint", "rejected_at_commit"} <= cols
    ne_cols = {r[1] for r in conn.execute("PRAGMA table_info(negative_evidence)")}
    assert "disputed" in ne_cols
    assert conn.execute("SELECT id FROM hypotheses").fetchall() == [("h1",)]
    assert conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION


def test_reopening_is_idempotent(tmp_path):
    EvidenceStore(tmp_path / "x.db")
    EvidenceStore(tmp_path / "x.db")
    conn = sqlite3.connect(tmp_path / "x.db")
    assert conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION


def test_newer_database_is_refused(tmp_path):
    path = tmp_path / "newer.db"
    conn = sqlite3.connect(path)
    conn.execute(f"PRAGMA user_version={SCHEMA_VERSION + 5}")
    conn.commit()
    conn.close()
    with pytest.raises(SchemaVersionError, match="upgrade Arad Code"):
        EvidenceStore(path)
