from __future__ import annotations
from typing import Any, Literal, Optional
from pydantic import BaseModel, Field
import uuid
from datetime import datetime


class Symbol(BaseModel):
    name: str
    qualified_name: str
    kind: str
    file_path: str
    line_start: int
    line_end: int
    language: str


class EntryPoint(BaseModel):
    kind: Literal["route", "consumer", "job", "command", "hook", "callback"]
    path: str
    method: Optional[str] = None
    handler_qn: str
    file_path: str
    line: int
    auth_decorators: list[str] = Field(default_factory=list)
    notes: str = ""


class ExecutionEdge(BaseModel):
    caller_qn: str
    callee_qn: str
    certainty: Literal["definite", "probable", "unknown"]
    call_site_file: str
    call_site_line: int


class DataFlowEdge(BaseModel):
    source_qn: str
    sink_qn: str
    field_path: str = ""
    transformation: Optional[str] = None
    constraint: Optional[str] = None


class Guard(BaseModel):
    location_qn: str
    file_path: str
    line: int
    checked_data: str
    covers_all_paths: bool
    same_context: bool
    before_effect: bool
    failure_mode: Literal["stop", "continue", "unknown"]
    bypassable: bool
    bypass_path: Optional[str] = None
    path_conditions: list[str] = Field(default_factory=list)
    bypassed_by: list[str] = Field(default_factory=list)
    temporal_scope: Literal["per_request", "cached", "startup", "unknown"] = "unknown"


class Resource(BaseModel):
    name: str
    kind: str
    sensitivity: Literal["low", "medium", "high", "critical"]
    ownership_model: str
    storage_locations: list[str] = Field(default_factory=list)


class Invariant(BaseModel):
    rule: str
    source: Literal["explicit", "test", "inferred", "hint", "model_guess"]
    scope: str = ""
    evidence: list[str] = Field(default_factory=list)


class AnalysisQuality(BaseModel):
    method: Literal["semantic", "structural", "textual", "inferred"] = "textual"
    confidence: Literal["high", "medium", "low", "speculative"] = "low"
    limitations: list[str] = Field(default_factory=list)
    unresolved_calls: int = 0
    unresolved_symbols: int = 0


class ProofObligation(BaseModel):
    question: str
    status: Literal["verified", "unresolved", "refuted"] = "unresolved"
    evidence_ref: Optional[str] = None
    reason: Optional[str] = None


class OpenQuestion(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    question: str
    raised_by_skill: str = ""
    raised_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    impact: Literal["blocks_finding", "affects_confidence", "informational"] = "informational"
    affects_hypothesis_ids: list[str] = Field(default_factory=list)
    resolution_hint: Optional[str] = None
    status: Literal["open", "resolved", "wont_fix"] = "open"
    resolved_by: Optional[str] = None


class FunctionSummary(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    qualified_name: str
    file_path: str
    line: int
    created_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    created_by_skill: str = ""
    commit: str = ""
    inputs: list[str] = Field(default_factory=list)
    reads: list[str] = Field(default_factory=list)
    writes: list[str] = Field(default_factory=list)
    external_effects: list[str] = Field(default_factory=list)
    guards: list[str] = Field(default_factory=list)
    transformations: list[str] = Field(default_factory=list)
    failure_behavior: str = ""
    preconditions: list[str] = Field(default_factory=list)
    guarantees: list[str] = Field(default_factory=list)
    required_authority: list[str] = Field(default_factory=list)
    unresolved_calls: list[str] = Field(default_factory=list)
    quality: AnalysisQuality = Field(default_factory=AnalysisQuality)


class ReturnValueContract(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    function_qualified_name: str
    file_path: str
    line: int
    return_type: str
    security_relevance: Literal["critical", "high", "medium", "low"] = "high"
    expected_handling: Literal["must_check", "may_ignore", "context_dependent"] = "must_check"
    consequence_if_ignored: str = ""
    created_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    created_by_skill: str = ""
    ignored_at: list[str] = Field(default_factory=list)


class ConflictRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    created_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    kind: Literal[
        "guard_mismatch",
        "status_inconsistency",
        "stale_reference",
        "contradicting_claims",
        "capability_mismatch",
    ]
    description: str
    left: str
    right: str
    severity: Literal["blocks_finding", "degrades_confidence", "informational"] = "degrades_confidence"
    status: Literal["open", "resolved"] = "open"
    resolved_by: Optional[str] = None


class Hypothesis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    created_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())

    actor: str
    capability: str
    entry_point: str
    preconditions: list[str] = Field(default_factory=list)
    execution_path: list[str] = Field(default_factory=list)
    security_boundary: str
    violated_invariant: str
    observable_impact: str
    counterevidence: list[str] = Field(default_factory=list)
    uncertainty: list[str] = Field(default_factory=list)

    reachability: Literal["proven", "probable", "unknown"] = "unknown"
    input_control: Literal["full", "partial", "unknown"] = "unknown"
    guard_analysis: Literal["complete", "incomplete"] = "incomplete"
    runtime_assumptions: Literal["verified", "env_dependent"] = "env_dependent"
    impact_basis: Literal["observed", "inferred"] = "inferred"
    validation: Literal["run", "not_run", "blocked"] = "not_run"
    status: Literal["initial", "evidence_supported", "reproduced", "refuted", "rejected", "blocked"] = "initial"

    severity: int = Field(ge=0, le=10, default=5)
    confidence: int = Field(ge=0, le=10, default=3)
    priority: int = 0

    skill_source: str = ""
    rejection_reason: Optional[str] = None
    commit: str = ""
    evidence_refs: list[str] = Field(default_factory=list)
    cwe: Optional[str] = None

    proof_obligations: list[ProofObligation] = Field(default_factory=list)
    guard_coverage: Literal["all_paths", "some_paths", "no_paths", "unknown"] = "unknown"
    uncovered_paths: list[str] = Field(default_factory=list)
    temporal_validity: Literal["checked_at_request", "snapshot", "unknown"] = "unknown"
    actor_capabilities: list[str] = Field(default_factory=list)

    def compute_priority(self) -> int:
        score = self.severity * 2 + self.confidence
        if self.reachability == "proven":
            score += 4
        elif self.reachability == "probable":
            score += 2
        if self.input_control == "full":
            score += 3
        elif self.input_control == "partial":
            score += 1
        return score


class Evidence(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    hypothesis_id: str
    kind: Literal["code", "config", "test", "trace", "runtime"]
    description: str
    file_path: str
    line_start: int
    line_end: int
    snippet: str
    commit: str = ""
    stale: bool = False
    analysis_quality: AnalysisQuality = Field(default_factory=AnalysisQuality)
    field_path: Optional[str] = None


class CoverageItem(BaseModel):
    kind: Literal["entry_point", "actor", "resource", "state_transition", "trust_boundary",
                  "sensitive_op", "error_path", "async_path", "environment"]
    name: str
    status: Literal[
        "unseen",
        "no_issue_found",
        "ruled_out",
        "not_applicable",
        "needs_follow_up",
        "reported",
        "blocked",
        "excluded",
    ]
    blocker: Optional[str] = None
    exclusion_reason: Optional[str] = None


class ThreatModel(BaseModel):
    target: str
    content: str
    created_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    amendments: list[dict] = Field(default_factory=list)
    created_by_skill: str = ""


class ValidationRun(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    hypothesis_id: str
    ran_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    approach: str
    positive_result: Optional[bool] = None
    negative_result: Optional[bool] = None
    notes: str = ""


class SkillResult(BaseModel):
    skill_name: str
    repo_path: str
    commit: str
    hypotheses: list[Hypothesis] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    coverage: list[CoverageItem] = Field(default_factory=list)
    symbols_found: list[str] = Field(default_factory=list)
    entry_points_found: list[EntryPoint] = Field(default_factory=list)
    guards_found: list[Guard] = Field(default_factory=list)
    open_questions: list[str] = Field(default_factory=list)
    structured_questions: list[OpenQuestion] = Field(default_factory=list)
    function_summaries: list[FunctionSummary] = Field(default_factory=list)
    conflicts: list[ConflictRecord] = Field(default_factory=list)
    ignored_returns: list[ReturnValueContract] = Field(default_factory=list)
    coverage_gaps: list[str] = Field(default_factory=list)
    analysis_quality: AnalysisQuality = Field(default_factory=AnalysisQuality)


FINDINGS_SCHEMA = {
    "type": "object",
    "properties": {
        "hypotheses": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["actor", "capability", "entry_point", "security_boundary",
                             "violated_invariant", "observable_impact", "severity", "confidence"],
                "properties": {
                    "actor": {"type": "string"},
                    "capability": {"type": "string"},
                    "entry_point": {"type": "string"},
                    "preconditions": {"type": "array", "items": {"type": "string"}},
                    "execution_path": {"type": "array", "items": {"type": "string"}},
                    "security_boundary": {"type": "string"},
                    "violated_invariant": {"type": "string"},
                    "observable_impact": {"type": "string"},
                    "counterevidence": {"type": "array", "items": {"type": "string"}},
                    "uncertainty": {"type": "array", "items": {"type": "string"}},
                    "reachability": {"type": "string", "enum": ["proven", "probable", "unknown"]},
                    "input_control": {"type": "string", "enum": ["full", "partial", "unknown"]},
                    "severity": {"type": "integer", "minimum": 0, "maximum": 10},
                    "confidence": {"type": "integer", "minimum": 0, "maximum": 10},
                    "skill_source": {"type": "string"},
                    "evidence_refs": {"type": "array", "items": {"type": "string"}},
                    "cwe": {"type": "string", "description": "CWE ID e.g. CWE-89, CWE-79, CWE-306"},
                    "proof_obligations": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "required": ["question"],
                            "properties": {
                                "question": {"type": "string"},
                                "status": {"type": "string", "enum": ["verified", "unresolved", "refuted"]},
                                "evidence_ref": {"type": "string"},
                                "reason": {"type": "string"},
                            }
                        }
                    },
                    "guard_coverage": {"type": "string", "enum": ["all_paths", "some_paths", "no_paths", "unknown"]},
                    "uncovered_paths": {"type": "array", "items": {"type": "string"}},
                    "temporal_validity": {"type": "string", "enum": ["checked_at_request", "snapshot", "unknown"]},
                    "actor_capabilities": {"type": "array", "items": {"type": "string"}},
                }
            }
        },
        "coverage": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["kind", "name", "status"],
                "properties": {
                    "kind": {"type": "string"},
                    "name": {"type": "string"},
                    "status": {"type": "string", "enum": [
                        "unseen", "no_issue_found", "ruled_out",
                        "not_applicable", "needs_follow_up", "reported",
                        "blocked", "excluded",
                    ]},
                    "blocker": {"type": "string"},
                }
            }
        },
        "open_questions": {"type": "array", "items": {"type": "string"}},
        "evidence": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["kind", "description", "file_path", "line_start", "line_end", "snippet"],
                "properties": {
                    "hypothesis_index": {
                        "type": "integer",
                        "description": "0-based index into the hypotheses array this evidence supports"
                    },
                    "kind": {"type": "string", "enum": ["code", "config", "test", "trace", "runtime"]},
                    "description": {"type": "string"},
                    "file_path": {"type": "string"},
                    "line_start": {"type": "integer"},
                    "line_end": {"type": "integer"},
                    "snippet": {"type": "string"},
                    "analysis_quality": {
                        "type": "object",
                        "properties": {
                            "method": {"type": "string", "enum": ["semantic", "structural", "textual", "inferred"]},
                            "confidence": {"type": "string", "enum": ["high", "medium", "low", "speculative"]},
                            "limitations": {"type": "array", "items": {"type": "string"}},
                            "unresolved_calls": {"type": "integer"},
                            "unresolved_symbols": {"type": "integer"},
                        }
                    },
                    "field_path": {"type": "string"},
                }
            }
        },
        "entry_points_found": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["kind", "path", "handler_qn", "file_path", "line"],
                "properties": {
                    "kind": {"type": "string",
                             "enum": ["route", "consumer", "job", "command", "hook", "callback"]},
                    "path": {"type": "string"},
                    "method": {"type": "string"},
                    "handler_qn": {"type": "string"},
                    "file_path": {"type": "string"},
                    "line": {"type": "integer"},
                    "auth_decorators": {"type": "array", "items": {"type": "string"}},
                    "notes": {"type": "string"},
                }
            }
        },
        "guards_found": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["location_qn", "file_path", "line", "checked_data",
                             "covers_all_paths", "same_context", "before_effect",
                             "failure_mode", "bypassable"],
                "properties": {
                    "location_qn": {"type": "string"},
                    "file_path": {"type": "string"},
                    "line": {"type": "integer"},
                    "checked_data": {"type": "string"},
                    "covers_all_paths": {"type": "boolean"},
                    "same_context": {"type": "boolean"},
                    "before_effect": {"type": "boolean"},
                    "failure_mode": {"type": "string", "enum": ["stop", "continue", "unknown"]},
                    "bypassable": {"type": "boolean"},
                    "bypass_path": {"type": "string"},
                    "path_conditions": {"type": "array", "items": {"type": "string"}},
                    "bypassed_by": {"type": "array", "items": {"type": "string"}},
                    "temporal_scope": {"type": "string", "enum": ["per_request", "cached", "startup", "unknown"]},
                }
            }
        },
        "function_summaries": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["qualified_name", "file_path", "line"],
                "properties": {
                    "qualified_name": {"type": "string"},
                    "file_path": {"type": "string"},
                    "line": {"type": "integer"},
                    "inputs": {"type": "array", "items": {"type": "string"}},
                    "reads": {"type": "array", "items": {"type": "string"}},
                    "writes": {"type": "array", "items": {"type": "string"}},
                    "external_effects": {"type": "array", "items": {"type": "string"}},
                    "guards": {"type": "array", "items": {"type": "string"}},
                    "transformations": {"type": "array", "items": {"type": "string"}},
                    "failure_behavior": {"type": "string"},
                    "preconditions": {"type": "array", "items": {"type": "string"}},
                    "guarantees": {"type": "array", "items": {"type": "string"}},
                    "required_authority": {"type": "array", "items": {"type": "string"}},
                    "unresolved_calls": {"type": "array", "items": {"type": "string"}},
                    "quality": {
                        "type": "object",
                        "properties": {
                            "method": {"type": "string"},
                            "confidence": {"type": "string"},
                            "limitations": {"type": "array", "items": {"type": "string"}},
                        }
                    },
                }
            }
        },
        "structured_questions": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["question"],
                "properties": {
                    "question": {"type": "string"},
                    "impact": {"type": "string", "enum": ["blocks_finding", "affects_confidence", "informational"]},
                    "affects_hypothesis_ids": {"type": "array", "items": {"type": "string"}},
                    "resolution_hint": {"type": "string"},
                }
            }
        },
        "analysis_quality": {
            "type": "object",
            "properties": {
                "method": {"type": "string", "enum": ["semantic", "structural", "textual", "inferred"]},
                "confidence": {"type": "string", "enum": ["high", "medium", "low", "speculative"]},
                "limitations": {"type": "array", "items": {"type": "string"}},
                "unresolved_calls": {"type": "integer"},
                "unresolved_symbols": {"type": "integer"},
            }
        },
        "ignored_returns": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["function_qualified_name", "file_path", "line", "return_type"],
                "properties": {
                    "function_qualified_name": {"type": "string"},
                    "file_path": {"type": "string"},
                    "line": {"type": "integer"},
                    "return_type": {"type": "string"},
                    "security_relevance": {"type": "string", "enum": ["critical", "high", "medium", "low"]},
                    "expected_handling": {"type": "string", "enum": ["must_check", "may_ignore", "context_dependent"]},
                    "consequence_if_ignored": {"type": "string"},
                    "ignored_at": {"type": "array", "items": {"type": "string"}},
                }
            }
        },
    },
    "required": ["hypotheses", "coverage", "open_questions"]
}
