from __future__ import annotations
from typing import Any, Optional
from .models import Evidence, Hypothesis, ProofObligation


_ENGINE_OWNED_HYPOTHESIS_FIELDS = (
    "id", "created_at", "status", "priority", "rejected_by", "rejected_at_commit",
    "rejection_reason", "rejection_condition", "rejection_controlling_evidence_ids",
    "validation", "model", "verified_with", "evidence_refs", "existing_id",
)

_EVIDENCE_LOCATION_FIELDS = ("file_path", "line_start", "line_end")
_LEAD_CONFIDENCE = 3


_MODEL_DEMOTION_STATUSES = frozenset({"refuted", "rejected", "blocked"})


_EXPOSURE_VALUES = frozenset({"internet", "authenticated", "internal", "admin_only", "unreachable"})


def _as_list(value: Any) -> list:
    return value if isinstance(value, list) else []


def _without_id(data: Any) -> Any:
    if isinstance(data, dict) and "id" in data:
        data = {k: v for k, v in data.items() if k != "id"}
    return data


def _prepare_model_hypothesis(h_data: dict, commit: str) -> tuple[dict, Optional[str]]:
    data = dict(h_data)
    claimed = data.get("status")
    for key in _ENGINE_OWNED_HYPOTHESIS_FIELDS:
        data.pop(key, None)
    data["commit"] = commit
    demotion = claimed if claimed in _MODEL_DEMOTION_STATUSES else None
    return data, demotion


_HYPOTHESIS_ENUM_DEFAULTS = {
    "reachability": "unknown",
    "input_control": "unknown",
    "guard_analysis": "incomplete",
    "runtime_assumptions": "env_dependent",
    "impact_basis": "inferred",
    "guard_coverage": "unknown",
    "temporal_validity": "unknown",
    "exposure": "unspecified",
}


def _coerce_model_hypothesis(data: dict) -> list[str]:
    from typing import get_args
    notes: list[str] = []
    for field, default in _HYPOTHESIS_ENUM_DEFAULTS.items():
        if field not in data:
            continue
        allowed = get_args(Hypothesis.model_fields[field].annotation)
        if data[field] not in allowed:
            notes.append(f"engine: {field}={data[field]!r} is not a recognised value; using {default!r}")
            data[field] = default
    for field in ("severity", "confidence"):
        if field not in data:
            continue
        try:
            value = int(round(float(data[field])))
        except (TypeError, ValueError):
            notes.append(f"engine: {field}={data[field]!r} is not a number; using the default")
            data.pop(field)
            continue
        if not 0 <= value <= 10:
            notes.append(f"engine: {field}={value} clamped to 0-10")
        data[field] = max(0, min(10, value))
    return notes


def _describe_validation_error(ex: Exception) -> str:
    errors = getattr(ex, "errors", None)
    if callable(errors):
        try:
            parts = []
            for e in errors()[:3]:
                loc = ".".join(str(p) for p in e.get("loc", ())) or "value"
                parts.append(f"{loc}: {e.get('msg', 'invalid')}")
            if parts:
                return "; ".join(parts)[:200]
        except Exception:
            pass
    return str(ex).splitlines()[0][:160]


def _validate_model_hypothesis(data: dict) -> tuple[Optional["Hypothesis"], str]:
    try:
        return Hypothesis.model_validate(data), ""
    except Exception:
        pass
    repaired = dict(data)
    notes = _coerce_model_hypothesis(repaired)
    try:
        h = Hypothesis.model_validate(repaired)
    except Exception as ex:
        return None, _describe_validation_error(ex)
    h.uncertainty.extend(notes)
    return h, ""


def _evidence_index(item: dict, count: int) -> Optional[int]:
    idx = item.get("hypothesis_index")
    if idx is None and count == 1:
        idx = 0
    if isinstance(idx, str) and idx.strip().isdigit():
        idx = int(idx.strip())
    if isinstance(idx, bool) or not isinstance(idx, int) or not 0 <= idx < count:
        return None
    return idx


def _prepare_model_evidence(data: dict) -> dict:
    out = dict(data)
    for key in ("id", "stale", "hypothesis_index", "hypothesis_id", "merged_by"):
        out.pop(key, None)
    if not isinstance(out.get("snippet"), str):
        out["snippet"] = ""
    return out


def _existing_id(h_data: Any) -> str:
    if not isinstance(h_data, dict):
        return ""
    return str(h_data.get("existing_id") or "").strip()


def _refuted_required(h_data: dict) -> list[str]:
    if h_data.get("status") in _MODEL_DEMOTION_STATUSES:
        return []
    out: list[str] = []
    for raw in _as_list(h_data.get("proof_obligations")):
        try:
            ob = ProofObligation.model_validate(raw)
        except Exception:
            continue
        if ob.required_for_finding and ob.status == "refuted":
            out.append(ob.question.strip())
    return out


def _finish_problems(findings: dict, commit: str = "",
                     known: "frozenset[str] | set[str]" = frozenset()) -> list[str]:
    problems: list[str] = []
    hyps = _as_list(findings.get("hypotheses"))
    valid: dict[int, Hypothesis] = {}
    merges: dict[int, str] = {}
    for i, h in enumerate(hyps):
        if not isinstance(h, dict):
            problems.append(f"hypotheses[{i}] is not an object")
            continue
        for question in _refuted_required(h):
            problems.append(
                f"hypotheses[{i}] marks the required obligation {question[:100]!r} refuted, which "
                "says the finding does not hold. Status is judged against the finding: a guard or "
                "check that does not exist is verified. Mark it verified if the evidence supports "
                "the finding, or drop the hypothesis if it does not")
        existing = _existing_id(h)
        if existing:
            if existing in known:
                merges[i] = existing
                continue
            problems.append(
                f"hypotheses[{i}] gives existing_id {existing!r}, which is not a recorded finding; "
                "use an id from the Known Context list or describe it as a new hypothesis")
            continue
        data, _ = _prepare_model_hypothesis(h, commit)
        obj, error = _validate_model_hypothesis(data)
        if obj is None:
            problems.append(f"hypotheses[{i}] is invalid: {error}")
        else:
            valid[i] = obj
    supported: set[int] = set()
    for j, e in enumerate(_as_list(findings.get("evidence"))):
        if not isinstance(e, dict):
            problems.append(f"evidence[{j}] is not an object")
            continue
        idx = _evidence_index(e, len(hyps))
        if idx is None:
            problems.append(
                f"evidence[{j}] needs hypothesis_index, a number from 0 to {len(hyps) - 1}"
                if hyps else f"evidence[{j}] belongs to no hypothesis")
            continue
        missing = [k for k in _EVIDENCE_LOCATION_FIELDS if e.get(k) in (None, "")]
        if missing:
            problems.append(f"evidence[{j}] is missing {', '.join(missing)}")
            continue
        try:
            Evidence.model_validate({**_prepare_model_evidence(e), "hypothesis_id": "check",
                                     "commit": commit})
        except Exception as ex:
            problems.append(f"evidence[{j}] is invalid: {_describe_validation_error(ex)}")
            continue
        supported.add(idx)
    for i, obj in valid.items():
        if i not in supported and obj.confidence > _LEAD_CONFIDENCE:
            label = (obj.violated_invariant or obj.entry_point)[:60]
            problems.append(f"hypotheses[{i}] ({label}) has no evidence item")
    for i, existing in merges.items():
        if i not in supported:
            problems.append(
                f"hypotheses[{i}] adds to finding {existing} but no evidence item has "
                f"hypothesis_index {i}; add the evidence or drop the entry")
    return problems


def _apply_model_demotion(h: "Hypothesis", demotion: Optional[str], commit: str) -> None:
    if not demotion:
        return
    h.status = demotion
    if demotion in ("rejected", "refuted"):
        h.rejected_at_commit = commit
    if demotion == "rejected":
        h.rejected_by = "model"


_CLAIM_ORDER = {
    "reachability": ("unknown", "probable", "proven"),
    "input_control": ("unknown", "partial", "full"),
}
_FILL_IN_CLAIMS = ("guard_coverage", "guard_analysis", "runtime_assumptions", "impact_basis",
                   "temporal_validity")


def _injected_and_met(h: "Hypothesis", ob) -> bool:
    if ob.status != "unresolved" or not (ob.reason or "").startswith("engine-injected"):
        return False
    if ob.claim_type == "reachability":
        return h.reachability == "proven"
    if ob.claim_type == "input_control":
        return h.input_control in ("full", "partial")
    if ob.claim_type == "guard":
        return h.guard_coverage not in ("unknown", "some_paths")
    return False


def _merge_model_claims(h: "Hypothesis", entries: list) -> None:
    from typing import get_args
    from .models import ProofObligation
    for data in entries:
        if not isinstance(data, dict):
            continue
        for field, order in _CLAIM_ORDER.items():
            new = data.get(field)
            if new in order and order.index(new) > order.index(getattr(h, field)):
                setattr(h, field, new)
        for field in _FILL_IN_CLAIMS:
            new = data.get(field)
            default = Hypothesis.model_fields[field].default
            if (new in get_args(Hypothesis.model_fields[field].annotation) and new != default
                    and getattr(h, field) == default):
                setattr(h, field, new)
        for path in _as_list(data.get("uncovered_paths")):
            if isinstance(path, str) and path.strip() and path not in h.uncovered_paths:
                h.uncovered_paths.append(path)
        for raw in _as_list(data.get("proof_obligations")):
            try:
                ob = ProofObligation.model_validate(raw)
            except Exception:
                continue
            question = ob.question.strip().lower()
            match = next((o for o in h.proof_obligations
                          if (ob.claim_type != "other" and o.claim_type == ob.claim_type
                              and o.required_for_finding == ob.required_for_finding)
                          or o.question.strip().lower() == question), None)
            if match is None:
                h.proof_obligations.append(ob)
            elif match.status == "unresolved" and ob.status != "unresolved":
                match.status = ob.status
                match.evidence_ref = ob.evidence_ref or match.evidence_ref
                match.reason = ob.reason or match.reason
    h.proof_obligations = [o for o in h.proof_obligations if not _injected_and_met(h, o)]
