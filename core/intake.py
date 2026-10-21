from __future__ import annotations
from typing import Any, Optional
from .models import Hypothesis


_ENGINE_OWNED_HYPOTHESIS_FIELDS = (
    "id", "created_at", "status", "priority", "rejected_by", "rejected_at_commit",
    "rejection_reason", "rejection_condition", "rejection_controlling_evidence_ids",
    "validation", "model", "verified_with", "evidence_refs",
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


def _finish_problems(findings: dict, commit: str = "") -> list[str]:
    problems: list[str] = []
    hyps = _as_list(findings.get("hypotheses"))
    valid: dict[int, Hypothesis] = {}
    for i, h in enumerate(hyps):
        if not isinstance(h, dict):
            problems.append(f"hypotheses[{i}] is not an object")
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
        supported.add(idx)
    for i, obj in valid.items():
        if i not in supported and obj.confidence > _LEAD_CONFIDENCE:
            label = (obj.violated_invariant or obj.entry_point)[:60]
            problems.append(f"hypotheses[{i}] ({label}) has no evidence item")
    return problems


def _apply_model_demotion(h: "Hypothesis", demotion: Optional[str], commit: str) -> None:
    if not demotion:
        return
    h.status = demotion
    if demotion in ("rejected", "refuted"):
        h.rejected_at_commit = commit
    if demotion == "rejected":
        h.rejected_by = "model"
