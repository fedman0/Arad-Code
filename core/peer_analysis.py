from __future__ import annotations
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .models import EntryPoint, Guard, Hypothesis, Evidence, AnalysisQuality
from .profile import ProjectProfile

MIN_CLUSTER_SIZE = 3
MIN_CONFORMITY = 0.75

_PARAM_SEGMENT = re.compile(r"^(\{.*\}|<.*>|:.+|\[.*\])$")


def _normalize_path(path: str) -> str:
    segments = []
    for seg in (path or "").strip("/").split("/"):
        if not seg:
            continue
        segments.append("*" if _PARAM_SEGMENT.match(seg) else seg)
    return "/" + "/".join(segments)


def _cluster_key(ep: EntryPoint) -> str:
    """Group peers that a reader would expect to be protected the same way."""
    literal = [s for s in _normalize_path(ep.path).strip("/").split("/") if s and s != "*"]
    if len(literal) >= 2:
        return "/" + "/".join(literal[:2])
    if literal:
        return "/" + literal[0]
    return Path(ep.file_path or "").parent.as_posix() or "<root>"


def _markers_for(ep: EntryPoint, guards_by_qn: dict[str, list[Guard]],
                 profile: Optional[ProjectProfile]) -> set[str]:
    markers = {d.strip() for d in ep.auth_decorators if d and d.strip()}
    for g in guards_by_qn.get(ep.handler_qn, []):
        markers.add(f"guard:{g.checked_data}")
    if profile:
        haystack = f"{ep.notes} {' '.join(ep.auth_decorators)}"
        for marker in profile.auth_markers():
            if marker and marker in haystack:
                markers.add(marker)
    return markers


@dataclass
class Deviation:
    entry_point: EntryPoint
    cluster_key: str
    missing_marker: str
    peers_with_marker: list[EntryPoint] = field(default_factory=list)
    cluster_size: int = 0

    @property
    def conformity(self) -> float:
        peers = self.cluster_size - 1
        return len(self.peers_with_marker) / peers if peers else 0.0

    def confidence(self) -> int:
        c, n = self.conformity, self.cluster_size
        if c >= 0.9 and n >= 8:
            return 8
        if c >= 0.85 and n >= 5:
            return 7
        if c >= MIN_CONFORMITY and n >= MIN_CLUSTER_SIZE:
            return 6
        return 5


def find_deviations(entry_points: list[EntryPoint], guards: list[Guard],
                    profile: Optional[ProjectProfile] = None) -> list[Deviation]:
    """Find entry points that lack a protection nearly all their peers carry.

    The comparison baseline is the codebase itself, so this needs no sink list
    and no framework knowledge — and a deviation from a strong local convention
    is far more likely to be a real defect than a pattern match is.
    """
    guards_by_qn: dict[str, list[Guard]] = defaultdict(list)
    for g in guards:
        guards_by_qn[g.location_qn].append(g)

    clusters: dict[str, list[EntryPoint]] = defaultdict(list)
    for ep in entry_points:
        clusters[_cluster_key(ep)].append(ep)

    deviations: list[Deviation] = []
    for key, members in clusters.items():
        if len(members) < MIN_CLUSTER_SIZE:
            continue
        marker_sets = {id(ep): _markers_for(ep, guards_by_qn, profile) for ep in members}
        marker_counts: dict[str, int] = defaultdict(int)
        for markers in marker_sets.values():
            for m in markers:
                marker_counts[m] += 1

        for ep in members:
            own = marker_sets[id(ep)]
            for marker, count in marker_counts.items():
                if marker in own:
                    continue
                peers_with = [p for p in members
                              if p is not ep and marker in marker_sets[id(p)]]
                if not peers_with:
                    continue
                if len(peers_with) / (len(members) - 1) < MIN_CONFORMITY:
                    continue
                deviations.append(Deviation(
                    entry_point=ep,
                    cluster_key=key,
                    missing_marker=marker,
                    peers_with_marker=peers_with,
                    cluster_size=len(members),
                ))
    return deviations


def deviation_to_hypothesis(d: Deviation, commit: str = "") -> tuple[Hypothesis, Evidence]:
    ep = d.entry_point
    peer_list = ", ".join(f"{p.path} ({Path(p.file_path).name}:{p.line})"
                          for p in d.peers_with_marker[:6])
    n_peers = len(d.peers_with_marker)

    h = Hypothesis(
        actor="unauthenticated or under-privileged caller",
        capability=f"reach {ep.path} without the protection its peers enforce",
        entry_point=f"{ep.method or ep.kind} {ep.path} -> {ep.handler_qn}",
        execution_path=[f"{ep.file_path}:{ep.line} handler {ep.handler_qn}"],
        security_boundary=f"convention established by {d.cluster_size - 1} peers under {d.cluster_key}",
        violated_invariant=(
            f"every entry point under {d.cluster_key} enforces {d.missing_marker!r}; "
            f"{ep.path} does not"
        ),
        observable_impact=(
            f"whatever {d.missing_marker!r} protects is unprotected on this route — "
            "confirm the concrete impact before reporting"
        ),
        counterevidence=[
            "the deviation may be intentional (public health check, login, webhook)",
            "protection may be applied by middleware not visible on the handler",
        ],
        uncertainty=[f"engine-detected deviation; {n_peers}/{d.cluster_size - 1} peers conform"],
        severity=6,
        confidence=d.confidence(),
        reachability="probable",
        input_control="unknown",
        skill_source="peer-consistency",
        commit=commit,
        proof_obligations=[],
    )
    h.priority = h.compute_priority()

    e = Evidence(
        hypothesis_id=h.id,
        kind="code",
        description=(
            f"{ep.path} lacks {d.missing_marker!r} while {n_peers} of "
            f"{d.cluster_size - 1} peers under {d.cluster_key} carry it. Peers: {peer_list}"
        ),
        file_path=ep.file_path,
        line_start=ep.line,
        line_end=ep.line,
        snippet="",
        commit=commit,
        analysis_quality=AnalysisQuality(
            method="structural",
            confidence="high" if d.conformity >= 0.9 else "medium",
            limitations=["peer comparison only; impact not independently verified"],
        ),
    )
    h.evidence_refs = [e.id]
    return h, e
