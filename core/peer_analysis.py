from __future__ import annotations
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .models import (
    EntryPoint, Guard, Hypothesis, Evidence, AnalysisQuality, ProofObligation,
)
from .profile import ProjectProfile

# 3 meant a "convention" inferred from two samples; at 5 a deviation is a real
# outlier rather than noise
MIN_CLUSTER_SIZE = 5
MIN_CONFORMITY = 0.75
# one straggler against a merely-common marker is weak evidence, so a cluster
# where several members lack the marker is not a convention at all
MAX_NONCONFORMERS_RATIO = 0.25

_PARAM_SEGMENT = re.compile(r"^(\{.*\}|<.*>|:.+|\[.*\])$")
_VERSION_SEGMENT = re.compile(r"^v\d+(\.\d+)?$")
_GENERIC_SEGMENTS = {
    "api", "rest", "rpc", "graphql", "web", "app", "public", "private",
    "internal", "external", "service", "services", "svc", "gateway",
}
_GUARD_STOPWORDS = {
    "self", "true", "false", "none", "null", "not", "and", "or", "is", "in",
    "if", "the", "request", "req", "ctx", "context", "current", "get", "id",
}


def _normalize_path(path: str) -> str:
    segments = []
    for seg in (path or "").strip("/").split("/"):
        if not seg:
            continue
        segments.append("*" if _PARAM_SEGMENT.match(seg) else seg)
    return "/" + "/".join(segments)


def _is_generic(segment: str) -> bool:
    return segment in _GENERIC_SEGMENTS or bool(_VERSION_SEGMENT.match(segment))


def _cluster_key(ep: EntryPoint) -> str:
    """Group peers a reader would expect to be protected the same way.

    Keying on the leading path segments put every route under one `/api/v1`
    bucket, which both drowned a genuine outlier and flagged /health and /login
    for not matching an average that spanned the whole API. The first
    domain-meaningful segment is the real unit of convention.

    `kind` is part of the key because a queue consumer and an HTTP route are not
    peers: comparing them flagged consumers for lacking route auth decorators.
    """
    literal = [s for s in _normalize_path(ep.path).strip("/").split("/") if s and s != "*"]
    meaningful = [s for s in literal if not _is_generic(s)]
    if meaningful:
        segment = "/" + meaningful[0]
    elif literal:
        segment = "/" + literal[0]
    else:
        segment = Path(ep.file_path or "").parent.as_posix() or "<root>"
    return f"{ep.kind}:{segment}"


def _guard_markers(g: Guard) -> set[str]:
    """Turn free-text checked_data into comparable tokens.

    `guard:user.id == order.owner_id` is never byte-identical between two
    handlers, so using it whole produced no signal at all.
    """
    tokens = {t for t in re.split(r"[^a-zA-Z0-9_]+", (g.checked_data or "").lower())
              if len(t) > 2 and t not in _GUARD_STOPWORDS and not t.isdigit()}
    return {f"guard-token:{t}" for t in tokens}


def _markers_for(ep: EntryPoint, guards_by_qn: dict[str, list[Guard]],
                 profile: Optional[ProjectProfile]) -> set[str]:
    markers = {d.strip() for d in ep.auth_decorators if d and d.strip()}
    for g in guards_by_qn.get(ep.handler_qn, []):
        markers |= _guard_markers(g)
    if profile:
        # only declared decorators count. Matching profile markers against
        # ep.notes treated "TODO: add @requires_scope here" as proof the route
        # WAS protected — configuring a profile suppressed real findings
        declared = {d.strip() for d in ep.auth_decorators if d and d.strip()}
        for marker in profile.auth_markers():
            if marker and any(marker == d or marker in d for d in declared):
                markers.add(marker)
    return markers


@dataclass
class Deviation:
    entry_point: EntryPoint
    cluster_key: str
    missing_markers: list[str] = field(default_factory=list)
    peers_with_marker: list[EntryPoint] = field(default_factory=list)
    cluster_size: int = 0

    @property
    def missing_marker(self) -> str:
        return ", ".join(self.missing_markers)

    @property
    def conformity(self) -> float:
        peers = self.cluster_size - 1
        return len(self.peers_with_marker) / peers if peers else 0.0

    def confidence(self) -> int:
        c, n = self.conformity, self.cluster_size
        nonconformers = n - 1 - len(self.peers_with_marker)
        # several members lacking the marker means it is merely common, not a
        # convention, so a straggler is not strong evidence
        if nonconformers > 0:
            return 5
        if c >= 0.9 and n >= 8:
            return 8
        if c >= 0.85 and n >= 5:
            return 7
        return 6


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

        for ep in members:
            own = marker_sets[id(ep)]
            missing: list[str] = []
            strongest: list[EntryPoint] = []
            for marker in {m for s in marker_sets.values() for m in s}:
                if marker in own:
                    continue
                peers_with = [p for p in members
                              if p is not ep and marker in marker_sets[id(p)]]
                if not peers_with:
                    continue
                if len(peers_with) / (len(members) - 1) < MIN_CONFORMITY:
                    continue
                missing.append(marker)
                if len(peers_with) > len(strongest):
                    strongest = peers_with
            if not missing:
                continue
            if all(m.startswith("guard-token:") for m in missing) and len(missing) < 2:
                peer_guard_sets = {
                    frozenset(m for m in marker_sets[id(p)] if m.startswith("guard-token:"))
                    for p in strongest
                }
                if len(peer_guard_sets) != 1:
                    continue
            # one finding per route: emitting one per marker made a reviewer
            # triage the same endpoint several times
            deviations.append(Deviation(
                entry_point=ep,
                cluster_key=key,
                missing_markers=sorted(missing),
                peers_with_marker=strongest,
                cluster_size=len(members),
            ))
    return deviations


def _read_snippet(repo_path: Optional[str], file_path: str, line: int,
                  span: int = 3) -> str:
    if not repo_path or not file_path:
        return ""
    try:
        target = (Path(repo_path) / file_path).resolve()
        target.relative_to(Path(repo_path).resolve())
        lines = target.read_text(errors="replace").splitlines()
    except (OSError, ValueError):
        return ""
    lo = max(0, line - 1)
    return "\n".join(lines[lo:lo + span])


def deviation_to_hypothesis(d: Deviation, commit: str = "",
                            repo_path: Optional[str] = None) -> tuple[Hypothesis, Evidence]:
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
        exposure="unspecified",
        proof_obligations=[
            ProofObligation(
                question=(
                    f"Is the absence of {d.missing_marker!r} on {ep.path} a defect rather "
                    "than an intentional exception (health check, login, public webhook)?"
                ),
                status="unresolved", claim_type="guard", required_for_finding=True,
                reason="engine-detected peer deviation; not verified against code",
            ),
            ProofObligation(
                question=f"What concrete impact follows from {d.missing_marker!r} being absent here?",
                status="unresolved", claim_type="impact", required_for_finding=True,
                reason="peer comparison establishes deviation, not consequence",
            ),
        ],
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
        # an empty snippet collapses every deviation in a file onto one SARIF
        # fingerprint, so they overwrite each other in code scanning
        snippet=_read_snippet(repo_path, ep.file_path, ep.line) or f"{ep.method or ep.kind} {ep.path}",
        commit=commit,
        analysis_quality=AnalysisQuality(
            method="structural",
            confidence="high" if d.conformity >= 0.9 else "medium",
            limitations=["peer comparison only; impact not independently verified"],
        ),
    )
    h.evidence_refs = [e.id]
    return h, e
