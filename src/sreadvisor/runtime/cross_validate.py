"""Matches Stage 1's code/infra-declared dependencies against a live topology, deterministically (no LLM: this is a
name-and-kind comparison, not a judgment call). A dependency on either side that finds no match on the other is
exactly the fact the brief asks for — "flag any dependency the observability provider shows that the code or infra
analysis did not find, and vice versa" — nothing here decides whether that is a problem; that is Stage 6's job.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

from sreadvisor.schema.common import Evidence
from sreadvisor.schema.dataset import ServiceDataset
from sreadvisor.schema.runtime import NodeKind, ServiceMetrics, ServiceTopology, TopologyEdge, TopologyNode
from sreadvisor.runtime.schema import (
    CodeOnlyDependency,
    CrossValidationSummary,
    MatchedDependency,
    RuntimeCrossValidation,
    RuntimeOnlyDependency,
)

_TOKEN = re.compile(r"[a-z0-9]{3,}")
_STOP = {"the", "and", "for", "com", "org", "net", "http", "https", "api", "default", "group", "process", "service",
        "server", "instance", "system"}

# A Stage 1 FlowDependency.kind is compatible with a live topology NodeKind when both describe the same category of
# outside-the-process thing; a dependency whose kind Stage 1 could not pin down ("other", "filesystem") is left
# without a compatible set, so a match for it can only ever come from name overlap (confidence "medium").
_CODE_KIND_TO_NODE_KINDS: dict[str, set[NodeKind]] = {
    "datastore": {"database"}, "cache": {"cache"}, "messaging": {"queue"},
    "http_service": {"service", "external_service"}, "external_api": {"external_service", "service"},
}


def _tokens(name: str) -> set[str]:
    return set(_TOKEN.findall(name.lower())) - _STOP


def _kind_compatible(code_kind: str, node_kind: NodeKind) -> bool:
    return node_kind in _CODE_KIND_TO_NODE_KINDS.get(code_kind, set())


@dataclass
class _CodeDependency:
    name: str
    kind: str
    evidence: list[Evidence] = field(default_factory=list)


def _collect_code_dependencies(dataset: ServiceDataset) -> list[_CodeDependency]:
    """Every distinct dependency named in a traced transaction flow, deduplicated by kind and name tokens (the same
    dependency is usually named identically by the flow tracer across flows, but this tolerates small wording
    differences without creating a duplicate)."""
    merged: dict[tuple[str, tuple[str, ...]], _CodeDependency] = {}
    for repo in dataset.repositories:
        for flow in repo.transaction_flows:
            for dep in flow.dependencies:
                key = (dep.kind, tuple(sorted(_tokens(dep.name))) or (dep.name.lower(),))
                entry = merged.setdefault(key, _CodeDependency(name=dep.name, kind=dep.kind))
                entry.evidence.append(dep.evidence)
    return list(merged.values())


def _dependency_like_edges(topology: ServiceTopology) -> list[tuple[TopologyEdge, TopologyNode]]:
    """Edges the cross-validation compares against code: outbound edges (the pilot service is the source, i.e.
    ``direction == "calls"``) to a neighbor whose kind represents an actual runtime dependency (service, database,
    cache, queue, external service), not a structural/containment relationship (runs on this host, is an instance of
    this process group, ...).

    Inbound edges (something else calls the pilot service) are excluded here on purpose, even though they are
    dependency-like: a :class:`~sreadvisor.schema.dataset.FlowDependency` is always something the traced code calls
    out to, never something that calls into it, so comparing an inbound caller against that list would only ever
    produce a guaranteed, meaningless "runtime-only" finding for every caller the service has. They are not lost —
    the full topology (every node and edge, both directions) is still returned in ``ServiceTopology`` untouched;
    only this comparison is scoped to what Stage 1 could possibly have declared."""
    nodes_by_id = {n.id: n for n in topology.nodes}
    out: list[tuple[TopologyEdge, TopologyNode]] = []
    for e in topology.edges:
        if not e.attributes.get("is_dependency_like") or e.direction != "calls" or e.source != topology.service_id:
            continue
        node = nodes_by_id.get(e.target)
        if node is not None and node.id != topology.service_id:
            out.append((e, node))
    return out


def cross_validate(dataset: ServiceDataset, topology: ServiceTopology, metrics: ServiceMetrics) -> RuntimeCrossValidation:
    """``dataset`` and ``topology`` are the caller's own choice of which Stage 1 service to compare against which
    live entity; nothing here checks they name the same real-world service (the dataset's ``observability.service_id``
    binding, resolved by the caller, is what makes that pairing correct)."""
    code_deps = _collect_code_dependencies(dataset)
    runtime_deps = _dependency_like_edges(topology)
    code_used = [False] * len(code_deps)

    matched: list[MatchedDependency] = []
    runtime_only: list[RuntimeOnlyDependency] = []
    for edge, node in runtime_deps:
        node_tokens = _tokens(node.name)
        best: tuple[int, set[str], str] | None = None  # (code index, overlap, confidence)
        for ci, cd in enumerate(code_deps):
            if code_used[ci]:
                continue
            overlap = node_tokens & _tokens(cd.name)
            if not overlap:
                continue
            confidence = "high" if _kind_compatible(cd.kind, node.kind) else "medium"
            if best is None or (confidence == "high" and best[2] == "medium") or (
                confidence == best[2] and len(overlap) > len(best[1])
            ):
                best = (ci, overlap, confidence)
        if best is None:
            runtime_only.append(RuntimeOnlyDependency(node=node, edge=edge))
            continue
        ci, overlap, confidence = best
        code_used[ci] = True
        cd = code_deps[ci]
        matched.append(MatchedDependency(runtime_node=node, runtime_edge=edge, code_name=cd.name, code_kind=cd.kind,
                                         code_evidence=list(cd.evidence), matched_on=sorted(overlap), confidence=confidence))

    code_only = [CodeOnlyDependency(name=cd.name, kind=cd.kind, evidence=list(cd.evidence))
                for ci, cd in enumerate(code_deps) if not code_used[ci]]

    warnings = []
    if not dataset.repositories or all(not r.transaction_flows for r in dataset.repositories):
        warnings.append("the dataset has no traced transaction flows (Stage 1 ran with --no-llm, or tracing failed); "
                        "every runtime dependency is reported as runtime-only because there is nothing to compare it against.")

    return RuntimeCrossValidation(
        service_name=dataset.service_name, provider=topology.provider, service_id=topology.service_id,
        generated_at=datetime.now(timezone.utc), topology=topology, metrics=metrics,
        summary=CrossValidationSummary(code_dependencies=len(code_deps), runtime_dependencies=len(runtime_deps),
                                       matched=len(matched), runtime_only=len(runtime_only), code_only=len(code_only)),
        matched=matched, runtime_only=runtime_only, code_only=code_only, warnings=warnings)
