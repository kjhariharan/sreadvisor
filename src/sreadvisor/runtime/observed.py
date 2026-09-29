"""Runtime-observable dimension checks (Stage 6).

A handful of NFR requirements have a claim that code or infrastructure configuration makes (a call is set up to use
TLS; an autoscaler is configured) and a separate, independent fact about what actually happens while the service
runs, which only a live observability platform can see. These functions build that live evidence, in plain text, for
Gap Analysis Pass 2 to hand to the same assessor agent Pass 1 uses (see ``gap.pass2``) alongside the dataset evidence
Pass 1 already builds — the model still makes the call, now weighing both.

``RUNTIME_CHECKS`` is the extension point: "apply the same runtime cross-check logic wherever observability data can
confirm or contradict a claim made by code or infra config" (the brief's own words) is this dict, not a fixed pair of
special cases — adding a new runtime-observable requirement later is one more entry, not new plumbing.

A second, unrelated kind of runtime-only finding — a live dependency the code never declared at all, with no
recorded resilience pattern protecting it — cannot be expressed as "more evidence for an existing verdict" (Pass 1
never produced one, since it never knew the dependency existed); :func:`undocumented_dependency_gaps` builds those as
new gaps directly, deterministically, with no LLM call needed.
"""

from __future__ import annotations

from typing import Callable

from sreadvisor.gap.schema import EvidenceRef, FindingEvidence, Gap, NfrRef
from sreadvisor.runtime.cross_validate import _tokens
from sreadvisor.runtime.schema import RuntimeCrossValidation
from sreadvisor.schema.dataset import ServiceDataset
from sreadvisor.schema.runtime import ServiceTopology, TopologyEdge, TopologyNode

# Schemes with an unambiguous secure/insecure counterpart in the same family. grpc and jdbc are deliberately absent:
# TLS for gRPC is negotiated independently of the "grpc://" scheme string (Dynatrace's remoteEndpoint does not use a
# distinct "grpcs://" convention), and a bare jdbc URL says nothing about its ssl mode without inspecting its query
# string (handled separately below) — guessing either way from the scheme alone would not be honest evidence.
_SECURE_SCHEMES = {"https", "wss", "ftps", "sftp", "rediss", "ldaps", "amqps"}
_INSECURE_SCHEMES = {"http", "ws", "ftp", "redis", "ldap", "amqp"}


def classify_endpoint_security(endpoint: str) -> str:
    """"secure" | "insecure" | "inconclusive", from a live remoteEndpoint-style URL a provider recorded for a call."""
    scheme = endpoint.split("://", 1)[0].lower() if "://" in endpoint else ""
    if scheme in _SECURE_SCHEMES:
        return "secure"
    if scheme in _INSECURE_SCHEMES:
        return "insecure"
    lowered = endpoint.lower()
    if any(t in lowered for t in ("sslmode=disable", "sslmode=allow", "ssl=false")):
        return "insecure"
    if any(t in lowered for t in ("sslmode=require", "sslmode=verify", "ssl=true")):
        return "secure"
    return "inconclusive"


def _dependency_edges(topology: ServiceTopology, kinds: set[str]) -> list[tuple[TopologyEdge, TopologyNode]]:
    """The same outbound, dependency-like edges cross_validate compares (see its own docstring for why inbound
    callers are excluded), filtered to node kinds relevant to one check."""
    nodes_by_id = {n.id: n for n in topology.nodes}
    out: list[tuple[TopologyEdge, TopologyNode]] = []
    for e in topology.edges:
        if not e.attributes.get("is_dependency_like") or e.direction != "calls" or e.source != topology.service_id:
            continue
        node = nodes_by_id.get(e.target)
        if node is not None and node.kind in kinds:
            out.append((e, node))
    return out


def _tls_runtime_evidence(entry_id: str, dataset: ServiceDataset, runtime: RuntimeCrossValidation) -> str | None:
    kinds = {"service", "external_service"} if entry_id == "ENC-002" else {"database", "cache", "queue"}
    lines: list[str] = []
    for _, node in _dependency_edges(runtime.topology, kinds):
        endpoint = node.attributes.get("remoteEndpoint")
        if not isinstance(endpoint, str) or not endpoint:
            continue
        verdict = classify_endpoint_security(endpoint)
        if verdict == "inconclusive":
            continue  # nothing usable to weigh; do not spend a re-assessment on a non-finding
        lines.append(f"- {node.name}: observed endpoint \"{endpoint}\" — the live call is {verdict} in transit.")
    if not lines:
        return None
    return (f"Runtime observability evidence (Stage 5 cross-validation, provider {runtime.provider}, live system):\n"
           + "\n".join(lines) + "\nThis is what is actually observed on the wire right now, distinct from what "
           "code or config above claims; weigh it as you would any other verification source listed for this "
           "requirement — it can confirm the claim, or contradict it.")


def _autoscaling_runtime_evidence(dataset: ServiceDataset, runtime: RuntimeCrossValidation) -> str | None:
    autoscalers = dataset.infrastructure.autoscalers if dataset.infrastructure else []
    if not autoscalers:
        return None  # nothing declared to cross-check against
    series = next((s for s in runtime.metrics.series
                  if s.name == "workload.replica_count" or (s.native_name or "").endswith(("pods", "replicas"))), None)
    if series is None or not series.samples:
        return None  # no replica-count time series available at this resolution; Pass 1's dataset-only verdict stands
    values = [round(v) for _, v in series.samples]
    names = ", ".join(f"{a.name} (min {a.min_replicas or '?'}, max {a.max_replicas or '?'})" for a in autoscalers)
    window = f"{series.window_seconds}s" if series.window_seconds else "the queried window"
    if len(set(values)) > 1:
        detail = (f"replica count varied over {window} (observed values: {sorted(set(values))}) — consistent with "
                 "the autoscaler having triggered.")
    else:
        detail = f"replica count stayed constant at {values[0]} throughout {window}: no scaling event was observed."
    return (f"Runtime observability evidence (Stage 5 cross-validation, provider {runtime.provider}, live system):\n"
           f"- Autoscaler(s) declared in infrastructure: {names}.\n- {detail}\n"
           "This is what is actually observed, distinct from what the autoscaler's own configuration claims above; "
           "weigh it as you would any other verification source listed for this requirement.")


RUNTIME_CHECKS: dict[str, Callable[[ServiceDataset, RuntimeCrossValidation], str | None]] = {
    "ENC-002": lambda ds, rt: _tls_runtime_evidence("ENC-002", ds, rt),
    "ENC-004": lambda ds, rt: _tls_runtime_evidence("ENC-004", ds, rt),
    "CAP-002": _autoscaling_runtime_evidence,
}


def runtime_evidence_for(entry_id: str, dataset: ServiceDataset, runtime: RuntimeCrossValidation) -> str | None:
    """Live evidence text for one NFR entry, or ``None`` when this entry has no runtime-observable dimension, or it
    does but nothing usable was actually observed (in which case Pass 1's dataset-only verdict is left standing)."""
    check = RUNTIME_CHECKS.get(entry_id)
    return check(dataset, runtime) if check else None


# ------------------------------------------------------------------------ undocumented dependency, no protection


def _protected_name_tokens(dataset: ServiceDataset) -> set[str]:
    tokens: set[str] = set()
    for repo in dataset.repositories:
        for p in repo.reliability_patterns:
            if p.protects:
                tokens |= _tokens(p.protects)
    return tokens


def undocumented_dependency_gaps(dataset: ServiceDataset, runtime: RuntimeCrossValidation, nfr: NfrRef) -> list[Gap]:
    """One gap per live dependency Stage 5 found that no repository's code declared (``runtime.runtime_only``) and
    that no reliability pattern's ``protects`` field names — the brief's own worked example of a runtime-only gap.
    Deterministic: whether a pattern's ``protects`` text overlaps a dependency's name is a token match, the same
    comparison :mod:`runtime.cross_validate` already uses for code-vs-runtime dependency names, not a judgment call.
    ``id`` is a placeholder; the caller renumbers every gap in the merged report."""
    protected = _protected_name_tokens(dataset)
    gaps: list[Gap] = []
    for rod in runtime.runtime_only:
        if _tokens(rod.node.name) & protected:
            continue
        gaps.append(Gap(
            id="PENDING", status="missing", priority=nfr.priority, confidence="medium", nfr=nfr,
            why=(f"Runtime observability (Stage 5 cross-validation, provider {runtime.provider}) found a live "
                f"dependency, \"{rod.node.name}\" ({rod.node.kind}), that no repository's code declared and that has "
                "no reliability pattern recorded protecting it. A dependency that was never known to exist cannot "
                "have been justified or protected."),
            evidence=FindingEvidence(
                found=[EvidenceRef(note=f"observed live: {rod.node.name} ({rod.node.kind}); edge attributes "
                                        f"{rod.edge.attributes}", shows="shortfall")],
                not_found=[f"a reliability pattern protecting {rod.node.name}"],
                examined_paths=["runtime_cross_validation.runtime_only", "repositories[].reliability_patterns[].protects"]),
            warnings=["found only through Stage 5 runtime observability; Gap Analysis Pass 1 could not see this dependency"],
            detection_source="runtime",
        ))
    return gaps
