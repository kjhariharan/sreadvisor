"""Builds the dependency graph: deterministic, no LLM call — a projection of facts Stage 1 (code + infra analysis)
and, optionally, Stage 5 (runtime cross-validation) already computed, the same reuse principle as the Stage 4
unified report and Stage 6's FMEA/runbook generators.

Reuses, rather than re-derives:
* :func:`sreadvisor.fmea.build._code_components` for the dependency list (DependencyClassification, falling back to
  raw traced FlowDependency names when Stage 1's classification step never ran);
* the ``dependency_mesh_policies`` cross-reference ``consolidation.py`` already builds per dependency (matching a
  dependency's name against Istio/Linkerd traffic policies) for mesh-layer resilience, instead of re-matching names;
* :class:`~sreadvisor.runtime.schema.RuntimeCrossValidation`'s own ``matched``/``runtime_only``/``code_only`` lists
  for runtime enrichment, instead of re-running the cross-validation logic.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from sreadvisor.depgraph.platform import classify_hosting_platform
from sreadvisor.depgraph.schema import (
    DatabaseInfo,
    DependencyGraph,
    DependencyGraphEdge,
    DependencyGraphNode,
    HostingPlatform,
    KeyManagement,
    MeshInfo,
    ResiliencePattern,
    TechStack,
)
from sreadvisor.fmea.build import _code_components
from sreadvisor.runtime.cross_validate import _tokens
from sreadvisor.runtime.schema import RuntimeCrossValidation
from sreadvisor.schema.common import Evidence
from sreadvisor.schema.dataset import ServiceDataset

SERVICE_NODE_ID = "service"

_KNOWN_DB_IMAGES = {
    "postgres": "postgresql", "postgresql": "postgresql", "mysql": "mysql", "mariadb": "mariadb",
    "mongo": "mongodb", "mongodb": "mongodb", "redis": "redis", "mssql": "sqlserver",
    "oracle": "oracle", "oracle-xe": "oracle", "cassandra": "cassandra", "elasticsearch": "elasticsearch",
}
_DB_TERRAFORM_TYPE_MARKERS = ("sql_database", "rds_cluster", "rds_instance", "cloudsql", "cosmosdb", "dynamodb",
                              "elasticache", "memorydb", "documentdb")


class DepGraphError(RuntimeError):
    pass


# --------------------------------------------------------------------------------------------- service-level facts


def _tech_stack(dataset: ServiceDataset) -> TechStack:
    languages: set[str] = set()
    frameworks: set[str] = set()
    build_tools: set[str] = set()
    runtime_versions: dict[str, str] = {}
    for repo in dataset.repositories:
        fp = repo.fingerprint
        languages |= set(fp.languages)
        build_tools |= set(fp.build_tools)
        for f in fp.frameworks:
            frameworks.add(f"{f.name} {f.version}".strip() if f.version else f.name)
        runtime_versions.update(fp.runtime_versions)
    return TechStack(languages=sorted(languages), frameworks=sorted(frameworks), build_tools=sorted(build_tools),
                     runtime_versions=runtime_versions)


def _key_management(dataset: ServiceDataset) -> KeyManagement:
    mechanisms: set[str] = set()
    evidence: list[Evidence] = []
    sources = [s for repo in dataset.repositories for s in repo.secrets.sourced_from] + list(dataset.infrastructure.secrets.sourced_from)
    for s in sources:
        mechanisms.add(s.mechanism)
        if len(evidence) < 8:
            evidence.append(s.evidence)
    return KeyManagement(mechanisms=sorted(mechanisms), evidence=evidence)


def _mesh_info(dataset: ServiceDataset) -> MeshInfo | None:
    mesh = dataset.infrastructure.mesh
    if not mesh.present:
        return None
    modes = sorted({m.mode for m in mesh.mtls})
    return MeshInfo(mesh=mesh.mesh, mtls_mode=", ".join(modes) or None, evidence=[m.evidence for m in mesh.mtls[:5]])


# ---------------------------------------------------------------------------------------------------- per-dependency


_CITATION = re.compile(r"^\s*(\S+):(\d+)\b")


def _app_resilience(dataset: ServiceDataset, protecting_patterns: list[str], name: str) -> list[ResiliencePattern]:
    """Application-level patterns for this dependency.

    Preferred source: ``DependencyClassification.protecting_patterns`` (the citations the classifier itself relied
    on), each formatted ``"file:line description"`` — resolved back to the real ``ReliabilityPattern`` object by
    ``(file, line)``. This is more reliable than matching a pattern's own ``protects`` field against the dependency
    name: ``protects`` usually names the *method* it protects (e.g. ``"findAll()"``), which does not token-overlap
    the dependency's own name (e.g. ``"relational database (Spring Data JPA)"``) at all.

    Only when there are no such citations at all (Stage 1's classifier never ran, so there is nothing to resolve)
    does this fall back to the weaker ``protects``-token-overlap match, as a best-effort signal rather than none.
    """
    by_loc = {(p.evidence.file, p.evidence.line): p for repo in dataset.repositories for p in repo.reliability_patterns}
    out: list[ResiliencePattern] = []
    if protecting_patterns:
        for citation in protecting_patterns:
            m = _CITATION.match(citation)
            p = by_loc.get((m.group(1), int(m.group(2)))) if m else None
            if p:
                out.append(ResiliencePattern(pattern=p.pattern, layer="application", mechanism=p.mechanism,
                                             parameters=dict(p.parameters), evidence=[p.evidence]))
        return out
    toks = _tokens(name)
    if not toks:
        return []
    for repo in dataset.repositories:
        for p in repo.reliability_patterns:
            if p.protects and _tokens(p.protects) & toks:
                out.append(ResiliencePattern(pattern=p.pattern, layer="application", mechanism=p.mechanism,
                                             parameters=dict(p.parameters), evidence=[p.evidence]))
    return out


def _mesh_resilience(dataset: ServiceDataset, name: str) -> list[ResiliencePattern]:
    """Reads the ``dependency_mesh_policies`` cross-reference ``consolidation.py`` already built for this exact
    dependency (matching its name against Istio/Linkerd traffic policies) rather than re-matching names here."""
    xref = next((x for x in dataset.cross_references if x.kind == "dependency_mesh_policies" and x.subject == name), None)
    if xref is None:
        return []
    matched_kinds = set(xref.facts.get("matched_mesh_policy_kinds") or [])
    matched_hosts = set(xref.facts.get("matched_mesh_hosts") or [])
    if not matched_kinds:
        return []
    out: list[ResiliencePattern] = []
    for policy in dataset.infrastructure.mesh.traffic_policies:
        if policy.kind in matched_kinds and policy.host in matched_hosts:
            out.append(ResiliencePattern(pattern=policy.kind, layer="mesh", mechanism=policy.resource,
                                         parameters={k: str(v) for k, v in policy.settings.items()}, evidence=[policy.evidence]))
    return out


def _database_candidates(dataset: ServiceDataset) -> list[tuple[str, str | None, Evidence]]:
    """Every (engine, version, evidence) a Terraform managed-database resource or a container image tag
    (``postgres:14.2``) names, anywhere in the infrastructure. Deliberately not matched against any one
    dependency's name here: a dependency like "relational database (Spring Data JPA)" describes a *role*, not a
    product, and does not token-overlap a real engine/image name at all (confirmed against the Pet Clinic pilot
    dataset, which names its dependency this way while its infra literally says "postgres"/"mysql") — see
    :func:`_infer_database` for how these candidates are actually attributed."""
    out: list[tuple[str, str | None, Evidence]] = []
    for tr in dataset.infrastructure.terraform_resources:
        if any(marker in tr.type for marker in _DB_TERRAFORM_TYPE_MARKERS):
            version = tr.attributes.get("engine_version") or tr.attributes.get("database_version")
            # The resource type alone rarely names the engine for a managed-database resource (Cloud SQL's own
            # type, for example, is generic; the engine lives in an attribute like database_version="POSTGRES_14").
            haystack = f"{tr.type} {tr.attributes.get('engine', '')} {version or ''}".lower()
            engine = next((v for k, v in _KNOWN_DB_IMAGES.items() if k in haystack), None)
            if engine:
                out.append((engine, str(version) if version else None, tr.evidence))
    # K8sContainer itself carries no evidence pointer; its containing workload's is the closest real citation.
    images = [(c.image, w.evidence) for w in dataset.infrastructure.workloads for c in w.containers if c.image]
    images += [(s.image, s.evidence) for s in dataset.infrastructure.compose_services if s.image]
    for image, evidence in images:
        base = image.split("/")[-1].split("@")[0]
        img_name, _, tag = base.partition(":")
        engine = _KNOWN_DB_IMAGES.get(img_name.lower())
        if engine:
            out.append((engine, tag or None, evidence))
    return out


def _infer_database(candidates: list[tuple[str, str | None, Evidence]], datastore_count: int) -> DatabaseInfo:
    """Attributed only when it is safe to: exactly one ``datastore``-kind dependency exists in the whole dataset, so
    every database signal found anywhere in the infra can only belong to it. With more than one datastore
    dependency there is no reliable way to tell which infra resource backs which (Stage 1 records no such link),
    so nothing is guessed — every one of them is left null rather than risk misattributing engine/version across
    dependencies that may be genuinely different databases."""
    if not candidates or datastore_count != 1:
        return DatabaseInfo()
    engines = sorted({c[0] for c in candidates})
    versions = sorted({c[1] for c in candidates if c[1]})
    evidence = [c[2] for c in candidates]
    return DatabaseInfo(engine=", ".join(engines), version=", ".join(versions) or None, evidence=evidence)


def _dedupe_resilience(patterns: list[ResiliencePattern]) -> list[ResiliencePattern]:
    """Merges entries that are the same (pattern, layer, mechanism) — for example the same ``@Cacheable`` annotation
    cited twice for two overloaded methods of the one dependency — into one, combining their evidence, so the graph
    reads as "this edge has X protection, seen at these N locations" rather than repeating the same line N times."""
    merged: dict[tuple[str, str, str], ResiliencePattern] = {}
    for p in patterns:
        key = (p.pattern, p.layer, p.mechanism)
        existing = merged.get(key)
        if existing is None:
            merged[key] = p.model_copy(deep=True)
            continue
        for e in p.evidence:
            if not any(e.file == existing_e.file and e.line == existing_e.line for existing_e in existing.evidence):
                existing.evidence.append(e)
    return list(merged.values())


# --------------------------------------------------------------------------------------------------------- runtime


def _apply_runtime(dataset: ServiceDataset, runtime: RuntimeCrossValidation, nodes: list[DependencyGraphNode],
                   edges: list[DependencyGraphEdge], next_seq: int) -> list[str]:
    warnings: list[str] = []

    def edge_for(name: str) -> DependencyGraphEdge | None:
        toks = _tokens(name)
        for n in nodes:
            if n.id == SERVICE_NODE_ID:
                continue
            if _tokens(n.name) & toks:
                e = next((e for e in edges if e.target == n.id), None)
                if e is not None:
                    return e
        return None

    for m in runtime.matched:
        e = edge_for(m.code_name)
        if e is not None:
            e.runtime_status = "matched_high" if m.confidence == "high" else "matched_medium"
        else:
            warnings.append(f"runtime cross-validation matched {m.code_name!r} but no corresponding graph edge was "
                            "found; the runtime cross-validation may be for a different dataset than this one")
    for c in runtime.code_only:
        e = edge_for(c.name)
        if e is not None:
            e.runtime_status = "code_only"
    for rod in runtime.runtime_only:
        node_id = f"dep-{next_seq:03d}"
        next_seq += 1
        nodes.append(DependencyGraphNode(id=node_id, name=rod.node.name, kind=rod.node.kind, origin="runtime_only"))
        edges.append(DependencyGraphEdge(id=f"edge-{node_id}", source=SERVICE_NODE_ID, target=node_id, kind=rod.node.kind,
                                        classification="unknown", runtime_status="runtime_only"))
    return warnings


# ---------------------------------------------------------------------------------------------------------- build


def build_dependency_graph(dataset: ServiceDataset, runtime: RuntimeCrossValidation | None = None) -> DependencyGraph:
    if runtime is not None and runtime.service_name != dataset.service_name:
        raise DepGraphError(
            f"the runtime cross-validation is for {runtime.service_name!r} but the dataset is for {dataset.service_name!r}")

    warnings: list[str] = []
    nodes: list[DependencyGraphNode] = [DependencyGraphNode(
        id=SERVICE_NODE_ID, name=dataset.service_name, kind="service", tech_stack=_tech_stack(dataset),
        hosting_platform=classify_hosting_platform(dataset.infrastructure), key_management=_key_management(dataset),
        mesh=_mesh_info(dataset))]
    if nodes[0].hosting_platform.kind == "unknown":
        warnings.append("hosting platform could not be determined from the dataset (no Kubernetes workload, "
                        "Terraform resource or Docker Compose service found)")

    components = _code_components(dataset)
    if not components:
        warnings.append("no traced dependency was found in the dataset (transaction flow tracing may have been "
                        "skipped, or the service genuinely has no external dependencies)")

    datastore_count = sum(1 for c in components if c.kind == "datastore")
    db_candidates = _database_candidates(dataset)
    if db_candidates and datastore_count > 1:
        warnings.append(f"{len(db_candidates)} database signal(s) found in the infrastructure "
                        f"({', '.join(sorted({c[0] for c in db_candidates}))}), but {datastore_count} datastore "
                        "dependencies exist and Stage 1 records no link between a specific one and a specific infra "
                        "resource, so engine/version were not attributed to any of them")

    edges: list[DependencyGraphEdge] = []
    seq = 1
    for c in components:
        node_id = f"dep-{seq:03d}"
        database = _infer_database(db_candidates, datastore_count) if c.kind == "datastore" else None
        nodes.append(DependencyGraphNode(id=node_id, name=c.name, kind=c.kind, origin="code_and_infra",
                                         database=database, evidence=c.evidence))
        resilience = _dedupe_resilience(_app_resilience(dataset, c.protecting_patterns, c.name) + _mesh_resilience(dataset, c.name))
        edges.append(DependencyGraphEdge(id=f"edge-{node_id}", source=SERVICE_NODE_ID, target=node_id, kind=c.kind,
                                        classification=c.classification, blast_radius=list(c.blast_radius),
                                        resilience=resilience, evidence=c.evidence))
        seq += 1

    if runtime is not None:
        warnings += _apply_runtime(dataset, runtime, nodes, edges, seq)

    inputs: dict[str, Any] = {
        "dataset": {"service_name": dataset.service_name, "schema_version": dataset.schema_version,
                    "generated_at": dataset.generated_at.isoformat()},
        "runtime_cross_validation": {"provider": runtime.provider, "generated_at": runtime.generated_at.isoformat()} if runtime else None,
        "sources_used": [s for s in ("stage1_dataset", "runtime_cross_validation" if runtime else None) if s],
    }
    return DependencyGraph(service_name=dataset.service_name, generated_at=datetime.now(timezone.utc), inputs=inputs,
                           nodes=nodes, edges=edges, warnings=warnings)
