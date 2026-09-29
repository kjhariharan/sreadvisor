"""Dependency graph: one service's architecture as nodes and edges, enriched with facts already captured elsewhere
in the pipeline (tech stack, hosting platform, key management, database, mesh/Istio, resilience) — no new
judgment, no LLM call. Like Stage 4's unified report, this is a projection of facts other stages already computed.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

from sreadvisor.schema.common import Evidence

DEPGRAPH_SCHEMA_VERSION = "1.0"

NodeOrigin = Literal["code_and_infra", "runtime_only"]
RuntimeStatus = Literal["matched_high", "matched_medium", "runtime_only", "code_only", "not_checked"]
ResilienceLayer = Literal["application", "mesh"]


class TechStack(BaseModel):
    languages: list[str] = Field(default_factory=list)
    frameworks: list[str] = Field(default_factory=list)  # "name version"
    build_tools: list[str] = Field(default_factory=list)
    runtime_versions: dict[str, str] = Field(default_factory=dict)


class HostingPlatform(BaseModel):
    kind: str  # kubernetes | openshift | gke | eks | aks | docker_compose | unknown
    detail: str | None = None
    evidence: list[Evidence] = Field(default_factory=list)


class KeyManagement(BaseModel):
    mechanisms: list[str] = Field(default_factory=list)  # deduped SecretSource.mechanism values
    evidence: list[Evidence] = Field(default_factory=list)


class DatabaseInfo(BaseModel):
    engine: str | None = None
    version: str | None = None
    evidence: list[Evidence] = Field(default_factory=list)


class MeshInfo(BaseModel):
    mesh: str | None = None  # istio | linkerd
    mtls_mode: str | None = None
    evidence: list[Evidence] = Field(default_factory=list)


class ResiliencePattern(BaseModel):
    pattern: str  # retry | circuit_breaker | timeout | fallback | bulkhead | rate_limiter | cache | ...
    layer: ResilienceLayer
    mechanism: str
    parameters: dict[str, str] = Field(default_factory=dict)
    evidence: list[Evidence] = Field(default_factory=list)


class DependencyGraphNode(BaseModel):
    id: str
    name: str
    kind: str  # service | datastore | cache | messaging | external_api | other
    origin: NodeOrigin = "code_and_infra"
    tech_stack: TechStack | None = None  # populated on the service's own node
    hosting_platform: HostingPlatform | None = None  # populated on the service's own node
    key_management: KeyManagement | None = None  # populated on the service's own node
    database: DatabaseInfo | None = None  # populated on datastore-kind dependency nodes, when determinable
    mesh: MeshInfo | None = None  # populated when a mesh is present
    evidence: list[Evidence] = Field(default_factory=list)


class DependencyGraphEdge(BaseModel):
    id: str
    source: str  # node id
    target: str  # node id
    kind: str  # mirrors FlowDependency.kind: datastore | cache | http_service | messaging | filesystem | external_api | other
    classification: Literal["hard_failure", "gracefully_degradable", "unknown"] = "unknown"
    blast_radius: list[str] = Field(default_factory=list)  # entry point symbols
    resilience: list[ResiliencePattern] = Field(default_factory=list)
    runtime_status: RuntimeStatus = "not_checked"
    evidence: list[Evidence] = Field(default_factory=list)


class DependencyGraph(BaseModel):
    schema_version: str = DEPGRAPH_SCHEMA_VERSION
    service_name: str
    generated_at: datetime
    inputs: dict[str, Any] = Field(default_factory=dict)
    nodes: list[DependencyGraphNode] = Field(default_factory=list)
    edges: list[DependencyGraphEdge] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
