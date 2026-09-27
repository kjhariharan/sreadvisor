"""Stage 1 consolidated dataset: facts only, one per service.

Nothing in this module expresses a judgment about adequacy or a gap; that is the job of
later stages, which run against an evolving requirements list. The only inferred content is
what the brief explicitly asks the LLM to infer (transaction flows, reliability pattern
adjudication, hard vs degradable classification, business context), and each such item
carries file:line evidence.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

from sreadvisor.schema.common import Evidence

SCHEMA_VERSION = "1.1"  # 1.1 adds fingerprint.unparsed_manifests

# --------------------------------------------------------------------------- tech stack


class Dependency(BaseModel):
    ecosystem: str  # maven, gradle, npm, pypi, nuget
    group: str | None = None
    name: str
    version: str | None = None
    scope: str | None = None
    categories: list[str] = Field(default_factory=list)  # datastore, http_client, messaging, ...
    evidence: Evidence


class Framework(BaseModel):
    name: str
    version: str | None = None
    evidence: list[Evidence] = Field(default_factory=list)


class UnparsedManifest(BaseModel):
    """A manifest of a stack Stage 1 has no parser for. Recorded so an unknown stack is never silently skipped."""

    file: str
    stack: str


class TechStackFingerprint(BaseModel):
    languages: list[str] = Field(default_factory=list)
    frameworks: list[Framework] = Field(default_factory=list)
    build_tools: list[str] = Field(default_factory=list)
    runtime_versions: dict[str, str] = Field(default_factory=dict)
    manifests: list[str] = Field(default_factory=list)
    dependencies: list[Dependency] = Field(default_factory=list)
    unparsed_manifests: list[UnparsedManifest] = Field(default_factory=list)
    parse_errors: list[str] = Field(default_factory=list)


# ------------------------------------------------------------------- flows and patterns


class EntryPoint(BaseModel):
    id: str  # stable graph node id
    kind: Literal["rest", "messaging", "scheduled", "grpc", "graphql", "event", "cli", "other"]
    symbol: str
    route: str | None = None
    http_method: str | None = None
    annotation: str | None = None
    evidence: Evidence


class FlowStep(BaseModel):
    order: int
    layer: str  # controller | service | repository | client | datastore | messaging | cache | other
    symbol: str
    action: str
    target_type: str | None = None  # internal | datastore | cache | http_service | messaging | filesystem | other
    target_name: str | None = None
    evidence: Evidence


class FlowDependency(BaseModel):
    name: str
    kind: str  # datastore | cache | http_service | messaging | filesystem | external_api | other
    evidence: Evidence


class TransactionFlow(BaseModel):
    entry_point: EntryPoint
    summary: str
    steps: list[FlowStep] = Field(default_factory=list)
    dependencies: list[FlowDependency] = Field(default_factory=list)


class ReliabilityPattern(BaseModel):
    pattern: str  # retry | circuit_breaker | timeout | fallback | bulkhead | rate_limiter | cache | ...
    mechanism: str  # library / annotation / setting that implements it
    protects: str | None = None  # symbol or dependency it applies to
    parameters: dict[str, str] = Field(default_factory=dict)
    note: str | None = None
    evidence: Evidence


class DependencyClassification(BaseModel):
    dependency: str
    kind: str
    classification: Literal["hard_failure", "gracefully_degradable"]
    rationale: str
    protecting_patterns: list[str] = Field(default_factory=list)
    # Flows (entry point symbols) that still complete in reduced form when this dependency is down.
    degradable_flows: list[str] = Field(default_factory=list)
    # Flows that fail if it is down: derived from the flow map (flows using it minus degradable_flows).
    blast_radius: list[str] = Field(default_factory=list)
    blast_radius_description: str | None = None
    evidence: list[Evidence] = Field(default_factory=list)


class BusinessContext(BaseModel):
    capability: str  # e.g. "Veterinary clinic management"
    category: str  # shopping_cart | order_management | notification | payments | ... | other
    rationale: str
    domain_entities: list[str] = Field(default_factory=list)
    key_operations: list[str] = Field(default_factory=list)
    confidence: Literal["high", "medium", "low"] = "medium"
    evidence: list[Evidence] = Field(default_factory=list)


# ---------------------------------------------------------------------------- capacity


class CapacitySetting(BaseModel):
    layer: Literal["application", "infrastructure"]
    category: str  # db_pool | thread_pool | server_connections | rate_limiter | resources | replicas | autoscaling
    key: str
    value: str
    origin: Literal["explicit", "framework_default"] = "explicit"
    subject: str | None = None  # e.g. workload / container name for infra
    evidence: Evidence | None = None


# ---------------------------------------------------------------------- secrets / crypto


class SecretFinding(BaseModel):
    kind: Literal[
        "hardcoded_credential",
        "default_value_in_placeholder",
        "private_key",
        "credentials_in_connection_string",
        "plaintext_secret_manifest",
    ]
    key: str | None = None
    value_redacted: str
    location_type: Literal["source", "config", "iac"]
    evidence: Evidence


class SecretSource(BaseModel):
    mechanism: Literal[
        "environment_variable", "vault", "secrets_manager", "kubernetes_secret", "kubernetes_configmap", "external_secrets"
    ]
    name: str | None = None
    detail: str | None = None
    location_type: Literal["source", "config", "iac"]
    evidence: Evidence


class SecretsAnalysis(BaseModel):
    hardcoded: list[SecretFinding] = Field(default_factory=list)
    sourced_from: list[SecretSource] = Field(default_factory=list)


class EncryptionAuditFact(BaseModel):
    domain: Literal["at_rest", "in_transit", "audit", "retention"]
    subject: str
    setting: str
    value: str
    status: Literal["enabled", "disabled", "plaintext", "configured", "detected"]
    layer: Literal["code", "config", "iac"]
    evidence: Evidence


class EncryptionAuditAnalysis(BaseModel):
    facts: list[EncryptionAuditFact] = Field(default_factory=list)


# --------------------------------------------------------------------------- telemetry


class TelemetryLibrary(BaseModel):
    library: str
    kind: str  # micrometer | opentelemetry | prometheus_client | dropwizard | kafka_client | ...
    version: str | None = None
    configuration: list[dict[str, Any]] = Field(default_factory=list)  # {key, value, evidence}
    documented_metrics: list[str] = Field(default_factory=list)
    documented_metrics_source: str = "curated library-documentation catalogue"
    custom_metrics: list[dict[str, Any]] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)


class TelemetryAnalysis(BaseModel):
    libraries: list[TelemetryLibrary] = Field(default_factory=list)
    note: str = (
        "Metrics listed here are emitted by application-level library instrumentation. They are distinct from "
        "the Dynatrace OneAgent default telemetry catalogue and must not be assumed to overlap or duplicate it."
    )


# ----------------------------------------------------------------------- per-repo result


class StepStatus(BaseModel):
    step: str
    status: Literal["ok", "no_findings", "skipped", "failed"]
    detail: str | None = None
    count: int | None = None


class RepoAnalysis(BaseModel):
    repo: str
    path: str
    fingerprint: TechStackFingerprint
    entry_points: list[EntryPoint] = Field(default_factory=list)
    transaction_flows: list[TransactionFlow] = Field(default_factory=list)
    reliability_patterns: list[ReliabilityPattern] = Field(default_factory=list)
    dependency_classification: list[DependencyClassification] = Field(default_factory=list)
    business_context: BusinessContext | None = None
    application_capacity: list[CapacitySetting] = Field(default_factory=list)
    secrets: SecretsAnalysis = Field(default_factory=SecretsAnalysis)
    encryption_audit: EncryptionAuditAnalysis = Field(default_factory=EncryptionAuditAnalysis)
    telemetry: TelemetryAnalysis = Field(default_factory=TelemetryAnalysis)
    graph_stats: dict[str, Any] = Field(default_factory=dict)
    status: list[StepStatus] = Field(default_factory=list)


# ------------------------------------------------------------------------------- infra


class Probe(BaseModel):
    type: str  # http | tcp | exec | grpc
    target: str | None = None
    initial_delay_seconds: int | None = None
    period_seconds: int | None = None
    timeout_seconds: int | None = None
    failure_threshold: int | None = None


class K8sContainer(BaseModel):
    name: str
    image: str | None = None
    ports: list[int] = Field(default_factory=list)
    requests: dict[str, str] = Field(default_factory=dict)
    limits: dict[str, str] = Field(default_factory=dict)
    liveness: Probe | None = None
    readiness: Probe | None = None
    startup: Probe | None = None
    env_from_secrets: list[str] = Field(default_factory=list)  # "ENV_NAME <- secret/key"
    env_from_configmaps: list[str] = Field(default_factory=list)
    run_as_non_root: bool | None = None


class K8sWorkload(BaseModel):
    kind: str
    name: str
    namespace: str | None = None
    replicas: str | None = None  # string: may be a template value in Helm
    strategy: str | None = None
    max_surge: str | None = None
    max_unavailable: str | None = None
    termination_grace_period_seconds: int | None = None
    containers: list[K8sContainer] = Field(default_factory=list)
    has_pod_anti_affinity: bool = False
    has_topology_spread: bool = False
    service_account: str | None = None
    mesh_injection: str | None = None
    templated: bool = False
    evidence: Evidence


class Autoscaler(BaseModel):
    kind: str  # HorizontalPodAutoscaler | ScaledObject | VerticalPodAutoscaler | terraform:...
    name: str
    target: str | None = None
    min_replicas: str | None = None
    max_replicas: str | None = None
    metrics: list[str] = Field(default_factory=list)
    evidence: Evidence


class DisruptionBudget(BaseModel):
    name: str
    selector: str | None = None
    min_available: str | None = None
    max_unavailable: str | None = None
    evidence: Evidence


class K8sService(BaseModel):
    name: str
    type: str | None = None
    ports: list[str] = Field(default_factory=list)
    selector: str | None = None
    evidence: Evidence


class K8sIngress(BaseModel):
    name: str
    hosts: list[str] = Field(default_factory=list)
    tls_hosts: list[str] = Field(default_factory=list)
    evidence: Evidence


class NetworkPolicyFact(BaseModel):
    name: str
    policy_types: list[str] = Field(default_factory=list)
    evidence: Evidence


class ComposeService(BaseModel):
    name: str
    image: str | None = None
    replicas: str | None = None
    restart: str | None = None
    healthcheck: bool = False
    limits: dict[str, str] = Field(default_factory=dict)
    ports: list[str] = Field(default_factory=list)
    depends_on: list[str] = Field(default_factory=list)
    evidence: Evidence


class DockerfileFact(BaseModel):
    file: str
    base_images: list[str] = Field(default_factory=list)
    user: str | None = None
    has_healthcheck: bool = False
    exposed_ports: list[str] = Field(default_factory=list)
    evidence: Evidence


class TerraformResource(BaseModel):
    type: str
    name: str
    provider: str
    attributes: dict[str, Any] = Field(default_factory=dict)
    evidence: Evidence


class HelmChart(BaseModel):
    name: str
    version: str | None = None
    path: str
    rendered_with_helm: bool
    values_of_interest: dict[str, Any] = Field(default_factory=dict)
    templates: list[str] = Field(default_factory=list)
    evidence: Evidence


class RollbackFact(BaseModel):
    mode: Literal["automated", "manual", "none_defined"]
    evidence: list[Evidence] = Field(default_factory=list)


class MigrationFact(BaseModel):
    present: bool
    tool: str | None = None
    separate_step: bool | None = None  # None when not determinable
    evidence: list[Evidence] = Field(default_factory=list)


class PipelineAnalysis(BaseModel):
    system: str  # github_actions | gitlab_ci | jenkins | harness | ucd | azure_pipelines | other
    file: str
    name: str | None = None
    deploys: bool = False
    deployment_strategy: Literal["rolling", "blue_green", "canary", "recreate", "unknown", "none"] = "unknown"
    strategy_evidence: list[Evidence] = Field(default_factory=list)
    rollback: RollbackFact = Field(default_factory=lambda: RollbackFact(mode="none_defined"))
    db_migration: MigrationFact = Field(default_factory=lambda: MigrationFact(present=False))
    deploy_steps: list[str] = Field(default_factory=list)


class MeshMtls(BaseModel):
    scope: str
    mode: str
    evidence: Evidence


class MeshTrafficPolicy(BaseModel):
    host: str
    kind: str  # retry | timeout | circuit_breaker | connection_pool | routing | fault_injection | mirror | load_balancing
    settings: dict[str, Any] = Field(default_factory=dict)
    resource: str
    evidence: Evidence


class MeshAnalysis(BaseModel):
    present: bool = False
    mesh: str | None = None  # istio | linkerd
    injection: list[str] = Field(default_factory=list)
    mtls: list[MeshMtls] = Field(default_factory=list)
    traffic_policies: list[MeshTrafficPolicy] = Field(default_factory=list)
    authorization_policies: list[str] = Field(default_factory=list)


class InfraAnalysis(BaseModel):
    roots: list[str] = Field(default_factory=list)
    workloads: list[K8sWorkload] = Field(default_factory=list)
    autoscalers: list[Autoscaler] = Field(default_factory=list)
    disruption_budgets: list[DisruptionBudget] = Field(default_factory=list)
    services: list[K8sService] = Field(default_factory=list)
    ingresses: list[K8sIngress] = Field(default_factory=list)
    network_policies: list[NetworkPolicyFact] = Field(default_factory=list)
    compose_services: list[ComposeService] = Field(default_factory=list)
    dockerfiles: list[DockerfileFact] = Field(default_factory=list)
    helm_charts: list[HelmChart] = Field(default_factory=list)
    terraform_resources: list[TerraformResource] = Field(default_factory=list)
    pipelines: list[PipelineAnalysis] = Field(default_factory=list)
    mesh: MeshAnalysis = Field(default_factory=MeshAnalysis)
    secrets: SecretsAnalysis = Field(default_factory=SecretsAnalysis)
    encryption_audit: EncryptionAuditAnalysis = Field(default_factory=EncryptionAuditAnalysis)
    capacity: list[CapacitySetting] = Field(default_factory=list)
    kubernetes_secret_definitions: list[str] = Field(default_factory=list)  # "name: key1,key2"
    files_scanned: int = 0
    parse_errors: list[str] = Field(default_factory=list)
    status: list[StepStatus] = Field(default_factory=list)


# --------------------------------------------------------------------- consolidation


class ObservabilityBinding(BaseModel):
    provider: str
    service_id: str
    options: dict[str, Any] = Field(default_factory=dict)  # never contains tokens


class CrossReference(BaseModel):
    """A factual link between findings from different modules (no adequacy judgment)."""

    kind: str
    subject: str
    facts: dict[str, Any] = Field(default_factory=dict)
    evidence: list[Evidence] = Field(default_factory=list)


class CapacityPosture(BaseModel):
    application: list[CapacitySetting] = Field(default_factory=list)
    infrastructure: list[CapacitySetting] = Field(default_factory=list)


class ServiceDataset(BaseModel):
    schema_version: str = SCHEMA_VERSION
    service_name: str
    generated_at: datetime
    model_backend: str | None = None
    observability: ObservabilityBinding
    business_context: BusinessContext | None = None
    repositories: list[RepoAnalysis] = Field(default_factory=list)
    infrastructure: InfraAnalysis = Field(default_factory=InfraAnalysis)
    capacity_posture: CapacityPosture = Field(default_factory=CapacityPosture)
    cross_references: list[CrossReference] = Field(default_factory=list)
    completeness: dict[str, Any] = Field(default_factory=dict)
