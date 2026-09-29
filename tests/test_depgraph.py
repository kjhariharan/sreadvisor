"""Dependency graph: deterministic, no LLM call. Node/edge construction from a hand-built dataset, the hosting
platform classifier, resilience merging (application + mesh), database engine/version inference, runtime
enrichment, HTML rendering, and CLI wiring."""

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from sreadvisor import cli
from sreadvisor.depgraph.build import DepGraphError, build_dependency_graph
from sreadvisor.depgraph.html import render_html
from sreadvisor.depgraph.platform import classify_hosting_platform
from sreadvisor.runtime.schema import CrossValidationSummary, MatchedDependency, RuntimeCrossValidation, RuntimeOnlyDependency
from sreadvisor.schema.common import Evidence
from sreadvisor.schema.dataset import (
    Autoscaler,
    ComposeService,
    CrossReference,
    DependencyClassification,
    EntryPoint,
    FlowDependency,
    InfraAnalysis,
    K8sContainer,
    K8sWorkload,
    MeshAnalysis,
    MeshMtls,
    MeshTrafficPolicy,
    RepoAnalysis,
    ReliabilityPattern,
    SecretSource,
    SecretsAnalysis,
    ServiceDataset,
    TechStackFingerprint,
    TerraformResource,
    TransactionFlow,
)
from sreadvisor.schema.runtime import ServiceMetrics, ServiceTopology, TopologyEdge, TopologyNode

SID = "SERVICE-1"
EP = EntryPoint(id="ep1", kind="rest", symbol="C.get()", route="/x", evidence=Evidence(file="C.java", line=1))
EV = Evidence(file="C.java", line=1)


def _dataset(*, dependency_classification=None, transaction_flows=None, reliability_patterns=None,
            secrets_sourced_from=None, infra=None, cross_references=None) -> ServiceDataset:
    flows = transaction_flows if transaction_flows is not None else [TransactionFlow(entry_point=EP, summary="s")]
    repo = RepoAnalysis(repo="orders", path="/r", fingerprint=TechStackFingerprint(languages=["Java"], build_tools=["gradle"]),
                        entry_points=[EP], transaction_flows=flows, dependency_classification=dependency_classification or [],
                        reliability_patterns=reliability_patterns or [],
                        secrets=SecretsAnalysis(sourced_from=secrets_sourced_from or []))
    return ServiceDataset(service_name="orders", generated_at=datetime.now(timezone.utc),
                          observability={"provider": "dynatrace", "service_id": SID}, repositories=[repo],
                          infrastructure=infra or InfraAnalysis(), cross_references=cross_references or [])


def _dc(name="orders-db", kind="datastore", classification="hard_failure", protecting_patterns=None, blast_radius=None) -> DependencyClassification:
    return DependencyClassification(dependency=name, kind=kind, classification=classification, rationale="r",
                                    protecting_patterns=protecting_patterns or [], blast_radius=blast_radius or ["C.get()"],
                                    evidence=[EV])


# ------------------------------------------------------------------------------------------------- basic construction


def test_service_node_carries_tech_stack_key_management_and_mesh():
    infra = InfraAnalysis(mesh=MeshAnalysis(present=True, mesh="istio", mtls=[MeshMtls(scope="mesh-wide", mode="STRICT", evidence=EV)]),
                          secrets=SecretsAnalysis(sourced_from=[SecretSource(mechanism="vault", location_type="config", evidence=EV)]))
    ds = _dataset(infra=infra, secrets_sourced_from=[SecretSource(mechanism="kubernetes_secret", location_type="iac", evidence=EV)])
    graph = build_dependency_graph(ds)
    svc = next(n for n in graph.nodes if n.id == "service")
    assert svc.tech_stack.languages == ["Java"] and svc.tech_stack.build_tools == ["gradle"]
    assert sorted(svc.key_management.mechanisms) == ["kubernetes_secret", "vault"]
    assert svc.mesh.mesh == "istio" and svc.mesh.mtls_mode == "STRICT"


def test_dependency_node_from_classification():
    ds = _dataset(dependency_classification=[_dc()])
    graph = build_dependency_graph(ds)
    deps = [n for n in graph.nodes if n.id != "service"]
    assert len(deps) == 1 and deps[0].name == "orders-db" and deps[0].kind == "datastore"
    edge = graph.edges[0]
    assert edge.classification == "hard_failure" and edge.blast_radius == ["C.get()"]


def test_falls_back_to_flow_dependencies_when_no_classification_exists():
    flow = TransactionFlow(entry_point=EP, summary="s", dependencies=[FlowDependency(name="legacy-billing", kind="http_service", evidence=EV)])
    ds = _dataset(dependency_classification=[], transaction_flows=[flow])
    graph = build_dependency_graph(ds)
    deps = [n for n in graph.nodes if n.id != "service"]
    assert len(deps) == 1 and deps[0].name == "legacy-billing"
    assert graph.edges[0].classification == "unknown"


def test_no_dependencies_warns_but_still_produces_the_service_node():
    ds = _dataset(transaction_flows=[])
    graph = build_dependency_graph(ds)
    assert [n.id for n in graph.nodes] == ["service"]
    assert any("no traced dependency" in w for w in graph.warnings)


# --------------------------------------------------------------------------------------------------------- resilience


def test_application_resilience_resolved_via_protecting_pattern_citation_not_name_overlap():
    """protects usually names the METHOD ("findAll()"), not the dependency ("orders-db") — matching must go through
    the file:line citation in protecting_patterns, not a token overlap against the dependency name."""
    pattern = ReliabilityPattern(pattern="cache", mechanism='@Cacheable("orders")', protects="findAll()",
                                 parameters={"cache_name": "orders"}, evidence=Evidence(file="Repo.java", line=10))
    dc = _dc(protecting_patterns=["Repo.java:10 cache via @Cacheable"])
    ds = _dataset(dependency_classification=[dc], reliability_patterns=[pattern])
    graph = build_dependency_graph(ds)
    res = graph.edges[0].resilience
    assert len(res) == 1 and res[0].pattern == "cache" and res[0].layer == "application" and res[0].parameters == {"cache_name": "orders"}


def test_duplicate_citations_for_the_same_pattern_are_merged_with_combined_evidence():
    p1 = ReliabilityPattern(pattern="transaction", mechanism="@Transactional", protects="findAll()", evidence=Evidence(file="R.java", line=10))
    p2 = ReliabilityPattern(pattern="transaction", mechanism="@Transactional", protects="findById()", evidence=Evidence(file="R.java", line=20))
    dc = _dc(protecting_patterns=["R.java:10 transaction", "R.java:20 transaction"])
    ds = _dataset(dependency_classification=[dc], reliability_patterns=[p1, p2])
    res = build_dependency_graph(ds).edges[0].resilience
    assert len(res) == 1 and len(res[0].evidence) == 2


def test_mesh_resilience_from_the_existing_dependency_mesh_policies_cross_reference():
    policy = MeshTrafficPolicy(host="orders-db.svc", kind="retry", settings={"attempts": "3"}, resource="DestinationRule/orders-db",
                              evidence=Evidence(file="dr.yaml", line=1))
    xref = CrossReference(kind="dependency_mesh_policies", subject="orders-db",
                          facts={"matched_mesh_policy_kinds": ["retry"], "matched_mesh_hosts": ["orders-db.svc"]})
    ds = _dataset(dependency_classification=[_dc()],
                 infra=InfraAnalysis(mesh=MeshAnalysis(present=True, mesh="istio", traffic_policies=[policy])),
                 cross_references=[xref])
    res = build_dependency_graph(ds).edges[0].resilience
    assert len(res) == 1 and res[0].layer == "mesh" and res[0].pattern == "retry" and res[0].parameters == {"attempts": "3"}


def test_no_resilience_anywhere_is_an_empty_list_not_fabricated():
    ds = _dataset(dependency_classification=[_dc()])
    assert build_dependency_graph(ds).edges[0].resilience == []


def test_fallback_dependency_uses_weaker_protects_token_overlap():
    """Only reached when there is no DependencyClassification at all (nothing to cite a file:line from)."""
    pattern = ReliabilityPattern(pattern="retry", mechanism="@Retryable", protects="legacy-billing", evidence=EV)
    flow = TransactionFlow(entry_point=EP, summary="s", dependencies=[FlowDependency(name="legacy-billing", kind="http_service", evidence=EV)])
    ds = _dataset(dependency_classification=[], transaction_flows=[flow], reliability_patterns=[pattern])
    res = build_dependency_graph(ds).edges[0].resilience
    assert len(res) == 1 and res[0].pattern == "retry"


# ---------------------------------------------------------------------------------------------------------- database


def test_database_engine_attributed_when_exactly_one_datastore_dependency():
    workload = K8sWorkload(kind="Deployment", name="db", containers=[K8sContainer(name="db", image="postgres:14.2")], evidence=EV)
    ds = _dataset(dependency_classification=[_dc()], infra=InfraAnalysis(workloads=[workload]))
    node = next(n for n in build_dependency_graph(ds).nodes if n.kind == "datastore")
    assert node.database.engine == "postgresql" and node.database.version == "14.2" and node.database.evidence


def test_database_via_terraform_resource():
    tr = TerraformResource(type="google_sql_database_instance", name="orders_db", provider="google",
                           attributes={"database_version": "POSTGRES_14"}, evidence=EV)
    ds = _dataset(dependency_classification=[_dc()], infra=InfraAnalysis(terraform_resources=[tr]))
    node = next(n for n in build_dependency_graph(ds).nodes if n.kind == "datastore")
    assert node.database.engine == "postgresql" and node.database.version == "POSTGRES_14"


def test_database_not_guessed_across_multiple_ambiguous_datastore_dependencies():
    workload = K8sWorkload(kind="Deployment", name="db", containers=[K8sContainer(name="db", image="mysql:8.0")], evidence=EV)
    dcs = [_dc(name="orders-db"), _dc(name="inventory-db")]
    ds = _dataset(dependency_classification=dcs, infra=InfraAnalysis(workloads=[workload]))
    graph = build_dependency_graph(ds)
    datastore_nodes = [n for n in graph.nodes if n.kind == "datastore"]
    assert len(datastore_nodes) == 2 and all(n.database.engine is None for n in datastore_nodes)
    assert any("2 datastore dependencies" in w for w in graph.warnings)


def test_no_database_signal_leaves_it_null():
    ds = _dataset(dependency_classification=[_dc()])
    node = next(n for n in build_dependency_graph(ds).nodes if n.kind == "datastore")
    assert node.database.engine is None and node.database.evidence == []


# --------------------------------------------------------------------------------------------- hosting platform


def test_openshift_detected_via_deployment_config():
    infra = InfraAnalysis(workloads=[K8sWorkload(kind="DeploymentConfig", name="app", evidence=EV)])
    assert classify_hosting_platform(infra).kind == "openshift"


@pytest.mark.parametrize("terraform_type,expected", [("google_container_cluster", "gke"), ("aws_eks_cluster", "eks"),
                                                     ("azurerm_kubernetes_cluster", "aks")])
def test_managed_kubernetes_detected_via_terraform_provider(terraform_type, expected):
    provider = terraform_type.split("_")[0]
    infra = InfraAnalysis(terraform_resources=[TerraformResource(type=terraform_type, name="cluster", provider=provider, evidence=EV)])
    assert classify_hosting_platform(infra).kind == expected


def test_generic_kubernetes_when_only_a_plain_workload_exists():
    infra = InfraAnalysis(workloads=[K8sWorkload(kind="Deployment", name="app", evidence=EV)])
    assert classify_hosting_platform(infra).kind == "kubernetes"


def test_docker_compose_when_only_compose_services_exist():
    infra = InfraAnalysis(compose_services=[ComposeService(name="app", evidence=EV)])
    assert classify_hosting_platform(infra).kind == "docker_compose"


def test_unknown_when_nothing_determinable():
    assert classify_hosting_platform(InfraAnalysis()).kind == "unknown"


# ------------------------------------------------------------------------------------------------------------ runtime


def _rt(*, matched=None, runtime_only=None, service_name="orders") -> RuntimeCrossValidation:
    topo = ServiceTopology(provider="dynatrace", service_id=SID, nodes=[TopologyNode(id=SID, name="orders", kind="service")])
    metrics = ServiceMetrics(provider="dynatrace", service_id=SID)
    return RuntimeCrossValidation(service_name=service_name, provider="dynatrace", service_id=SID,
                                  generated_at=datetime.now(timezone.utc), topology=topo, metrics=metrics,
                                  summary=CrossValidationSummary(code_dependencies=0, runtime_dependencies=0, matched=len(matched or []),
                                                                 runtime_only=len(runtime_only or []), code_only=0),
                                  matched=matched or [], runtime_only=runtime_only or [])


def test_runtime_matched_dependency_tags_the_existing_edge():
    ds = _dataset(dependency_classification=[_dc()])
    m = MatchedDependency(runtime_node=TopologyNode(id="DB-1", name="orders-db", kind="database"),
                          runtime_edge=TopologyEdge(source=SID, target="DB-1", direction="calls"),
                          code_name="orders-db", code_kind="datastore", matched_on=["orders", "db"], confidence="high")
    graph = build_dependency_graph(ds, _rt(matched=[m]))
    assert graph.edges[0].runtime_status == "matched_high"


def test_runtime_only_dependency_becomes_a_new_node_and_edge():
    ds = _dataset(dependency_classification=[_dc()])
    ro = RuntimeOnlyDependency(node=TopologyNode(id="SVC-2", name="flagd", kind="service"),
                              edge=TopologyEdge(source=SID, target="SVC-2", direction="calls"))
    graph = build_dependency_graph(ds, _rt(runtime_only=[ro]))
    new_node = next(n for n in graph.nodes if n.name == "flagd")
    assert new_node.origin == "runtime_only"
    new_edge = next(e for e in graph.edges if e.target == new_node.id)
    assert new_edge.runtime_status == "runtime_only"


def test_runtime_for_a_different_service_is_rejected():
    ds = _dataset(dependency_classification=[_dc()])
    with pytest.raises(DepGraphError):
        build_dependency_graph(ds, _rt(service_name="not-orders"))


# --------------------------------------------------------------------------------------------------------------- html


def test_html_renders_and_escapes_dynamic_values():
    dc = _dc(name='<script>alert(1)</script>')
    ds = _dataset(dependency_classification=[dc])
    html = render_html(build_dependency_graph(ds))
    assert "<!doctype html>" in html.lower()
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_html_renders_with_only_the_service_node():
    ds = _dataset(transaction_flows=[])
    html = render_html(build_dependency_graph(ds))
    assert "orders" in html and "<svg" in html


def test_html_round_trips_through_the_schema():
    from sreadvisor.depgraph.schema import DependencyGraph

    ds = _dataset(dependency_classification=[_dc()])
    graph = build_dependency_graph(ds)
    DependencyGraph.model_validate_json(graph.model_dump_json())


# ---------------------------------------------------------------------------------------------------------------- CLI


def test_graph_cli_writes_json_and_html(tmp_path):
    ds = _dataset(dependency_classification=[_dc()])
    ds_file = tmp_path / "orders.dataset.json"
    ds_file.write_text(ds.model_dump_json(), encoding="utf-8")
    out_dir = tmp_path / "out"
    rc = cli.main(["graph", "--dataset", str(ds_file), "--out", str(out_dir)])
    assert rc == 0
    assert (out_dir / "orders.dependency-graph.json").exists()
    assert (out_dir / "orders.dependency-graph.html").exists()


def test_graph_cli_missing_dataset_is_an_error():
    assert cli.main(["graph", "--dataset", "definitely-missing.json"]) == 2


def test_graph_cli_missing_runtime_file_is_an_error(tmp_path):
    ds = _dataset(dependency_classification=[_dc()])
    ds_file = tmp_path / "orders.dataset.json"
    ds_file.write_text(ds.model_dump_json(), encoding="utf-8")
    assert cli.main(["graph", "--dataset", str(ds_file), "--runtime", str(tmp_path / "nope.json")]) == 2
