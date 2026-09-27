"""Stage 6: the deterministic runtime-observable-dimension checks (runtime.observed), in isolation from Gap
Analysis Pass 2's LLM re-assessment plumbing (covered separately in test_gap_pass2.py)."""

from datetime import datetime, timezone

from sreadvisor.gap.schema import NfrRef
from sreadvisor.runtime.observed import classify_endpoint_security, runtime_evidence_for, undocumented_dependency_gaps
from sreadvisor.runtime.schema import CrossValidationSummary, RuntimeCrossValidation, RuntimeOnlyDependency
from sreadvisor.schema.common import Evidence
from sreadvisor.schema.dataset import (
    Autoscaler, EntryPoint, FlowDependency, InfraAnalysis, ReliabilityPattern, RepoAnalysis, ServiceDataset,
    TechStackFingerprint, TransactionFlow,
)
from sreadvisor.schema.runtime import MetricSeries, ServiceMetrics, ServiceTopology, TopologyEdge, TopologyNode

SID = "SERVICE-1"
EP = EntryPoint(id="ep1", kind="rest", symbol="C.get()", route="/x", evidence=Evidence(file="C.java", line=1))


def _dataset(*, autoscalers=None, patterns=None) -> ServiceDataset:
    repo = RepoAnalysis(repo="r", path="/r", fingerprint=TechStackFingerprint(), entry_points=[EP],
                        transaction_flows=[TransactionFlow(entry_point=EP, summary="s")],
                        reliability_patterns=patterns or [])
    return ServiceDataset(service_name="orders", generated_at=datetime.now(timezone.utc),
                          observability={"provider": "dynatrace", "service_id": SID}, repositories=[repo],
                          infrastructure=InfraAnalysis(autoscalers=autoscalers or []))


def _rt(*, edges=None, nodes=None, series=None, runtime_only=None) -> RuntimeCrossValidation:
    topo = ServiceTopology(provider="dynatrace", service_id=SID,
                           nodes=[TopologyNode(id=SID, name="orders", kind="service")] + (nodes or []), edges=edges or [])
    metrics = ServiceMetrics(provider="dynatrace", service_id=SID, series=series or [])
    ro = runtime_only or []
    return RuntimeCrossValidation(service_name="orders", provider="dynatrace", service_id=SID,
                                  generated_at=datetime.now(timezone.utc), topology=topo, metrics=metrics,
                                  summary=CrossValidationSummary(code_dependencies=0, runtime_dependencies=len(edges or []),
                                                                 matched=0, runtime_only=len(ro), code_only=0),
                                  runtime_only=ro)


# ------------------------------------------------------------------------------------------- endpoint classification


def test_scheme_pairs_classify_unambiguously():
    assert classify_endpoint_security("https://api.example.com") == "secure"
    assert classify_endpoint_security("http://api.example.com") == "insecure"
    assert classify_endpoint_security("wss://x") == "secure" and classify_endpoint_security("ws://x") == "insecure"


def test_grpc_and_bare_jdbc_are_inconclusive_not_guessed():
    assert classify_endpoint_security("grpc://oteldemo.CartService") == "inconclusive"
    assert classify_endpoint_security("jdbc:postgresql://host:5432/db") == "inconclusive"


def test_jdbc_sslmode_query_param_is_read():
    assert classify_endpoint_security("jdbc:postgresql://host:5432/db?sslmode=disable") == "insecure"
    assert classify_endpoint_security("jdbc:postgresql://host:5432/db?sslmode=require") == "secure"


# ---------------------------------------------------------------------------------------------- TLS runtime evidence


def _edge(target="SERVICE-2"):
    return TopologyEdge(source=SID, target=target, direction="calls", attributes={"is_dependency_like": True})


def test_enc_002_only_looks_at_service_and_external_nodes():
    ds = _dataset()
    rt = _rt(edges=[_edge()], nodes=[TopologyNode(id="SERVICE-2", name="checkout", kind="service",
                                                  attributes={"remoteEndpoint": "http://checkout:8080"})])
    ev = runtime_evidence_for("ENC-002", ds, rt)
    assert ev and "checkout" in ev and "insecure" in ev and "Runtime observability evidence" in ev


def test_enc_004_looks_at_database_and_cache_nodes():
    ds = _dataset()
    rt = _rt(edges=[_edge("DATABASE-1")], nodes=[TopologyNode(id="DATABASE-1", name="orders-db", kind="database",
                                                              attributes={"remoteEndpoint": "jdbc:postgresql://h/db?sslmode=require"})])
    ev = runtime_evidence_for("ENC-004", ds, rt)
    assert ev and "secure" in ev
    # the same edge is irrelevant to ENC-002 (wrong node kind: database, not service/external)
    assert runtime_evidence_for("ENC-002", ds, rt) is None


def test_inconclusive_scheme_alone_produces_no_evidence_no_wasted_recheck():
    ds = _dataset()
    rt = _rt(edges=[_edge()], nodes=[TopologyNode(id="SERVICE-2", name="checkout", kind="service",
                                                  attributes={"remoteEndpoint": "grpc://checkout"})])
    assert runtime_evidence_for("ENC-002", ds, rt) is None


def test_no_remote_endpoint_recorded_is_no_evidence():
    ds = _dataset()
    rt = _rt(edges=[_edge()], nodes=[TopologyNode(id="SERVICE-2", name="checkout", kind="service")])
    assert runtime_evidence_for("ENC-002", ds, rt) is None


def test_inbound_or_structural_edges_are_not_considered():
    ds = _dataset()
    inbound = TopologyEdge(source="SERVICE-2", target=SID, direction="called_by", attributes={"is_dependency_like": True})
    rt = _rt(edges=[inbound], nodes=[TopologyNode(id="SERVICE-2", name="frontend", kind="service",
                                                  attributes={"remoteEndpoint": "http://frontend"})])
    assert runtime_evidence_for("ENC-002", ds, rt) is None


def test_unknown_entry_id_has_no_check_registered():
    assert runtime_evidence_for("BASE-HC-001", _dataset(), _rt()) is None


# ----------------------------------------------------------------------------------------- autoscaling runtime evidence


def test_no_autoscaler_declared_is_no_evidence_even_with_samples():
    ds = _dataset(autoscalers=[])
    samples = [(datetime(2026, 1, 1, tzinfo=timezone.utc), 2.0), (datetime(2026, 1, 1, 1, tzinfo=timezone.utc), 5.0)]
    rt = _rt(series=[MetricSeries(name="workload.replica_count", avg=3.5, samples=samples)])
    assert runtime_evidence_for("CAP-002", ds, rt) is None


def test_autoscaler_declared_but_no_series_available_is_no_evidence():
    ds = _dataset(autoscalers=[Autoscaler(kind="HorizontalPodAutoscaler", name="orders", min_replicas="2", max_replicas="10",
                                          evidence=Evidence(file="k8s.yaml", line=1))])
    assert runtime_evidence_for("CAP-002", ds, _rt()) is None  # no series at all
    only_aggregate = _rt(series=[MetricSeries(name="workload.replica_count", avg=3.0)])  # no .samples: aggregate only
    assert runtime_evidence_for("CAP-002", ds, only_aggregate) is None


def test_autoscaler_constant_replica_count_is_evidence_it_never_triggered():
    ds = _dataset(autoscalers=[Autoscaler(kind="HorizontalPodAutoscaler", name="orders", min_replicas="2", max_replicas="10",
                                          evidence=Evidence(file="k8s.yaml", line=1))])
    samples = [(datetime(2026, 1, 1, tzinfo=timezone.utc), 3.0), (datetime(2026, 1, 1, 1, tzinfo=timezone.utc), 3.0)]
    rt = _rt(series=[MetricSeries(name="workload.replica_count", avg=3.0, window_seconds=7200, samples=samples)])
    ev = runtime_evidence_for("CAP-002", ds, rt)
    assert ev and "no scaling event was observed" in ev


def test_autoscaler_varying_replica_count_is_evidence_it_triggered():
    ds = _dataset(autoscalers=[Autoscaler(kind="HorizontalPodAutoscaler", name="orders", min_replicas="2", max_replicas="10",
                                          evidence=Evidence(file="k8s.yaml", line=1))])
    samples = [(datetime(2026, 1, 1, tzinfo=timezone.utc), 2.0), (datetime(2026, 1, 1, 1, tzinfo=timezone.utc), 6.0)]
    rt = _rt(series=[MetricSeries(name="workload.replica_count", avg=4.0, samples=samples)])
    ev = runtime_evidence_for("CAP-002", ds, rt)
    assert ev and "having triggered" in ev


# --------------------------------------------------------------------------------------- undocumented dependency gaps

NFR = NfrRef(id="DC-001", module_id="dependency_criticality", module_title="Dependency criticality", layer="cross_cutting",
            title="Every hard failure dependency is justified or protected", priority="critical", requirement="r",
            best_practice="b", criteria="c")


def test_runtime_only_dependency_with_no_pattern_is_a_gap():
    ds = _dataset()
    ro = [RuntimeOnlyDependency(node=TopologyNode(id="SERVICE-2", name="flagd", kind="service"), edge=_edge())]
    gaps = undocumented_dependency_gaps(ds, _rt(runtime_only=ro), NFR)
    assert len(gaps) == 1 and gaps[0].nfr.id == "DC-001" and "flagd" in gaps[0].why
    assert gaps[0].detection_source == "runtime" and gaps[0].status == "missing"


def test_runtime_only_dependency_protected_by_a_named_pattern_is_not_a_gap():
    pattern = ReliabilityPattern(pattern="circuit_breaker", mechanism="resilience4j", protects="flagd feature flag service",
                                evidence=Evidence(file="C.java", line=1))
    ds = _dataset(patterns=[pattern])
    ro = [RuntimeOnlyDependency(node=TopologyNode(id="SERVICE-2", name="flagd", kind="service"), edge=_edge())]
    assert undocumented_dependency_gaps(ds, _rt(runtime_only=ro), NFR) == []


def test_multiple_runtime_only_dependencies_each_get_their_own_gap():
    ds = _dataset()
    ro = [RuntimeOnlyDependency(node=TopologyNode(id="SERVICE-2", name="flagd", kind="service"), edge=_edge("SERVICE-2")),
         RuntimeOnlyDependency(node=TopologyNode(id="SERVICE-3", name="pricing", kind="service"), edge=_edge("SERVICE-3"))]
    gaps = undocumented_dependency_gaps(ds, _rt(runtime_only=ro), NFR)
    assert {g.why.split('"')[1] for g in gaps} == {"flagd", "pricing"}
