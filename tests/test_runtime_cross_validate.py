"""Stage 5: matching Stage 1's code/infra-declared dependencies against a live topology. Deterministic (no LLM,
no network): a name-and-kind comparison over hand-built dataset and topology fixtures."""

from datetime import datetime, timezone

import pytest

from sreadvisor.runtime.cross_validate import cross_validate
from sreadvisor.schema.common import Evidence
from sreadvisor.schema.dataset import EntryPoint, FlowDependency, RepoAnalysis, ServiceDataset, TechStackFingerprint, TransactionFlow
from sreadvisor.schema.runtime import MetricSeries, ServiceMetrics, ServiceTopology, TopologyEdge, TopologyNode

EP = EntryPoint(id="ep1", kind="rest", symbol="CartController.get()", route="/cart", http_method="GET",
                evidence=Evidence(file="Cart.java", line=10))


def _flow(*deps: FlowDependency) -> TransactionFlow:
    return TransactionFlow(entry_point=EP, summary="s", dependencies=list(deps))


def _dataset(*flows: TransactionFlow, service_name="orders") -> ServiceDataset:
    repo = RepoAnalysis(repo="r", path="/r", fingerprint=TechStackFingerprint(), entry_points=[EP], transaction_flows=list(flows))
    return ServiceDataset(service_name=service_name, generated_at=datetime.now(timezone.utc),
                          observability={"provider": "dynatrace", "service_id": "SERVICE-1"}, repositories=[repo])


def _topology(edges: list[TopologyEdge], nodes: list[TopologyNode], service_id="SERVICE-1") -> ServiceTopology:
    return ServiceTopology(provider="dynatrace", service_id=service_id, nodes=[TopologyNode(id=service_id, name="orders", kind="service")] + nodes, edges=edges)


def _metrics() -> ServiceMetrics:
    return ServiceMetrics(provider="dynatrace", service_id="SERVICE-1", series=[MetricSeries(name="request.rate", avg=1.0)])


def _dep_edge(target_id: str, direction="calls") -> TopologyEdge:
    return TopologyEdge(source="SERVICE-1" if direction == "calls" else target_id,
                        target=target_id if direction == "calls" else "SERVICE-1", direction=direction,
                        attributes={"is_dependency_like": True, "relationship_kind": "calls"})


def _structural_edge(target_id: str) -> TopologyEdge:
    return TopologyEdge(source=target_id, target="SERVICE-1", direction="called_by",
                        attributes={"is_dependency_like": False, "relationship_kind": "runsOn"})


# ------------------------------------------------------------------------------------------------- matching


def test_kind_compatible_name_overlap_is_a_high_confidence_match():
    ds = _dataset(_flow(FlowDependency(name="relational database (Spring Data JPA)", kind="datastore",
                                       evidence=Evidence(file="Repo.java", line=5))))
    topo = _topology([_dep_edge("DATABASE-1")], [TopologyNode(id="DATABASE-1", name="orders-postgres-database", kind="database")])
    result = cross_validate(ds, topo, _metrics())
    assert result.summary.matched == 1 and result.summary.runtime_only == 0 and result.summary.code_only == 0
    m = result.matched[0]
    assert m.confidence == "high" and "database" in m.matched_on and m.code_name.startswith("relational database")
    assert m.runtime_node.id == "DATABASE-1"


def test_name_overlap_with_incompatible_kind_is_medium_confidence():
    # Same tokens overlap ("cache"), but the code called it a cache while the runtime node is a queue: still worth
    # surfacing as a match (the name overlap is real), just not with full confidence.
    ds = _dataset(_flow(FlowDependency(name="orders cache", kind="cache", evidence=Evidence(file="X.java", line=1))))
    topo = _topology([_dep_edge("QUEUE-1")], [TopologyNode(id="QUEUE-1", name="orders cache queue", kind="queue")])
    result = cross_validate(ds, topo, _metrics())
    assert result.matched[0].confidence == "medium"


def test_runtime_only_dependency_is_flagged_undeclared():
    """The brief's own scenario: a transient dependency the observability platform shows that the code never
    declared (a feature-flag service call, like the real Dynatrace playground example this was modelled on)."""
    ds = _dataset(_flow())  # traced, but this dependency was never seen in code
    topo = _topology([_dep_edge("SERVICE-2")], [TopologyNode(id="SERVICE-2", name="flagd", kind="service")])
    result = cross_validate(ds, topo, _metrics())
    assert result.summary.runtime_only == 1 and result.runtime_only[0].node.name == "flagd"
    assert result.summary.matched == 0 and result.summary.code_only == 0


def test_code_only_dependency_is_flagged_not_observed():
    ds = _dataset(_flow(FlowDependency(name="legacy billing service", kind="http_service", evidence=Evidence(file="X.java", line=1))))
    topo = _topology([], [])  # nothing observed at runtime
    result = cross_validate(ds, topo, _metrics())
    assert result.summary.code_only == 1 and result.code_only[0].name == "legacy billing service"
    assert len(result.code_only[0].evidence) == 1


def test_structural_edges_are_never_compared_even_with_a_matching_name():
    ds = _dataset(_flow(FlowDependency(name="orders host", kind="datastore", evidence=Evidence(file="X.java", line=1))))
    topo = _topology([_structural_edge("HOST-1")], [TopologyNode(id="HOST-1", name="orders host", kind="host")])
    result = cross_validate(ds, topo, _metrics())
    assert result.summary.matched == 0 and result.summary.runtime_only == 0  # the structural edge is excluded entirely
    assert result.summary.code_only == 1  # so the code side is still unmatched


def test_outbound_dependency_is_compared_but_an_inbound_caller_is_excluded_entirely():
    """A FlowDependency is always something the code calls out to, never something that calls into it, so an
    inbound "called_by" edge (a caller of the pilot service) is not a fair comparison against it — it is neither
    matched, nor runtime-only, nor code-only; it simply is not part of this cross-validation at all."""
    ds = _dataset(_flow(FlowDependency(name="checkout", kind="http_service", evidence=Evidence(file="X.java", line=1))))
    outbound = _topology([_dep_edge("SERVICE-2", direction="calls")], [TopologyNode(id="SERVICE-2", name="checkout", kind="service")])
    assert cross_validate(ds, outbound, _metrics()).summary.matched == 1

    inbound = _topology([_dep_edge("SERVICE-3", direction="called_by")], [TopologyNode(id="SERVICE-3", name="frontend", kind="service")])
    result = cross_validate(ds, inbound, _metrics())
    assert result.summary.runtime_dependencies == 0  # the inbound edge was never even considered
    assert result.summary.matched == 0 and result.summary.runtime_only == 0
    assert result.summary.code_only == 1  # "checkout" still has nothing to match against in this topology


def test_no_dependencies_anywhere_is_a_clean_empty_result():
    from sreadvisor.runtime.schema import CrossValidationSummary

    ds = _dataset(_flow())
    result = cross_validate(ds, _topology([], []), _metrics())
    assert result.summary == CrossValidationSummary(code_dependencies=0, runtime_dependencies=0, matched=0, runtime_only=0, code_only=0)
    assert result.matched == [] and result.runtime_only == [] and result.code_only == []


# ---------------------------------------------------------------------------------------------- deduplication


def test_the_same_dependency_named_identically_across_flows_is_one_code_dependency():
    dep = lambda: FlowDependency(name="relational database (Spring Data JPA)", kind="datastore", evidence=Evidence(file="A.java", line=1))
    ds = _dataset(_flow(dep()), _flow(dep()))
    topo = _topology([], [])
    result = cross_validate(ds, topo, _metrics())
    assert result.summary.code_dependencies == 1
    assert len(result.code_only[0].evidence) == 2  # both occurrences' evidence kept


def test_dedup_needs_the_exact_same_token_set_a_subset_name_stays_a_separate_entry():
    """Stage 1's flow tracer is instructed to reuse one exact name per dependency across every flow, so this
    dedup only needs to tolerate case/punctuation, not arbitrary rewording — a differently-worded name (even one
    that is a strict subset of another's tokens) is kept as its own entry rather than guessed to be the same thing."""
    ds = _dataset(_flow(FlowDependency(name="relational database (Spring Data JPA)", kind="datastore", evidence=Evidence(file="A.java", line=1)),
                        FlowDependency(name="relational database", kind="datastore", evidence=Evidence(file="B.java", line=2))))
    result = cross_validate(ds, _topology([], []), _metrics())
    assert result.summary.code_dependencies == 2


# ------------------------------------------------------------------------------------------------------ warnings


def test_a_dataset_with_no_traced_flows_warns_and_everything_runtime_is_flagged():
    ds = _dataset()  # no repositories at all
    topo = _topology([_dep_edge("SERVICE-2")], [TopologyNode(id="SERVICE-2", name="flagd", kind="service")])
    result = cross_validate(ds, topo, _metrics())
    assert any("no traced transaction flows" in w for w in result.warnings)
    assert result.summary.runtime_only == 1


# ------------------------------------------------------------------------------------------------------- schema


def test_result_embeds_topology_and_metrics_verbatim_and_round_trips():
    ds = _dataset(_flow(FlowDependency(name="orders db", kind="datastore", evidence=Evidence(file="A.java", line=1))))
    topo = _topology([_dep_edge("DATABASE-1")], [TopologyNode(id="DATABASE-1", name="orders db", kind="database")])
    metrics = _metrics()
    result = cross_validate(ds, topo, metrics)
    assert result.topology == topo and result.metrics == metrics
    assert result.service_name == "orders" and result.provider == "dynatrace" and result.service_id == "SERVICE-1"
    from sreadvisor.runtime.schema import RuntimeCrossValidation

    RuntimeCrossValidation.model_validate_json(result.model_dump_json())
