"""Stage 6: the FMEA generator. The model is replaced by a scripted runner (no Ollama needed), so these tests check
everything around the judgment: which components are analysed (code-classified, fallen-back-to-flow, or
runtime-only), what context each gets, cross-referencing to gaps, ordering/numbering, and failure handling.
"""

import asyncio
import re
from datetime import datetime, timezone
from pathlib import Path

import pytest

from sreadvisor import cli
from sreadvisor.agents import outputs as out
from sreadvisor.agents.runner import AgentError
from sreadvisor.fmea.build import FmeaError, build_fmea
from sreadvisor.fmea.schema import FmeaReport
from sreadvisor.gap.schema import Assessment, FindingEvidence, Gap, GapReport, GapSummary, NfrRef
from sreadvisor.registry import Registry
from sreadvisor.runtime.schema import CrossValidationSummary, RuntimeCrossValidation, RuntimeOnlyDependency
from sreadvisor.schema.common import Evidence
from sreadvisor.schema.dataset import (
    BusinessContext, DependencyClassification, EntryPoint, FlowDependency, RepoAnalysis, ServiceDataset,
    TechStackFingerprint, TransactionFlow,
)
from sreadvisor.schema.runtime import ServiceMetrics, ServiceTopology, TopologyEdge, TopologyNode

SID = "SERVICE-1"
EP = EntryPoint(id="ep1", kind="rest", symbol="C.get()", route="/x", evidence=Evidence(file="C.java", line=1))


def _dataset(*, dependency_classification=None, transaction_flows=None, business_context=None) -> ServiceDataset:
    flows = transaction_flows if transaction_flows is not None else [TransactionFlow(entry_point=EP, summary="s")]
    repo = RepoAnalysis(repo="orders", path="/r", fingerprint=TechStackFingerprint(), entry_points=[EP],
                        transaction_flows=flows, dependency_classification=dependency_classification or [])
    return ServiceDataset(service_name="orders", generated_at=datetime.now(timezone.utc),
                          observability={"provider": "dynatrace", "service_id": SID}, repositories=[repo],
                          business_context=business_context)


def _runtime(runtime_only=None) -> RuntimeCrossValidation:
    ro = runtime_only or []
    topo = ServiceTopology(provider="dynatrace", service_id=SID, nodes=[TopologyNode(id=SID, name="orders", kind="service")])
    return RuntimeCrossValidation(service_name="orders", provider="dynatrace", service_id=SID,
                                  generated_at=datetime.now(timezone.utc), topology=topo,
                                  metrics=ServiceMetrics(provider="dynatrace", service_id=SID),
                                  summary=CrossValidationSummary(code_dependencies=0, runtime_dependencies=0, matched=0,
                                                                 runtime_only=len(ro), code_only=0),
                                  runtime_only=ro)


def default_fm(name="generic failure") -> out.FmeaComponentOut:
    return out.FmeaComponentOut(failure_modes=[out.FailureModeOut(
        failure_mode=name, likely_cause="unknown cause", effect_on_transaction_flow="requests fail",
        severity="medium", severity_rationale="default test rationale")])


class ScriptedFmeaRunner:
    def __init__(self, script=None, default=None):
        self.script, self.default = script or {}, default
        self.prompts: dict[str, str] = {}

    async def run(self, agent, prompt, schema):
        name = re.search(r"Component: (.+?) \(kind", prompt).group(1)
        self.prompts[name] = prompt
        result = self.script.get(name, self.default)
        if isinstance(result, Exception):
            raise result
        return result if result is not None else default_fm()


def run_fmea(dataset, gap_report, runtime, runner, **kw) -> FmeaReport:
    return asyncio.run(build_fmea(dataset, gap_report, runtime, Registry.load(), Path(".sreadvisor-test"), runner=runner))


# ------------------------------------------------------------------------------------------------- component sourcing


def test_no_components_at_all_is_an_empty_report_with_a_warning():
    r = run_fmea(_dataset(transaction_flows=[]), None, None, ScriptedFmeaRunner())
    assert r.components_analyzed == 0 and r.failure_modes == [] and r.warnings


def test_dependency_classification_becomes_a_component_with_full_context():
    dc = DependencyClassification(dependency="orders-db", kind="datastore", classification="hard_failure",
                                  rationale="no fallback", protecting_patterns=[], blast_radius=["C.get()"],
                                  blast_radius_description="Every read fails.", evidence=[Evidence(file="C.java", line=1)])
    ds = _dataset(dependency_classification=[dc], business_context=BusinessContext(capability="Orders", category="order_management", rationale="r"))
    runner = ScriptedFmeaRunner()
    r = run_fmea(ds, None, None, runner)
    assert r.components_analyzed == 1
    fm = r.failure_modes[0]
    assert fm.component == "orders-db" and fm.origin == "code_and_infra" and fm.classification == "hard_failure"
    assert fm.affected_flows == ["C.get()"]  # falls back to blast_radius since the scripted output gave none
    p = runner.prompts["orders-db"]
    assert "hard_failure" in p and "Every read fails" in p and "Orders (order_management)" in p


def test_falls_back_to_flow_dependencies_when_no_classification_exists():
    flow = TransactionFlow(entry_point=EP, summary="s",
                           dependencies=[FlowDependency(name="legacy-billing", kind="http_service", evidence=Evidence(file="C.java", line=2))])
    ds = _dataset(dependency_classification=[], transaction_flows=[flow])
    r = run_fmea(ds, None, None, ScriptedFmeaRunner())
    assert r.components_analyzed == 1 and r.failure_modes[0].component == "legacy-billing"
    assert r.failure_modes[0].classification == "unknown"


def test_runtime_only_dependency_is_a_component_with_runtime_origin_and_unknown_classification():
    ro = [RuntimeOnlyDependency(node=TopologyNode(id="SERVICE-2", name="flagd", kind="service"),
                                edge=TopologyEdge(source=SID, target="SERVICE-2", direction="calls",
                                                  attributes={"is_dependency_like": True}))]
    ds = _dataset(transaction_flows=[])
    r = run_fmea(ds, None, _runtime(runtime_only=ro), ScriptedFmeaRunner())
    assert r.components_analyzed == 1
    fm = r.failure_modes[0]
    assert fm.component == "flagd" and fm.origin == "runtime_only" and fm.classification == "unknown"


def test_components_are_deduplicated_by_name():
    dc = lambda: DependencyClassification(dependency="orders-db", kind="datastore", classification="hard_failure",
                                          rationale="r", evidence=[])
    ds = _dataset(dependency_classification=[dc(), dc()])
    r = run_fmea(ds, None, None, ScriptedFmeaRunner())
    assert r.components_analyzed == 1


# ------------------------------------------------------------------------------------------------------- assembly


def test_multiple_failure_modes_and_severity_ordering_and_numbering():
    dc1 = DependencyClassification(dependency="cache", kind="cache", classification="gracefully_degradable", rationale="r", evidence=[])
    dc2 = DependencyClassification(dependency="payments-api", kind="http_service", classification="hard_failure", rationale="r", evidence=[])
    ds = _dataset(dependency_classification=[dc1, dc2])
    two_modes = out.FmeaComponentOut(failure_modes=[
        out.FailureModeOut(failure_mode="stale reads", likely_cause="eviction storm", effect_on_transaction_flow="slower reads",
                          severity="low", severity_rationale="cache has a fallback"),
        out.FailureModeOut(failure_mode="total outage", likely_cause="upstream down", effect_on_transaction_flow="all calls fail",
                          severity="critical", severity_rationale="no fallback exists")])
    runner = ScriptedFmeaRunner({"cache": two_modes, "payments-api": default_fm("outage")})
    r = run_fmea(ds, None, None, runner)
    assert len(r.failure_modes) == 3
    assert [m.severity for m in r.failure_modes] == ["critical", "medium", "low"]
    assert [m.id for m in r.failure_modes] == ["FM-001", "FM-002", "FM-003"]
    assert r.summary_by_severity == {"critical": 1, "high": 0, "medium": 1, "low": 1}


def test_related_gaps_are_cross_referenced_by_name_overlap():
    dc = DependencyClassification(dependency="orders-db", kind="datastore", classification="hard_failure", rationale="r", evidence=[])
    ds = _dataset(dependency_classification=[dc])
    nfr = NfrRef(id="DC-001", module_id="dependency_criticality", module_title="Dependency criticality", layer="cross_cutting",
                title="t", priority="critical", requirement="r", best_practice="b", criteria="c")
    gap = Gap(id="GAP-001", status="missing", priority="critical", confidence="high", nfr=nfr,
             why="orders-db has no protecting pattern", evidence=FindingEvidence())
    gap_report = GapReport(service_name="orders", generated_at=datetime.now(timezone.utc), inputs={},
                           summary=GapSummary(applicable_requirements=1, by_status={}, gaps_by_priority={}, gap_count=1,
                                             unrecognized_tech_gap_count=0, assessed_by_llm=0),
                           modules=[], gaps=[gap], unrecognized_tech_gaps=[], assessments=[])
    r = run_fmea(ds, gap_report, None, ScriptedFmeaRunner())
    assert r.failure_modes[0].related_gap_ids == ["GAP-001"]


def test_agent_failure_for_one_component_is_a_warning_not_a_crash_and_others_still_run():
    dc1 = DependencyClassification(dependency="cache", kind="cache", classification="gracefully_degradable", rationale="r", evidence=[])
    dc2 = DependencyClassification(dependency="payments-api", kind="http_service", classification="hard_failure", rationale="r", evidence=[])
    ds = _dataset(dependency_classification=[dc1, dc2])
    runner = ScriptedFmeaRunner({"cache": AgentError("fmea_analyst: no valid JSON")})
    r = run_fmea(ds, None, None, runner)
    assert len(r.failure_modes) == 1 and r.failure_modes[0].component == "payments-api"
    assert any("cache" in w and "failed" in w for w in r.warnings)


def test_report_round_trips_and_names_its_sources():
    dc = DependencyClassification(dependency="orders-db", kind="datastore", classification="hard_failure", rationale="r", evidence=[])
    ds = _dataset(dependency_classification=[dc])
    r = run_fmea(ds, None, _runtime(), ScriptedFmeaRunner())
    FmeaReport.model_validate_json(r.model_dump_json())
    assert "runtime_cross_validation" in r.inputs["sources_used"]


def test_backend_unavailable_raises_fmea_error_when_no_runner_given(monkeypatch):
    import sreadvisor.fmea.build as build_mod

    monkeypatch.setattr(build_mod, "check_backend", lambda settings: "Ollama is not reachable")
    dc = DependencyClassification(dependency="x", kind="datastore", classification="hard_failure", rationale="r", evidence=[])
    with pytest.raises(FmeaError):
        asyncio.run(build_fmea(_dataset(dependency_classification=[dc]), None, None, Registry.load(), Path(".sreadvisor-test")))


# --------------------------------------------------------------------------------------------------------- CLI


def test_fmea_cli_reports_missing_dataset_cleanly():
    assert cli.main(["fmea", "--dataset", "definitely-missing.dataset.json"]) == 2
