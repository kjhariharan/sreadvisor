"""Stage 6, Gap Analysis Pass 2: Pass 1 plus Stage 5's runtime cross-validation. Reuses test_gap.py's ScriptedRunner
(the model is scripted, so these tests check the merge/tagging logic, not judgment) and test_nfr's dataset builders.
No Ollama needed.
"""

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from sreadvisor import cli
from sreadvisor.agents import outputs as out
from sreadvisor.gap.pass1 import GapAnalysisError
from sreadvisor.gap.pass2 import GapAnalysisPass2
from sreadvisor.gap.schema import GapReport
from sreadvisor.registry import Registry
from sreadvisor.runtime.schema import CrossValidationSummary, RuntimeCrossValidation, RuntimeOnlyDependency
from sreadvisor.schema.common import Evidence
from sreadvisor.schema.dataset import ReliabilityPattern
from sreadvisor.schema.runtime import MetricSeries, ServiceMetrics, ServiceTopology, TopologyEdge, TopologyNode

from test_gap import ScriptedRunner, met_with_citation
from test_nfr import analyse, boot_repo, w

SERVICE_ID = "SERVICE-0123456789ABCDEF"

K8S_HPA = """
apiVersion: apps/v1
kind: Deployment
metadata: {name: orders}
spec:
  replicas: 2
  selector: {matchLabels: {a: o}}
  template:
    metadata: {labels: {a: o}}
    spec:
      containers:
        - {name: orders, image: 'orders:1'}
---
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata: {name: orders}
spec:
  scaleTargetRef: {kind: Deployment, name: orders}
  minReplicas: 2
  maxReplicas: 10
  metrics:
    - type: Resource
      resource: {name: cpu, target: {type: Utilization, averageUtilization: 70}}
"""


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("DT_API_TOKEN", "test-token")


@pytest.fixture
def dataset(tmp_path):
    repo = boot_repo(tmp_path)
    w(repo, "k8s/app.yaml", K8S_HPA)
    return analyse(tmp_path, repo, repo)


def by_id(report: GapReport, nid: str):
    return next(a for a in report.assessments if a.nfr.id == nid)


def run_pass2(dataset, runner, runtime=None, **kw) -> GapReport:
    module = GapAnalysisPass2(**kw)
    module.bind(Registry.load(), Path(".sreadvisor-test"), runner=runner, log=lambda *_: None)
    return asyncio.run(module.evaluate(dataset, runtime))


def _runtime(*, edges=None, nodes=None, series=None, runtime_only=None) -> RuntimeCrossValidation:
    topo = ServiceTopology(provider="dynatrace", service_id=SERVICE_ID,
                           nodes=[TopologyNode(id=SERVICE_ID, name="orders", kind="service")] + (nodes or []),
                           edges=edges or [])
    metrics = ServiceMetrics(provider="dynatrace", service_id=SERVICE_ID, series=series or [])
    ro = runtime_only or []
    return RuntimeCrossValidation(
        service_name="orders", provider="dynatrace", service_id=SERVICE_ID, generated_at=datetime.now(timezone.utc),
        topology=topo, metrics=metrics,
        summary=CrossValidationSummary(code_dependencies=0, runtime_dependencies=len(edges or []), matched=0,
                                       runtime_only=len(ro), code_only=0),
        runtime_only=ro)


# ------------------------------------------------------------------------------------ no runtime given: passthrough


def test_no_runtime_given_pass2_degrades_to_pass1(dataset):
    r = run_pass2(dataset, ScriptedRunner())
    assert r.pass_name == "gap_analysis_pass_2"
    assert any("no Stage 5 runtime cross-validation was given" in w for w in r.warnings)
    assert all(g.detection_source == "code_and_infra" for g in r.gaps)
    assert all(a.detection_source == "code_and_infra" for a in r.assessments)


def test_runtime_for_a_different_service_is_rejected(dataset):
    rt = _runtime()
    rt.service_name = "not-orders"
    with pytest.raises(GapAnalysisError):
        run_pass2(dataset, ScriptedRunner(), runtime=rt)


# ------------------------------------------------------------------------------------------- TLS observed mismatch


def test_tls_claimed_but_observed_plaintext_is_caught_and_tagged_runtime(dataset):
    contradicted = out.GapAssessmentOut(
        status="missing", rationale="A live call to checkout is observed over plain HTTP, not TLS.",
        found=[out.GapRefOut(note="observed http://checkout:8080", shows="shortfall")])
    runner = ScriptedRunner({"ENC-002": [met_with_citation(), contradicted]}, verify={"ENC-002": met_with_citation()})
    rt = _runtime(edges=[TopologyEdge(source=SERVICE_ID, target="SERVICE-2", direction="calls",
                                      attributes={"is_dependency_like": True})],
                 nodes=[TopologyNode(id="SERVICE-2", name="checkout", kind="service",
                                     attributes={"remoteEndpoint": "http://checkout:8080"})])
    r = run_pass2(dataset, runner, runtime=rt)
    a = by_id(r, "ENC-002")
    assert a.status == "missing" and a.detection_source == "runtime"
    assert any("revised from met" in w for w in a.warnings)
    assert "Runtime observability evidence" in runner.prompts["ENC-002"]
    g = next(g for g in r.gaps if g.nfr.id == "ENC-002")
    assert g.detection_source == "runtime"
    assert any(g.detection_source == "runtime" for g in r.gaps) and sum(1 for g in r.gaps if g.detection_source == "runtime") >= 1
    assert "runtime" in "\n".join(r.warnings)  # the summary line about how many gaps needed runtime data


def test_tls_observed_secure_is_inconclusive_evidence_left_alone_if_scheme_unknown(dataset):
    """grpc/jdbc endpoints cannot show TLS from the scheme alone: no usable evidence, Pass 1's verdict stands."""
    runner = ScriptedRunner({"ENC-002": met_with_citation()}, verify={"ENC-002": met_with_citation()})
    rt = _runtime(edges=[TopologyEdge(source=SERVICE_ID, target="SERVICE-2", direction="calls",
                                      attributes={"is_dependency_like": True})],
                 nodes=[TopologyNode(id="SERVICE-2", name="checkout", kind="service",
                                     attributes={"remoteEndpoint": "grpc://checkout"})])
    r = run_pass2(dataset, runner, runtime=rt)
    a = by_id(r, "ENC-002")
    assert a.status == "met" and a.detection_source == "code_and_infra"
    assert "ENC-002" not in runner.prompts or "Runtime observability evidence" not in runner.prompts["ENC-002"]


def test_verdict_unchanged_after_runtime_recheck_keeps_code_and_infra_source(dataset):
    runner = ScriptedRunner({"ENC-002": met_with_citation()}, verify={"ENC-002": met_with_citation()})
    rt = _runtime(edges=[TopologyEdge(source=SERVICE_ID, target="SERVICE-2", direction="calls",
                                      attributes={"is_dependency_like": True})],
                 nodes=[TopologyNode(id="SERVICE-2", name="checkout", kind="service",
                                     attributes={"remoteEndpoint": "http://checkout:8080"})])
    r = run_pass2(dataset, runner, runtime=rt)
    a = by_id(r, "ENC-002")
    assert a.status == "met" and a.detection_source == "code_and_infra"
    assert any("verdict unchanged" in w for w in a.warnings)


# ------------------------------------------------------------------------------------ autoscaling observed mismatch


def test_autoscaler_never_observed_triggering_downgrades_verdict(dataset):
    never_triggered = out.GapAssessmentOut(
        status="partially_met", rationale="The autoscaler is configured but was never observed scaling under load.",
        found=[out.GapRefOut(path="infrastructure.autoscalers[0]", shows="satisfied"),
              out.GapRefOut(note="replica count constant", shows="shortfall")])
    runner = ScriptedRunner({"CAP-002": [met_with_citation(), never_triggered]}, verify={"CAP-002": met_with_citation()})
    samples = [(datetime(2026, 1, 1, tzinfo=timezone.utc), 3.0), (datetime(2026, 1, 1, 1, tzinfo=timezone.utc), 3.0),
              (datetime(2026, 1, 1, 2, tzinfo=timezone.utc), 3.0)]
    rt = _runtime(series=[MetricSeries(name="workload.replica_count", avg=3.0, window_seconds=7200, samples=samples)])
    r = run_pass2(dataset, runner, runtime=rt)
    a = by_id(r, "CAP-002")
    assert a.status == "partially_met" and a.detection_source == "runtime"
    assert "Runtime observability evidence" in runner.prompts["CAP-002"] and "no scaling event" in runner.prompts["CAP-002"]


def test_autoscaler_replica_count_varying_is_evidence_the_policy_triggered(dataset):
    runner = ScriptedRunner({"CAP-002": met_with_citation()}, verify={"CAP-002": met_with_citation()})
    samples = [(datetime(2026, 1, 1, tzinfo=timezone.utc), 2.0), (datetime(2026, 1, 1, 1, tzinfo=timezone.utc), 5.0)]
    rt = _runtime(series=[MetricSeries(name="workload.replica_count", avg=3.5, window_seconds=7200, samples=samples)])
    run_pass2(dataset, runner, runtime=rt)
    assert "having triggered" in runner.prompts["CAP-002"]


def test_no_autoscaler_declared_means_no_runtime_evidence_to_check(tmp_path):
    repo = boot_repo(tmp_path)  # no k8s/HPA at all
    ds = analyse(tmp_path, repo)
    runner = ScriptedRunner(default=out.GapAssessmentOut(status="not_assessable", rationale="No autoscaler exists to check."))
    samples = [(datetime(2026, 1, 1, tzinfo=timezone.utc), 2.0), (datetime(2026, 1, 1, 1, tzinfo=timezone.utc), 5.0)]
    rt = _runtime(series=[MetricSeries(name="workload.replica_count", avg=3.5, samples=samples)])
    r = run_pass2(ds, runner, runtime=rt)
    assert "CAP-002" not in runner.prompts  # CAP-002 was already not_assessable from Pass 1 with nothing to recheck


# --------------------------------------------------------------------------------- undocumented runtime dependency


def test_undocumented_dependency_with_no_protection_is_a_new_runtime_only_gap(dataset):
    ro = [RuntimeOnlyDependency(node=TopologyNode(id="SERVICE-2", name="flagd", kind="service"),
                                edge=TopologyEdge(source=SERVICE_ID, target="SERVICE-2", direction="calls",
                                                  attributes={"is_dependency_like": True}))]
    rt = _runtime(runtime_only=ro)
    r = run_pass2(dataset, ScriptedRunner(), runtime=rt)
    g = next((g for g in r.gaps if g.nfr.id == "DC-001" and "flagd" in g.why), None)
    assert g is not None and g.detection_source == "runtime" and g.status == "missing"
    assert "found only through Stage 5 runtime observability" in g.warnings[0]
    assert g.evidence.not_found == ["a reliability pattern protecting flagd"]


def test_undocumented_dependency_with_a_recorded_pattern_is_not_flagged(dataset):
    dataset.repositories[0].reliability_patterns.append(
        ReliabilityPattern(pattern="circuit_breaker", mechanism="resilience4j", protects="flagd",
                           evidence=Evidence(file="C.java", line=1)))
    ro = [RuntimeOnlyDependency(node=TopologyNode(id="SERVICE-2", name="flagd", kind="service"),
                                edge=TopologyEdge(source=SERVICE_ID, target="SERVICE-2", direction="calls",
                                                  attributes={"is_dependency_like": True}))]
    rt = _runtime(runtime_only=ro)
    r = run_pass2(dataset, ScriptedRunner(), runtime=rt)
    assert not any(g.nfr.id == "DC-001" and "flagd" in g.why for g in r.gaps)


def test_merged_report_round_trips_and_tallies_runtime_informed_gaps(dataset):
    ro = [RuntimeOnlyDependency(node=TopologyNode(id="SERVICE-2", name="flagd", kind="service"),
                                edge=TopologyEdge(source=SERVICE_ID, target="SERVICE-2", direction="calls",
                                                  attributes={"is_dependency_like": True}))]
    rt = _runtime(runtime_only=ro)
    r = run_pass2(dataset, ScriptedRunner(), runtime=rt)
    GapReport.model_validate_json(r.model_dump_json())
    assert [g.id for g in r.gaps] == [f"GAP-{i:03d}" for i in range(1, len(r.gaps) + 1)]
    assert r.summary.gap_count == len(r.gaps)
    assert r.inputs["sources_used"][-1] == "runtime_cross_validation"
    assert r.inputs["runtime_cross_validation"]["provider"] == "dynatrace"


# --------------------------------------------------------------------------------------------------------- CLI


def test_gaps_cli_pass_2_with_runtime_file_no_llm(tmp_path):
    repo = boot_repo(tmp_path)
    w(repo, "k8s/app.yaml", K8S_HPA)
    analyse(tmp_path, repo, repo)
    ds_file = next((tmp_path / "out").glob("*.dataset.json"))
    ds_data = json.loads(ds_file.read_text(encoding="utf-8"))
    service_id = ds_data["observability"]["service_id"]

    ro = [RuntimeOnlyDependency(node=TopologyNode(id="SERVICE-2", name="flagd", kind="service"),
                                edge=TopologyEdge(source=service_id, target="SERVICE-2", direction="calls",
                                                  attributes={"is_dependency_like": True}))]
    rt = RuntimeCrossValidation(
        service_name="orders", provider="dynatrace", service_id=service_id, generated_at=datetime.now(timezone.utc),
        topology=ServiceTopology(provider="dynatrace", service_id=service_id,
                                 nodes=[TopologyNode(id=service_id, name="orders", kind="service")],
                                 edges=[e for r in ro for e in [r.edge]]),
        metrics=ServiceMetrics(provider="dynatrace", service_id=service_id),
        summary=CrossValidationSummary(code_dependencies=0, runtime_dependencies=1, matched=0, runtime_only=1, code_only=0),
        runtime_only=ro)
    rt_file = tmp_path / "orders.runtime-cross-validation.json"
    rt_file.write_text(rt.model_dump_json(), encoding="utf-8")

    out_dir = tmp_path / "gaps2"
    rc = cli.main(["gaps", "--dataset", str(ds_file), "--runtime", str(rt_file), "--no-llm", "--out", str(out_dir)])
    assert rc == 0
    written = json.loads(next(out_dir.glob("*.gaps.json")).read_text(encoding="utf-8"))
    assert written["pass_name"] == "gap_analysis_pass_2"
    assert any(g["nfr"]["id"] == "DC-001" and "flagd" in g["why"] and g["detection_source"] == "runtime"
              for g in written["gaps"])


def test_gaps_cli_missing_runtime_file_is_an_error(tmp_path):
    repo = boot_repo(tmp_path)
    analyse(tmp_path, repo)
    ds_file = next((tmp_path / "out").glob("*.dataset.json"))
    assert cli.main(["gaps", "--dataset", str(ds_file), "--runtime", str(tmp_path / "nope.json"), "--no-llm"]) == 2
