"""Stage 6: the operations runbook generator. The model is replaced by a scripted runner (no Ollama needed): these
tests check the merge with FMEA output, reuse of Stage 4 SLI suggestions as detection signals, ordering/numbering,
the Markdown render, and failure handling.
"""

import asyncio
from datetime import datetime, timezone
from pathlib import Path

import pytest

import re

from sreadvisor import cli
from sreadvisor.agents import outputs as out
from sreadvisor.agents.runner import AgentError
from sreadvisor.fmea.schema import FailureMode, FmeaReport
from sreadvisor.registry import Registry
from sreadvisor.report.schema import SliSuggestion
from sreadvisor.runbook.build import RunbookError, build_runbook
from sreadvisor.runbook.output import to_markdown
from sreadvisor.runbook.schema import Runbook
from sreadvisor.schema.common import Evidence
from sreadvisor.schema.dataset import BusinessContext, EntryPoint, RepoAnalysis, ServiceDataset, TechStackFingerprint

EP = EntryPoint(id="ep1", kind="rest", symbol="C.get()", route="/x", evidence=Evidence(file="C.java", line=1))


def _dataset(business_context=None) -> ServiceDataset:
    repo = RepoAnalysis(repo="orders", path="/r", fingerprint=TechStackFingerprint(), entry_points=[EP])
    return ServiceDataset(service_name="orders", generated_at=datetime.now(timezone.utc),
                          observability={"provider": "dynatrace", "service_id": "SERVICE-1"}, repositories=[repo],
                          business_context=business_context)


def _fm(**kw) -> FailureMode:
    base = dict(id="FM-001", component="orders-db", component_kind="datastore", origin="code_and_infra",
               classification="hard_failure", failure_mode="total outage", likely_cause="network partition",
               effect_on_transaction_flow="every read and write fails", severity="critical",
               severity_rationale="no fallback exists", existing_mitigations=[], related_gap_ids=["GAP-001"])
    base.update(kw)
    return FailureMode(**base)


def _fmea(*modes) -> FmeaReport:
    return FmeaReport(service_name="orders", generated_at=datetime.now(timezone.utc), inputs={},
                      components_analyzed=len(modes), failure_modes=list(modes),
                      summary_by_severity={"critical": 0, "high": 0, "medium": 0, "low": 0})


def default_steps() -> out.RunbookStepsOut:
    return out.RunbookStepsOut(detection_signals=["generic alert"], immediate_actions=["check dashboards"],
                              escalate_to="the service owner team", escalate_when="if not resolved in 15 minutes")


class ScriptedRunbookRunner:
    def __init__(self, script=None, default=None):
        self.script, self.default = script or {}, default
        self.prompts: dict[str, str] = {}

    async def run(self, agent, prompt, schema):
        component = re.search(r"Component: (.+?) \(kind", prompt).group(1)
        self.prompts[component] = prompt
        result = self.script.get(component, self.default)
        if isinstance(result, Exception):
            raise result
        return result if result is not None else default_steps()


def run_runbook(dataset, fmea, slis, runner) -> Runbook:
    return asyncio.run(build_runbook(dataset, fmea, slis, Registry.load(), Path(".sreadvisor-test"), runner=runner))


# --------------------------------------------------------------------------------------------------------- building


def test_empty_fmea_produces_an_empty_runbook_with_a_warning():
    r = run_runbook(_dataset(), _fmea(), None, ScriptedRunbookRunner())
    assert r.entries == [] and r.warnings


def test_entry_carries_the_fmeas_own_findings_verbatim():
    fmea = _fmea(_fm())
    r = run_runbook(_dataset(BusinessContext(capability="Orders", category="order_management", rationale="r")),
                    fmea, None, ScriptedRunbookRunner())
    e = r.entries[0]
    assert e.fmea_id == "FM-001" and e.component == "orders-db" and e.severity == "critical"
    assert e.failure_mode == "total outage" and e.effect_on_transaction_flow == "every read and write fails"
    assert e.related_gap_ids == ["GAP-001"]
    assert e.escalate_to == "the service owner team" and "15 minutes" in e.escalate_when
    assert e.immediate_actions == ["check dashboards"]


def test_known_slis_are_preferred_and_merged_ahead_of_model_signals():
    fmea = _fmea(_fm())
    slis = [SliSuggestion(id="SLI-001", name="Query latency: orders-db", description="d", kind="latency",
                          subject="orders-db", tier=1, tier_label="OneAgent default",
                          measurement_source="OneAgent: builtin:service.response.time", rationale="r")]
    runner = ScriptedRunbookRunner()
    r = run_runbook(_dataset(), fmea, slis, runner)
    assert r.entries[0].detection_signals[0].startswith("Query latency: orders-db")
    assert "generic alert" in r.entries[0].detection_signals  # the model's own signal still merged in, not discarded
    assert "Query latency: orders-db" in runner.prompts["orders-db"]  # the model was told about the known signal


def test_unrelated_sli_is_not_pulled_in():
    fmea = _fmea(_fm())
    slis = [SliSuggestion(id="SLI-001", name="Checkout latency", description="d", kind="latency", subject="checkout",
                          tier=1, tier_label="OneAgent default", measurement_source="OneAgent: x", rationale="r")]
    r = run_runbook(_dataset(), fmea, slis, ScriptedRunbookRunner())
    assert r.entries[0].detection_signals == ["generic alert"]


def test_multiple_entries_ordered_by_severity_and_numbered():
    fmea = _fmea(_fm(id="FM-001", component="cache", severity="low"), _fm(id="FM-002", component="payments-api", severity="critical"))
    r = run_runbook(_dataset(), fmea, None, ScriptedRunbookRunner())
    assert [e.severity for e in r.entries] == ["critical", "low"]
    assert [e.id for e in r.entries] == ["RB-001", "RB-002"]


def test_model_added_ordinal_prefixes_are_stripped_so_rendering_never_double_numbers():
    fmea = _fmea(_fm())
    steps = out.RunbookStepsOut(detection_signals=["x"], immediate_actions=["1. check dashboards", "2) restart the pool"],
                                escalate_to="the service owner team", escalate_when="after 10 minutes")
    r = run_runbook(_dataset(), fmea, None, ScriptedRunbookRunner(default=steps))
    assert r.entries[0].immediate_actions == ["check dashboards", "restart the pool"]


def test_agent_failure_for_one_entry_is_a_warning_not_a_crash():
    fmea = _fmea(_fm(id="FM-001", component="cache"), _fm(id="FM-002", component="payments-api"))
    runner = ScriptedRunbookRunner({"cache": AgentError("runbook_writer: no valid JSON")})
    r = run_runbook(_dataset(), fmea, None, runner)
    assert len(r.entries) == 1 and r.entries[0].component == "payments-api"
    assert any("cache" in w for w in r.warnings)


def test_backend_unavailable_raises_runbook_error_when_no_runner_given(monkeypatch):
    import sreadvisor.runbook.build as build_mod

    monkeypatch.setattr(build_mod, "check_backend", lambda settings: "Ollama is not reachable")
    with pytest.raises(RunbookError):
        asyncio.run(build_runbook(_dataset(), _fmea(_fm()), None, Registry.load(), Path(".sreadvisor-test")))


def test_round_trips():
    r = run_runbook(_dataset(), _fmea(_fm()), None, ScriptedRunbookRunner())
    Runbook.model_validate_json(r.model_dump_json())


# --------------------------------------------------------------------------------------------------------- markdown


def test_markdown_groups_by_severity_and_includes_the_undocumented_dependency_tag():
    runtime_only = _fm(id="FM-002", component="flagd", origin="runtime_only", severity="high", related_gap_ids=[])
    fmea = _fmea(_fm(), runtime_only)
    r = run_runbook(_dataset(), fmea, None, ScriptedRunbookRunner())
    md = to_markdown(r)
    assert "## CRITICAL" in md and "## HIGH" in md
    assert md.index("## CRITICAL") < md.index("## HIGH")
    assert "undocumented dependency" in md and "flagd" in md
    assert "Escalate to:" in md and "Immediate actions" in md and "Detection signals" in md


# --------------------------------------------------------------------------------------------------------- CLI


def test_runbook_cli_reports_missing_dataset_cleanly(tmp_path):
    fmea_file = tmp_path / "orders.fmea.json"
    fmea_file.write_text(_fmea().model_dump_json(), encoding="utf-8")
    assert cli.main(["runbook", "--dataset", "definitely-missing.dataset.json", "--fmea", str(fmea_file)]) == 2


def test_runbook_cli_reports_missing_fmea_file_cleanly(tmp_path):
    ds_file = tmp_path / "orders.dataset.json"
    ds_file.write_text(_dataset().model_dump_json(), encoding="utf-8")
    assert cli.main(["runbook", "--dataset", str(ds_file), "--fmea", str(tmp_path / "nope.json")]) == 2
