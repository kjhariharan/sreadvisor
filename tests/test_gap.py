"""Stage 3, Gap Analysis Pass 1. The model is replaced by a scripted runner, so these tests check everything around the judgment:
which requirements are assessed, the evidence given, grounding of citations, consistency rules, ordering and the separate
unrecognized-tech-stack gaps. No Ollama needed."""

import json
import re
from pathlib import Path

import pytest
from pydantic import ValidationError

from sreadvisor import cli
from sreadvisor.agents import outputs as out
from sreadvisor.agents.runner import AgentError, extract_json_objects
from sreadvisor.gap import paths as dp
from sreadvisor.gap.pass1 import GapAnalysisError, GapAnalysisPass1
from sreadvisor.gap.schema import GapReport
from sreadvisor.nfr.coverage import load_dataset
from sreadvisor.registry import Registry

from test_nfr import analyse, boot_repo, w


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("DT_API_TOKEN", "test-token")


DATA = {
    "repositories": [{"repo": "svc", "secrets": {"hardcoded": []}, "status": [{"step": "secrets_handling", "status": "ok", "count": 2}]}],
    "infrastructure": {
        "workloads": [
            {"name": "api", "kind": "Deployment", "evidence": {"file": "k8s/api.yml", "line": 3},
             "containers": [{"name": "app", "readiness": {"type": "http"}, "startup": None, "limits": {}}]},
            {"name": "db", "kind": "StatefulSet", "evidence": {"file": "k8s/db.yml", "line": 9},
             "containers": [{"name": "pg", "readiness": None, "startup": None, "limits": {"memory": "1Gi"}}]},
        ],
        "autoscalers": [],
        "pipelines": [{"system": "github_actions", "file": ".github/workflows/ci.yml", "deploy_steps": ["kubectl apply"]}],
        "status": [{"step": "kubernetes", "status": "ok", "count": 2}, {"step": "terraform", "status": "skipped", "detail": "no iac"}],
    },
}


# ------------------------------------------------------------------------ dataset access


def test_path_validity_wildcards_indexes_and_empty_lists():
    assert dp.path_valid(DATA, "infrastructure.workloads[].containers[].readiness")
    assert dp.path_valid(DATA, "infrastructure.workloads[1].containers[0].limits")
    assert dp.path_valid(DATA, "infrastructure.autoscalers[].min_replicas")  # empty list: cannot be disproved
    assert not dp.path_valid(DATA, "infrastructure.workloads[5]")
    assert not dp.path_valid(DATA, "infrastructure.nope")
    assert not dp.path_valid(DATA, "infrastructure.workloads.name")  # missing []
    assert not dp.path_valid(DATA, "in valid")


def test_projection_keeps_identity_and_location_and_shows_absence():
    text = dp.project(DATA, ["infrastructure.workloads[].containers[].readiness", "infrastructure.workloads[].containers[].startup"])
    obj = json.loads(text)
    api, db = obj["infrastructure"]["workloads"]
    assert api["name"] == "api" and api["at"] == "k8s/api.yml:3" and api["_path"] == "infrastructure.workloads[0]"
    assert api["containers"][0]["readiness"] == {"type": "http"} and api["containers"][0]["startup"] is None
    assert db["containers"][0]["readiness"] is None  # absence is explicit, not omitted
    assert "limits" not in api["containers"][0]  # only the requested paths


def test_projection_is_bounded():
    big = {"items": [{"name": f"n{i}", "v": "x" * 100} for i in range(200)]}
    text = dp.project(big, ["items[].v"], max_items=12, max_chars=1500)
    assert len(text) <= 3000 and "more of 200" in text


def test_locate_and_examined_locations():
    assert dp.locate(DATA, "infrastructure.workloads[1].containers[0]") == ("k8s/db.yml", 9)
    assert dp.locate(DATA, "infrastructure.pipelines[0]") == (".github/workflows/ci.yml", None)
    assert dp.locate(DATA, "infrastructure.nope") is None
    assert dp.at_locations(DATA, ["infrastructure.workloads[].containers[].readiness"]) == ["k8s/api.yml:3", "k8s/db.yml:9"]
    locs, files = dp.locations(DATA)
    assert ("k8s/api.yml", 3) in locs and "k8s/db.yml" in files


def test_stage1_step_accountability():
    assert dp.steps_for_path("infrastructure.workloads[].containers[].readiness") == ["infra.kubernetes", "infra.helm"]
    assert dp.steps_for_path("repositories[].secrets.hardcoded[].kind") == ["code.secrets_handling"]
    assert dp.steps_for_path("business_context.key_operations") == ["code.business_context"]
    st = dp.step_statuses(DATA)
    assert st["infra.terraform"]["status"] == "skipped" and st["code.secrets_handling"]["count"] == 2


def test_model_output_contract():
    assert out.GapAssessmentOut(status="Partially Met", rationale="Two of three containers have probes.").status == "partially_met"
    with pytest.raises(ValidationError):
        out.GapAssessmentOut(status="...", rationale="Two of three containers have probes.")
    with pytest.raises(ValidationError):
        out.GapAssessmentOut(status="met", rationale="...")
    assert out.GapRefOut(shows="Satisfies").shows == "satisfied" and out.GapRefOut(shows="gap").shows == "shortfall"


def test_reply_parsing_prefers_the_answer_over_echoed_input():
    reply = 'Evidence: {"infrastructure": {"autoscalers": []}}\nAnswer:\n```json\n{"status": "missing", "rationale": "No autoscalers exist."}\n```'
    objs = extract_json_objects(reply)
    assert len(objs) == 2 and objs[-1]["status"] == "missing"
    assert out.GapAssessmentOut.model_validate(objs[-1]).status == "missing"


# ------------------------------------------------------------------------ the pass itself


class ScriptedRunner:
    """Stands in for AgentRunner. ``script`` maps an NFR id to the model output (or an exception) for that requirement."""

    def __init__(self, script=None, default=None, verify=None):
        self.script, self.default, self.verify = script or {}, default, verify or {}
        self.prompts: dict[str, str] = {}
        self.verify_prompts: dict[str, str] = {}

    async def run(self, agent, prompt, schema):
        nid = re.search(r"NFR (\S+) \(", prompt).group(1)
        if "VERIFICATION OF A 'MET' VERDICT" in prompt:  # the adversarial re-check of a met verdict
            self.verify_prompts[nid] = prompt
            result = self.verify.get(nid)
            if isinstance(result, Exception):
                raise result
            return result or self.script_met()
        self.prompts[nid] = prompt
        result = self.script.get(nid, self.default)
        if isinstance(result, list):  # a sequence of answers: first call, then the re-check
            result = result.pop(0) if len(result) > 1 else result[0]
        if isinstance(result, Exception):
            raise result
        if result is None:
            return self.script_met()
        return result

    @staticmethod
    def script_met():
        return out.GapAssessmentOut(status="met", rationale="Everything shown satisfies the criteria.",
                                    found=[out.GapRefOut(path="infrastructure", shows="satisfied")])


def run_pass(dataset, runner, **kw) -> GapReport:
    module = GapAnalysisPass1(**kw)
    module.bind(Registry.load(), Path(".sreadvisor-test"), runner=runner, log=lambda *_: None)
    import asyncio

    return asyncio.run(module.evaluate(dataset))


@pytest.fixture
def dataset(tmp_path):
    repo = boot_repo(tmp_path)
    w(repo, "k8s/app.yaml", "apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: orders}\nspec:\n  replicas: 1\n  selector: {matchLabels: {a: o}}\n"
                            "  template:\n    metadata: {labels: {a: o}}\n    spec:\n      containers:\n        - {name: orders, image: 'orders:1'}\n")
    return analyse(tmp_path, repo, repo)


def by_id(report, nid):
    return next(a for a in report.assessments if a.nfr.id == nid)


def test_every_applicable_requirement_gets_an_assessment(dataset):
    r = run_pass(dataset, ScriptedRunner())
    ids = [a.nfr.id for a in r.assessments]
    assert len(ids) == len(set(ids)) == r.summary.applicable_requirements
    assert {"BASE-RETRY-001", "CAP-001", "SB-001", "K8S-001"} <= set(ids)
    assert not any(i.startswith(("SBK-", "QK-", "LGO-")) for i in ids)  # modules that do not apply are not assessed
    assert sum(r.summary.by_status.values()) == len(ids)
    assert r.inputs["sources_used"] == ["stage1_dataset", "master_nfr_list"]  # nothing else feeds Pass 1


def test_requirements_the_dataset_cannot_answer_are_not_gaps_and_cost_no_llm_call(dataset):
    runner = ScriptedRunner(default=out.GapAssessmentOut(status="missing", rationale="Nothing found in the dataset for this.",
                                                          not_found=["x"]))
    r = run_pass(dataset, runner)
    a = by_id(r, "BASE-LOG-002")  # verification source is manual_review only
    assert a.status == "not_assessable" and a.method == "deterministic" and "BASE-LOG-002" not in runner.prompts
    assert "manual_review" in a.rationale
    assert all(g.nfr.id != "BASE-LOG-002" for g in r.gaps)


def test_skipped_stage1_steps_mean_not_assessable_not_missing(tmp_path):
    repo = boot_repo(tmp_path)
    ds = analyse(tmp_path, repo)  # no IaC path: every infra step is skipped
    runner = ScriptedRunner(default=out.GapAssessmentOut(status="missing", rationale="Nothing in the dataset for this requirement."))
    r = run_pass(ds, runner)
    cap1 = by_id(r, "CAP-001")
    assert cap1.status == "not_assessable" and "did not run" in cap1.rationale and "CAP-001" not in runner.prompts
    assert cap1.evidence.stage1_steps and all(v.startswith("skipped") for v in cap1.evidence.stage1_steps.values())


def test_prompt_contains_only_the_requirement_and_its_evidence_slice(dataset):
    runner = ScriptedRunner()
    run_pass(dataset, runner)
    p = runner.prompts["K8S-001"]
    assert "PASS CRITERIA" in p and "infrastructure.workloads[].containers[].readiness" in p and "orders" in p
    assert "repositories" not in p.split("Dataset evidence")[1]  # nothing outside the entry's own paths


def test_ungrounded_citations_are_dropped_and_paths_get_file_locations(dataset):
    good = out.GapRefOut(path="infrastructure.workloads[0].containers[0]", shows="shortfall", note="no probes")
    fake_file = out.GapRefOut(file="does/not/exist.yml", line=3, shows="shortfall")
    fake_path = out.GapRefOut(path="infrastructure.nothing[0]", shows="shortfall")
    res = out.GapAssessmentOut(status="missing", rationale="No readiness probe on the only container.", found=[good, fake_file, fake_path],
                               not_found=["readiness probe"])
    r = run_pass(dataset, ScriptedRunner({"K8S-001": res}))
    a = by_id(r, "K8S-001")
    assert len(a.evidence.found) == 1
    ref = a.evidence.found[0]
    assert ref.file == "k8s/app.yaml" and ref.line and ref.path.startswith("infrastructure.workloads[0]")  # location attached from the dataset
    assert sum("ungrounded" in w for w in a.warnings) == 2
    assert a.evidence.examined_locations  # where the absence was checked


def test_met_without_any_valid_citation_is_not_accepted(dataset):
    res = out.GapAssessmentOut(status="met", rationale="It looks fine to me overall.", found=[out.GapRefOut(file="nope.yml", line=1)])
    a = by_id(run_pass(dataset, ScriptedRunner({"K8S-001": res})), "K8S-001")
    assert a.status == "not_assessable" and a.confidence == "low" and "no valid citation" in a.rationale and a.warnings


def test_verdict_that_contradicts_its_citations_is_challenged_not_overridden(dataset):
    shortfall = [out.GapRefOut(path="infrastructure.workloads[0]", shows="shortfall")]
    satisfied = [out.GapRefOut(path="infrastructure.workloads[0]", shows="satisfied")]
    contradictory = out.GapAssessmentOut(status="partially_met", rationale="Some probes are present on some pods.", found=shortfall)
    fixed = out.GapAssessmentOut(status="partially_met", rationale="Liveness probes exist; readiness thresholds are missing.",
                                 found=satisfied + shortfall)
    met_but_shortfall = out.GapAssessmentOut(status="met", rationale="All containers have a readiness probe.", found=shortfall)
    corrected = out.GapAssessmentOut(status="missing", rationale="No container has a readiness probe at all.", found=shortfall)
    missing_but_satisfied = out.GapAssessmentOut(status="missing", rationale="No readiness probes exist.", found=satisfied)
    fixed_missing = out.GapAssessmentOut(status="partially_met", rationale="One container has a readiness probe; others do not.",
                                         found=satisfied + shortfall)
    runner = ScriptedRunner({"K8S-001": [contradictory, fixed], "K8S-002": [met_but_shortfall, corrected],
                             "K8S-003": [missing_but_satisfied, fixed_missing]})
    r = run_pass(dataset, runner)
    a = by_id(r, "K8S-001")
    assert a.status == "partially_met" and any("re-assessed" in w for w in a.warnings)  # the model was asked again, and fixed it
    assert "Problem:" in runner.prompts["K8S-001"]  # the second call named the specific problem
    assert by_id(r, "K8S-002").status == "missing"  # the model changed its own verdict when challenged
    a3 = by_id(r, "K8S-003")
    assert a3.status == "partially_met" and any("re-assessed" in w for w in a3.warnings)  # missing+satisfied is also caught
    assert "tagged a citation as satisfied" in runner.prompts["K8S-003"]


def test_unresolved_contradiction_keeps_the_verdict_but_lowers_confidence(dataset):
    shortfall = [out.GapRefOut(path="infrastructure.workloads[0]", shows="shortfall")]
    stubborn = out.GapAssessmentOut(status="partially_met", confidence="high", rationale="Probes exist but are incomplete.", found=shortfall)
    a = by_id(run_pass(dataset, ScriptedRunner({"K8S-001": [stubborn, stubborn]})), "K8S-001")
    assert a.status == "partially_met"  # not silently rewritten by us
    assert a.confidence == "medium" and any("disagree after a re-check" in w for w in a.warnings)


def test_failed_assessment_is_recorded_not_dropped(dataset):
    r = run_pass(dataset, ScriptedRunner({"K8S-001": AgentError("gap_assessor: no valid JSON after 2 attempt(s)")}))
    a = by_id(r, "K8S-001")
    assert a.status == "not_assessable" and "assessment failed" in a.warnings[0]
    assert r.summary.failed_assessments == 1 and all(g.nfr.id != "K8S-001" for g in r.gaps)


def test_gaps_are_structured_ordered_and_reference_the_dataset(dataset):
    shortfall = out.GapAssessmentOut(status="missing", rationale="No such control appears anywhere in the dataset.", not_found=["control"])
    partial = out.GapAssessmentOut(status="partially_met", rationale="One of the two things required is present.",
                                   found=[out.GapRefOut(path="infrastructure.workloads[0]", shows="satisfied"),
                                          out.GapRefOut(path="infrastructure.workloads[0].containers[0]", shows="shortfall")])
    r = run_pass(dataset, ScriptedRunner({"BASE-HC-001": partial, "K8S-001": shortfall, "K8S-003": shortfall, "DKR-005": shortfall}))
    order = [(g.priority, g.status) for g in r.gaps]
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    assert order == sorted(order, key=lambda t: (rank[t[0]], {"missing": 0, "partially_met": 1}[t[1]]))  # priority, then missing first
    assert [g.id for g in r.gaps] == [f"GAP-{i:03d}" for i in range(1, len(r.gaps) + 1)]
    g = next(g for g in r.gaps if g.nfr.id == "BASE-HC-001")
    assert g.gap_type == "nfr_gap" and g.why and g.nfr.requirement and g.nfr.best_practice and g.nfr.criteria
    assert g.evidence.found and g.evidence.examined_paths and g.evidence.stage1_steps
    assert r.summary.gap_count == len(r.gaps) == sum(r.summary.gaps_by_priority.values())
    assert sum(m.assessed for m in r.modules) == r.summary.applicable_requirements
    GapReport.model_validate_json(r.model_dump_json())  # round-trips


def test_unrecognized_tech_stacks_are_separate_from_nfr_gaps(tmp_path):
    repo = boot_repo(tmp_path, "<dependency><groupId>org.mongodb</groupId><artifactId>mongodb-driver-sync</artifactId></dependency>")
    w(repo, "Gemfile", "gem 'rails'\n")
    ds = analyse(tmp_path, repo)
    r = run_pass(ds, ScriptedRunner(default=out.GapAssessmentOut(status="missing", rationale="Nothing about this exists in the dataset.")))
    assert {(u.kind, u.name) for u in r.unrecognized_tech_gaps} >= {("dependency", "org.mongodb:mongodb-driver-sync"), ("manifest", "Ruby")}
    assert all(u.gap_type == "unrecognized_tech_stack" and u.highlight for u in r.unrecognized_tech_gaps)
    assert [u.id for u in r.unrecognized_tech_gaps][0] == "UTG-001"
    assert all(g.gap_type == "nfr_gap" for g in r.gaps)  # never mixed into the ordinary gap list
    assert not any(u.name in g.why for g in r.gaps for u in r.unrecognized_tech_gaps)
    assert r.summary.unrecognized_tech_gap_count == len(r.unrecognized_tech_gaps)
    assert all(u.finding and u.impact and u.recommended_action for u in r.unrecognized_tech_gaps)


def test_module_filter_and_unknown_module(dataset):
    r = run_pass(dataset, ScriptedRunner(), only_modules=["capacity_scaling"])
    assert {a.nfr.module_id for a in r.assessments} == {"capacity_scaling"}
    with pytest.raises(GapAnalysisError):
        run_pass(dataset, ScriptedRunner(), only_modules=["nope"])


def test_no_llm_mode_still_reports_unrecognized_tech(tmp_path):
    repo = boot_repo(tmp_path, "<dependency><groupId>org.mongodb</groupId><artifactId>mongodb-driver-sync</artifactId></dependency>")
    ds = analyse(tmp_path, repo)
    r = run_pass(ds, None, use_llm=False)
    assert r.summary.by_status["not_assessable"] == r.summary.applicable_requirements and not r.gaps
    assert r.unrecognized_tech_gaps and r.summary.assessed_by_llm == 0


# --------------------------------------------------------------------------------- CLI


def test_gaps_cli_writes_report_and_highlights_unrecognized(tmp_path, capsys):
    repo = boot_repo(tmp_path, "<dependency><groupId>org.mongodb</groupId><artifactId>mongodb-driver-sync</artifactId></dependency>")
    analyse(tmp_path, repo)
    ds_file = next((tmp_path / "out").glob("*.dataset.json"))
    capsys.readouterr()
    assert cli.main(["gaps", "--dataset", str(ds_file), "--no-llm", "--out", str(tmp_path / "gaps")]) == 0
    text = capsys.readouterr().out
    assert "UNRECOGNIZED TECH STACK GAPS" in text and "mongodb-driver-sync" in text
    data = json.loads(next((tmp_path / "gaps").glob("*.gaps.json")).read_text(encoding="utf-8"))
    assert {"summary", "gaps", "unrecognized_tech_gaps", "assessments", "inputs"} <= set(data)
    assert cli.main(["gaps", "--dataset", str(tmp_path / "missing.json")]) == 2
    assert load_dataset(ds_file).service_name


# ------------------------------------------------ evidence completeness (found by auditing real verdicts)


def test_small_records_are_shown_whole_so_no_relevant_field_is_hidden():
    data = {"repositories": [{"repo": "r", "application_capacity": [
        {"layer": "application", "category": "thread_pool", "key": "server.tomcat.threads.max", "value": "200",
         "origin": "framework_default", "evidence": {"file": "build.gradle", "line": 37}}]}]}
    obj = json.loads(dp.project(data, ["repositories[].application_capacity[].key"]))
    item = obj["repositories"][0]["application_capacity"][0]
    assert item["origin"] == "framework_default" and item["value"] == "200" and item["at"] == "build.gradle:37"  # not only .key was asked for


def test_truncated_evidence_is_flagged_in_the_prompt_and_caps_confidence(dataset):
    from sreadvisor.gap.pass1 import _prompt

    big = {"repositories": [{"repo": "r", "fingerprint": {"dependencies": [{"name": f"lib{i}", "version": "1"} for i in range(60)]}}]}
    text = dp.project(big, ["repositories[].fingerprint.dependencies[].name"], max_items=30)
    assert dp.truncated(text) and "more of 60" in text
    assert not dp.truncated(dp.project(big, ["repositories[].repo"]))
    runner = ScriptedRunner()
    run_pass(dataset, runner)
    assert "Verification sources for this requirement:" in runner.prompts["K8S-001"]  # the assessor is told what can be verified where
    assert "truncated" not in runner.prompts["K8S-001"].split("Dataset evidence")[1]  # small slice: no notice


def test_default_evidence_window_is_large_enough_for_real_dependency_lists():
    assert Registry.load().analysis.gap.max_evidence_items >= 30


# ------------------------------------------------------ adversarial re-check of met verdicts (a false met hides a real gap)


def met_with_citation():
    return out.GapAssessmentOut(status="met", rationale="Every instance satisfies the pass criteria.",
                                found=[out.GapRefOut(path="infrastructure.workloads[0]", shows="satisfied")])


def test_met_is_downgraded_when_the_recheck_finds_a_cited_shortfall(dataset):
    found = out.GapAssessmentOut(status="partially_met", rationale="The petclinic image has no tag, so it is not pinned.",
                                 found=[out.GapRefOut(path="infrastructure.workloads[0]", shows="shortfall", note="image without a tag")],
                                 not_found=["an explicit image tag"])
    runner = ScriptedRunner({"K8S-001": met_with_citation()}, verify={"K8S-001": found})
    a = by_id(run_pass(dataset, runner), "K8S-001")
    assert a.status == "partially_met" and "no tag" in a.rationale and a.confidence == "medium"
    assert any("downgraded from met" in w for w in a.warnings) and a.evidence.found[0].shows == "shortfall"
    assert "Try to disprove it" in runner.verify_prompts["K8S-001"] and "EVERY instance" in runner.verify_prompts["K8S-001"]


def test_met_stands_when_the_recheck_confirms_it(dataset):
    a = by_id(run_pass(dataset, ScriptedRunner({"K8S-001": met_with_citation()}, verify={"K8S-001": met_with_citation()})), "K8S-001")
    assert a.status == "met" and a.confidence == "medium" and any("confirmed" in w for w in a.warnings)


def test_recheck_disagreement_without_a_citation_does_not_override_met(dataset):
    vague = out.GapAssessmentOut(status="missing", rationale="I have a general feeling this is not really met.", found=[])
    a = by_id(run_pass(dataset, ScriptedRunner({"K8S-001": met_with_citation()}, verify={"K8S-001": vague})), "K8S-001")
    assert a.status == "met" and a.confidence == "medium" and any("without a citable shortfall" in w for w in a.warnings)


def test_recheck_failure_keeps_met_and_says_so(dataset):
    runner = ScriptedRunner({"K8S-001": met_with_citation()}, verify={"K8S-001": AgentError("gap_assessor: no valid JSON")})
    a = by_id(run_pass(dataset, runner), "K8S-001")
    assert a.status == "met" and any("could not be re-checked" in w for w in a.warnings)


def test_recheck_can_be_switched_off_and_only_applies_to_met(dataset):
    runner = ScriptedRunner({"K8S-001": met_with_citation()}, default=out.GapAssessmentOut(status="missing", rationale="Nothing about this exists."))
    reg = Registry.load()
    reg.analysis.gap.verify_met = False
    module = GapAnalysisPass1()
    module.bind(reg, Path(".sreadvisor-test"), runner=runner, log=lambda *_: None)
    import asyncio

    asyncio.run(module.evaluate(dataset))
    assert runner.verify_prompts == {}  # switched off
    runner2 = ScriptedRunner(default=out.GapAssessmentOut(status="missing", rationale="Nothing about this exists in the dataset."))
    run_pass(dataset, runner2)
    assert runner2.verify_prompts == {}  # missing verdicts are never re-checked, only met ones
