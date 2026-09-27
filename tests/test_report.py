"""Stage 4: the unified report (JSON), its HTML render, SLI suggestions and the Dynatrace dashboard generator.

Everything here is deterministic (no LLM, no network): Stage 4 only combines facts Stage 1-3 already produced. The
gap report fixtures are built by running the real Gap Analysis Pass 1 pipeline against a scripted model, so these
tests also confirm Stage 3's output is actually consumable by Stage 4, not just shaped like it."""

import json
from pathlib import Path

import pytest

from sreadvisor import cli
from sreadvisor.agents import outputs as out
from sreadvisor.gap.schema import EvidenceRef, FindingEvidence, Gap, NfrRef
from sreadvisor.nfr.coverage import compute_coverage
from sreadvisor.report import sli as sli_mod
from sreadvisor.report.build import action_from_gap, build_report
from sreadvisor.report.dynatrace_dashboard import DynatraceDashboard, build_dashboard
from sreadvisor.report.html import render_html
from sreadvisor.report.output import write_report
from sreadvisor.report.schema import UnifiedReport
from sreadvisor.schema.dataset import BusinessContext, FlowDependency, FlowStep, TransactionFlow

from test_gap import ScriptedRunner, run_pass
from test_nfr import analyse, boot_repo, w


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("DT_API_TOKEN", "test-token")


# ---------------------------------------------------------------------------------- fixtures


def _nfr(id_="CAP-001", module_id="capacity_scaling", module_title="Capacity and scaling", title="Resource requests and limits defined for every container") -> NfrRef:
    return NfrRef(id=id_, module_id=module_id, module_title=module_title, layer="cross_cutting", title=title,
                 priority="critical", requirement="Every container declares requests and limits.",
                 best_practice="Set requests from steady-state usage.", audit_requirement="Sizing is recorded.",
                 criteria="Every container has non-empty requests and limits.")


def _gap(status, nfr=None, found=None, priority="critical") -> Gap:
    return Gap(id="GAP-001", status=status, priority=priority, confidence="high", nfr=nfr or _nfr(),
              why="The dataset shows the containers lack resource limits.",
              evidence=FindingEvidence(found=found or [], not_found=["Non-empty requests and limits"],
                                       examined_paths=["infrastructure.workloads[].containers[].limits"]))


def _synthetic_flow(dataset, *, kind: str, name: str) -> TransactionFlow:
    """A flow using the dataset's own (real) entry point, with one synthetic dependency of the given kind.

    ``analyse()`` always runs with ``--no-llm`` (deterministic Stage 1 only), so no transaction flow is ever traced;
    the SLI engine reads dependencies from ``transaction_flows``, not from the fingerprint, since only a traced flow
    is evidence the dependency is actually reached. This injects one, matching the real shape Stage 1 would produce."""
    ep = dataset.repositories[0].entry_points[0]
    return TransactionFlow(entry_point=ep, summary="synthetic flow for testing",
                           steps=[FlowStep(order=1, layer="controller", symbol=ep.symbol, action="handles the request",
                                           evidence=ep.evidence)],
                           dependencies=[FlowDependency(name=name, kind=kind, evidence=ep.evidence)])


def synthetic_report(tmp_path: Path, *, business: BusinessContext | None = None, script=None,
                     dependencies: list[tuple[str, str]] | None = None) -> UnifiedReport:
    """A real dataset (Spring Boot + Postgres + Caffeine + Kafka) and a real GapReport (Stage 3 pipeline, scripted
    model), combined into a UnifiedReport. ``script`` overrides specific NFR verdicts; everything else defaults to
    met. ``dependencies`` (kind, name) pairs become synthetic transaction-flow dependencies (default: one datastore,
    one cache, one messaging, matching the fingerprint's Postgres/Caffeine/Kafka dependencies)."""
    repo = boot_repo(tmp_path, "".join([
        "<dependency><groupId>org.postgresql</groupId><artifactId>postgresql</artifactId></dependency>",
        "<dependency><groupId>com.github.ben-manes.caffeine</groupId><artifactId>caffeine</artifactId></dependency>",
        "<dependency><groupId>org.springframework.kafka</groupId><artifactId>spring-kafka</artifactId></dependency>",
    ]))
    w(repo, "k8s/app.yaml", "apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: orders}\nspec:\n  replicas: 1\n"
                            "  selector: {matchLabels: {a: o}}\n  template:\n    metadata: {labels: {a: o}}\n"
                            "    spec:\n      containers:\n        - {name: orders, image: 'orders:1'}\n")
    dataset = analyse(tmp_path, repo, repo)
    if business is not None:
        dataset = dataset.model_copy(update={"business_context": business})
    deps = dependencies if dependencies is not None else [
        ("datastore", "relational database (Spring Data JPA)"), ("cache", "cache (Spring Cache)"), ("messaging", "orders-topic (Kafka)")]
    flows = [_synthetic_flow(dataset, kind=k, name=n) for k, n in deps]
    repo_analysis = dataset.repositories[0].model_copy(update={"transaction_flows": flows})
    dataset = dataset.model_copy(update={"repositories": [repo_analysis]})
    gap_report = run_pass(dataset, ScriptedRunner(script))
    return build_report(dataset, gap_report)


# --------------------------------------------------------------------------------- action_from_gap


def test_action_reads_as_an_instruction_for_missing_and_partial():
    missing = _gap("missing", found=[EvidenceRef(file="k8s/db.yml", line=28, shows="shortfall")])
    partial = _gap("partially_met", found=[EvidenceRef(file="k8s/db.yml", line=28, shows="satisfied")])
    assert action_from_gap(missing) == "Fix: Resource requests and limits defined for every container — see k8s/db.yml."
    assert action_from_gap(partial).startswith("Complete: Resource requests and limits defined for every container")


def test_action_handles_negatively_phrased_titles_without_broken_grammar():
    nfr = _nfr(id_="SEC-001", module_id="secrets_configuration", title="No hardcoded credentials or sensitive values in code")
    action = action_from_gap(_gap("missing", nfr=nfr))
    assert action == "Fix: No hardcoded credentials or sensitive values in code."
    assert "add no hardcoded" not in action.lower()  # never re-conjugates the title into a verb phrase


def test_action_with_no_locations_and_many_locations():
    no_loc = _gap("missing", found=[])
    assert action_from_gap(no_loc) == "Fix: Resource requests and limits defined for every container."
    many = _gap("missing", found=[EvidenceRef(file=f"f{i}.yml", line=i, shows="shortfall") for i in range(6)])
    action = action_from_gap(many)
    assert action.count(".yml") == 4 and action.endswith(", ...") and not action.endswith("....")  # capped, no double period


# ----------------------------------------------------------------------------------------- build_report


def test_build_report_combines_tech_stack_flow_gaps_and_tiers(tmp_path):
    report = synthetic_report(tmp_path)
    assert report.service_name == "orders" and report.schema_version == "1.0"
    repo = report.tech_stack[0]
    assert repo.fingerprint.frameworks and repo.entry_points and repo.transaction_flows
    assert "datastore" in repo.dependency_highlights and "cache" in repo.dependency_highlights
    assert report.infrastructure.workloads == 1
    assert report.action_item_summary.applicable_requirements > 0
    assert len(report.action_items) == report.action_item_summary.gap_count
    assert all(a.status in ("missing", "partially_met") for a in report.action_items)
    assert all(a.action for a in report.action_items)
    assert report.telemetry_tiers.tier1_oneagent_default.signals  # tier 1 present
    assert report.applicable_modules
    UnifiedReport.model_validate_json(report.model_dump_json())  # round-trips


def test_dependency_highlights_exclude_test_scope(tmp_path):
    report = synthetic_report(tmp_path)
    highlights = report.tech_stack[0].dependency_highlights
    assert not any("test" in coord.lower() and "testcontainers" in coord.lower() for coords in highlights.values() for coord in coords)
    assert all("junit" not in c.lower() for coords in highlights.values() for c in coords)


def test_service_name_mismatch_is_rejected(tmp_path):
    repo = boot_repo(tmp_path)
    dataset = analyse(tmp_path, repo)
    gap_report = run_pass(dataset, ScriptedRunner())
    renamed = dataset.model_copy(update={"service_name": "a-different-service"})
    with pytest.raises(ValueError, match="orders"):
        build_report(renamed, gap_report)


def test_stale_gap_report_against_a_changed_dataset_is_flagged(tmp_path):
    repo = boot_repo(tmp_path)
    dataset = analyse(tmp_path, repo)
    gap_report = run_pass(dataset, ScriptedRunner())
    redated = dataset.model_copy(update={"generated_at": dataset.generated_at.replace(year=dataset.generated_at.year + 1)})
    report = build_report(redated, gap_report)
    assert any("different run" in w for w in report.warnings)


def test_gap_report_warnings_are_carried_through_unchanged(tmp_path):
    repo = boot_repo(tmp_path)
    dataset = analyse(tmp_path, repo)
    bad = out.GapAssessmentOut(status="missing", rationale="Nothing about this exists in the dataset at all.")
    gap_report = run_pass(dataset, ScriptedRunner({"BASE-RETRY-001": bad}))
    report = build_report(dataset, gap_report)
    assert set(gap_report.warnings) <= set(report.warnings)


# --------------------------------------------------------------------------------------------- SLIs


def test_entry_point_slis_latency_error_rate_and_one_throughput_per_repo(tmp_path):
    report = synthetic_report(tmp_path)
    names = [s.name for s in report.sli_suggestions]
    assert any(n.startswith("Latency: ") for n in names) and any(n.startswith("Error rate: ") for n in names)
    assert sum(1 for n in names if n.startswith("Request throughput:")) == 1  # not one per entry point
    latency = next(s for s in report.sli_suggestions if s.name.startswith("Latency:"))
    assert latency.tier == 1 and latency.metric_key == "builtin:service.response.time" and latency.kind == "latency"


def test_dependency_slis_datastore_cache_and_kafka_lag(tmp_path):
    report = synthetic_report(tmp_path)
    by_name = {s.name: s for s in report.sli_suggestions}
    query_lat = next(s for n, s in by_name.items() if n.startswith("Query latency:"))
    assert query_lat.tier == 1 and query_lat.measurement_source.startswith("OneAgent:")
    # oa.db.call_time carries no confirmed builtin: key (see the OneAgent catalogue's own honesty about unverified
    # keys), so this specific tier-1 SLI has no metric_key; the dashboard must render it as a note, never a fabricated chart.
    pool = next((s for n, s in by_name.items() if "saturation" in n.lower() and "connection pool" in n.lower()), None)
    assert pool is not None and pool.tier == 2 and pool.metric_key is None  # hikaricp: no builtin: key, never fabricated
    lag = next((s for n, s in by_name.items() if n.startswith("Consumer lag:")), None)
    assert lag is not None and lag.tier == 2 and "kafka_client" in lag.measurement_source
    cache = next((s for n, s in by_name.items() if "Cache hit ratio" in n or "Cache call latency" in n), None)
    assert cache is not None  # Caffeine has no OneAgent trace and no hit-ratio metric detected by default (stats off)


def test_business_slis_use_the_table_for_a_known_category(tmp_path):
    b = BusinessContext(capability="Online shop cart", category="shopping_cart", rationale="r", key_operations=["Checkout"])
    report = synthetic_report(tmp_path, business=b)
    tier3 = [s for s in report.sli_suggestions if s.tier == 3]
    assert {s.name for s in tier3} == {"Cart abandonment rate", "Checkout completion latency"}
    assert all(s.metric_key is None and "not yet implemented" in s.measurement_source for s in tier3)


def test_business_slis_fall_back_to_key_operations_for_unlisted_category(tmp_path):
    b = BusinessContext(capability="Something bespoke", category="other", rationale="r",
                        key_operations=["Reticulate splines", "Discombobulate"])
    report = synthetic_report(tmp_path, business=b)
    names = {s.name for s in report.sli_suggestions if s.tier == 3}
    assert names == {"Reticulate splines success rate", "Reticulate splines latency",
                     "Discombobulate success rate", "Discombobulate latency"}


def test_no_business_context_means_no_tier3_slis(tmp_path):
    repo = boot_repo(tmp_path)
    dataset = analyse(tmp_path, repo)  # --no-llm: business_context is never inferred
    assert dataset.business_context is None
    tiers = compute_coverage(dataset).telemetry_tiers
    tier3 = [s for s in sli_mod.suggest_slis(dataset.repositories, None, tiers) if s.tier == 3]
    assert tier3 == []


def test_sli_ids_are_sequential_and_unique(tmp_path):
    report = synthetic_report(tmp_path)
    ids = [s.id for s in report.sli_suggestions]
    assert ids == [f"SLI-{i:03d}" for i in range(1, len(ids) + 1)]
    assert len(set(s.name for s in report.sli_suggestions)) == len(report.sli_suggestions)  # deduped


# -------------------------------------------------------------------------------------------- HTML


def test_html_escapes_hostile_content_and_never_emits_a_raw_script_tag(tmp_path):
    b = BusinessContext(capability='<script>alert(1)</script>', category="other", rationale="r", key_operations=["<img src=x onerror=alert(1)>"])
    report = synthetic_report(tmp_path, business=b)
    page = render_html(report)
    assert "<script>" not in page and "<img " not in page  # no unescaped tag delimiter reaches the page
    assert "&lt;script&gt;" in page and "&lt;img src=x onerror=alert(1)&gt;" in page  # the hostile text still appears, safely inert


def test_html_contains_expected_sections_and_badges(tmp_path):
    report = synthetic_report(tmp_path, script={"CAP-001": out.GapAssessmentOut(
        status="missing", rationale="No containers declare requests or limits at all.", not_found=["requests and limits"])})
    page = render_html(report)
    for anchor in ('id="unrecognized"', 'id="action-items"', 'id="tech-stack"', 'id="telemetry"', 'id="slis"'):
        assert anchor in page
    assert "<!doctype html>" in page.lower() and "<style>" in page
    assert 'class="badge prio-critical"' in page
    assert "Fix: Resource requests and limits" in page
    assert "SLI suggestions (" in page


def test_html_shows_unrecognized_highlight_when_present(tmp_path):
    repo = boot_repo(tmp_path, "<dependency><groupId>org.mongodb</groupId><artifactId>mongodb-driver-sync</artifactId></dependency>")
    dataset = analyse(tmp_path, repo)
    gap_report = run_pass(dataset, ScriptedRunner())
    report = build_report(dataset, gap_report)
    page = render_html(report)
    assert 'class="highlight"' in page and "mongodb-driver-sync" in page and "unrecognized tech stack" in page.lower()


def test_html_none_unrecognized_when_clean(tmp_path):
    report = synthetic_report(tmp_path)
    page = render_html(report)
    assert "None. Every technology found" in page


# ------------------------------------------------------------------------------------ Dynatrace dashboard


def test_dashboard_round_trips_the_strict_schema(tmp_path):
    report = synthetic_report(tmp_path)
    dashboard = build_dashboard(report)
    DynatraceDashboard.model_validate(dashboard.model_dump())  # extra="forbid" everywhere: no stray fields anywhere
    assert dashboard.dashboardMetadata.name.startswith("orders")
    assert "sreadvisor" in dashboard.dashboardMetadata.tags


def test_tier1_slis_become_chart_tiles_with_real_metric_keys_never_fabricated_otherwise(tmp_path):
    report = synthetic_report(tmp_path)
    dashboard = build_dashboard(report)
    charts = [t for t in dashboard.tiles if t.tileType == "DATA_EXPLORER"]
    notes = [t for t in dashboard.tiles if t.tileType == "MARKDOWN"]
    assert charts and notes
    tier1_with_key = [s for s in report.sli_suggestions if s.tier == 1 and s.metric_key]
    assert len(charts) == len(tier1_with_key)
    for t in charts:
        assert t.queries and t.queries[0].metricSelector.startswith("builtin:") and t.queries[0].metricSelector.endswith(":avg")
    tier23_names = {s.name for s in report.sli_suggestions if s.tier in (2, 3)}
    chart_names = {t.name for t in charts}
    assert not (tier23_names & chart_names)  # tier 2/3 never become a chart tile (no key to fabricate one from)


def test_dashboard_has_a_header_per_populated_tier_and_no_tile_uses_negative_bounds(tmp_path):
    report = synthetic_report(tmp_path)
    dashboard = build_dashboard(report)
    header_texts = [t.markdown for t in dashboard.tiles if t.tileType == "MARKDOWN" and t.name == ""]
    assert any("Tier 1" in (h or "") for h in header_texts)
    tiers_present = {s.tier for s in report.sli_suggestions}
    for tier, label in ((2, "Tier 2"), (3, "Tier 3")):
        if tier in tiers_present:
            assert any(label in (h or "") for h in header_texts)
    assert all(t.bounds.top >= 0 and t.bounds.left >= 0 and t.bounds.width > 0 and t.bounds.height > 0 for t in dashboard.tiles)


def test_dashboard_json_file_is_directly_the_dynatrace_shape_no_wrapper(tmp_path):
    report = synthetic_report(tmp_path)
    written = write_report(report, tmp_path / "out")
    data = json.loads(written["dashboard"].read_text(encoding="utf-8"))
    assert set(data.keys()) == {"dashboardMetadata", "tiles"}  # nothing to unwrap before importing


# -------------------------------------------------------------------------------------------------- CLI


def test_report_cli_writes_all_three_artifacts(tmp_path):
    repo = boot_repo(tmp_path)
    assert cli.main(["analyze", "--repo", str(repo), "--provider", "dynatrace", "--service-id", "SERVICE-0123456789ABCDEF",
                    "--dt-environment-url", "https://abc.live.dynatrace.com", "--no-llm", "--out", str(tmp_path / "out"),
                    "--state-dir", str(tmp_path / "state")]) == 0
    ds_file = next((tmp_path / "out").glob("*.dataset.json"))
    assert cli.main(["gaps", "--dataset", str(ds_file), "--no-llm", "--out", str(tmp_path / "out")]) == 0
    gaps_file = next((tmp_path / "out").glob("*.gaps.json"))
    assert cli.main(["report", "--dataset", str(ds_file), "--gaps", str(gaps_file), "--out", str(tmp_path / "out2")]) == 0
    out2 = tmp_path / "out2"
    assert (out2 / "orders.unified-report.json").is_file()
    assert (out2 / "orders.unified-report.html").is_file()
    assert (out2 / "orders.dynatrace-dashboard.json").is_file()
    UnifiedReport.model_validate_json((out2 / "orders.unified-report.json").read_text(encoding="utf-8"))


def test_analyze_report_flag_chains_gaps_and_report_in_one_run(tmp_path):
    repo = boot_repo(tmp_path)
    out_dir = tmp_path / "out"
    rc = cli.main(["analyze", "--repo", str(repo), "--provider", "dynatrace", "--service-id", "SERVICE-0123456789ABCDEF",
                  "--dt-environment-url", "https://abc.live.dynatrace.com", "--no-llm", "--report", "--out", str(out_dir),
                  "--state-dir", str(tmp_path / "state")])
    assert rc == 0
    for suffix in (".dataset.json", ".gaps.json", ".unified-report.json", ".unified-report.html", ".dynatrace-dashboard.json"):
        assert any(f.name.endswith(suffix) for f in out_dir.iterdir()), suffix


def test_report_cli_rejects_mismatched_inputs(tmp_path):
    repo = boot_repo(tmp_path)
    assert cli.main(["analyze", "--repo", str(repo), "--provider", "dynatrace", "--service-id", "SERVICE-0123456789ABCDEF",
                     "--dt-environment-url", "https://abc.live.dynatrace.com", "--no-llm", "--out", str(tmp_path / "out"),
                     "--state-dir", str(tmp_path / "state")]) == 0
    ds_file = next((tmp_path / "out").glob("*.dataset.json"))
    assert cli.main(["report", "--dataset", str(ds_file), "--gaps", str(tmp_path / "nope.json")]) == 2


def test_report_subcommand_and_analyze_flag_are_registered():
    ns = cli._parser().parse_args(["report", "--dataset", "d.json", "--gaps", "g.json", "--out", "o"])
    assert (ns.dataset, ns.gaps, ns.out) == ("d.json", "g.json", "o")
    ns2 = cli._parser().parse_args(["analyze", "--repo", "r", "--report"])
    assert ns2.report is True and ns2.gaps is False
