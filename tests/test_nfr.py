"""Stage 2: the Master NFR List, the two telemetry catalogues, module matching, the unrecognized-stack
feedback loop and the three-tier telemetry view. No LLM or network needed."""

import json
from pathlib import Path

import pytest

from sreadvisor import cli
from sreadvisor.nfr import loader
from sreadvisor.nfr.coverage import compute_coverage, load_dataset
from sreadvisor.nfr.detect import Signals, rule_match
from sreadvisor.nfr.schema import DetectRule, MasterNfrList
from sreadvisor.schema.dataset import ServiceDataset

EXPECTED_TECH_MODULES = {
    # languages
    "lang_java", "lang_python", "lang_javascript_typescript", "lang_go", "lang_rust",
    # frameworks and architecture
    "spring_boot", "microservices_architecture", "quarkus",
    # source control, CI/CD
    "source_github", "cicd_harness", "cicd_ucd",
    # IaC and containers
    "iac_terraform", "docker", "kubernetes", "openshift", "gke",
    # integration layer
    "rest_apis", "api_gateway", "service_mesh", "event_driven_messaging", "spring_boot_kafka",
    # data
    "data_postgres", "data_oracle", "data_sqlserver", "data_bigquery", "data_relational", "data_gcp_managed",
    # security, observability
    "zero_trust", "jwt_authentication", "oauth2_identity", "observability_dynatrace",
}
EXPECTED_CROSS_CUTTING = {"capacity_scaling", "deployment_rollback_safety", "dependency_criticality",
                          "secrets_configuration", "encryption_audit", "telemetry_coverage_tiers"}


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("DT_API_TOKEN", "test-token")


# ------------------------------------------------------------------- the knowledge base itself


def test_committed_json_matches_yaml_sources():
    assert loader.is_up_to_date() == []


def test_master_list_is_flat_json_organised_by_module():
    raw = json.loads((loader.DATA_DIR / loader.MASTER_FILE).read_text(encoding="utf-8"))
    assert set(raw) == {"kb_schema_version", "description", "layers", "modules"}
    assert set(raw["modules"]) >= EXPECTED_TECH_MODULES | EXPECTED_CROSS_CUTTING | {"baseline"}
    for mid, module in raw["modules"].items():
        assert module["id"] == mid and module["entries"]
        for e in module["entries"]:  # the four core fields are always present, so Stage 3 never needs defaults
            assert {"requirement", "best_practice", "audit_requirement", "monitoring"} <= set(e)
            assert e["monitoring"] and all({"source", "signal"} <= set(m) for m in e["monitoring"])


def test_baseline_covers_the_six_generic_areas():
    ids = {e.id for e in loader.load_master().modules["baseline"].entries}
    for area in ("RETRY", "CB", "TO", "HC", "LOG", "MON"):
        assert any(i.startswith(f"BASE-{area}-") for i in ids), area


def test_layer_two_extends_baseline_and_layers_are_labelled():
    kb = loader.load_master()
    for m in kb.modules.values():
        if m.layer == "tech_stack":
            assert "baseline" in m.extends
    assert {m.id for m in kb.modules.values() if m.layer == "cross_cutting"} >= EXPECTED_CROSS_CUTTING


def test_cross_cutting_entries_name_stage1_evidence_and_criteria():
    kb = loader.load_master()
    for mid in ("capacity_scaling", "deployment_rollback_safety", "dependency_criticality", "secrets_configuration", "encryption_audit"):
        for e in kb.modules[mid].entries:
            assert e.verification.criteria and e.verification.stage1_paths, e.id


def test_stage1_paths_are_validated_against_the_dataset_schema():
    assert loader.path_exists(ServiceDataset, "infrastructure.workloads[].containers[].requests")
    assert loader.path_exists(ServiceDataset, "infrastructure.pipelines[].rollback.mode")
    assert loader.path_exists(ServiceDataset, "business_context.key_operations")  # a list of plain values may omit []
    assert not loader.path_exists(ServiceDataset, "infrastructure.workloads.replicas")  # missing []
    assert not loader.path_exists(ServiceDataset, "infrastructure.workloads[].no_such_field")
    assert not loader.path_exists(ServiceDataset, "service_name[]")


def test_entries_accept_module_specific_extension_fields():
    e = next(e for e in loader.load_master().modules["spring_boot_kafka"].entries if e.id == "SBK-003")
    assert e.model_dump()["kafka_property"].startswith("DefaultErrorHandler")  # extra field survives validation


def test_bad_source_is_rejected_with_a_clear_error(tmp_path):
    src = tmp_path / "src"
    (src / "modules").mkdir(parents=True)
    for name in ("master.yaml", "oneagent.yaml", "instrumentation.yaml"):
        (src / name).write_text((loader.SRC_DIR / name).read_text(encoding="utf-8"), encoding="utf-8")
    (src / "modules" / "x.yaml").write_text(
        "id: x\ntitle: X\nlayer: tech_stack\ncategory: language\ndescription: d\nextends: []\n"
        "detect: [{language: X}]\nentries:\n  - {id: X-1, title: t, requirement: r, best_practice: b, monitoring: [], verification: {sources: [manual_review], criteria: c}}\n",
        encoding="utf-8")
    with pytest.raises(loader.KnowledgeBaseError) as e:
        loader.build(src)
    assert "baseline" in str(e.value) or "monitoring" in str(e.value)


def test_detect_rule_needs_a_condition_and_known_infra_signal():
    with pytest.raises(ValueError):
        DetectRule()
    with pytest.raises(ValueError):
        DetectRule(infra="not_a_signal")
    assert rule_match(DetectRule(framework="Spring Boot", dependency="kafka"),
                      Signals(frameworks={"spring boot"}, dependencies=["org.springframework.kafka:spring-kafka"]))
    assert not rule_match(DetectRule(framework="Spring Boot", dependency="kafka"), Signals(frameworks={"spring boot"}))


# ------------------------------------------------------------------------- catalogues


def test_every_tech_stack_module_has_an_entry_in_both_catalogues():
    kb, oa, app = loader.load_master(), loader.load_oneagent(), loader.load_app_catalogue()
    for m in kb.modules.values():
        if m.layer == "tech_stack":
            assert m.id in oa.modules, f"OneAgent catalogue lacks {m.id}"
            assert m.id in app.modules, f"instrumentation catalogue lacks {m.id}"


def test_catalogues_are_tagged_and_kept_distinct():
    oa, app = loader.load_oneagent(), loader.load_app_catalogue()
    assert oa.tier == "oneagent_default" and oa.coverage == "default_out_of_the_box"
    assert app.tier == "application_level_library_emitted" and "overlap" in app.overlap_policy
    raw_oa = json.loads((loader.DATA_DIR / loader.ONEAGENT_FILE).read_text(encoding="utf-8"))
    raw_app = json.loads((loader.DATA_DIR / loader.APP_FILE).read_text(encoding="utf-8"))
    assert raw_oa["tier"] != raw_app["tier"]


def test_kafka_consumer_lag_is_library_emitted_not_a_oneagent_default():
    oa, app = loader.load_oneagent(), loader.load_app_catalogue()
    kafka = oa.modules["spring_boot_kafka"]
    assert any("lag" in g.signal.lower() and g.likely_source == "library_emitted" for g in kafka.not_covered_by_default)
    names = {m.name for lib in app.modules["spring_boot_kafka"].libraries for m in lib.metrics}
    assert {"records-lag-max", "commit-latency-avg", "records-per-request-avg"} <= names
    all_oa = {s.name.lower() for m in oa.modules.values() for s in m.signals}
    assert not any("lag" in n for n in all_oa)  # OneAgent defaults never claim consumer lag


def test_rust_has_no_oneagent_sensor():
    rust = loader.load_oneagent().modules["lang_rust"]
    assert rust.support_level == "none" and not rust.signals


# ---------------------------------------------------------------------------- helpers


def w(root: Path, name: str, text: str) -> None:
    p = root / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def analyse(tmp_path: Path, repo: Path, iac: Path | None = None) -> ServiceDataset:
    out = tmp_path / "out"
    args = ["analyze", "--repo", str(repo), "--provider", "dynatrace", "--service-id", "SERVICE-0123456789ABCDEF",
            "--dt-environment-url", "https://abc.live.dynatrace.com", "--no-llm", "--out", str(out),
            "--state-dir", str(tmp_path / "state")]
    if iac:
        args += ["--iac", str(iac)]
    assert cli.main(args) == 0
    return load_dataset(next(out.glob("*.dataset.json")))


POM_BOOT = """<project><modelVersion>4.0.0</modelVersion>
<parent><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-parent</artifactId><version>3.3.0</version></parent>
<groupId>demo</groupId><artifactId>orders</artifactId>
<dependencies>
<dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-web</artifactId></dependency>
<dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-actuator</artifactId></dependency>
{extra}
</dependencies></project>"""
CONTROLLER = """package demo;
import org.springframework.web.bind.annotation.*;
@RestController
class C {
    @GetMapping("/x")
    public String x() { return ""; }
}
"""


def boot_repo(tmp_path: Path, extra: str = "") -> Path:
    repo = tmp_path / "orders"
    w(repo, "pom.xml", POM_BOOT.format(extra=extra))
    w(repo, "src/main/java/demo/C.java", CONTROLLER)
    return repo


# ---------------------------------------------------------------- module matching


def test_matching_modules_for_a_spring_boot_service(tmp_path):
    repo = boot_repo(tmp_path, "<dependency><groupId>org.postgresql</groupId><artifactId>postgresql</artifactId></dependency>")
    w(repo, "k8s/app.yaml", "apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: o}\nspec:\n  replicas: 2\n  selector: {matchLabels: {a: o}}\n"
                            "  template:\n    metadata: {labels: {a: o}}\n    spec:\n      containers:\n        - {name: o, image: 'orders:1'}\n")
    w(repo, ".github/workflows/ci.yml", "name: ci\non: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: ./gradlew build\n")
    cov = compute_coverage(analyse(tmp_path, repo, repo))
    ids = {m.id for m in cov.applicable_modules}
    assert {"baseline", "lang_java", "spring_boot", "rest_apis", "data_postgres", "data_relational", "kubernetes",
            "source_github", "observability_dynatrace"} <= ids
    assert EXPECTED_CROSS_CUTTING <= ids  # cross-cutting modules always apply
    assert not ids & {"spring_boot_kafka", "quarkus", "lang_go", "openshift", "service_mesh", "cicd_harness"}
    assert cov.applicable_entry_count == sum(m.entry_count for m in cov.applicable_modules)
    assert cov.unrecognized_tech_stacks == []  # nothing found without a module


def test_spring_boot_plus_kafka_module_needs_both(tmp_path):
    repo = boot_repo(tmp_path, "<dependency><groupId>org.springframework.kafka</groupId><artifactId>spring-kafka</artifactId></dependency>")
    ids = {m.id for m in compute_coverage(analyse(tmp_path, repo)).applicable_modules}
    assert {"spring_boot_kafka", "event_driven_messaging", "spring_boot"} <= ids


# ------------------------------------------------------------- feedback loop (unrecognized)


def test_unrecognized_stacks_are_flagged_not_skipped(tmp_path):
    repo = boot_repo(tmp_path, "<dependency><groupId>org.mongodb</groupId><artifactId>mongodb-driver-sync</artifactId></dependency>")
    w(repo, "Gemfile", "source 'https://rubygems.org'\ngem 'rails'\n")
    w(repo, "svc/Service.csproj", '<Project Sdk="Microsoft.NET.Sdk.Web"><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>')
    w(repo, ".gitlab-ci.yml", "stages: [deploy]\ndeploy:\n  stage: deploy\n  script: [kubectl apply -f k8s/]\n")
    cov = compute_coverage(analyse(tmp_path, repo, repo))
    flagged = {(u.kind, u.name) for u in cov.unrecognized_tech_stacks}
    assert ("dependency", "org.mongodb:mongodb-driver-sync") in flagged  # a datastore with no module
    assert ("manifest", "Ruby") in flagged  # a manifest Stage 1 has no parser for
    assert ("language", "C#") in flagged  # .NET has no module in the list
    assert ("infrastructure", "GitLab CI") in flagged
    assert all(u.action and "NFR module" in u.action for u in cov.unrecognized_tech_stacks)
    assert ("language", "Java") not in flagged and ("framework", "Spring Boot") not in flagged


def test_report_lists_unrecognized_stacks_explicitly(tmp_path, capsys):
    repo = boot_repo(tmp_path, "<dependency><groupId>org.mongodb</groupId><artifactId>mongodb-driver-sync</artifactId></dependency>")
    analyse(tmp_path, repo)
    md = next((tmp_path / "out").glob("*.report.md")).read_text(encoding="utf-8")
    assert "## Unrecognized tech stacks requiring NFR coverage" in md and "mongodb-driver-sync" in md
    assert "Unrecognized tech stacks requiring NFR coverage (1)" in capsys.readouterr().out  # also on the console


def test_clean_service_reports_none_unrecognized(tmp_path):
    analyse(tmp_path, boot_repo(tmp_path))
    md = next((tmp_path / "out").glob("*.report.md")).read_text(encoding="utf-8")
    assert "None. Every technology found" in md


def test_go_and_rust_manifests_are_fingerprinted_and_matched(tmp_path):
    (tmp_path / "go").mkdir()
    go = tmp_path / "go" / "gosvc"
    gomod = "\n".join([
        "module example.com/svc", "", "go 1.22", "", "require (",
        "\tgithub.com/gin-gonic/gin v1.9.1",
        "\tgithub.com/lib/pq v1.10.9",
        "\tgolang.org/x/sys v0.1.0 // indirect",
        ")", ""])
    w(go, "go.mod", gomod)
    w(go, "main.go", "package main\nfunc main() {}\n")
    ds = analyse(tmp_path / "go", go)
    fp = ds.repositories[0].fingerprint
    assert fp.languages == ["Go"] and fp.runtime_versions["go"] == "1.22"
    assert "Gin" in [f.name for f in fp.frameworks]
    assert next(d for d in fp.dependencies if d.name.endswith("lib/pq")).categories == ["datastore"]
    assert next(d for d in fp.dependencies if d.name.endswith("x/sys")).scope == "indirect"
    cov = compute_coverage(ds)
    assert {"lang_go", "data_relational", "data_postgres"} <= {m.id for m in cov.applicable_modules}
    assert cov.unrecognized_tech_stacks == []  # Gin is recognised through the Go module

    (tmp_path / "rust").mkdir()
    rust = tmp_path / "rust" / "rustsvc"
    cargo = "\n".join([
        "[package]", 'name = "svc"', 'edition = "2021"', 'rust-version = "1.75"',
        "[dependencies]", 'axum = "0.7"', 'tokio = { version = "1", features = ["full"] }', ""])
    w(rust, "Cargo.toml", cargo)
    w(rust, "src/main.rs", "fn main() {}\n")
    ds = analyse(tmp_path / "rust", rust)
    assert ds.repositories[0].fingerprint.languages == ["Rust"]
    cov = compute_coverage(ds)
    assert "lang_rust" in {m.id for m in cov.applicable_modules} and cov.unrecognized_tech_stacks == []


# -------------------------------------------------------------------------- tiers


def test_three_tiers_are_separate_and_kafka_lag_is_tier_two(tmp_path):
    repo = boot_repo(tmp_path, "<dependency><groupId>org.springframework.kafka</groupId><artifactId>spring-kafka</artifactId></dependency>")
    tiers = compute_coverage(analyse(tmp_path, repo)).telemetry_tiers
    assert tiers.tier1_oneagent_default.tag == "oneagent_default"
    assert tiers.tier2_application_library.tag == "application_level_library_emitted"
    assert tiers.tier3_custom_instrumentation.tag == "custom_instrumentation"
    detected = {d.library_id: d for d in tiers.tier2_application_library.detected_in_service}
    assert {"micrometer", "kafka_client"} <= set(detected)
    assert "records-lag-max" in {m.name for m in detected["kafka_client"].metrics}
    tier1_names = {s.signal.name.lower() for s in tiers.tier1_oneagent_default.signals}
    assert not any("lag" in n for n in tier1_names)  # not a OneAgent default
    gaps = {g.item.signal.lower() for g in tiers.tier1_oneagent_default.not_covered_by_default}
    assert any("consumer lag" in g for g in gaps)
    by_tier = {}
    for entry in tiers.metric_index:
        by_tier.setdefault(entry.tier, []).append(entry)
        assert entry.tier_tag == {1: "oneagent_default", 2: "application_level_library_emitted"}[entry.tier]
    assert by_tier[1] and by_tier[2]
    lag = [e for e in by_tier[2] if e.name == "records-lag-max"]
    assert lag and lag[0].present_in_service is True


def test_metrics_require_matching_dependencies(tmp_path):
    tiers = compute_coverage(analyse(tmp_path, boot_repo(tmp_path))).telemetry_tiers
    micrometer = next(d for d in tiers.tier2_application_library.detected_in_service if d.library_id == "micrometer")
    names = {m.name for m in micrometer.metrics}
    assert "http.server.requests" in names and "jvm.memory.used" in names
    assert not any(n.startswith("hikaricp") or n.startswith("kafka.consumer") for n in names)  # no datastore or messaging dependency


def test_oneagent_inheritance_resolves_shared_signals(tmp_path):
    oa = loader.load_oneagent()
    from sreadvisor.nfr.tiers import resolve_oneagent
    chain = resolve_oneagent(oa, "spring_boot")
    assert chain[0] == "spring_boot" and {"lang_java", "oneagent_service_layer", "oneagent_platform"} <= set(chain)


def test_stage1_telemetry_metrics_come_from_the_catalogue(tmp_path):
    ds = analyse(tmp_path, boot_repo(tmp_path, "<dependency><groupId>org.springframework.kafka</groupId><artifactId>spring-kafka</artifactId></dependency>"))
    libs = {l.kind: l for l in ds.repositories[0].telemetry.libraries}
    assert "records-lag-max" in libs["kafka_client"].documented_metrics
    assert "application instrumentation catalogue" in libs["kafka_client"].documented_metrics_source


# ------------------------------------------------------------------------ CLI


def test_nfr_cli_check_list_and_coverage(tmp_path, capsys):
    assert cli.main(["nfr", "check"]) == 0
    assert "39 modules" in capsys.readouterr().out
    assert cli.main(["nfr", "list", "--module", "spring_boot_kafka"]) == 0
    assert "SBK-003" in capsys.readouterr().out
    assert cli.main(["nfr", "list", "--module", "nope"]) == 2
    repo = boot_repo(tmp_path)
    analyse(tmp_path, repo)
    ds_file = next((tmp_path / "out").glob("*.dataset.json"))
    out = tmp_path / "cov"
    assert cli.main(["nfr", "coverage", "--dataset", str(ds_file), "--out", str(out)]) == 0
    data = json.loads(next(out.glob("*.nfr-coverage.json")).read_text(encoding="utf-8"))
    assert {"applicable_modules", "unrecognized_tech_stacks", "telemetry_tiers"} <= set(data)
    assert MasterNfrList.model_validate_json((loader.DATA_DIR / loader.MASTER_FILE).read_text(encoding="utf-8"))


# ------------------------------------------------- heuristics apply modules but do not "recognize" technologies


def test_grpc_entry_points_apply_microservices_but_are_flagged_as_uncovered():
    from sreadvisor.nfr.detect import Candidate, applicable_modules, is_recognized

    kb = loader.load_master()
    sig = Signals(entry_point_kinds={"grpc"})
    assert "microservices_architecture" in {m.module.id for m in applicable_modules(kb, sig)}  # heuristic still applies the module
    assert not is_recognized(kb, Candidate("api_style", "gRPC", "", sig))  # but no module covers gRPC itself
    assert is_recognized(kb, Candidate("api_style", "x", "", Signals(entry_point_kinds={"rest"}))) is False  # only grpc/graphql are candidates


def test_gke_is_its_own_module_and_not_triggered_by_a_database_module():
    kb = loader.load_master()
    assert "gke" in kb.modules and "data_gcp_managed" in kb.modules
    only_gke = Signals(terraform_types=["google_container_cluster"], images=["us-docker.pkg.dev/p/r/app:1"], infra={"gcp"})
    from sreadvisor.nfr.detect import applicable_modules

    ids = {m.module.id for m in applicable_modules(kb, only_gke)}
    assert "gke" in ids and "data_gcp_managed" not in ids
    with_db = Signals(terraform_types=["google_sql_database_instance"], infra={"gcp"})
    assert "data_gcp_managed" in {m.module.id for m in applicable_modules(kb, with_db)}
