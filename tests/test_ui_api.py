"""The UI's HTTP API: knowledge-base editing (validation, etags, backups, rollback), configs, jobs and reports."""

import copy
import json
import shutil
import time
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from sreadvisor.nfr import loader
from sreadvisor.ui import server as server_mod
from sreadvisor.ui.server import create_app

from test_nfr import analyse, boot_repo


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("DT_API_TOKEN", "test-token")
    monkeypatch.setattr(server_mod, "check_backend", lambda ms: None)  # no Ollama needed


@pytest.fixture
def ws(tmp_path):
    ws = tmp_path / "ws"
    (ws / "config").mkdir(parents=True)
    data = tmp_path / "data"
    shutil.copytree(loader.DATA_DIR, data, ignore=shutil.ignore_patterns("__pycache__"))
    return ws, data


@pytest.fixture
def client(ws):
    workspace, data = ws
    return TestClient(create_app(workspace, src_dir=data / "src", data_dir=data))


def module(client, mid):
    return client.get(f"/api/nfr/modules/{mid}").json()


# ------------------------------------------------------------------------------- catalogue


def test_module_list_hints_and_dataset_paths(client):
    mods = client.get("/api/nfr/modules").json()
    assert len(mods) == 39 and {"baseline", "spring_boot_kafka", "gke", "capacity_scaling"} <= {m["id"] for m in mods}
    assert all(m["entry_count"] > 0 and m["file"].endswith(".yaml") for m in mods)
    h = client.get("/api/nfr/hints").json()
    assert {"critical", "high", "medium", "low"} == set(h["priorities"]) and "oneagent_default" in h["signal_sources"]
    assert "BASE-RETRY-001" in h["entry_ids"] and "kubernetes" in h["infra_signals"]
    paths = client.get("/api/nfr/dataset-paths").json()
    assert "infrastructure.workloads[].containers[].requests" in paths and "business_context.key_operations" in paths
    assert all(loader.path_exists(__import__("sreadvisor.schema.dataset", fromlist=["ServiceDataset"]).ServiceDataset, p) for p in paths)


def test_editing_an_entry_validates_backs_up_and_rebuilds(client, ws):
    workspace, data = ws
    got = module(client, "caching")
    doc = copy.deepcopy(got["module"])
    doc["entries"][0]["title"] = "Bounded size and explicit expiry (edited)"
    doc["entries"][0]["priority"] = "critical"
    r = client.put("/api/nfr/modules/caching", json={"module": doc, "etag": got["etag"]})
    assert r.status_code == 200 and r.json()["module"]["entries"][0]["title"].endswith("(edited)")
    built = json.loads((data / loader.MASTER_FILE).read_text(encoding="utf-8"))  # the JSON Stage 3 loads was rebuilt
    assert built["modules"]["caching"]["entries"][0]["priority"] == "critical"
    assert client.get("/api/nfr/modules/caching").json()["backups"]  # previous version kept
    assert list((workspace / ".sreadvisor" / "nfr_backups").glob("*caching*"))


def test_invalid_edit_is_rejected_with_located_problems_and_changes_nothing(client, ws):
    _, data = ws
    got = module(client, "caching")
    before = (data / loader.MASTER_FILE).read_text(encoding="utf-8")
    doc = copy.deepcopy(got["module"])
    doc["entries"][1]["monitoring"] = []
    doc["entries"][2]["verification"]["stage1_paths"] = ["infrastructure.workloads.nope"]
    r = client.put("/api/nfr/modules/caching", json={"module": doc, "etag": got["etag"]})
    assert r.status_code == 422
    msgs = " ".join(p["path"] + " " + p["message"] for p in r.json()["problems"])
    assert "entries[1].monitoring" in msgs
    assert (data / loader.MASTER_FILE).read_text(encoding="utf-8") == before
    assert module(client, "caching")["etag"] == got["etag"]  # source file untouched too
    bad_path = copy.deepcopy(got["module"])
    bad_path["entries"][2]["verification"]["stage1_paths"] = ["infrastructure.workloads.nope"]
    r = client.post("/api/nfr/validate", json={"module": bad_path, "module_id": "caching"}).json()
    assert not r["valid"] and any("does not exist in the Stage 1 dataset schema" in p["message"] for p in r["problems"])


def test_stale_edit_is_refused_and_ids_cannot_change(client):
    got = module(client, "caching")
    doc = copy.deepcopy(got["module"])
    doc["entries"][0]["title"] = "first edit"
    assert client.put("/api/nfr/modules/caching", json={"module": doc, "etag": got["etag"]}).status_code == 200
    doc["entries"][0]["title"] = "second edit from a stale page"
    assert client.put("/api/nfr/modules/caching", json={"module": doc, "etag": got["etag"]}).status_code == 409
    renamed = copy.deepcopy(doc)
    renamed["id"] = "other"
    fresh = module(client, "caching")["etag"]
    assert client.put("/api/nfr/modules/caching", json={"module": renamed, "etag": fresh}).status_code == 422


def test_create_tech_stack_module_adds_catalogue_placeholders_and_deletes_cleanly(client, ws):
    _, data = ws
    doc = {"id": "mongodb", "title": "MongoDB", "layer": "tech_stack", "category": "data", "description": "Document database requirements.",
           "extends": ["baseline"], "detect": [{"dependency": "mongo"}],
           "entries": [{"id": "MDB-001", "title": "Replica set", "requirement": "Runs as a replica set.", "best_practice": "Three members.",
                        "audit_requirement": None, "priority": "high",
                        "monitoring": [{"source": "platform", "signal": "replication lag"}],
                        "verification": {"sources": ["manual_review"], "criteria": "A replica set is configured."}}]}
    r = client.post("/api/nfr/modules", json={"module": doc})
    assert r.status_code == 200, r.text
    assert r.json()["file"].endswith("_mongodb.yaml")
    oa = client.get("/api/nfr/catalogues/oneagent").json()["modules"]["mongodb"]
    assert oa["support_level"] == "none" and "Not yet catalogued" in oa["summary"]  # an honest placeholder, not a claim
    app_c = client.get("/api/nfr/catalogues/instrumentation").json()["modules"]["mongodb"]
    assert "Not yet catalogued" in app_c["reason_none"]
    assert "mongodb" in json.loads((data / loader.MASTER_FILE).read_text(encoding="utf-8"))["modules"]
    assert client.post("/api/nfr/modules", json={"module": doc}).status_code == 422  # duplicate id
    assert client.delete("/api/nfr/modules/mongodb").status_code == 200
    assert "mongodb" not in {m["id"] for m in client.get("/api/nfr/modules").json()}
    assert "mongodb" not in client.get("/api/nfr/catalogues/oneagent").json()["modules"]
    assert loader.is_up_to_date(data, data / "src") == []


def test_cannot_delete_baseline_or_a_module_others_extend(client):
    assert client.delete("/api/nfr/modules/baseline").status_code == 422
    r = client.delete("/api/nfr/modules/spring_boot")  # spring_boot_kafka extends it
    assert r.status_code == 422 and "nothing was deleted" in r.json()["error"]
    assert "spring_boot" in {m["id"] for m in client.get("/api/nfr/modules").json()}


def test_restore_a_previous_version(client):
    got = module(client, "caching")
    original_title = got["module"]["entries"][0]["title"]
    doc = copy.deepcopy(got["module"])
    doc["entries"][0]["title"] = "changed"
    client.put("/api/nfr/modules/caching", json={"module": doc, "etag": got["etag"]})
    after = module(client, "caching")
    backup = after["backups"][0]["name"]
    r = client.post("/api/nfr/modules/caching/restore", json={"backup": backup, "etag": after["etag"]})
    assert r.status_code == 200 and r.json()["module"]["entries"][0]["title"] == original_title
    assert client.post("/api/nfr/modules/caching/restore", json={"backup": "../../etc/passwd", "etag": None}).status_code == 404


def test_catalogues_are_served_read_only(client):
    oa = client.get("/api/nfr/catalogues/oneagent").json()
    assert oa["tier"] == "oneagent_default" and "spring_boot" in oa["modules"]
    assert client.get("/api/nfr/catalogues/nope").status_code == 404
    assert client.put("/api/nfr/catalogues/oneagent", json={}).status_code == 405


# --------------------------------------------------------------------------------- configs


CFG = {"service_name": "orders", "code_repos": [{"path": "repo"}], "iac_paths": [],
       "observability": {"provider": "dynatrace", "service_id": "SERVICE-0123456789ABCDEF",
                         "options": {"environment_url": "https://abc.live.dynatrace.com", "api_token_env": "DT_API_TOKEN",
                                     "api_token": "secret-should-not-be-kept"}}}


def test_config_validation_names_bad_fields(client, ws):
    workspace, _ = ws
    (workspace / "repo").mkdir()
    ok = client.post("/api/configs/validate", json={"config": CFG}).json()
    assert ok["valid"] and ok["normalised"]["code_repos"][0]["path"] == str((workspace / "repo").resolve())
    assert "api_token" not in ok["normalised"]["observability"]["options"]
    bad = copy.deepcopy(CFG)
    bad["code_repos"] = [{"path": "no/such/dir"}]
    bad["observability"]["service_id"] = "not-an-id"
    problems = client.post("/api/configs/validate", json={"config": bad}).json()["problems"]
    assert any("code_repos[0].path" in p for p in problems) and any("service_id" in p for p in problems)


def test_saving_a_config_never_writes_the_token(client, ws):
    workspace, _ = ws
    (workspace / "repo").mkdir()
    r = client.put("/api/configs/orders", json={"config": CFG, "token": "s3cr3t-token-value"})
    assert r.status_code == 200, r.text
    text = (workspace / "config" / "orders.yaml").read_text(encoding="utf-8")
    assert "s3cr3t-token-value" not in text and "secret-should-not-be-kept" not in text and "api_token_env" in text
    got = client.get("/api/configs/orders").json()
    assert got["config"]["service_name"] == "orders"
    assert [c["name"] for c in client.get("/api/meta").json()["configs"]] == ["orders"]
    bad = copy.deepcopy(CFG)
    bad["service_name"] = ""
    assert client.put("/api/configs/broken", json={"config": {**bad, "code_repos": []}}).status_code == 422
    assert not (workspace / "config" / "broken.yaml").exists()


def test_config_names_cannot_escape_the_workspace(client):
    assert client.get("/api/configs/..%2Fsecret").status_code in (400, 404)
    assert client.get("/api/configs/nope").status_code == 404


def test_meta_reports_environment_without_exposing_values(client):
    m = client.get("/api/meta").json()
    assert m["env"]["DT_API_TOKEN"] is True and "test-token" not in json.dumps(m)
    assert {"dynatrace", "static"} <= {p["name"] for p in m["providers"]}
    assert m["model"]["backend"] == "ollama"


# ------------------------------------------------------------------------- jobs and reports


def wait(client, job_id, timeout=120):
    end = time.time() + timeout
    while time.time() < end:
        j = client.get(f"/api/jobs/{job_id}").json()
        if j["status"] != "running":
            return j
        time.sleep(0.3)
    raise AssertionError("job did not finish")


def test_reports_and_a_gap_analysis_job(client, ws, tmp_path):
    workspace, _ = ws
    repo = boot_repo(tmp_path / "svc")
    out = workspace / "output"
    assert analyse(tmp_path / "svc", repo) is not None  # writes under tmp_path/svc/out
    shutil.copytree(tmp_path / "svc" / "out", out)
    rows = client.get("/api/reports").json()
    assert [r["service"] for r in rows] == ["orders"] and set(rows[0]["files"]) >= {"dataset", "report", "coverage"}
    facts = client.get("/api/reports/orders/dataset-facts").json()
    assert facts["repositories"][0]["frameworks"] and "completeness" in facts
    assert client.get("/api/reports/orders/gaps").status_code == 404  # none yet
    job = client.post("/api/jobs/gaps", json={"service": "orders", "no_llm": True}).json()
    done = wait(client, job["id"])
    assert done["status"] == "succeeded", done["log"][-5:]
    assert any("Gap analysis pass 1" in line for line in done["log"]) and "sreadvisor gaps" in done["command"]
    gaps = client.get("/api/reports/orders/gaps").json()
    assert gaps["summary"]["applicable_requirements"] > 0 and "unrecognized_tech_gaps" in gaps
    assert client.get("/api/reports").json()[0]["gap_summary"]["applicable_requirements"] == gaps["summary"]["applicable_requirements"]
    assert "NFR coverage report" in client.get("/api/reports/orders/markdown").text
    assert client.get("/api/reports/orders/download/gaps").status_code == 200
    assert client.get("/api/reports/nope/gaps").status_code == 404


def test_one_job_at_a_time_and_argument_validation(client, ws, tmp_path):
    workspace, _ = ws
    assert client.post("/api/jobs/gaps", json={"service": "missing"}).status_code == 404
    repo = boot_repo(tmp_path / "svc")
    analyse(tmp_path / "svc", repo)
    shutil.copytree(tmp_path / "svc" / "out", workspace / "output")
    assert client.post("/api/jobs/gaps", json={"service": "orders", "modules": ["bad id; rm -rf"]}).status_code == 400
    assert client.post("/api/jobs/gaps", json={"service": "orders", "ollama_model": "x; y", "no_llm": True}).status_code == 400
    first = client.post("/api/jobs/gaps", json={"service": "orders", "no_llm": True})
    assert first.status_code == 200
    second = client.post("/api/jobs/gaps", json={"service": "orders", "no_llm": True})
    if wait_status(client, first.json()["id"]) == "running":  # only assertable while the first is still going
        assert second.status_code == 409
    wait(client, first.json()["id"])


def wait_status(client, job_id):
    return client.get(f"/api/jobs/{job_id}").json()["status"]


def test_static_page_is_served(client):
    r = client.get("/")
    assert r.status_code == 200 and "sreadvisor" in r.text.lower()
    assert client.get("/static/app.js").status_code == 200


def test_cross_module_problems_name_the_requirement(client):
    got = module(client, "caching")
    doc = copy.deepcopy(got["module"])
    doc["entries"][2]["verification"]["stage1_paths"] = ["infrastructure.workloads.nope"]
    r = client.post("/api/nfr/validate", json={"module": doc, "module_id": "caching"}).json()
    assert not r["valid"]
    hit = next(p for p in r["problems"] if "does not exist in the Stage 1 dataset schema" in p["message"])
    assert hit["entry"] == "CACHE-003" and not hit["message"].startswith("CACHE-003")  # the id is a field, not text to parse
    assert not any(p["message"].endswith("inconsistent:") for p in r["problems"])


def test_loaded_config_paths_are_relative_to_the_config_file_like_the_cli(client, ws):
    workspace, _ = ws
    (workspace / "repos" / "svc").mkdir(parents=True)
    (workspace / "config" / "rel.yaml").write_text(yaml.safe_dump({**{k: v for k, v in CFG.items() if k != "code_repos"},
                                                                   "code_repos": [{"path": "../repos/svc"}]}), encoding="utf-8")
    got = client.get("/api/configs/rel").json()["config"]
    assert got["code_repos"][0]["path"] == str((workspace / "repos" / "svc").resolve())  # config dir, not the workspace
    assert client.post("/api/configs/validate", json={"config": got}).json()["valid"]
