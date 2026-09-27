"""End-to-end checks of the CLI/pipeline, consolidation and the LLM-step plumbing (no real model or network)."""

import asyncio
import json
from pathlib import Path

import pytest

from sreadvisor import cli
from sreadvisor.agents import outputs as out
from sreadvisor.code import llm_steps
from sreadvisor.code.reliability_candidates import find_candidates
from sreadvisor.graph.code_graph import CodeGraph
from sreadvisor.model_provider import ModelSettings
from sreadvisor.registry import LlmSettings, Registry
from sreadvisor.schema.dataset import ServiceDataset

CONTROLLER = """package demo;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/orders")
class OrderController {
    private final OrderService service;
    OrderController(OrderService service) { this.service = service; }

    @GetMapping("/{id}")
    public String get(@PathVariable int id) {
        return service.find(id);
    }
}
"""
SERVICE = """package demo;

import org.springframework.stereotype.Service;
import org.springframework.cache.annotation.Cacheable;

@Service
class OrderService {
    private final OrderRepository repo;
    OrderService(OrderRepository repo) { this.repo = repo; }

    @Cacheable("orders")
    public String find(int id) {
        return repo.findById(id).toString();
    }
}
"""
REPOSITORY = """package demo;

import org.springframework.data.repository.Repository;

interface OrderRepository extends Repository<String, Integer> {
    java.util.Optional<String> findById(int id);
}
"""
POM = """<project><modelVersion>4.0.0</modelVersion>
<parent><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-parent</artifactId><version>3.3.0</version></parent>
<groupId>demo</groupId><artifactId>orders</artifactId>
<dependencies>
<dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-web</artifactId></dependency>
<dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-data-jpa</artifactId></dependency>
</dependencies></project>
"""


def w(root: Path, name: str, text: str) -> None:
    p = root / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


@pytest.fixture
def service_repo(tmp_path):
    root = tmp_path / "orders"
    w(root, "pom.xml", POM)
    w(root, "src/main/java/demo/OrderController.java", CONTROLLER)
    w(root, "src/main/java/demo/OrderService.java", SERVICE)
    w(root, "src/main/java/demo/OrderRepository.java", REPOSITORY)
    w(root, "src/main/resources/application.properties",
      "spring.datasource.hikari.maximum-pool-size=15\nspring.datasource.password=hunter2hunter2\n")
    w(root, "k8s/app.yaml", """apiVersion: apps/v1
kind: Deployment
metadata: {name: orders}
spec:
  replicas: 2
  selector: {matchLabels: {app: orders}}
  template:
    metadata: {labels: {app: orders}}
    spec:
      containers:
        - name: orders
          image: orders:1
          resources: {limits: {cpu: 500m, memory: 512Mi}}
          readinessProbe: {httpGet: {path: /actuator/health, port: 8080}}
""")
    return root


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("DT_API_TOKEN", "test-token")


def _write_config(tmp_path: Path, repo: Path) -> Path:
    cfg = tmp_path / "svc.yaml"
    cfg.write_text(json.dumps({
        "service_name": "orders",
        "code_repos": [str(repo)],
        "iac_paths": [str(repo / "k8s")],
        "observability": {"provider": "dynatrace", "service_id": "SERVICE-0123456789ABCDEF",
                          "options": {"environment_url": "https://abc.live.dynatrace.com"}},
        "output_dir": str(tmp_path / "out"),
    }), encoding="utf-8")
    return cfg


def test_main_loads_dotenv_before_doing_anything_else(monkeypatch):
    calls = []
    monkeypatch.setattr(cli, "load_dotenv", lambda *a, **kw: calls.append(True))
    cli.main(["nfr", "list"])
    assert calls == [True]


def test_output_dir_env_var_is_used_when_no_flag_or_config_output_dir_is_given(service_repo, tmp_path, monkeypatch):
    """Precedence: --out flag > config output_dir > $SREADVISOR_OUTPUT_DIR > "output"."""
    cfg = tmp_path / "svc.yaml"
    cfg.write_text(json.dumps({
        "service_name": "orders",
        "code_repos": [str(service_repo)],
        "observability": {"provider": "dynatrace", "service_id": "SERVICE-0123456789ABCDEF",
                          "options": {"environment_url": "https://abc.live.dynatrace.com"}},
        # deliberately no output_dir here
    }), encoding="utf-8")
    custom_out = tmp_path / "custom-out-dir"
    monkeypatch.setenv("SREADVISOR_OUTPUT_DIR", str(custom_out))
    rc = cli.main(["analyze", "--config", str(cfg), "--no-llm", "--state-dir", str(tmp_path / "state")])
    assert rc == 0
    assert (custom_out / "orders.dataset.json").exists()


def test_cli_no_llm_produces_complete_structured_dataset(service_repo, tmp_path, capsys):
    cfg = _write_config(tmp_path, service_repo)
    rc = cli.main(["analyze", "--config", str(cfg), "--no-llm", "--state-dir", str(tmp_path / "state")])
    assert rc == 0, capsys.readouterr()
    data = json.loads((tmp_path / "out" / "orders.dataset.json").read_text(encoding="utf-8"))
    ds = ServiceDataset.model_validate(data)  # the written file round-trips through the schema
    repo = ds.repositories[0]
    assert "Spring Boot" in [f.name for f in repo.fingerprint.frameworks]
    assert [(e.http_method, e.route) for e in repo.entry_points] == [("GET", "/orders/{id}")]
    assert repo.application_capacity and repo.secrets.hardcoded  # facts, with the secret redacted
    assert "hunter2hunter2" not in json.dumps(data)
    assert ds.infrastructure.workloads[0].replicas == "2"
    assert ds.capacity_posture.application and ds.capacity_posture.infrastructure
    assert ds.completeness["structurally_complete"] is True
    assert ds.completeness["steps"]["skipped"] == 4  # the four LLM steps are skipped, not silently absent


def test_cli_reports_bad_config_and_missing_file(tmp_path, capsys):
    bad = tmp_path / "bad.yaml"
    bad.write_text("service_name: x\ncode_repos: []\n", encoding="utf-8")
    assert cli.main(["analyze", "--config", str(bad)]) == 2
    err = capsys.readouterr().err
    assert "code_repos" in err and "observability: missing required field" in err
    assert cli.main(["validate-config", "--config", str(tmp_path / "nope.yaml")]) == 2


def test_cli_flags_run_matches_config_run(service_repo, tmp_path):
    rc = cli.main(["analyze", "--repo", str(service_repo), "--iac", str(service_repo / "k8s"), "--provider", "dynatrace",
                   "--service-id", "SERVICE-0123456789ABCDEF", "--dt-environment-url", "https://abc.live.dynatrace.com",
                   "--no-llm", "--out", str(tmp_path / "out"), "--state-dir", str(tmp_path / "state")])
    assert rc == 0
    assert (tmp_path / "out" / "orders.dataset.json").is_file()


# -------------------------------------------------------------------- LLM-step plumbing


class ScriptedRunner:
    """Stands in for AgentRunner: returns canned agent output and records the prompts."""

    def __init__(self, replies):
        self.replies = replies
        self.prompts: list[str] = []
        self.calls = self.cache_hits = 0

    async def run(self, agent, prompt, schema):
        self.prompts.append(prompt)
        reply = self.replies[agent.name]
        return reply(prompt) if callable(reply) else reply


def _graph(service_repo, tmp_path) -> CodeGraph:
    g = CodeGraph(service_repo, tmp_path / "state")
    g.build()
    return g


def test_flow_tracing_drops_ungrounded_and_backfills_data_access(service_repo, tmp_path):
    graph = _graph(service_repo, tmp_path)
    ep = graph.entry_points()[0]
    ctrl = "src/main/java/demo/OrderController.java"
    reply = out.FlowTraceOut(
        summary="GET /orders/{id} returns an order.",
        steps=[
            out.FlowStepOut(order=1, layer="controller", symbol="OrderController.get()", action="handles request",
                            file=ctrl, line=12),
            out.FlowStepOut(order=2, layer="repository", symbol="Ghost.call()", action="invented",
                            file="src/main/java/demo/Ghost.java", line=3),  # file does not exist
        ],
        dependencies=[out.FlowDependencyOut(name="phantom", kind="datastore", file="nope.java", line=1)],
    )
    runner = ScriptedRunner({"flow_tracer": reply})
    from sreadvisor.code.fingerprint import fingerprint_repo

    flows, problems = asyncio.run(llm_steps.trace_flows(
        graph, runner, ModelSettings(), LlmSettings(), [ep], fingerprint_repo(service_repo)))
    steps = flows[0].steps
    assert all(s.symbol != "Ghost.call()" for s in steps)  # ungrounded step never reaches the dataset
    assert not flows[0].dependencies  # ungrounded dependency dropped, nothing to borrow evidence from
    assert any(s.layer == "repository" and "findById" in s.symbol for s in steps)  # backfilled from the call graph
    assert any("dropped" in p for p in problems)


def test_classification_derives_blast_radius_from_flow_map(service_repo, tmp_path):
    graph = _graph(service_repo, tmp_path)
    ep = graph.entry_points()[0]
    from sreadvisor.schema.dataset import FlowDependency, TransactionFlow
    from sreadvisor.util.files import evidence

    ev = evidence("src/main/java/demo/OrderService.java", 13)
    flow = TransactionFlow(entry_point=ep, summary="s", steps=[],
                           dependencies=[FlowDependency(name="relational database", kind="datastore", evidence=ev)])
    runner = ScriptedRunner({"dependency_classifier": out.ClassificationOut(
        classification="Hard Failure", rationale="no fallback", blast_radius_description="GET /orders/{id} fails.")})
    classes, problems = asyncio.run(llm_steps.classify_dependencies(
        graph, runner, ModelSettings(), LlmSettings(), [flow], []))
    assert not problems
    assert classes[0].classification == "hard_failure"  # normalised from free text
    assert classes[0].blast_radius == [ep.symbol]


def test_classification_drops_ungrounded_protecting_patterns_and_flags_all_ungrounded_evidence(service_repo, tmp_path):
    graph = _graph(service_repo, tmp_path)
    ep = graph.entry_points()[0]
    from sreadvisor.schema.dataset import FlowDependency, TransactionFlow
    from sreadvisor.util.files import evidence

    real_pattern = "src/main/java/demo/OrderService.java:13 cache via @Cacheable"
    flow = TransactionFlow(entry_point=ep, summary="s", steps=[],
                           dependencies=[FlowDependency(name="relational database", kind="datastore",
                                                        evidence=evidence("src/main/java/demo/OrderService.java", 13))])
    reply = out.ClassificationOut(
        classification="hard_failure", rationale="no fallback",
        protecting_patterns=[real_pattern, "src/main/java/demo/Ghost.java:999 fictitious pattern"],
        evidence=[out._Loc(file="src/main/java/demo/Ghost.java", line=999)])  # the only citation given does not exist
    classes, problems = asyncio.run(llm_steps.classify_dependencies(
        graph, ScriptedRunner({"dependency_classifier": reply}), ModelSettings(), LlmSettings(), [flow], []))
    assert classes[0].protecting_patterns == [real_pattern]  # the fictitious one is dropped
    assert any("dropped 1 protecting_patterns" in p for p in problems)
    assert any("none of the model's evidence citations were grounded" in p for p in problems)


def test_business_context_confidence_is_forced_low_when_every_citation_is_ungrounded(service_repo, tmp_path):
    graph = _graph(service_repo, tmp_path)
    ep = graph.entry_points()[0]
    from sreadvisor.code.fingerprint import fingerprint_repo

    reply = out.BusinessContextOut(
        capability="Order management", category="order_management", rationale="handles orders", confidence="high",
        evidence=[out._Loc(file="src/main/java/demo/Ghost.java", line=999)])  # the only citation does not exist
    business, problems = asyncio.run(llm_steps.infer_business(
        graph, ScriptedRunner({"business_context_inferrer": reply}), ModelSettings(), LlmSettings(),
        "orders", fingerprint_repo(service_repo), [ep], []))
    assert business.capability == "Order management"  # the claim itself is kept, not discarded
    assert business.confidence == "low"  # never the model's own "high": nothing here was actually verified
    assert business.evidence == []
    assert any("ungrounded" in p for p in problems)


def test_reliability_candidates_found_deterministically(service_repo, tmp_path):
    w(service_repo, "src/main/java/demo/Client.java", """package demo;
class Client {
    @Retryable(maxAttempts = 3)
    String call() { return ""; }
}
""")
    graph = _graph(service_repo, tmp_path)
    cands = find_candidates(graph)
    assert any("Retryable" in c.context for c in cands)  # the LLM only adjudicates what search surfaced


def test_default_registry_lists_expected_extension_points():
    reg = Registry.load()
    assert {"dynatrace", "static"} <= set(reg.provider_names())
    assert {s.name for s in reg.active_sinks()} >= {"json_file", "console_summary"}


def test_pipeline_continues_after_one_repo_fails_producing_a_partial_dataset(service_repo, tmp_path, monkeypatch):
    """One repo crashing (bad git ref, network error, an unexpected exception) must not discard the other repos'
    already-completed analysis; the dataset comes out partial instead of not coming out at all."""
    import sreadvisor.pipeline as pipeline_mod

    real_analyze_repo = pipeline_mod.analyze_repo

    async def flaky(label, root, *a, **kw):
        if label == "bad":
            raise RuntimeError("simulated crash mid-analysis")
        return await real_analyze_repo(label, root, *a, **kw)

    monkeypatch.setattr(pipeline_mod, "analyze_repo", flaky)

    cfg = tmp_path / "svc.yaml"
    cfg.write_text(json.dumps({
        "service_name": "orders",
        "code_repos": [{"path": str(service_repo), "name": "good"}, {"path": str(service_repo), "name": "bad"}],
        "observability": {"provider": "dynatrace", "service_id": "SERVICE-0123456789ABCDEF",
                          "options": {"environment_url": "https://abc.live.dynatrace.com"}},
        "output_dir": str(tmp_path / "out"),
    }), encoding="utf-8")

    rc = cli.main(["analyze", "--config", str(cfg), "--no-llm", "--state-dir", str(tmp_path / "state")])
    assert rc == 1  # partial, not a hard failure: the dataset still comes out and gets written
    data = json.loads((tmp_path / "out" / "orders.dataset.json").read_text(encoding="utf-8"))
    ds = ServiceDataset.model_validate(data)
    assert [r.repo for r in ds.repositories] == ["good", "bad"]
    good, bad = ds.repositories
    assert "Spring Boot" in [f.name for f in good.fingerprint.frameworks]  # the good repo's real work is preserved
    assert bad.status == [] or bad.status[0].status == "failed"
    assert any(s.status == "failed" and "simulated crash" in (s.detail or "") for s in bad.status)
    assert ds.completeness["structurally_complete"] is False


def test_a_malformed_file_degrades_the_graph_build_instead_of_crashing_it(tmp_path, monkeypatch):
    w(tmp_path, "Ok.java", "class Ok { void m() {} }\n")
    graph = CodeGraph(tmp_path, tmp_path / ".state")

    def boom(*a, **kw):
        raise SyntaxError("simulated malformed file")

    monkeypatch.setattr("graphify.extract.extract", boom)
    stats = graph.build()
    assert stats["error"] and "simulated malformed file" in stats["error"]
    assert stats["nodes"] == 0 and graph.entry_points() == []  # degrades gracefully, does not raise
