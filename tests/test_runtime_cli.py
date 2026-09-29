"""Stage 5 CLI (`sreadvisor runtime`): wiring only — provider resolution through the registry, --service-id override,
error handling, file output — using a fake provider so no live network or MCP subprocess is needed."""

import json
from pathlib import Path

import pytest

from sreadvisor import cli
from sreadvisor.providers.base import ObservabilityError, ObservabilityProvider
from sreadvisor.schema.runtime import MetricSeries, ServiceMetrics, ServiceTopology, TopologyNode

from test_nfr import analyse, boot_repo


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("DT_API_TOKEN", "test-token")


class RecordingProvider(ObservabilityProvider):
    """A fake provider: records which service id it was asked for, so the CLI's --service-id override is verifiable
    without a real MCP round trip."""

    name = "fake_runtime"
    requested: list[str] = []
    fail = False

    async def get_topology(self, service_id: str) -> ServiceTopology:
        RecordingProvider.requested.append(service_id)
        if RecordingProvider.fail:
            raise ObservabilityError("the fake tenant is unreachable")
        return ServiceTopology(provider="fake_runtime", service_id=service_id,
                               nodes=[TopologyNode(id=service_id, name="orders", kind="service"),
                                      TopologyNode(id="DATABASE-1", name="orders-db", kind="database")],
                               edges=[{"source": service_id, "target": "DATABASE-1", "direction": "calls",
                                      "attributes": {"is_dependency_like": True}}])

    async def get_metrics(self, service_id: str, metric_keys=None, from_time: str = "now-2h") -> ServiceMetrics:
        return ServiceMetrics(provider="fake_runtime", service_id=service_id,
                              series=[MetricSeries(name="request.rate", avg=42.0, window_seconds=7200)])


def _registry_file(tmp_path: Path) -> Path:
    p = tmp_path / "registry.yaml"
    p.write_text("providers:\n  fake_runtime:\n    class: test_runtime_cli.RecordingProvider\n"
                "  dynatrace:\n    class: sreadvisor.providers.dynatrace.DynatraceProvider\n    enabled: false\n",
                encoding="utf-8")
    return p


def test_runtime_cli_pulls_cross_validates_and_writes_the_report(tmp_path):
    RecordingProvider.requested, RecordingProvider.fail = [], False
    repo = boot_repo(tmp_path, "<dependency><groupId>org.postgresql</groupId><artifactId>postgresql</artifactId></dependency>")
    dataset = analyse(tmp_path, repo)
    ds_file = next((tmp_path / "out").glob("*.dataset.json"))
    reg = _registry_file(tmp_path)
    # The dataset's own observability binding names dynatrace (disabled in this scratch registry); point --registry at
    # one where a fake provider stands in, and reuse the dataset's real service_id via a config edit is unnecessary
    # since the CLI reads observability.provider from the dataset itself — patch the dataset file's provider name.
    data = json.loads(ds_file.read_text(encoding="utf-8"))
    data["observability"]["provider"] = "fake_runtime"
    data["observability"]["options"] = {}
    ds_file.write_text(json.dumps(data), encoding="utf-8")

    out_dir = tmp_path / "runtime_out"
    rc = cli.main(["runtime", "--dataset", str(ds_file), "--registry", str(reg), "--out", str(out_dir)])
    assert rc == 0
    assert RecordingProvider.requested == [data["observability"]["service_id"]]
    written = next(out_dir.glob("*.runtime-cross-validation.json"))
    result = json.loads(written.read_text(encoding="utf-8"))
    assert result["provider"] == "fake_runtime" and len(result["topology"]["nodes"]) == 2
    assert result["summary"]["runtime_dependencies"] == 1


def test_runtime_cli_service_id_override(tmp_path):
    RecordingProvider.requested, RecordingProvider.fail = [], False
    repo = boot_repo(tmp_path)
    analyse(tmp_path, repo)
    ds_file = next((tmp_path / "out").glob("*.dataset.json"))
    data = json.loads(ds_file.read_text(encoding="utf-8"))
    data["observability"]["provider"] = "fake_runtime"
    data["observability"]["options"] = {}
    ds_file.write_text(json.dumps(data), encoding="utf-8")
    reg = _registry_file(tmp_path)

    assert cli.main(["runtime", "--dataset", str(ds_file), "--registry", str(reg), "--service-id", "SERVICE-OVERRIDE",
                     "--out", str(tmp_path / "o2")]) == 0
    assert RecordingProvider.requested == ["SERVICE-OVERRIDE"]


def test_runtime_cli_reports_provider_failure_without_a_traceback(tmp_path, capsys):
    RecordingProvider.requested, RecordingProvider.fail = [], True
    repo = boot_repo(tmp_path)
    analyse(tmp_path, repo)
    ds_file = next((tmp_path / "out").glob("*.dataset.json"))
    data = json.loads(ds_file.read_text(encoding="utf-8"))
    data["observability"]["provider"] = "fake_runtime"
    data["observability"]["options"] = {}
    ds_file.write_text(json.dumps(data), encoding="utf-8")
    reg = _registry_file(tmp_path)

    rc = cli.main(["runtime", "--dataset", str(ds_file), "--registry", str(reg), "--out", str(tmp_path / "o3")])
    assert rc == 2
    assert "unreachable" in capsys.readouterr().err
    assert not (tmp_path / "o3").exists()


def test_runtime_cli_names_a_missing_dataset_file(tmp_path):
    assert cli.main(["runtime", "--dataset", str(tmp_path / "nope.json")]) == 2
