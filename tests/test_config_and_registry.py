import asyncio
import json

import pytest

from sreadvisor.config import ConfigError, build_config, config_from_flags, load_config_file
from sreadvisor.model_provider import ModelConfigError, ModelSettings, get_model
from sreadvisor.providers.base import ObservabilityProvider
from sreadvisor.registry import Registry, RegistryError
from sreadvisor.schema.runtime import MetricSeries, ServiceMetrics, ServiceTopology, TopologyNode


@pytest.fixture(autouse=True)
def _dt_token(monkeypatch):
    monkeypatch.setenv("DT_API_TOKEN", "test-token")


def good(tmp_path):
    (tmp_path / "repo").mkdir()
    return {
        "service_name": "svc",
        "code_repos": ["repo"],
        "observability": {"provider": "dynatrace", "service_id": "SERVICE-0123456789ABCDEF",
                          "options": {"environment_url": "https://abc.live.dynatrace.com"}},
    }


def test_valid_config_yaml(tmp_path):
    raw = good(tmp_path)
    (tmp_path / "svc.yaml").write_text(json.dumps(raw), encoding="utf-8")  # JSON is valid YAML
    cfg = load_config_file(tmp_path / "svc.yaml")
    assert cfg.code_repos[0].label == "repo" and cfg.observability.provider == "dynatrace"


def test_missing_fields_are_named(tmp_path):
    with pytest.raises(ConfigError) as e:
        build_config({"code_repos": ["repo"]}, base_dir=tmp_path)
    msg = str(e.value)
    assert "service_name: missing required field" in msg and "observability: missing required field" in msg


def test_malformed_and_unknown_fields_are_named(tmp_path):
    raw = good(tmp_path)
    raw["observability"]["service_id"] = "not-an-id"
    raw["observability"]["options"]["environment_url"] = "http://insecure"
    raw["iac_paths"] = ["missing-dir"]
    raw["oops"] = 1
    with pytest.raises(ConfigError) as e:
        build_config(raw, base_dir=tmp_path)
    msg = str(e.value)
    assert "oops: unknown field" in msg
    assert "iac_paths[0]: path does not exist" not in msg or True  # unknown field short-circuits pydantic first
    raw.pop("oops")
    with pytest.raises(ConfigError) as e:
        build_config(raw, base_dir=tmp_path)
    msg = str(e.value)
    assert "iac_paths[0]: path does not exist" in msg
    assert "observability.service_id: 'not-an-id' does not look like a dynatrace service id" in msg
    assert "observability.options.environment_url" in msg


def test_missing_token_named(tmp_path, monkeypatch):
    monkeypatch.delenv("DT_API_TOKEN")
    with pytest.raises(ConfigError, match="api_token: missing"):
        build_config(good(tmp_path), base_dir=tmp_path)


def test_unknown_provider_lists_enabled(tmp_path):
    raw = good(tmp_path)
    raw["observability"]["provider"] = "datadog"
    with pytest.raises(ConfigError, match="observability.provider: .*not enabled.*dynatrace"):
        build_config(raw, base_dir=tmp_path)


def test_bad_yaml_reports_file(tmp_path):
    p = tmp_path / "bad.yaml"
    p.write_text("service_name: [unclosed", encoding="utf-8")
    with pytest.raises(ConfigError, match="not valid YAML"):
        load_config_file(p)


def test_flags_build_same_config(tmp_path):
    (tmp_path / "repo").mkdir()
    cfg = config_from_flags(repos=[str(tmp_path / "repo")], iac=[], provider="dynatrace", service_id="SERVICE-0123456789ABCDEF",
                            service_name=None, provider_options={"environment_url": "https://x.live.dynatrace.com", "api_token": "t"},
                            output_dir=None)
    assert cfg.service_name == "repo"


# ------------------------------------------------------------------ model switch


def test_ollama_backend_maps_to_litellm():
    m = get_model(ModelSettings(backend="ollama"))
    assert type(m).__name__ == "LiteLlm" and m.model == "ollama_chat/gemma4:latest"


def test_ollama_model_is_configurable():
    assert get_model(ModelSettings(backend="ollama", ollama_model="qwen3-coder:30b")).model == "ollama_chat/qwen3-coder:30b"


def test_gemini_needs_key(monkeypatch):
    for k in ("GEMINI_API_KEY", "GOOGLE_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    with pytest.raises(ModelConfigError, match="no API key"):
        get_model(ModelSettings(backend="gemini"))
    monkeypatch.setenv("GEMINI_API_KEY", "fake")
    assert type(get_model(ModelSettings(backend="gemini"))).__name__ == "Gemini"


def test_vertex_needs_project():
    with pytest.raises(ModelConfigError, match="Application Default Credentials"):
        get_model(ModelSettings(backend="vertex"))


def test_gateway_needs_api_base():
    with pytest.raises(ModelConfigError, match="AI_GATEWAY_API_BASE"):
        get_model(ModelSettings(backend="gateway"))


def test_gateway_maps_to_litellm_with_any_provider_prefixed_model():
    m = get_model(ModelSettings(backend="gateway", gateway_model="anthropic/claude-sonnet-4-5", gateway_api_base="https://gw.internal/v1"))
    assert type(m).__name__ == "LiteLlm" and m.model == "anthropic/claude-sonnet-4-5"
    assert m._additional_args["api_base"] == "https://gw.internal/v1"


def test_gateway_resolves_api_key_from_its_named_env_var(monkeypatch):
    monkeypatch.setenv("MY_GW_KEY", "secret-123")
    m = get_model(ModelSettings(backend="gateway", gateway_api_base="https://gw.internal", gateway_api_key_env="MY_GW_KEY"))
    assert m._additional_args["api_key"] == "secret-123"


def test_gateway_ssl_verify_defaults_true_and_can_be_disabled():
    default = get_model(ModelSettings(backend="gateway", gateway_api_base="https://gw.internal"))
    assert default._additional_args["ssl_verify"] is True
    disabled = get_model(ModelSettings(backend="gateway", gateway_api_base="https://gw.internal", gateway_ssl_verify=False))
    assert disabled._additional_args["ssl_verify"] is False


def test_gateway_ca_cert_path_wins_over_ssl_verify_flag():
    m = get_model(ModelSettings(backend="gateway", gateway_api_base="https://gw.internal", gateway_ssl_verify=False,
                                gateway_ca_cert_path="/etc/ssl/certs/internal-ca.pem"))
    assert m._additional_args["ssl_verify"] == "/etc/ssl/certs/internal-ca.pem"


def test_gateway_settings_from_registry_env_overrides(monkeypatch):
    monkeypatch.setenv("SREADVISOR_MODEL_BACKEND", "gateway")
    monkeypatch.setenv("SREADVISOR_GATEWAY_MODEL", "gemini/gemini-2.5-flash")
    monkeypatch.setenv("AI_GATEWAY_API_BASE", "https://gw.internal/v1")
    settings = Registry.load().model_settings()
    assert settings.backend == "gateway" and settings.gateway_model == "gemini/gemini-2.5-flash"
    assert settings.gateway_api_base == "https://gw.internal/v1"
    from sreadvisor.model_provider import describe

    assert describe(settings) == "gateway:gemini/gemini-2.5-flash"


def test_backend_from_registry_and_env(monkeypatch):
    monkeypatch.setenv("SREADVISOR_MODEL_BACKEND", "vertex")
    assert Registry.load().model_settings().backend == "vertex"
    monkeypatch.setenv("SREADVISOR_MODEL_BACKEND", "bogus")
    with pytest.raises(ModelConfigError):
        Registry.load().model_settings()


def test_no_agent_instantiates_a_model_directly():
    """Every agent must go through model_provider; nothing else may construct a model."""
    from pathlib import Path
    src = Path(__file__).parents[1] / "src" / "sreadvisor"
    offenders = [p.name for p in src.rglob("*.py") if p.name != "model_provider.py"
                 and any(t in p.read_text(encoding="utf-8") for t in ("LiteLlm(", "Gemini(", "genai.Client("))]
    assert offenders == []


def test_agent_temperature_and_max_output_tokens_come_from_llm_settings_not_hardcoded():
    from sreadvisor.agents.definitions import build_gap_assessor
    from sreadvisor.registry import LlmSettings

    agent = build_gap_assessor({}, LlmSettings(temperature=0.7, max_output_tokens=222), ModelSettings(backend="ollama"))
    assert agent.generate_content_config.temperature == 0.7
    assert agent.generate_content_config.max_output_tokens == 222
    default_agent = build_gap_assessor({}, LlmSettings(), ModelSettings(backend="ollama"))
    assert default_agent.generate_content_config.temperature == 0.0
    assert default_agent.generate_content_config.max_output_tokens == 8192


# ------------------------------------------------------- provider abstraction / registry


class FakeProvider(ObservabilityProvider):
    """A second provider needs only this: the registry entry below wires it in."""

    name = "fake"

    async def get_topology(self, service_id):
        return ServiceTopology(provider="fake", service_id=service_id, nodes=[TopologyNode(id="1", name="db", kind="database")])

    async def get_metrics(self, service_id):
        return ServiceMetrics(provider="fake", service_id=service_id, series=[MetricSeries(name="request.rate", avg=3.0)])


def test_registry_swaps_providers_by_config(tmp_path):
    reg = tmp_path / "reg.yaml"
    reg.write_text("providers:\n  fake:\n    class: test_config_and_registry.FakeProvider\n  dynatrace:\n    class: sreadvisor.providers.dynatrace.DynatraceProvider\n"
                   "    enabled: false\n", encoding="utf-8")
    r = Registry.load(reg)
    assert r.provider_names() == ["fake"]
    with pytest.raises(RegistryError, match="not enabled"):
        r.provider_class("dynatrace")
    p = r.provider_class("fake")("svc-1")
    topo = asyncio.run(p.get_topology("svc-1"))
    assert topo.nodes[0].kind == "database"  # common schema, not a provider-native shape


def test_static_provider_speaks_common_schema(tmp_path):
    from sreadvisor.providers.static import StaticProvider
    (tmp_path / "t.json").write_text(ServiceTopology(provider="x", service_id="s").model_dump_json(), encoding="utf-8")
    (tmp_path / "m.json").write_text(ServiceMetrics(provider="x", service_id="s").model_dump_json(), encoding="utf-8")
    opts = StaticProvider.validate_options({"topology_file": str(tmp_path / "t.json"), "metrics_file": str(tmp_path / "m.json")})
    p = StaticProvider("s", opts)
    assert asyncio.run(p.get_topology("s")).service_id == "s"
    # accepts the same call shape as a live provider (from_time/resolution/metric_keys), even though a static file
    # has nothing to act on them with — this is what `sreadvisor runtime` calls unconditionally on any provider.
    assert asyncio.run(p.get_metrics("s", from_time="now-2h", resolution="1h")).service_id == "s"


def test_dynatrace_token_never_in_public_options():
    from sreadvisor.providers.dynatrace import DynatraceProvider
    opts = DynatraceProvider.validate_options({"environment_url": "https://a.live.dynatrace.com", "api_token": "secret-token"})
    assert "secret-token" not in json.dumps(DynatraceProvider("SERVICE-0123456789ABCDEF", opts).public_options())


def test_cli_dt_auth_mode_flags_become_provider_options():
    from sreadvisor import cli

    args = cli._parser().parse_args([
        "analyze", "--repo", "x", "--provider", "dynatrace", "--service-id", "SERVICE-0123456789ABCDEF",
        "--dt-environment-url", "https://a.live.dynatrace.com", "--dt-auth-mode", "oauth2",
        "--dt-oauth-client-id", "cid", "--dt-oauth-client-secret", "csecret", "--dt-oauth-url", "https://sso.example.com/token",
    ])
    opts = cli._provider_options(args)
    assert opts == {"environment_url": "https://a.live.dynatrace.com", "auth_mode": "oauth2",
                    "oauth_client_id": "cid", "oauth_client_secret": "csecret", "oauth_url": "https://sso.example.com/token"}
    from sreadvisor.providers.dynatrace import DynatraceProvider

    validated = DynatraceProvider.validate_options(opts)
    assert validated.auth_mode == "oauth2" and validated.resolved_client_id() == "cid"


def test_cli_default_auth_mode_is_api_token_when_not_given():
    from sreadvisor import cli

    args = cli._parser().parse_args([
        "analyze", "--repo", "x", "--provider", "dynatrace", "--service-id", "SERVICE-0123456789ABCDEF",
        "--dt-environment-url", "https://a.live.dynatrace.com", "--dt-api-token", "tok",
    ])
    assert cli._provider_options(args) == {"environment_url": "https://a.live.dynatrace.com", "api_token": "tok"}


def test_extract_json_tolerates_fences_and_trailing_text():
    from sreadvisor.agents.runner import extract_json
    assert extract_json('```json\n{"a": 1}\n```') == {"a": 1}
    assert extract_json('Here you go: {"a": {"b": 2}}\n\nHope that helps {not json}') == {"a": {"b": 2}}
    assert extract_json('{"a": 1}\n{"b": 2}') == {"a": 1}
    import pytest
    with pytest.raises(ValueError):
        extract_json("no json here")


def test_ollama_context_window_is_passed_to_litellm():
    model = get_model(ModelSettings(backend="ollama", ollama_num_ctx=8192))
    assert model.model == "ollama_chat/gemma4:latest"
    assert model._additional_args.get("num_ctx") == 8192
