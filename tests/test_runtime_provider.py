"""Stage 5: the Dynatrace MCP server's core fetch functions, the provider's normalization into the common runtime
schema, and the MCP transport itself (one real stdio round trip against the real server, but talking to a local
mock HTTP endpoint, not the live tenant). No live Dynatrace call and no token needed for any test here; the live
smoke test against the real playground tenant is separate (see the session's own verification, not a pytest test,
since it needs a real personal token)."""

import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import httpx
import pytest

from sreadvisor.mcp_servers import dynatrace_server as srv
from sreadvisor.providers.base import ObservabilityError
from sreadvisor.providers.dynatrace import (
    DynatraceError,
    DynatraceOptions,
    DynatraceProvider,
    _call_tool,
    normalize_metrics,
    normalize_topology,
)

# ------------------------------------------------------------------------------------------- real captured shapes
# Trimmed but verbatim-shaped responses captured live from a real Dynatrace SaaS tenant (playground.live.dynatrace.com),
# for the OpenTelemetry Astronomy Shop demo's cart service, so the normalizer is tested against the real API shape,
# not a shape I imagined.

CART_ENTITY = {
    "entityId": "SERVICE-E5D0D50C747C9AC4", "type": "SERVICE", "displayName": "astroshop-cart",
    "properties": {"serviceType": "UNIFIED", "detectedName": "astroshop-cart",
                   "serviceDetectionAttributes": {"k8s.namespace.name": "astroshop", "k8s.workload.name": "cart"}},
    "tags": [{"key": "team", "value": "Team-ECommerce"}],
    "fromRelationships": {"calls": [{"id": "SERVICE-B1BE5B14F0388F4E", "type": "SERVICE"}],
                          "isServiceOf": [{"id": "CLOUD_APPLICATION-8C621FD5C53B27C6", "type": "CLOUD_APPLICATION"}]},
    "toRelationships": {"isClusterOfService": [{"id": "KUBERNETES_CLUSTER-289857DC8E688B2B", "type": "KUBERNETES_CLUSTER"}],
                        "calls": [{"id": "SERVICE-39720C1E0047A5C0", "type": "SERVICE"},
                                 {"id": "SERVICE-5ACC60E0079F8E6D", "type": "SERVICE"}],
                        "isGroupOf": [{"id": "SERVICE_METHOD_GROUP-E5D0D50C747C9AC4", "type": "SERVICE_METHOD_GROUP"}]},
}
FLAGD_ENTITY = {"entityId": "SERVICE-B1BE5B14F0388F4E", "type": "SERVICE", "displayName": "astroshop-flagd",
               "properties": {"serviceType": "UNIFIED"}}
FRONTEND_ENTITY = {"entityId": "SERVICE-39720C1E0047A5C0", "type": "SERVICE", "displayName": "astroshop-frontend",
                   "properties": {"serviceType": "UNIFIED"}}
CHECKOUT_ENTITY = {"entityId": "SERVICE-5ACC60E0079F8E6D", "type": "SERVICE", "displayName": "astroshop-checkout",
                   "properties": {"serviceType": "UNIFIED"}}
CLUSTER_ENTITY = {"entityId": "KUBERNETES_CLUSTER-289857DC8E688B2B", "type": "KUBERNETES_CLUSTER", "displayName": "eks-playground"}

RAW_TOPOLOGY = {
    "entity": CART_ENTITY,
    "neighbors": {"SERVICE-B1BE5B14F0388F4E": FLAGD_ENTITY, "SERVICE-39720C1E0047A5C0": FRONTEND_ENTITY,
                 "SERVICE-5ACC60E0079F8E6D": CHECKOUT_ENTITY, "CLOUD_APPLICATION-8C621FD5C53B27C6": {"entityId": "CLOUD_APPLICATION-8C621FD5C53B27C6", "type": "CLOUD_APPLICATION", "displayName": "cart"},
                 "KUBERNETES_CLUSTER-289857DC8E688B2B": CLUSTER_ENTITY,
                 "SERVICE_METHOD_GROUP-E5D0D50C747C9AC4": {"entityId": "SERVICE_METHOD_GROUP-E5D0D50C747C9AC4", "type": "SERVICE_METHOD_GROUP", "displayName": "methods"}},
    "edges": [
        {"neighbor_id": "SERVICE-B1BE5B14F0388F4E", "relationship_kind": "calls", "direction": "calls", "is_dependency_like": True},
        {"neighbor_id": "CLOUD_APPLICATION-8C621FD5C53B27C6", "relationship_kind": "isServiceOf", "direction": "calls", "is_dependency_like": False},
        {"neighbor_id": "KUBERNETES_CLUSTER-289857DC8E688B2B", "relationship_kind": "isClusterOfService", "direction": "called_by", "is_dependency_like": False},
        {"neighbor_id": "SERVICE-39720C1E0047A5C0", "relationship_kind": "calls", "direction": "called_by", "is_dependency_like": True},
        {"neighbor_id": "SERVICE-5ACC60E0079F8E6D", "relationship_kind": "calls", "direction": "called_by", "is_dependency_like": True},
        {"neighbor_id": "SERVICE_METHOD_GROUP-E5D0D50C747C9AC4", "relationship_kind": "isGroupOf", "direction": "called_by", "is_dependency_like": False},
    ],
}

RAW_METRICS = {
    "service_id": "SERVICE-E5D0D50C747C9AC4", "from_time": "now-30d",
    "raw": {"totalCount": 3, "resolution": "Inf", "result": [
        {"metricId": "builtin:service.response.time", "data": [{"dimensionMap": {"dt.entity.service": "SERVICE-E5D0D50C747C9AC4"},
                                                                 "timestamps": [1790502720000], "values": [35062.844718748696]}]},
        {"metricId": "builtin:service.requestCount.total", "data": [{"dimensionMap": {"dt.entity.service": "SERVICE-E5D0D50C747C9AC4"},
                                                                     "timestamps": [1790502720000], "values": [813614]}]},
        {"metricId": "builtin:service.errors.total.rate", "data": [{"dimensionMap": {"dt.entity.service": "SERVICE-E5D0D50C747C9AC4"},
                                                                    "timestamps": [1790502720000], "values": [0.00012290840619753348]}]},
        {"metricId": "some:custom.metric.not.in.our.table", "data": [{"dimensionMap": {}, "timestamps": [1], "values": [None, 2.0]}]},
        {"metricId": "builtin:service.cpu.time", "data": []},  # no data at all for this one: must be skipped, not crash
    ]},
}


# ---------------------------------------------------------------------------------- normalize_topology


def test_normalize_topology_from_the_real_captured_shape():
    topo = normalize_topology("SERVICE-E5D0D50C747C9AC4", RAW_TOPOLOGY)
    assert topo.provider == "dynatrace" and topo.service_id == "SERVICE-E5D0D50C747C9AC4" and topo.retrieved_at is not None
    by_id = {n.id: n for n in topo.nodes}
    assert by_id["SERVICE-E5D0D50C747C9AC4"].name == "astroshop-cart" and by_id["SERVICE-E5D0D50C747C9AC4"].kind == "service"
    assert by_id["KUBERNETES_CLUSTER-289857DC8E688B2B"].kind == "other"  # no service-type mapping for this entity type
    assert len(topo.edges) == 6
    dep_like = [e for e in topo.edges if e.attributes["is_dependency_like"]]
    structural = [e for e in topo.edges if not e.attributes["is_dependency_like"]]
    assert len(dep_like) == 3 and len(structural) == 3
    flagd_edge = next(e for e in dep_like if "SERVICE-B1BE5B14F0388F4E" in (e.source, e.target))
    assert flagd_edge.source == "SERVICE-E5D0D50C747C9AC4" and flagd_edge.direction == "calls"  # cart calls flagd
    frontend_edge = next(e for e in dep_like if "SERVICE-39720C1E0047A5C0" in (e.source, e.target))
    assert frontend_edge.target == "SERVICE-E5D0D50C747C9AC4" and frontend_edge.direction == "called_by"  # frontend calls cart


def test_normalize_topology_resolution_error_is_kept_as_an_attribute_not_a_crash():
    raw = json.loads(json.dumps(RAW_TOPOLOGY))
    raw["neighbors"]["SERVICE-B1BE5B14F0388F4E"] = {"entityId": "SERVICE-B1BE5B14F0388F4E", "type": "SERVICE",
                                                    "displayName": "SERVICE-B1BE5B14F0388F4E", "error": "404: gone"}
    topo = normalize_topology("SERVICE-E5D0D50C747C9AC4", raw)
    node = next(n for n in topo.nodes if n.id == "SERVICE-B1BE5B14F0388F4E")
    assert node.attributes["resolution_error"] == "404: gone"


@pytest.mark.parametrize("service_type,expected", [("DATABASE", "database"), ("MESSAGING_SERVICE", "queue"),
                                                    ("RPC_SERVICE", "service"), ("UNKNOWN_FUTURE_TYPE", "service")])
def test_node_kind_from_service_type(service_type, expected):
    e = {"entityId": "SERVICE-1", "type": "SERVICE", "displayName": "x", "properties": {"serviceType": service_type}}
    topo = normalize_topology("SERVICE-1", {"entity": e, "neighbors": {}, "edges": []})
    assert topo.nodes[0].kind == expected


def test_node_kind_falls_back_to_entity_type_when_no_service_type():
    e = {"entityId": "HOST-1", "type": "HOST", "displayName": "h"}
    topo = normalize_topology("HOST-1", {"entity": e, "neighbors": {}, "edges": []})
    assert topo.nodes[0].kind == "host"


def test_edge_protocol_comes_from_the_neighbors_own_remote_endpoint_not_the_pilot_services(monkeypatch):
    """Stage 6 regression: remoteEndpoint describes the specific call TARGET, so each edge's protocol must come from
    that neighbor's own properties. The pilot service's own entity may carry an unrelated (or absent) remoteEndpoint;
    using it for every edge would silently misattribute every dependency's observed scheme."""
    entity = {**CART_ENTITY, "properties": {**CART_ENTITY["properties"], "remoteEndpoint": "grpc://unrelated-self-record"}}
    raw = {**RAW_TOPOLOGY, "entity": entity,
          "neighbors": {**RAW_TOPOLOGY["neighbors"],
                        "SERVICE-B1BE5B14F0388F4E": {**FLAGD_ENTITY, "properties": {**FLAGD_ENTITY["properties"],
                                                                                    "remoteEndpoint": "http://flagd:8013"}}}}
    topo = normalize_topology("SERVICE-E5D0D50C747C9AC4", raw)
    flagd_edge = next(e for e in topo.edges if "SERVICE-B1BE5B14F0388F4E" in (e.source, e.target))
    assert flagd_edge.protocol == "http"  # the neighbor's own scheme, not "grpc" from the pilot service's own record
    by_id = {n.id: n for n in topo.nodes}
    assert by_id["SERVICE-B1BE5B14F0388F4E"].attributes["remoteEndpoint"] == "http://flagd:8013"


# ------------------------------------------------------------------------------------ normalize_metrics


def test_normalize_metrics_from_the_real_captured_shape():
    m = normalize_metrics("SERVICE-E5D0D50C747C9AC4", RAW_METRICS)
    assert m.provider == "dynatrace" and m.retrieved_at is not None
    by_name = {s.name: s for s in m.series}
    assert set(by_name) == {"request.latency", "request.rate", "request.error_rate", "some:custom.metric.not.in.our.table"}
    lat = by_name["request.latency"]
    assert lat.native_name == "builtin:service.response.time" and lat.unit == "microsecond" and lat.avg == pytest.approx(35062.84, abs=0.1)
    assert lat.window_seconds == 30 * 86400
    custom = by_name["some:custom.metric.not.in.our.table"]
    assert custom.avg == 2.0 and custom.count == 1  # the null value is dropped, not averaged in as zero
    assert "builtin:service.cpu.time" not in [s.native_name for s in m.series]  # empty data -> no series, not a zero


def test_normalize_metrics_window_parsing_hours_and_no_match():
    assert normalize_metrics("s", {**RAW_METRICS, "from_time": "now-2h"}).series[0].window_seconds == 7200
    assert normalize_metrics("s", {**RAW_METRICS, "from_time": "2026-01-01T00:00:00Z"}).series[0].window_seconds is None


def test_normalize_metrics_single_aggregate_point_has_no_samples():
    m = normalize_metrics("s", RAW_METRICS)
    assert m.series[0].samples is None  # resolution=Inf: one point per series, nothing to detect variation from


def test_normalize_metrics_multi_point_series_keeps_samples_for_variation_detection():
    """Stage 6: a finer ``resolution`` (e.g. workload pod count over time) returns several points; normalize_metrics
    must keep them (not just the average) so a caller can detect whether the value ever changed."""
    raw = {"service_id": "s", "from_time": "now-2h", "raw": {"result": [
        {"metricId": "builtin:cloud.application.pods", "data": [
            {"dimensionMap": {}, "timestamps": [1790502720000, 1790506320000, 1790509920000], "values": [3, 3, 5]}]}]}}
    m = normalize_metrics("s", raw)
    series = m.series[0]
    assert series.samples is not None and len(series.samples) == 3
    assert [v for _, v in series.samples] == [3, 3, 5]
    assert series.samples[0][0].year == 2026  # timestamps converted from epoch ms to real datetimes


def test_normalize_metrics_a_null_point_in_a_multi_point_series_is_dropped_not_kept_as_a_sample():
    raw = {"service_id": "s", "from_time": "now-1h", "raw": {"result": [
        {"metricId": "custom:x", "data": [{"dimensionMap": {}, "timestamps": [1, 2, 3], "values": [1.0, None, 3.0]}]}]}}
    m = normalize_metrics("s", raw)
    assert [v for _, v in m.series[0].samples] == [1.0, 3.0]


# --------------------------------------------------------------------------------------- server core fetch functions


class _FakeResponse:
    def __init__(self, status_code, payload):
        self.status_code, self._payload, self.is_error, self.text = status_code, payload, status_code >= 400, json.dumps(payload)

    def json(self):
        return self._payload


class _FakeAsyncClient:
    """Stands in for httpx.AsyncClient as an async context manager; each test assigns its own ``.get``."""

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("DT_ENVIRONMENT", "https://fake.example.dynatrace.com")
    monkeypatch.setenv("DT_API_TOKEN", "dt0c01.fake")


def _client_returning(*payloads, urls: list | None = None):
    """An httpx.AsyncClient factory whose .get() returns each (status, payload) pair in turn, optionally recording
    every URL it was called with into the given list."""
    seq = iter(payloads)

    def factory():
        client = _FakeAsyncClient()

        async def get(url, params, headers, timeout):
            if urls is not None:
                urls.append(url)
            status, payload = next(seq)
            return _FakeResponse(status, payload)
        client.get = get
        return client
    return factory


_CART_NEIGHBOR_IDS = ["SERVICE-B1BE5B14F0388F4E", "CLOUD_APPLICATION-8C621FD5C53B27C6", "KUBERNETES_CLUSTER-289857DC8E688B2B",
                     "SERVICE-39720C1E0047A5C0", "SERVICE-5ACC60E0079F8E6D", "SERVICE_METHOD_GROUP-E5D0D50C747C9AC4"]


def test_fetch_topology_resolves_neighbors_individually(monkeypatch):
    # Every relationship target is resolved, not only "calls": which edges are dependency-like versus structural is
    # decided later, from the relationship kind already carried on the edge, not by skipping resolution here.
    urls: list[str] = []
    monkeypatch.setattr(srv.httpx, "AsyncClient",
                        _client_returning((200, CART_ENTITY), *[(200, {"entityId": nid, "type": "X", "displayName": nid})
                                                                for nid in _CART_NEIGHBOR_IDS], urls=urls))
    result = asyncio.run(srv.fetch_topology("SERVICE-E5D0D50C747C9AC4"))
    assert result["entity"]["entityId"] == "SERVICE-E5D0D50C747C9AC4"
    assert set(result["neighbors"]) == set(_CART_NEIGHBOR_IDS)
    assert len(result["edges"]) == 6
    assert sum(e["is_dependency_like"] for e in result["edges"]) == 3  # the three "calls" edges; isServiceOf/isClusterOfService/isGroupOf are structural
    assert urls[0].endswith("/api/v2/entities/SERVICE-E5D0D50C747C9AC4")


def test_fetch_topology_neighbor_resolution_failure_is_captured_not_raised(monkeypatch):
    monkeypatch.setattr(srv.httpx, "AsyncClient",
                        _client_returning((200, CART_ENTITY), *[(404, {"error": {"message": "gone"}}) for _ in _CART_NEIGHBOR_IDS]))
    result = asyncio.run(srv.fetch_topology("SERVICE-E5D0D50C747C9AC4"))
    assert all("error" in n for n in result["neighbors"].values())


@pytest.mark.parametrize("status,fragment", [(401, "rejected the API token"), (403, "missing a required scope"), (404, "check the service id")])
def test_get_maps_status_codes_to_clear_errors(monkeypatch, status, fragment):
    monkeypatch.setattr(srv.httpx, "AsyncClient", _client_returning((status, {"error": "x"})))
    with pytest.raises(srv.DynatraceApiError, match=fragment):
        asyncio.run(srv.fetch_metrics("SERVICE-1"))


@pytest.fixture
def _no_real_sleep(monkeypatch):
    async def instant(_seconds):
        return None

    monkeypatch.setattr(srv.asyncio, "sleep", instant)


def test_a_transient_503_is_retried_and_succeeds(monkeypatch, _no_real_sleep):
    calls: list = []
    monkeypatch.setattr(srv.httpx, "AsyncClient", _client_returning(
        (503, {"error": "x"}), (503, {"error": "x"}), (200, RAW_METRICS["raw"]), urls=calls))
    result = asyncio.run(srv.fetch_metrics("SERVICE-1"))
    assert result["raw"] == RAW_METRICS["raw"] and len(calls) == 3  # failed twice, succeeded on the 3rd (final) attempt


def test_a_persistent_429_gives_up_after_the_retry_budget(monkeypatch, _no_real_sleep):
    calls: list = []
    monkeypatch.setattr(srv.httpx, "AsyncClient", _client_returning(
        (429, {"error": "x"}), (429, {"error": "x"}), (429, {"error": "x"}), urls=calls))
    with pytest.raises(srv.DynatraceApiError, match="429"):
        asyncio.run(srv.fetch_metrics("SERVICE-1"))
    assert len(calls) == srv._DT_RETRIES == 3


def test_a_connection_error_is_retried_then_raised_as_a_clear_message(monkeypatch, _no_real_sleep):
    class _FlakyClient(_FakeAsyncClient):
        calls = 0

        async def get(self, url, params, headers, timeout):
            _FlakyClient.calls += 1
            raise httpx.ConnectError("connection refused")

    monkeypatch.setattr(srv.httpx, "AsyncClient", _FlakyClient)
    with pytest.raises(srv.DynatraceApiError, match="could not reach"):
        asyncio.run(srv.fetch_metrics("SERVICE-1"))
    assert _FlakyClient.calls == srv._DT_RETRIES == 3


def test_a_401_is_not_retried_fails_on_the_first_attempt(monkeypatch, _no_real_sleep):
    calls: list = []
    monkeypatch.setattr(srv.httpx, "AsyncClient", _client_returning((401, {"error": "x"}), urls=calls))
    with pytest.raises(srv.DynatraceApiError, match="rejected the API token"):
        asyncio.run(srv.fetch_metrics("SERVICE-1"))
    assert len(calls) == 1  # a permanent auth failure is never retried


def test_missing_env_vars_are_a_clear_error(monkeypatch):
    monkeypatch.delenv("DT_API_TOKEN", raising=False)
    with pytest.raises(srv.DynatraceApiError, match="DT_API_TOKEN"):
        asyncio.run(srv.fetch_topology("SERVICE-1"))
    monkeypatch.delenv("DT_ENVIRONMENT", raising=False)
    with pytest.raises(srv.DynatraceApiError, match="DT_ENVIRONMENT"):
        asyncio.run(srv.fetch_topology("SERVICE-1"))


def test_fetch_metrics_uses_the_canonical_default_keys_and_a_custom_selector(monkeypatch):
    captured = {}

    def factory():
        client = _FakeAsyncClient()

        async def get(url, params, headers, timeout):
            captured.update(params)
            return _FakeResponse(200, RAW_METRICS["raw"])
        client.get = get
        return client

    monkeypatch.setattr(srv.httpx, "AsyncClient", factory)
    asyncio.run(srv.fetch_metrics("SERVICE-1"))
    assert set(captured["metricSelector"].split(",")) == set(srv.CANONICAL_METRIC_KEYS.values())
    asyncio.run(srv.fetch_metrics("SERVICE-1", metric_keys=["builtin:service.cpu.time"]))
    assert captured["metricSelector"] == "builtin:service.cpu.time"
    assert captured["resolution"] == "Inf"  # default: one aggregate value, unchanged behaviour
    asyncio.run(srv.fetch_metrics("SERVICE-1", resolution="1h"))
    assert captured["resolution"] == "1h"  # Stage 6: a finer resolution returns a real time series instead


# -------------------------------------------------------------------------------- real MCP transport, mock HTTP

class _MockDynatraceHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        assert self.headers.get("Authorization") == "Api-Token dt0c01.mock-token-for-tests"
        if self.path.startswith("/api/v2/entities/SERVICE-E5D0D50C747C9AC4"):
            body = json.dumps({**CART_ENTITY, "fromRelationships": {}, "toRelationships": {}}).encode()
        elif self.path.startswith("/api/v2/metrics/query"):
            body = json.dumps(RAW_METRICS["raw"]).encode()
        else:
            self.send_response(404)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": {"message": "not found in the mock"}}).encode())
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


@pytest.fixture
def mock_dynatrace_server():
    httpd = HTTPServer(("127.0.0.1", 0), _MockDynatraceHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_address[1]}"
    finally:
        httpd.shutdown()


def test_real_mcp_stdio_round_trip_against_a_mock_http_endpoint(mock_dynatrace_server):
    """Spawns the real thin MCP server as a real stdio subprocess and calls it through the real MCP client SDK —
    exactly the mechanism DynatraceProvider and, later, an ADK agent both use — pointed at a local mock HTTP server
    instead of the live tenant, so this proves the MCP transport itself with no network or token dependency."""
    raw = asyncio.run(_call_tool(mock_dynatrace_server, "dt0c01.mock-token-for-tests", "get_smartscape_topology",
                                 {"service_id": "SERVICE-E5D0D50C747C9AC4"}))
    assert raw["entity"]["entityId"] == "SERVICE-E5D0D50C747C9AC4"
    topo = normalize_topology("SERVICE-E5D0D50C747C9AC4", raw)
    assert topo.nodes[0].name == "astroshop-cart"

    raw_m = asyncio.run(_call_tool(mock_dynatrace_server, "dt0c01.mock-token-for-tests", "get_service_metrics",
                                   {"service_id": "SERVICE-E5D0D50C747C9AC4"}))
    metrics = normalize_metrics("SERVICE-E5D0D50C747C9AC4", raw_m)
    assert any(s.name == "request.latency" for s in metrics.series)


def test_call_tool_reports_a_dynatrace_error_from_the_server(mock_dynatrace_server):
    with pytest.raises(DynatraceError, match="404"):
        asyncio.run(_call_tool(mock_dynatrace_server, "dt0c01.mock-token-for-tests", "get_smartscape_topology",
                               {"service_id": "not-in-the-mock"}))  # wrong path shape -> the mock 404s -> DynatraceApiError -> tool error


def test_dynatrace_error_is_an_observability_error():
    assert issubclass(DynatraceError, ObservabilityError)


# ------------------------------------------------------------------------------------------------ options/provider


def test_dynatrace_options_validate_and_never_expose_the_token():
    opts = DynatraceOptions.model_validate({"environment_url": "https://abc.live.dynatrace.com/", "api_token_env": "DT_API_TOKEN"})
    assert opts.environment_url == "https://abc.live.dynatrace.com" and opts.resolved_token() == "dt0c01.fake"
    p = DynatraceProvider("SERVICE-1", opts)
    assert p.public_options() == {"environment_url": "https://abc.live.dynatrace.com"}


def test_mcp_toolset_points_at_the_thin_python_server_not_npx():
    opts = DynatraceOptions.model_validate({"environment_url": "https://abc.live.dynatrace.com"})
    p = DynatraceProvider("SERVICE-1", opts)
    toolset = p.mcp_toolset()
    params = toolset.connection_params.server_params
    assert params.command.endswith("python.exe") or params.command.endswith("python")
    assert params.args == ["-m", "sreadvisor.mcp_servers.dynatrace_server"]
    assert params.env["DT_ENVIRONMENT"] == "https://abc.live.dynatrace.com" and params.env["DT_API_TOKEN"] == "dt0c01.fake"
