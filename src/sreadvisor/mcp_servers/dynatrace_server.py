"""A thin MCP server that wraps the Dynatrace Environment API v2 (entities/Smartscape and metrics).

Runs as a stdio subprocess (``python -m sreadvisor.mcp_servers.dynatrace_server``), started on demand by an MCP
client — either :class:`~sreadvisor.providers.dynatrace.DynatraceProvider` calling it directly (no LLM judgment is
needed to fetch one service's topology and metrics, so that call is made directly rather than through an agent), or
later an ADK ``LlmAgent`` through the same :meth:`DynatraceProvider.mcp_toolset`. One server, two consumers, neither
of which ever sees a raw Dynatrace payload or makes its own REST call: this module is where every Dynatrace REST
call in the whole codebase happens, and it is the only module that is allowed to change if Dynatrace's API does.

No official Dynatrace MCP server is usable here (it ships as an npm package that needs Node.js and ``npx``, neither
installed in this environment) — following the project's own fallback rule ("if a suitable MCP server does not
already exist, build a thin one"), this one is a plain Python MCP server built on the ``mcp`` SDK already declared
as a project dependency.

Authentication: the environment URL and API token are read only from this process's own environment
(``DT_ENVIRONMENT``, ``DT_API_TOKEN``), which the client sets when it spawns the subprocess — never hardcoded, and
never passed as a tool argument (so an agent calling these tools cannot see or leak the token).
"""

from __future__ import annotations

import asyncio
import os
from typing import Any

import httpx

API_TIMEOUT = 30.0
_DT_RETRIES = 3  # attempts for a transient failure (timeout, connection error, 429, 5xx); a 4xx fails fast, on the first try
_RETRYABLE_STATUS = {429, 500, 502, 503, 504}
# The Metrics API has no service-level equivalent for these CANONICAL_METRICS (schema.runtime); they are host,
# process or JVM level in Dynatrace's own model too (see the OneAgent default catalogue's own module split), so they
# are deliberately left unmapped rather than queried against the wrong entity scope.
CANONICAL_METRIC_KEYS: dict[str, str] = {
    "request.rate": "builtin:service.requestCount.total",
    "request.latency": "builtin:service.response.time",
    "request.error_rate": "builtin:service.errors.total.rate",
    "cpu.utilization": "builtin:service.cpu.time",
}
# Units are not returned by the query endpoint itself; these are Dynatrace's documented units for exactly these
# builtin: keys (a second lookup against the metric descriptor endpoint would confirm them per-tenant, but for this
# fixed, small, hand-picked set that is not needed).
METRIC_UNITS: dict[str, str] = {
    "builtin:service.requestCount.total": "count",
    "builtin:service.response.time": "microsecond",
    "builtin:service.errors.total.rate": "ratio",
    "builtin:service.cpu.time": "microsecond",
}


class DynatraceApiError(RuntimeError):
    """A Dynatrace API call failed. The message is safe to show a user: it never contains the token."""


def _env_and_token() -> tuple[str, str]:
    env_url = os.environ.get("DT_ENVIRONMENT", "").strip().rstrip("/")
    token = os.environ.get("DT_API_TOKEN", "").strip()
    if not env_url:
        raise DynatraceApiError("DT_ENVIRONMENT is not set in the server process's environment.")
    if not token:
        raise DynatraceApiError("DT_API_TOKEN is not set in the server process's environment.")
    return env_url, token


async def _get(client: httpx.AsyncClient, env_url: str, token: str, path: str, params: dict[str, Any]) -> dict:
    """A transient failure (a timeout/connection error, or a 429/5xx response) is retried with exponential backoff;
    a permanent one (401/403/404, or any other 4xx) fails on the first attempt, exactly as before — retrying a
    request that will never succeed only delays reporting the real problem."""
    for attempt in range(_DT_RETRIES):
        try:
            r = await client.get(f"{env_url}{path}", params=params, headers={"Authorization": f"Api-Token {token}"}, timeout=API_TIMEOUT)
        except httpx.HTTPError as exc:
            if attempt == _DT_RETRIES - 1:
                raise DynatraceApiError(f"could not reach {env_url}: {exc}") from exc
            await asyncio.sleep(2**attempt)
            continue
        if r.status_code == 401:
            raise DynatraceApiError("Dynatrace rejected the API token (401). Check DT_API_TOKEN is current and unexpired.")
        if r.status_code == 403:
            raise DynatraceApiError("Dynatrace refused the request (403). The token is missing a required scope "
                                   "(entities.read for topology, metrics.read for metrics).")
        if r.status_code == 404:
            raise DynatraceApiError(f"Dynatrace returned 404 for {path} — check the service id and environment URL.")
        if r.status_code in _RETRYABLE_STATUS and attempt < _DT_RETRIES - 1:
            await asyncio.sleep(2**attempt)
            continue
        if r.is_error:
            detail = r.text[:300]
            raise DynatraceApiError(f"Dynatrace API error {r.status_code} on {path}: {detail}")
        return r.json()
    raise DynatraceApiError(f"Dynatrace API did not succeed after {_DT_RETRIES} attempts on {path}")  # unreachable in practice


# ---------------------------------------------------------------------------------------- topology (Smartscape)

# Structural/containment relationships (which host, process group, cluster or namespace something runs in or
# belongs to) are still returned as edges — the brief asks for the full node and edge set — but are marked
# `is_dependency_like: false` so a consumer such as the Stage 5 cross-validation can tell them apart from an actual
# runtime call dependency without re-deriving the distinction itself.
_DEPENDENCY_RELATIONSHIP_KINDS = {"calls", "isCalledBy"}


async def _resolve_entity(client: httpx.AsyncClient, env_url: str, token: str, entity_id: str) -> dict:
    # remoteEndpoint (when Dynatrace records one for this entity) is what lets Stage 6 observe the actual scheme of a
    # live call (e.g. "http://" vs "https://", or a jdbc url's own sslmode) — requested explicitly rather than relying
    # on it coming back incidentally with another field.
    return await _get(client, env_url, token, f"/api/v2/entities/{entity_id}",
                      {"fields": "+properties.detectedName,+properties.serviceType,+properties.databaseVendor,"
                                 "+properties.remoteEndpoint"})


async def fetch_topology(service_id: str) -> dict:
    """The service entity plus one hop of its Smartscape relationships, each neighbor resolved to a display name
    and type. Raw (still Dynatrace-shaped) so :mod:`providers.dynatrace` can normalize it; kept separate from that
    normalization so this function alone is what changes if Dynatrace's entity API shape changes."""
    env_url, token = _env_and_token()
    async with httpx.AsyncClient() as client:
        entity = await _get(client, env_url, token, f"/api/v2/entities/{service_id}",
                            {"fields": "+fromRelationships,+toRelationships,+properties.detectedName,"
                                       "+properties.serviceType,+properties.databaseVendor,+tags"})
        neighbor_ids: dict[str, str] = {}  # id -> relationship kind, direction folded into the caller's own edge list
        edges: list[dict[str, Any]] = []
        for direction, rel_field in (("calls", "fromRelationships"), ("called_by", "toRelationships")):
            for kind, targets in (entity.get(rel_field) or {}).items():
                for t in targets:
                    neighbor_ids[t["id"]] = t.get("type", "")
                    edges.append({"neighbor_id": t["id"], "relationship_kind": kind,
                                  "direction": "calls" if direction == "calls" else "called_by",
                                  "is_dependency_like": kind in _DEPENDENCY_RELATIONSHIP_KINDS})
        neighbors: dict[str, dict] = {}
        for nid in neighbor_ids:
            try:
                neighbors[nid] = await _resolve_entity(client, env_url, token, nid)
            except DynatraceApiError as exc:
                neighbors[nid] = {"entityId": nid, "type": neighbor_ids[nid], "displayName": nid, "error": str(exc)}
    return {"entity": entity, "neighbors": neighbors, "edges": edges}


# --------------------------------------------------------------------------------------------------- metrics


async def fetch_metrics(service_id: str, metric_keys: list[str] | None = None, from_time: str = "now-2h",
                        resolution: str = "Inf") -> dict:
    """Metrics already being collected for this service: the ones in :data:`CANONICAL_METRIC_KEYS` by default, or an
    explicit set of ``builtin:``/custom metric keys. One aggregate value per metric over the whole window by default
    (``resolution=Inf``), which is what "metrics already being collected" means for a point-in-time pull; passing a
    finer ``resolution`` (for example ``"1h"``) instead returns the individual data points, which is what a caller
    checking for variation over time (for example whether a workload's replica count ever changed) needs."""
    env_url, token = _env_and_token()
    keys = metric_keys or list(CANONICAL_METRIC_KEYS.values())
    async with httpx.AsyncClient() as client:
        data = await _get(client, env_url, token, "/api/v2/metrics/query",
                          {"metricSelector": ",".join(keys), "entitySelector": f"entityId({service_id})",
                           "resolution": resolution, "from": from_time})
    return {"service_id": service_id, "from_time": from_time, "raw": data}


def _register_tools(mcp: Any) -> None:
    from mcp.server.mcpserver.exceptions import ToolError

    @mcp.tool()
    async def get_smartscape_topology(service_id: str) -> dict:
        """Pull the Smartscape topology for one Dynatrace service: the service entity plus every node one hop away
        (services it calls, services that call it, the process group, host and cluster it runs on/in), so
        dependencies not declared anywhere in code are still captured.

        Args:
            service_id: a Dynatrace entity id, for example SERVICE-0123456789ABCDEF.
        """
        try:
            return await fetch_topology(service_id)
        except DynatraceApiError as exc:
            raise ToolError(str(exc)) from exc  # an anticipated failure (bad id, auth, network): the message is safe to return

    @mcp.tool()
    async def get_service_metrics(service_id: str, metric_keys: list[str] | None = None, from_time: str = "now-2h",
                                  resolution: str = "Inf") -> dict:
        """Pull metrics already being collected for one Dynatrace service: request rate, response time, error rate
        and CPU time by default, aggregated over the requested window.

        Args:
            service_id: a Dynatrace entity id, for example SERVICE-0123456789ABCDEF.
            metric_keys: explicit Dynatrace metric keys (for example ["builtin:service.response.time"]); the
                default set is used when omitted.
            from_time: the start of the window in Dynatrace's relative time syntax, for example "now-2h" or "now-7d".
            resolution: "Inf" (default) returns one aggregate value per metric over the whole window; a finer
                resolution (for example "1h") returns the individual data points, needed to detect variation over
                time rather than just a single average.
        """
        try:
            return await fetch_metrics(service_id, metric_keys, from_time, resolution)
        except DynatraceApiError as exc:
            raise ToolError(str(exc)) from exc


def build_server() -> Any:
    from mcp.server.mcpserver import MCPServer

    mcp = MCPServer("dynatrace", instructions="Read-only access to one Dynatrace environment's Smartscape topology "
                                              "and already-collected metrics, scoped to a single service id per call.")
    _register_tools(mcp)
    return mcp


def main() -> None:
    build_server().run()


if __name__ == "__main__":
    main()
