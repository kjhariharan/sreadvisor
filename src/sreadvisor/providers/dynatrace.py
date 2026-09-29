"""Dynatrace: the first ObservabilityProvider implementation.

Retrieval goes through the Dynatrace MCP server (:mod:`sreadvisor.mcp_servers.dynatrace_server`) via the standard MCP
client SDK, never a hand-rolled REST client — the server is the only place that ever makes a Dynatrace API call, and
the only place that changes if Dynatrace's API does. Fetching one named service's topology and metrics needs no LLM
judgment, so :meth:`get_topology`/:meth:`get_metrics` call the server directly, as an ordinary MCP client; the exact
same server is what :meth:`mcp_toolset` registers for an ADK ``LlmAgent`` to call the same way later. The
normalization into the common runtime schema lives here so that no other module ever sees a Dynatrace-shaped payload.
"""

from __future__ import annotations

import os
import re
import sys
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import SecretStr, field_validator

from sreadvisor.providers.base import ObservabilityError, ObservabilityProvider, ProviderOptions
from sreadvisor.schema.runtime import MetricSeries, NodeKind, ServiceMetrics, ServiceTopology, TopologyEdge, TopologyNode

AuthMode = Literal["api_token", "oauth2"]
DEFAULT_OAUTH_URL = "https://sso.dynatrace.com/sso/oauth2/token"
DEFAULT_OAUTH_SCOPES = "environment-api:entities:read environment-api:metrics:read"


class DynatraceOptions(ProviderOptions):
    environment_url: str
    auth_mode: AuthMode = "api_token"

    # auth_mode "api_token": the token may be given inline (CLI flag) or, preferably, by naming an environment
    # variable — resolved fresh at call time, never persisted to the dataset or the registry.
    api_token: SecretStr | None = None
    api_token_env: str = "DT_API_TOKEN"

    # auth_mode "oauth2": an OAuth2 client-credentials grant against Dynatrace SSO exchanges a client id/secret for
    # a short-lived bearer access token (fetched, and cached only in memory, by the MCP server — see
    # mcp_servers/dynatrace_server.py). Same resolution pattern as api_token: an inline value or an env var name.
    oauth_client_id: SecretStr | None = None
    oauth_client_id_env: str = "DT_OAUTH_CLIENT_ID"
    oauth_client_secret: SecretStr | None = None
    oauth_client_secret_env: str = "DT_OAUTH_CLIENT_SECRET"
    oauth_url: str = DEFAULT_OAUTH_URL
    oauth_scopes: str = DEFAULT_OAUTH_SCOPES

    @field_validator("environment_url")
    @classmethod
    def _url(cls, v: str) -> str:
        v = v.strip().rstrip("/")
        if not re.match(r"^https://[^/\s]+", v):
            raise ValueError("must be an https URL such as https://abc12345.live.dynatrace.com")
        return v

    def resolved_token(self) -> str | None:
        if self.api_token is not None:
            return self.api_token.get_secret_value()
        return os.environ.get(self.api_token_env)

    def resolved_client_id(self) -> str | None:
        if self.oauth_client_id is not None:
            return self.oauth_client_id.get_secret_value()
        return os.environ.get(self.oauth_client_id_env)

    def resolved_client_secret(self) -> str | None:
        if self.oauth_client_secret is not None:
            return self.oauth_client_secret.get_secret_value()
        return os.environ.get(self.oauth_client_secret_env)


class DynatraceError(ObservabilityError):
    pass


# ------------------------------------------------------------------------------------- entity type -> NodeKind

# properties.serviceType (only meaningful when the entity's own type is SERVICE) takes priority over the coarser
# entity type, since Dynatrace's own topology already distinguishes a database call from an ordinary service call
# at this level.
_SERVICE_TYPE_TO_KIND: dict[str, NodeKind] = {
    "DATABASE": "database", "MESSAGING_SERVICE": "queue", "WEB_REQUEST_SERVICE": "external_service",
    "RPC_SERVICE": "service", "UNIFIED": "service", "WEB_SERVICE": "service", "QUEUE_LISTENER_SERVICE": "queue",
    "EXTERNAL": "external_service", "BACKGROUND_ACTIVITY": "service",
}
_ENTITY_TYPE_TO_KIND: dict[str, NodeKind] = {
    "SERVICE": "service", "HOST": "host", "PROCESS_GROUP": "process", "PROCESS_GROUP_INSTANCE": "process",
    "SERVICE_INSTANCE": "process",
}
# A relationship kind between the service and a neighbor whose node kind is one of these represents an actual
# runtime dependency; everything else (runsOn, isServiceOf, isClusterOfService, isInstanceOf, isGroupOf, ...) is a
# structural/containment relationship, still returned as an edge (the full node and edge set was asked for) but not
# something Stage 5's cross-validation compares against code-declared dependencies.
_DEPENDENCY_KINDS: set[NodeKind] = {"service", "database", "cache", "queue", "external_service"}


def _node_kind(entity: dict[str, Any]) -> NodeKind:
    props = entity.get("properties") or {}
    service_type = props.get("serviceType")
    if service_type and service_type in _SERVICE_TYPE_TO_KIND:
        return _SERVICE_TYPE_TO_KIND[service_type]
    if props.get("databaseVendor"):
        return "database"
    return _ENTITY_TYPE_TO_KIND.get(entity.get("type", ""), "other")


def _node_from_entity(entity: dict[str, Any]) -> TopologyNode:
    props = entity.get("properties") or {}
    attrs = {k: v for k, v in props.items() if isinstance(v, (str, int, float, bool))}
    if entity.get("error"):
        attrs["resolution_error"] = entity["error"]
    return TopologyNode(id=entity["entityId"], name=entity.get("displayName") or entity["entityId"],
                        kind=_node_kind(entity), attributes=attrs)


def normalize_topology(service_id: str, raw: dict[str, Any]) -> ServiceTopology:
    """Dynatrace's entity + one-hop-relationships JSON (see ``fetch_topology``) into the common runtime schema."""
    entity = raw["entity"]
    nodes = {service_id: _node_from_entity(entity)}
    edges: list[TopologyEdge] = []
    for e in raw["edges"]:
        neighbor = raw["neighbors"].get(e["neighbor_id"], {"entityId": e["neighbor_id"], "type": "", "displayName": e["neighbor_id"]})
        node = _node_from_entity(neighbor)
        nodes.setdefault(node.id, node)
        source, target = (service_id, node.id) if e["direction"] == "calls" else (node.id, service_id)
        # remoteEndpoint (when present) is a property of the specific call TARGET, not of the pilot service itself —
        # each neighbor's own properties are what describe the connection to it (e.g. "grpc://x" or "http://y:8080").
        edges.append(TopologyEdge(source=source, target=target,
                                  protocol=(neighbor.get("properties") or {}).get("remoteEndpoint", "").split("://")[0] or None,
                                  direction="calls" if e["direction"] == "calls" else "called_by",
                                  attributes={"relationship_kind": e["relationship_kind"], "is_dependency_like": e["is_dependency_like"]}))
    return ServiceTopology(provider="dynatrace", service_id=service_id, nodes=list(nodes.values()), edges=edges,
                           retrieved_at=datetime.now(timezone.utc))


def normalize_metrics(service_id: str, raw: dict[str, Any]) -> ServiceMetrics:
    """Dynatrace's ``/api/v2/metrics/query`` response (see ``fetch_metrics``) into the common runtime schema."""
    from sreadvisor.mcp_servers.dynatrace_server import CANONICAL_METRIC_KEYS, METRIC_UNITS

    native_to_canonical = {v: k for k, v in CANONICAL_METRIC_KEYS.items()}
    window_seconds = None
    m = re.match(r"^now-(\d+)([smhd])$", raw.get("from_time", ""))
    if m:
        window_seconds = int(m.group(1)) * {"s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]

    series: list[MetricSeries] = []
    for result in raw["raw"].get("result", []):
        metric_id = result["metricId"]
        for point in result.get("data", []):
            timestamps, raw_values = point.get("timestamps", []), point.get("values", [])
            values = [v for v in raw_values if v is not None]
            if not values:
                continue
            avg = sum(values) / len(values)
            # More than one non-null point means this was queried at a finer resolution than "Inf": keep the raw
            # series too, so a caller can check for variation over time (not just the average) — for example whether
            # a workload's replica count ever changed, evidence an autoscaling policy did or did not observably trigger.
            samples = ([(datetime.fromtimestamp(ts / 1000, tz=timezone.utc), v)
                       for ts, v in zip(timestamps, raw_values) if v is not None] if len(values) > 1 else None)
            series.append(MetricSeries(
                name=native_to_canonical.get(metric_id, metric_id), native_name=metric_id,
                unit=METRIC_UNITS.get(metric_id), dimensions=point.get("dimensionMap") or {},
                avg=avg, min=min(values), max=max(values), count=len(values), window_seconds=window_seconds, samples=samples))
    return ServiceMetrics(provider="dynatrace", service_id=service_id, series=series, retrieved_at=datetime.now(timezone.utc))


# --------------------------------------------------------------------------------------------------- MCP client


async def _call_tool(environment_url: str, auth_env: dict[str, str], tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    params = StdioServerParameters(
        command=sys.executable, args=["-m", "sreadvisor.mcp_servers.dynatrace_server"],
        env={**os.environ, "DT_ENVIRONMENT": environment_url, **auth_env},
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool(tool_name, arguments)
    if result.is_error:
        text = "; ".join(getattr(c, "text", str(c)) for c in (result.content or []))
        raise DynatraceError(f"{tool_name} failed: {text or 'no error detail returned'}")
    if result.structured_content is not None:
        return result.structured_content
    for block in result.content or []:
        if getattr(block, "text", None):
            import json

            return json.loads(block.text)
    raise DynatraceError(f"{tool_name} returned no content")


class DynatraceProvider(ObservabilityProvider):
    name = "dynatrace"
    OptionsModel = DynatraceOptions
    options: DynatraceOptions

    # Dynatrace entity ids look like SERVICE-0123456789ABCDEF.
    SERVICE_ID_RE = re.compile(r"^SERVICE-[0-9A-Fa-f]{16}$")

    @classmethod
    def validate_options(cls, raw: dict[str, Any]) -> DynatraceOptions:
        opts = DynatraceOptions(**raw)
        if opts.auth_mode == "oauth2":
            missing = []
            if not opts.resolved_client_id():
                missing.append(f"oauth_client_id (or ${opts.oauth_client_id_env})")
            if not opts.resolved_client_secret():
                missing.append(f"oauth_client_secret (or ${opts.oauth_client_secret_env})")
            if missing:
                raise ValueError(f"auth_mode is 'oauth2' but missing: {', '.join(missing)}.")
        elif opts.resolved_token() is None:
            raise ValueError(
                f"api_token: missing. Pass --dt-api-token, set api_token, or export ${opts.api_token_env}. "
                "(Or set auth_mode: oauth2 to authenticate with a client id/secret instead.)"
            )
        return opts

    def public_options(self) -> dict[str, Any]:
        return {"environment_url": self.options.environment_url, "auth_mode": self.options.auth_mode}

    def _token(self) -> str:
        token = self.options.resolved_token()
        if not token:
            raise DynatraceError(f"no API token available (checked options.api_token and ${self.options.api_token_env}).")
        return token

    def _auth_env(self) -> dict[str, str]:
        """Env vars for the MCP server subprocess describing how to authenticate — never logged or returned from
        :meth:`public_options`. Resolved fresh on every call, the same as :meth:`_token`."""
        if self.options.auth_mode == "oauth2":
            client_id = self.options.resolved_client_id()
            client_secret = self.options.resolved_client_secret()
            if not client_id or not client_secret:
                raise DynatraceError(
                    "auth_mode is 'oauth2' but the client id/secret could not be resolved (checked options and "
                    f"${self.options.oauth_client_id_env}/${self.options.oauth_client_secret_env})."
                )
            return {"DT_AUTH_MODE": "oauth2", "DT_OAUTH_CLIENT_ID": client_id, "DT_OAUTH_CLIENT_SECRET": client_secret,
                   "DT_OAUTH_URL": self.options.oauth_url, "DT_OAUTH_SCOPES": self.options.oauth_scopes}
        return {"DT_AUTH_MODE": "api_token", "DT_API_TOKEN": self._token()}

    def mcp_toolset(self) -> Any:
        """ADK MCPToolset for the Dynatrace MCP server: the same thin Python server ``get_topology``/``get_metrics``
        call directly, registered here so an ADK ``LlmAgent`` can call it too (Stage 6)."""
        from google.adk.tools.mcp_tool import McpToolset, StdioConnectionParams
        from mcp import StdioServerParameters

        return McpToolset(
            connection_params=StdioConnectionParams(
                server_params=StdioServerParameters(
                    command=sys.executable, args=["-m", "sreadvisor.mcp_servers.dynatrace_server"],
                    env={**os.environ, "DT_ENVIRONMENT": self.options.environment_url, **self._auth_env()},
                ),
                timeout=60,
            )
        )

    async def get_topology(self, service_id: str) -> ServiceTopology:
        raw = await _call_tool(self.options.environment_url, self._auth_env(), "get_smartscape_topology", {"service_id": service_id})
        return normalize_topology(service_id, raw)

    async def get_metrics(self, service_id: str, metric_keys: list[str] | None = None, from_time: str = "now-2h",
                          resolution: str = "Inf") -> ServiceMetrics:
        args: dict[str, Any] = {"service_id": service_id, "from_time": from_time, "resolution": resolution}
        if metric_keys:
            args["metric_keys"] = metric_keys
        raw = await _call_tool(self.options.environment_url, self._auth_env(), "get_service_metrics", args)
        return normalize_metrics(service_id, raw)
