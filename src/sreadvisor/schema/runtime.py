"""Common runtime data schema.

Every ``ObservabilityProvider`` normalizes its native topology and metrics into these
models. All downstream reasoning (Stage 6 cross-validation, gap analysis) operates on
these types only, never on a provider's native payload. Adding a provider therefore
means writing one adapter, not touching any analysis logic.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

NodeKind = Literal["service", "database", "cache", "queue", "external_service", "host", "process", "other"]


class TopologyNode(BaseModel):
    id: str
    name: str
    kind: NodeKind = "other"
    attributes: dict[str, Any] = Field(default_factory=dict)


class TopologyEdge(BaseModel):
    source: str
    target: str
    protocol: str | None = None  # e.g. http, grpc, jdbc, kafka
    direction: Literal["calls", "called_by"] = "calls"
    attributes: dict[str, Any] = Field(default_factory=dict)


class ServiceTopology(BaseModel):
    provider: str
    service_id: str
    nodes: list[TopologyNode] = Field(default_factory=list)
    edges: list[TopologyEdge] = Field(default_factory=list)
    retrieved_at: datetime | None = None


class MetricSeries(BaseModel):
    """One metric for one service, aggregated over a window. Names are provider-neutral
    where a canonical name exists (see ``CANONICAL_METRICS``); otherwise the native name."""

    name: str
    native_name: str | None = None
    unit: str | None = None
    dimensions: dict[str, str] = Field(default_factory=dict)
    avg: float | None = None
    min: float | None = None
    max: float | None = None
    p50: float | None = None
    p95: float | None = None
    p99: float | None = None
    count: int | None = None
    window_seconds: int | None = None
    # Raw (timestamp, value) points, only when the provider retrieved a time series rather than one aggregate
    # (resolution finer than the whole window). Lets a consumer detect variation over time — for example whether a
    # workload's replica count ever changed, as evidence an autoscaling policy did or did not observably trigger —
    # without the common schema needing a dedicated field for every such question.
    samples: list[tuple[datetime, float]] | None = None


class ServiceMetrics(BaseModel):
    provider: str
    service_id: str
    series: list[MetricSeries] = Field(default_factory=list)
    retrieved_at: datetime | None = None


CANONICAL_METRICS = (
    "request.rate",
    "request.latency",
    "request.error_rate",
    "cpu.utilization",
    "memory.utilization",
    "db.pool.utilization",
    "thread.pool.utilization",
    "gc.pause",
    "workload.replica_count",  # a time series of this, when available, is how Stage 6 detects an observed autoscaling event
)
