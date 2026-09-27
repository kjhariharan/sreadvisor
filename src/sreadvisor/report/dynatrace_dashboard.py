"""Generates an importable Dynatrace dashboard from a service's SLI suggestions.

Targets the classic Dynatrace Dashboards configuration schema (``dashboardMetadata`` + ``tiles``, the shape accepted
by ``POST /api/config/v1/dashboards`` and by the dashboard JSON import/export in the web UI). The document this
module builds is validated against :class:`DynatraceDashboard` before it is written, so a structural mistake fails
loudly here rather than at import time in a tenant.

Only tier 1 (OneAgent default) SLIs become chartable tiles: the OneAgent catalogue gives them a real ``builtin:``
metric key, so the generated metric selector is one Dynatrace already recognises with no configuration. Tier 2 and
tier 3 SLIs do not yet have a metric key — their eventual key depends on how each organisation exports them (a
Micrometer registry prefixes names differently than raw OTLP, and a business metric does not exist until someone
instruments it) — so fabricating a metric selector for them would produce a tile that looks real but is either wrong
or permanently empty. They are rendered as Markdown tiles naming the metric, its source and why it isn't chartable
yet, so the SRE sees the full picture without the dashboard lying about what it can show today.

Not validated against a live tenant: confirm every ``builtin:`` metric key against the target environment's Metrics
API before relying on this (the same caveat the OneAgent catalogue itself carries).
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from sreadvisor.report.schema import SliSuggestion, UnifiedReport

DASHBOARD_SCHEMA_NOTE = "dynatrace-dashboards-config-v1"

# Classic-dashboard grid: pixel bounds, 12-pixel gutter, three chart tiles per row.
_MARGIN, _GUTTER, _HEADER_H, _TILE_W, _TILE_H, _COLS = 0, 12, 60, 372, 260, 3


class TileBounds(BaseModel):
    model_config = ConfigDict(extra="forbid")

    top: int
    left: int
    width: int
    height: int


class DataExplorerQuery(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    metricSelector: str
    enabled: bool = True


class DashboardTile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    tileType: Literal["MARKDOWN", "DATA_EXPLORER"]
    configured: bool = True
    bounds: TileBounds
    tileFilter: dict[str, Any] = Field(default_factory=dict)
    markdown: str | None = None
    queries: list[DataExplorerQuery] | None = None


class SharingDetails(BaseModel):
    model_config = ConfigDict(extra="forbid")

    linkShared: bool = True
    published: bool = False


class DashboardFilter(BaseModel):
    model_config = ConfigDict(extra="forbid")

    timeframe: str = "l_2_HOURS"


class DashboardMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    shared: bool = False
    sharingDetails: SharingDetails = Field(default_factory=SharingDetails)
    dashboardFilter: DashboardFilter = Field(default_factory=DashboardFilter)
    tags: list[str] = Field(default_factory=list)
    preset: bool = False


class DynatraceDashboard(BaseModel):
    """Round-trips to exactly the JSON Dynatrace's Dashboards API expects: no extra top-level keys, so the file
    written to disk can be imported as-is, with no wrapper to strip first."""

    model_config = ConfigDict(extra="forbid")

    dashboardMetadata: DashboardMetadata
    tiles: list[DashboardTile]


class _Layout:
    """Hands out tile bounds top to bottom: a full-width header row, then a grid of equal tiles."""

    def __init__(self) -> None:
        self.y = _MARGIN
        self.col = 0

    def header(self, height: int = _HEADER_H) -> TileBounds:
        if self.col:  # a header always starts its own row
            self.y += _TILE_H + _GUTTER
            self.col = 0
        b = TileBounds(top=self.y, left=_MARGIN, width=_COLS * _TILE_W + (_COLS - 1) * _GUTTER, height=height)
        self.y += height + _GUTTER
        return b

    def tile(self) -> TileBounds:
        b = TileBounds(top=self.y, left=_MARGIN + self.col * (_TILE_W + _GUTTER), width=_TILE_W, height=_TILE_H)
        self.col += 1
        if self.col >= _COLS:
            self.col = 0
            self.y += _TILE_H + _GUTTER
        return b


def _metric_selector(sli: SliSuggestion) -> str:
    # A minimal, always-valid Metrics v2 selector: the metric id plus a single aggregation transformation.
    # `avg` matches how Dynatrace's own default service dashboards chart these same builtin: keys.
    return f"{sli.metric_key}:avg"


def _chart_tile(layout: _Layout, sli: SliSuggestion) -> DashboardTile:
    return DashboardTile(
        name=sli.name, tileType="DATA_EXPLORER", bounds=layout.tile(),
        queries=[DataExplorerQuery(id="A", metricSelector=_metric_selector(sli))],
    )


def _markdown_tile(layout: _Layout, sli: SliSuggestion) -> DashboardTile:
    text = (
        f"## {sli.name}\n\n"
        f"**Subject:** {sli.subject}\n\n"
        f"**Source:** {sli.measurement_source}\n\n"
        f"{sli.rationale}\n\n"
        "_Not chartable yet: this metric has no Dynatrace metric key until it is exported to the tenant "
        "(for tier 2, wire the library's registry to Dynatrace or OTLP; for tier 3, add the instrumentation)._"
    )
    return DashboardTile(name=sli.name, tileType="MARKDOWN", bounds=layout.tile(), markdown=text)


def _header_tile(layout: _Layout, text: str) -> DashboardTile:
    return DashboardTile(name="", tileType="MARKDOWN", bounds=layout.header(), markdown=text)


def build_dashboard(report: UnifiedReport) -> DynatraceDashboard:
    layout = _Layout()
    tiles: list[DashboardTile] = [_header_tile(layout, (
        f"# {report.service_name} — SRE readiness dashboard\n\n"
        "Generated by sreadvisor from the service's tech stack fingerprint, transaction flows and inferred business "
        "purpose. Tier 1 tiles chart a real OneAgent metric with no further setup. Tier 2 and tier 3 items are shown "
        "as notes until the metric is exported to this tenant; see the unified report for the full rationale."
    ))]

    by_tier: dict[int, list[SliSuggestion]] = {1: [], 2: [], 3: []}
    for s in report.sli_suggestions:
        by_tier[s.tier].append(s)

    tier_titles = {
        1: "## Tier 1 — OneAgent default (charted below)",
        2: "## Tier 2 — application level, library emitted (needs export to this tenant)",
        3: "## Tier 3 — business-aware custom (needs new instrumentation)",
    }
    for tier in (1, 2, 3):
        items = by_tier[tier]
        if not items:
            continue
        tiles.append(_header_tile(layout, tier_titles[tier]))
        for s in items:
            tiles.append(_chart_tile(layout, s) if tier == 1 and s.metric_key else _markdown_tile(layout, s))

    metadata = DashboardMetadata(name=f"{report.service_name} — SRE readiness (sreadvisor)", tags=["sreadvisor", "auto-generated", report.service_name])
    return DynatraceDashboard(dashboardMetadata=metadata, tiles=tiles)


def dashboard_json(report: UnifiedReport) -> str:
    return build_dashboard(report).model_dump_json(indent=2, exclude_none=True)
