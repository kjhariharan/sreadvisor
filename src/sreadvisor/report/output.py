"""Writes the three Stage 4 artifacts and a short console summary.

* ``<service>.unified-report.json``      the structured report (schema.UnifiedReport)
* ``<service>.unified-report.html``      the same report, rendered as one self-contained page
* ``<service>.dynatrace-dashboard.json``  an importable Dynatrace dashboard covering the suggested SLIs
"""

from __future__ import annotations

import re
from pathlib import Path

from sreadvisor.report.dynatrace_dashboard import dashboard_json
from sreadvisor.report.html import render_html
from sreadvisor.report.schema import UnifiedReport


def _slug(service_name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", service_name).strip("-") or "service"


def paths(service_name: str, out_dir: Path) -> dict[str, Path]:
    safe = _slug(service_name)
    return {
        "json": out_dir / f"{safe}.unified-report.json",
        "html": out_dir / f"{safe}.unified-report.html",
        "dashboard": out_dir / f"{safe}.dynatrace-dashboard.json",
    }


def write_report(report: UnifiedReport, out_dir: Path) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    p = paths(report.service_name, out_dir)
    p["json"].write_text(report.model_dump_json(indent=2, exclude_none=True), encoding="utf-8")
    p["html"].write_text(render_html(report), encoding="utf-8")
    p["dashboard"].write_text(dashboard_json(report), encoding="utf-8")
    return p


def console_summary(report: UnifiedReport, written: dict[str, Path]) -> str:
    s = report.action_item_summary
    tiers = report.telemetry_tiers
    lines = [
        f"\nUnified report: {report.service_name}",
        f"  {len(report.action_items)} action items ({s.by_status.get('met', 0)} met, "
        f"{s.by_status.get('not_assessable', 0)} not assessable of {s.applicable_requirements} applicable requirements)",
        f"  {len(report.unrecognized_tech_gaps)} unrecognized tech stack gap(s)",
        f"  {len(report.sli_suggestions)} SLI suggestions "
        f"(tier 1: {sum(1 for x in report.sli_suggestions if x.tier == 1)}, "
        f"tier 2: {sum(1 for x in report.sli_suggestions if x.tier == 2)}, "
        f"tier 3: {sum(1 for x in report.sli_suggestions if x.tier == 3)})",
        f"  telemetry: {len(tiers.tier1_oneagent_default.signals)} OneAgent signals, "
        f"{len(tiers.tier2_application_library.detected_in_service)} application libraries detected",
    ]
    for w in report.warnings[:5]:
        lines.append(f"  ! {w}")
    lines += [f"\nWrote {p}" for p in written.values()]
    return "\n".join(lines)
