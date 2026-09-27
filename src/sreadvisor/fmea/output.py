"""Writing the FMEA report and a short console summary."""

from __future__ import annotations

import re
from pathlib import Path

from sreadvisor.fmea.schema import FmeaReport


def report_path(service_name: str, out_dir: Path) -> Path:
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "-", service_name).strip("-") or "service"
    return out_dir / f"{safe}.fmea.json"


def write_report(report: FmeaReport, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = report_path(report.service_name, out_dir)
    path.write_text(report.model_dump_json(indent=2, exclude_none=True), encoding="utf-8")
    return path


def console_summary(report: FmeaReport, top: int = 15) -> str:
    lines = [
        f"\nFMEA: {report.service_name}  ({report.components_analyzed} component(s) analysed, "
        f"{len(report.failure_modes)} failure mode(s))",
        "  by severity: " + ", ".join(f"{n} {s}" for s, n in report.summary_by_severity.items()),
    ]
    for m in report.failure_modes[:top]:
        tag = " [runtime-only dependency]" if m.origin == "runtime_only" else ""
        lines.append(f"    {m.id} [{m.severity}] {m.component} ({m.component_kind}){tag}: {m.failure_mode}")
    if len(report.failure_modes) > top:
        lines.append(f"    ... and {len(report.failure_modes) - top} more")
    for w in report.warnings:
        lines.append(f"  ! {w}")
    return "\n".join(lines)
