"""Writing the gap report and a short console summary. The Markdown report is Stage 4's job."""

from __future__ import annotations

import re
from pathlib import Path

from sreadvisor.gap.schema import GapReport


def report_path(service_name: str, out_dir: Path) -> Path:
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "-", service_name).strip("-") or "service"
    return out_dir / f"{safe}.gaps.json"


def write_report(report: GapReport, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = report_path(report.service_name, out_dir)
    path.write_text(report.model_dump_json(indent=2, exclude_none=True), encoding="utf-8")
    return path


def console_summary(report: GapReport, top: int = 12) -> str:
    s = report.summary
    st = s.by_status
    lines = [
        f"\n{report.pass_name.replace('_', ' ').capitalize()}: {report.service_name}  (assessor: {report.inputs.get('assessor_model')})",
        f"  {s.applicable_requirements} applicable requirements in {len(report.modules)} modules: "
        f"{st['met']} met, {st['partially_met']} partially met, {st['missing']} missing, {st['not_assessable']} not assessable",
        "  gaps by priority: " + ", ".join(f"{n} {p}" for p, n in s.gaps_by_priority.items()),
    ]
    if report.gaps:
        lines.append(f"  top gaps (of {s.gap_count}):")
        for g in report.gaps[:top]:
            tag = " [runtime]" if g.detection_source == "runtime" else ""
            lines.append(f"    {g.id} [{g.priority}] {g.status:13} {g.nfr.id} {g.nfr.title}{tag}")
    if report.unrecognized_tech_gaps:
        lines.append(f"  UNRECOGNIZED TECH STACK GAPS ({s.unrecognized_tech_gap_count}), for review and addition to the Master NFR List:")
        for u in report.unrecognized_tech_gaps:
            lines.append(f"    {u.id} {u.kind}: {u.name} ({u.found_as})")
    if s.failed_assessments:
        lines.append(f"  {s.failed_assessments} assessment(s) failed and are recorded as not assessable")
    for w in report.warnings[:6]:
        lines.append(f"  ! {w}")
    if len(report.warnings) > 6:
        lines.append(f"  ! ... and {len(report.warnings) - 6} more warnings in the report")
    return "\n".join(lines)
