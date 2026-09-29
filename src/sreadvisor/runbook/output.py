"""Writing the runbook: JSON (for other tooling) and a Markdown render (for an on-call engineer during a live
failure — the brief's own words: "a runbook the operations team can use during a live failure")."""

from __future__ import annotations

import re
from pathlib import Path

from sreadvisor.runbook.schema import Runbook

_SEVERITY_ORDER = ("critical", "high", "medium", "low")


def report_path(service_name: str, out_dir: Path) -> Path:
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "-", service_name).strip("-") or "service"
    return out_dir / f"{safe}.runbook.json"


def markdown_path(service_name: str, out_dir: Path) -> Path:
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "-", service_name).strip("-") or "service"
    return out_dir / f"{safe}.runbook.md"


def write_report(runbook: Runbook, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = report_path(runbook.service_name, out_dir)
    path.write_text(runbook.model_dump_json(indent=2, exclude_none=True), encoding="utf-8")
    return path


def to_markdown(runbook: Runbook) -> str:
    lines = [f"# Operations runbook: {runbook.service_name}", "", f"_Generated {runbook.generated_at.isoformat()}_", ""]
    if runbook.business_context:
        lines += [f"**Business purpose:** {runbook.business_context}", ""]
    if not runbook.entries:
        lines += ["No failure modes were available to build a runbook from.", ""]
    for severity in _SEVERITY_ORDER:
        entries = [e for e in runbook.entries if e.severity == severity]
        if not entries:
            continue
        lines.append(f"## {severity.upper()}")
        lines.append("")
        for e in entries:
            tag = " _(undocumented dependency — found only via runtime observability, not in code)_" if e.origin == "runtime_only" else ""
            lines.append(f"### {e.id}: {e.component} — {e.failure_mode}{tag}")
            lines.append("")
            lines.append(f"**Effect:** {e.effect_on_transaction_flow}")
            lines.append("")
            lines.append("**Detection signals**")
            for s in e.detection_signals or ["(none identified)"]:
                lines.append(f"- {s}")
            lines.append("")
            lines.append("**Immediate actions**")
            for i, a in enumerate(e.immediate_actions or ["(none identified)"], 1):
                lines.append(f"{i}. {a}")
            lines.append("")
            lines.append(f"**Escalate to:** {e.escalate_to}  ")
            lines.append(f"**Escalate when:** {e.escalate_when}")
            if e.related_gap_ids:
                lines.append("")
                lines.append(f"**Related gaps:** {', '.join(e.related_gap_ids)}")
            lines.append("")
    if runbook.warnings:
        lines.append("## Warnings")
        for w in runbook.warnings:
            lines.append(f"- {w}")
        lines.append("")
    return "\n".join(lines)


def write_markdown(runbook: Runbook, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = markdown_path(runbook.service_name, out_dir)
    path.write_text(to_markdown(runbook), encoding="utf-8")
    return path


def console_summary(runbook: Runbook) -> str:
    lines = [f"\nOperations runbook: {runbook.service_name}  ({len(runbook.entries)} entry/entries)"]
    for e in runbook.entries[:15]:
        lines.append(f"    {e.id} [{e.severity}] {e.component}: {e.failure_mode} -> escalate to {e.escalate_to}")
    if len(runbook.entries) > 15:
        lines.append(f"    ... and {len(runbook.entries) - 15} more")
    for w in runbook.warnings:
        lines.append(f"  ! {w}")
    return "\n".join(lines)
