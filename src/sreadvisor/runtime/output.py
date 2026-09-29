"""Writes the Stage 5 cross-validation artifact and a short console summary."""

from __future__ import annotations

import re
from pathlib import Path

from sreadvisor.runtime.schema import RuntimeCrossValidation


def _slug(service_name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", service_name).strip("-") or "service"


def report_path(service_name: str, out_dir: Path) -> Path:
    return out_dir / f"{_slug(service_name)}.runtime-cross-validation.json"


def write_report(result: RuntimeCrossValidation, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = report_path(result.service_name, out_dir)
    path.write_text(result.model_dump_json(indent=2, exclude_none=True), encoding="utf-8")
    return path


def console_summary(result: RuntimeCrossValidation) -> str:
    s = result.summary
    lines = [
        f"\nRuntime cross-validation: {result.service_name}  ({result.provider}:{result.service_id})",
        f"  live topology: {len(result.topology.nodes)} nodes, {len(result.topology.edges)} edges "
        f"({s.runtime_dependencies} dependency-like)",
        f"  live metrics: {len(result.metrics.series)} series retrieved",
        f"  Stage 1 dependencies: {s.code_dependencies}",
        f"  matched: {s.matched}   runtime-only (undeclared/transient): {s.runtime_only}   code-only (not observed): {s.code_only}",
    ]
    if result.runtime_only:
        lines.append("  runtime-only dependencies (not found by code or infra analysis):")
        for r in result.runtime_only[:10]:
            lines.append(f"    ! {r.node.kind}: {r.node.name} ({r.node.id})")
    if result.code_only:
        lines.append("  code-only dependencies (not observed in the live topology):")
        for c in result.code_only[:10]:
            lines.append(f"    ! {c.kind}: {c.name}")
    for w in result.warnings:
        lines.append(f"  ! {w}")
    return "\n".join(lines)
