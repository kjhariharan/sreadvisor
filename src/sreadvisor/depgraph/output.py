"""Writing the dependency graph: JSON (for other tooling) and a self-contained HTML visual, mirroring
``report/output.py``'s and ``fmea/output.py``'s shape."""

from __future__ import annotations

import re
from pathlib import Path

from sreadvisor.depgraph.html import render_html
from sreadvisor.depgraph.schema import DependencyGraph


def _slug(service_name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", service_name).strip("-") or "service"


def report_path(service_name: str, out_dir: Path) -> Path:
    return out_dir / f"{_slug(service_name)}.dependency-graph.json"


def html_path(service_name: str, out_dir: Path) -> Path:
    return out_dir / f"{_slug(service_name)}.dependency-graph.html"


def write_report(graph: DependencyGraph, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = report_path(graph.service_name, out_dir)
    path.write_text(graph.model_dump_json(indent=2, exclude_none=True), encoding="utf-8")
    return path


def write_html(graph: DependencyGraph, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = html_path(graph.service_name, out_dir)
    path.write_text(render_html(graph), encoding="utf-8")
    return path


def console_summary(graph: DependencyGraph) -> str:
    deps = [n for n in graph.nodes if n.id != "service"]
    by_kind: dict[str, int] = {}
    for n in deps:
        by_kind[n.kind] = by_kind.get(n.kind, 0) + 1
    runtime_only = sum(1 for n in deps if n.origin == "runtime_only")
    no_resilience = sum(1 for e in graph.edges if not e.resilience)
    lines = [
        f"\nDependency graph: {graph.service_name}  ({len(deps)} dependency node(s), {len(graph.edges)} edge(s))",
        "  by kind: " + (", ".join(f"{n} {k}" for k, n in sorted(by_kind.items())) or "none"),
    ]
    if runtime_only:
        lines.append(f"  {runtime_only} found only via runtime observability (not declared in code)")
    if no_resilience:
        lines.append(f"  {no_resilience} dependency/dependencies with no resilience pattern found (code or mesh)")
    for w in graph.warnings:
        lines.append(f"  ! {w}")
    return "\n".join(lines)
