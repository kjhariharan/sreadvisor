"""Deterministic access to the Stage 1 dataset for gap analysis: no LLM, no repository access.

* :func:`project` keeps only the parts of the dataset an NFR entry says verify it (its ``stage1_paths``),
  with each list item's identity and ``file:line`` retained and missing values shown explicitly as null,
  so absence is visible to the assessor. Cost therefore scales with the number of requirements, not with dataset size.
* :func:`path_valid` and :func:`locations` are the grounding checks: a citation the model returns must exist.
* :func:`steps_for_path` maps a dataset path to the Stage 1 steps that produce it, so "nothing found" can be told
  apart from "the step that would have found it did not run".

Path syntax: ``a.b[].c`` (wildcard over a list), ``a.b[3].c`` (one item), a trailing list of plain values may omit ``[]``.
"""

from __future__ import annotations

import json
import re
from typing import Any

IDENTITY_KEYS = ("name", "id", "kind", "symbol", "system", "dependency", "pattern", "library", "key", "namespace",
                 "mechanism", "domain", "subject", "host", "type", "file", "repo", "provider")
_SEG = re.compile(r"^(\w+)(\[(\d*)\])?$")


class PathError(ValueError):
    pass


def parse(path: str) -> list[tuple[str, str | None]]:
    """Segments as (name, index) where index is None (plain), "" (wildcard) or a digit string."""
    out = []
    for seg in path.split("."):
        m = _SEG.match(seg)
        if not m:
            raise PathError(f"bad path segment {seg!r} in {path!r}")
        out.append((m.group(1), m.group(3) if m.group(2) else None))
    return out


# --------------------------------------------------------------------------------- validity


def path_valid(data: Any, path: str) -> bool:
    """True if the path names something that exists in the dataset (an empty list still counts as existing)."""
    try:
        segs = parse(path)
    except PathError:
        return False

    def walk(node: Any, rest: list[tuple[str, str | None]]) -> bool:
        if not rest:
            return True
        name, idx = rest[0]
        if not isinstance(node, dict) or name not in node:
            return False
        child = node[name]
        if idx is None:
            return walk(child, rest[1:])
        if not isinstance(child, list):
            return False
        if idx == "":
            return True if not child else any(walk(item, rest[1:]) for item in child)
        return int(idx) < len(child) and walk(child[int(idx)], rest[1:])

    return walk(data, segs)


def locate(data: Any, path: str) -> tuple[str, int | None] | None:
    """The file (and line) behind a concrete dataset path: the deepest node on the path that carries evidence."""
    try:
        segs = parse(path)
    except PathError:
        return None
    node, best = data, None
    for name, idx in segs:
        if not isinstance(node, dict) or name not in node:
            break
        node = node[name]
        if idx is not None:
            if not isinstance(node, list) or not idx or int(idx) >= len(node):
                break
            node = node[int(idx)]
        if isinstance(node, dict):
            ev = node.get("evidence") if isinstance(node.get("evidence"), dict) else node
            if isinstance(ev.get("file"), str):
                best = (ev["file"], ev.get("line") if isinstance(ev.get("line"), int) else None)
    return best


def at_locations(data: dict, paths: list[str], max_items: int = 12, limit: int = 12) -> list[str]:
    """file:line of every item the projection of ``paths`` shows: where the absence of something was checked."""
    found: list[str] = []

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            at = node.get("at")
            if isinstance(at, str) and at not in found:
                found.append(at)
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    walk(_render(data, _trie(paths), "", max_items))
    return found[:limit]


def locations(data: Any) -> tuple[set[tuple[str, int]], set[str]]:
    """Every (file, line) and every file the dataset cites, for checking a model's citations."""
    locs: set[tuple[str, int]] = set()
    files: set[str] = set()

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            f = node.get("file")
            if isinstance(f, str):
                files.add(f)
                if isinstance(node.get("line"), int):
                    locs.add((f, node["line"]))
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    walk(data)
    return locs, files


# -------------------------------------------------------------------------------- projection


def _trie(paths: list[str]) -> dict:
    root: dict = {}
    for p in paths:
        node = root
        segs = parse(p)
        for i, (name, idx) in enumerate(segs):
            entry = node.setdefault(name, {"list": idx is not None, "kids": {}, "leaf": False})
            if idx is not None:
                entry["list"] = True
            if i == len(segs) - 1:
                entry["leaf"] = True
            node = entry["kids"]
    return root


def _short(value: Any, max_items: int, max_str: int = 240) -> Any:
    if isinstance(value, str):
        return value if len(value) <= max_str else value[: max_str - 3] + "..."
    if isinstance(value, list):
        items = [_short(v, max_items, max_str) for v in value[:max_items]]
        if len(value) > max_items:
            items.append(f"... (+{len(value) - max_items} more of {len(value)})")
        return items
    if isinstance(value, dict):
        return {k: _short(v, max_items, max_str) for k, v in value.items()}
    return value


def _identity(item: dict) -> dict:
    ident = {k: item[k] for k in IDENTITY_KEYS if k in item and isinstance(item[k], (str, int, bool))}
    ev = item.get("evidence")
    if isinstance(ev, dict) and ev.get("file"):
        ident["at"] = f"{ev['file']}:{ev['line']}" if ev.get("line") else ev["file"]
    return ident


def _is_small_record(item: dict) -> bool:
    """A flat record (at most 8 fields, plain values, short lists, an evidence pointer): cheap enough to always show whole."""
    if len(item) > 8:
        return False
    for k, v in item.items():
        if isinstance(v, (str, int, float, bool)) or v is None:
            continue
        if isinstance(v, list) and len(v) <= 6 and all(isinstance(x, (str, int, float, bool)) for x in v):
            continue
        if k == "evidence" and isinstance(v, dict):
            continue
        return False
    return True


def _render(node: Any, trie: dict, path: str, max_items: int, is_item: bool = False) -> Any:
    if not isinstance(node, dict):
        return _short(node, max_items)
    out: dict[str, Any] = {"_path": path} if path else {}
    if path:
        out.update(_identity(node))
    if is_item and _is_small_record(node):  # show the whole record so no relevant field (origin, value, scope...) is hidden
        for k, v in node.items():
            if k != "evidence":
                out.setdefault(k, _short(v, max_items))
        return out
    for name, spec in trie.items():
        child = node.get(name)
        cpath = f"{path}.{name}" if path else name
        if spec["leaf"] or not spec["kids"]:
            out[name] = _short(child, max_items)
        elif spec["list"] and isinstance(child, list):
            items = [_render(it, spec["kids"], f"{cpath}[{i}]", max_items, is_item=True) for i, it in enumerate(child[:max_items])]
            if len(child) > max_items:
                items.append(f"... (+{len(child) - max_items} more of {len(child)})")
            out[name] = items
        elif isinstance(child, dict):
            out[name] = _render(child, spec["kids"], cpath, max_items)
        else:
            out[name] = child
    return out


def project(data: dict, paths: list[str], max_items: int = 12, max_chars: int = 6000) -> str:
    """Compact JSON of only the dataset parts named by ``paths``, shrunk until it fits ``max_chars``."""
    trie = _trie(paths)
    items = max_items
    while True:
        text = json.dumps(_render(data, trie, "", items), separators=(",", ":"), ensure_ascii=False, default=str)
        if len(text) <= max_chars or items <= 2:
            return text if len(text) <= max_chars * 2 else text[: max_chars * 2] + "...(truncated)"
        items = max(2, items // 2)


# ---------------------------------------------------------------- Stage 1 step accountability

_INFRA_PREFIXES = {
    "workloads": ["kubernetes", "helm"], "services": ["kubernetes", "helm"], "ingresses": ["kubernetes", "helm"],
    "network_policies": ["kubernetes", "helm"], "disruption_budgets": ["kubernetes", "helm"],
    "autoscalers": ["kubernetes", "helm", "terraform"], "capacity": ["kubernetes", "helm", "compose_and_docker"],
    "pipelines": ["cicd_pipelines"], "mesh": ["service_mesh"], "terraform_resources": ["terraform"],
    "dockerfiles": ["compose_and_docker"], "compose_services": ["compose_and_docker"], "helm_charts": ["helm"],
    "kubernetes_secret_definitions": ["kubernetes", "helm"],
    "secrets": ["kubernetes", "helm", "terraform", "compose_and_docker", "cicd_pipelines"],
    "encryption_audit": ["kubernetes", "helm", "terraform", "compose_and_docker"],
}
_REPO_PREFIXES = {
    "fingerprint": ["tech_stack_fingerprint"], "entry_points": ["entry_point_detection"],
    "transaction_flows": ["transaction_flow_tracing"], "reliability_patterns": ["reliability_patterns"],
    "dependency_classification": ["dependency_classification"], "business_context": ["business_context"],
    "application_capacity": ["application_capacity"], "secrets": ["secrets_handling"],
    "encryption_audit": ["encryption_and_audit"], "telemetry": ["application_telemetry"],
}


def steps_for_path(path: str) -> list[str]:
    """Stage 1 step names (``code.<step>`` or ``infra.<step>``) whose output a dataset path draws on."""
    parts = [p for p, _ in parse(path)]
    head = parts[0]
    if head == "repositories" and len(parts) > 1:
        return [f"code.{s}" for s in _REPO_PREFIXES.get(parts[1], [])]
    if head == "infrastructure" and len(parts) > 1:
        return [f"infra.{s}" for s in _INFRA_PREFIXES.get(parts[1], [])]
    if head == "capacity_posture":
        return ["code.application_capacity", "infra.kubernetes", "infra.compose_and_docker"]
    if head == "business_context":
        return ["code.business_context"]
    if head == "cross_references":
        return ["code.dependency_classification", "infra.kubernetes", "infra.service_mesh", "infra.cicd_pipelines"]
    return []


def step_statuses(data: dict) -> dict[str, dict[str, Any]]:
    """Stage 1 step results by qualified name, merged across repositories (worst status wins per step)."""
    order = {"failed": 3, "skipped": 2, "ok": 1, "no_findings": 0}
    out: dict[str, dict[str, Any]] = {}

    def put(name: str, st: dict) -> None:
        cur = out.get(name)
        if cur is None or order[st["status"]] > order[cur["status"]]:
            out[name] = {"status": st["status"], "count": st.get("count"), "detail": st.get("detail")}
        elif cur["status"] == st["status"] and cur.get("count") is not None and st.get("count") is not None:
            cur["count"] += st["count"]

    for repo in data.get("repositories", []):
        for st in repo.get("status", []):
            put(f"code.{st['step']}", st)
    for st in data.get("infrastructure", {}).get("status", []):
        put(f"infra.{st['step']}", st)
    return out


def truncated(projection: str) -> bool:
    """True if the projected evidence hides list items (absence cannot be concluded from what is shown)."""
    return " more of " in projection
