"""Graphify-backed structural code graph with a query surface for the LLM agents.

Graphify's extraction pass is deterministic (tree-sitter, no LLM calls). It runs first, across
the whole repository, and is cached per file, so only changed files are re-parsed on later
runs. Agents never walk files by hand: they ask this graph for entry points and call chains.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import time
from collections import deque
from pathlib import Path
from typing import Any

from sreadvisor.graph import entrypoints as ep
from sreadvisor.graph.source import SourceReader
from sreadvisor.schema.dataset import EntryPoint
from sreadvisor.util.files import evidence, is_test_path, iter_files, rel
from sreadvisor.util.redact import redact_line

DOC_SUFFIXES = {".md", ".markdown", ".rst", ".txt"}
SOURCE_SUFFIXES = (".java", ".kt", ".groovy", ".scala", ".py", ".cs", ".js", ".jsx", ".ts", ".tsx", ".go", ".rb", ".php")


def repo_slug(root: Path) -> str:
    digest = hashlib.sha1(str(root.resolve()).encode()).hexdigest()[:8]
    return f"{re.sub(r'[^A-Za-z0-9_.-]+', '-', root.name)}-{digest}"


class CodeGraph:
    def __init__(self, root: Path, state_dir: Path, *, exclude_tests: bool = True, parallel: bool = False) -> None:
        self.root = root.resolve()
        self.cache_root = state_dir / "graphify" / repo_slug(root)
        self.exclude_tests = exclude_tests
        self.parallel = parallel
        self.reader = SourceReader(self.root)
        self.nodes: dict[str, dict[str, Any]] = {}
        self.out_edges: dict[str, list[dict[str, Any]]] = {}
        self.class_of: dict[str, str] = {}
        self.stats: dict[str, Any] = {}

    # ------------------------------------------------------------------ build
    def build(self, refresh: bool = False) -> dict[str, Any]:
        from graphify.extract import collect_files, extract

        if refresh:
            shutil.rmtree(self.cache_root, ignore_errors=True)
        self.cache_root.mkdir(parents=True, exist_ok=True)

        all_files = collect_files(self.root)
        files = [
            f for f in all_files
            if f.suffix.lower() not in DOC_SUFFIXES and not (self.exclude_tests and is_test_path(rel(f, self.root)))
        ]
        cache_dir = self.cache_root / "graphify-out" / "cache"
        before = sum(1 for _ in cache_dir.rglob("*.json")) if cache_dir.exists() else 0
        t0 = time.time()
        try:
            extraction = extract(files, cache_root=self.cache_root, root=self.root, parallel=self.parallel)
        except Exception as exc:
            # A single malformed file must degrade this repo's structural analysis, not crash the whole run: every
            # other scan step in this codebase already reports a failure this way (see code/analyze.py's `_status`).
            self.stats = {
                "engine": "graphify (tree-sitter structural extraction, no LLM)", "files_extracted": 0,
                "test_files_excluded": 0, "nodes": 0, "edges": 0, "cache_entries_added": 0, "cache_entries_total": 0,
                "seconds": round(time.time() - t0, 2), "cache_dir": str(self.cache_root), "error": str(exc)[:500],
            }
            return self.stats
        elapsed = time.time() - t0
        after = sum(1 for _ in cache_dir.rglob("*.json")) if cache_dir.exists() else 0
        (self.cache_root / "extraction.json").write_text(json.dumps(extraction), encoding="utf-8")

        self._index(extraction)
        self.stats = {
            "engine": "graphify (tree-sitter structural extraction, no LLM)",
            "files_extracted": len(files),
            "test_files_excluded": len(all_files) - len(files) if self.exclude_tests else 0,
            "nodes": len(self.nodes),
            "edges": sum(len(v) for v in self.out_edges.values()),
            "cache_entries_added": max(0, after - before),
            "cache_entries_total": after,
            "seconds": round(elapsed, 2),
            "cache_dir": str(self.cache_root),
        }
        return self.stats

    def _index(self, extraction: dict[str, Any]) -> None:
        self.nodes = {n["id"]: n for n in extraction["nodes"] if n.get("file_type") == "code"}
        self.out_edges, self.class_of = {}, {}
        for e in extraction["edges"]:
            if e["source"] in self.nodes:
                self.out_edges.setdefault(e["source"], []).append(e)
            if e.get("relation") == "method" and e["target"] in self.nodes:
                self.class_of[e["target"]] = e["source"]

    # ---------------------------------------------------------------- node helpers
    def line(self, node_id: str) -> int:
        loc = self.nodes[node_id].get("source_location") or "L1"
        m = re.match(r"L(\d+)", str(loc))
        return int(m.group(1)) if m else 1

    def file(self, node_id: str) -> str:
        return self.nodes[node_id].get("source_file", "")

    def kind(self, node_id: str) -> str:
        n = self.nodes[node_id]
        label = n.get("label", "")
        if node_id in self.class_of:
            return "method"
        if label.endswith(")"):
            return "function"
        if label == Path(n.get("source_file", "")).name:
            return "file"
        return "class"

    def symbol(self, node_id: str) -> str:
        n = self.nodes[node_id]
        label = n.get("label", "").lstrip(".")
        cls = self.class_of.get(node_id)
        return f"{self.nodes[cls]['label']}.{label}" if cls in self.nodes else label

    def ev(self, node_id: str):
        return evidence(self.file(node_id), self.line(node_id))

    def callables(self) -> list[str]:
        return [i for i in self.nodes if self.kind(i) in ("method", "function") and not self._excluded(i)]

    def _excluded(self, node_id: str) -> bool:
        return self.exclude_tests and is_test_path(self.file(node_id))

    # ---------------------------------------------------------------- entry points
    def entry_points(self) -> list[EntryPoint]:
        found: dict[str, EntryPoint] = {}
        for nid in self.callables():
            f, line = self.file(nid), self.line(nid)
            suffix = Path(f).suffix.lower()
            annotations, _sig = self.reader.declaration(f, line)
            hit = self._match_rules(nid, f, line, suffix, annotations)
            if hit:
                found[nid] = hit
        self._add_base_class_entry_points(found)
        self._add_js_routes(found)
        return sorted(found.values(), key=lambda e: (e.evidence.file, e.evidence.line or 0))

    def _match_rules(self, nid: str, f: str, line: int, suffix: str, annotations: list[tuple[int, str]]) -> EntryPoint | None:
        for aline, atext in annotations:
            for rule in ep.RULES:
                if suffix not in rule.suffixes or not rule.regex.match(atext):
                    continue
                full = self.reader.annotation_text(f, aline)
                verb = None
                if rule.http_group:
                    verb = rule.regex.match(atext).group(rule.http_group).upper()
                elif rule.kind == "rest":
                    verb = ep.request_method(full)
                route = ep.first_string(full[full.find("("):]) if "(" in full else None
                for l2, t2 in annotations:  # JAX-RS @Path / ASP.NET [Route] on the method itself
                    if ep.METHOD_ROUTE_EXTRA.match(t2) and route is None:
                        route = ep.first_string(self.reader.annotation_text(f, l2))
                prefix = self._class_route(nid)
                full_route = ep.join_route(prefix, route) if rule.kind in ("rest", "graphql") else route
                return EntryPoint(
                    id=nid, kind=rule.kind, symbol=self.symbol(nid), route=full_route or None,
                    http_method=verb, annotation=atext.split("(")[0], evidence=evidence(f, aline, full),
                )
        return None

    def _class_route(self, method_id: str) -> str | None:
        cls = self.class_of.get(method_id)
        if not cls or cls not in self.nodes:
            return None
        for aline, atext in self.reader.declaration(self.file(cls), self.line(cls))[0]:
            if any(r.match(atext) for r in ep.CLASS_ROUTE_RULES):
                return ep.first_string(self.reader.annotation_text(self.file(cls), aline))
        return None

    def _add_base_class_entry_points(self, found: dict[str, EntryPoint]) -> None:
        for cid, edges in self.out_edges.items():
            if self.kind(cid) != "class":
                continue
            bases = [self.nodes[e["target"]]["label"] if e["target"] in self.nodes else e["target"]
                     for e in edges if e.get("relation") in ("inherits", "implements")]
            base_names = [b.split(".")[-1] for b in bases]
            grpc = any(ep.GRPC_BASES.search(b) for b in base_names)
            hosted = any(ep.HOSTED_BASES.match(b) for b in base_names)
            if not (grpc or hosted):
                continue
            for e in edges:
                m = e["target"]
                if e.get("relation") != "method" or m in found or m not in self.nodes:
                    continue
                name = self.nodes[m]["label"].lstrip(".")
                if grpc and not name.startswith("<"):
                    found[m] = EntryPoint(id=m, kind="grpc", symbol=self.symbol(m), annotation="gRPC service base class",
                                          evidence=self.ev(m))
                elif hosted and name.startswith("ExecuteAsync"):
                    found[m] = EntryPoint(id=m, kind="scheduled", symbol=self.symbol(m), annotation="hosted background service",
                                          evidence=self.ev(m))

    def _add_js_routes(self, found: dict[str, EntryPoint]) -> None:
        for f in iter_files(self.root, suffixes=(".js", ".ts", ".mjs", ".cjs"), include_tests=not self.exclude_tests):
            rp = rel(f, self.root)
            for i, text in enumerate(self.reader.lines(rp), 1):
                m = ep.JS_ROUTE.search(text)
                if not m:
                    continue
                nid = f"route:{rp}:{i}"
                found[nid] = EntryPoint(id=nid, kind="rest", symbol=f"{rp}:{i}", route=m.group(2),
                                        http_method=m.group(1).upper(), annotation="route registration",
                                        evidence=evidence(rp, i, text))

    # ------------------------------------------------------------------ call chains
    def call_chain(self, node_id: str, max_nodes: int = 30) -> list[dict[str, Any]]:
        """Breadth-first walk of ``calls`` edges from ``node_id`` (including interface dispatch)."""
        if node_id not in self.nodes:
            return []
        order: list[dict[str, Any]] = []
        seen = {node_id}
        queue: deque[tuple[str, int, str | None, int | None, str | None]] = deque([(node_id, 0, None, None, None)])
        while queue and len(order) < max_nodes:
            nid, depth, parent, call_line, confidence = queue.popleft()
            order.append({
                "id": nid, "symbol": self.symbol(nid), "file": self.file(nid), "line": self.line(nid),
                "depth": depth, "called_from": self.symbol(parent) if parent else None,
                "call_site_line": call_line, "confidence": confidence,
            })
            for e in self.out_edges.get(nid, []):
                if e.get("relation") != "calls" or e["target"] not in self.nodes:
                    continue
                for target in [e["target"], *self._dispatch_targets(e["target"])]:
                    if target in seen or self._excluded(target):
                        continue
                    seen.add(target)
                    m = re.match(r"L(\d+)", str(e.get("source_location", "")))
                    queue.append((target, depth + 1, nid, int(m.group(1)) if m else None, e.get("confidence")))
        return order

    def _dispatch_targets(self, method_id: str) -> list[str]:
        """Implementations of an interface/abstract method, matched by name."""
        cls = self.class_of.get(method_id)
        if not cls:
            return []
        name = self.nodes[method_id]["label"]
        out: list[str] = []
        for other, edges in self.out_edges.items():
            if any(e.get("relation") in ("implements", "inherits") and e["target"] == cls for e in edges):
                for e in self.out_edges.get(other, []):
                    if e.get("relation") == "method" and self.nodes.get(e["target"], {}).get("label") == name:
                        out.append(e["target"])
        return out

    _LAYER_ANN = (
        (re.compile(r"^@(RestController|Controller|RestControllerAdvice|Path|ApiController)|^\[ApiController"), "controller"),
        (re.compile(r"^@(Service|Transactional)"), "service"),
        (re.compile(r"^@(Repository)"), "repository"),
        (re.compile(r"^@(FeignClient|RegisterRestClient)"), "client"),
    )
    _LAYER_NAME = (
        (re.compile(r"(Controller|Resource|Endpoint|Handler|Router|View)$"), "controller"),
        (re.compile(r"(Repository|Repo|Dao|DAO|Store|Mapper)$"), "repository"),
        (re.compile(r"(Client|Gateway|Adapter|Proxy|Publisher|Producer|Sender)$"), "client"),
        (re.compile(r"(Service|Manager|UseCase|Facade|Processor)$"), "service"),
    )
    _DATA_BASES = re.compile(r"(Repository|CrudRepository|JpaRepository|PagingAndSortingRepository|MongoRepository|DbContext|Model|Base)$")

    def layer_hint(self, node_id: str) -> str:
        """Deterministic layer guess from class annotations, base types and naming (a hint, not a verdict)."""
        cls = self.class_of.get(node_id)
        if not cls or cls not in self.nodes:
            return "other"
        anns = [a for _, a in self.reader.declaration(self.file(cls), self.line(cls))[0]]
        for rx, layer in self._LAYER_ANN:
            if any(rx.match(a) for a in anns):
                return layer
        bases = [self.nodes[e["target"]]["label"] if e["target"] in self.nodes else e["target"]
                 for e in self.out_edges.get(cls, []) if e.get("relation") in ("inherits", "implements")]
        if any(b.endswith("Repository") for b in bases):
            return "repository"
        name = self.nodes[cls]["label"]
        for rx, layer in self._LAYER_NAME:
            if rx.search(name):
                return layer
        return "other"

    _CALL_RE = re.compile(r"(?!this)([a-z_]\w*)\s*\.\s*(\w+)\s*\(")
    _COMMON_TYPES = {"String", "List", "Map", "Set", "Optional", "Collection", "Integer", "Long", "Object", "Objects", "Arrays",
                     "Collections", "Math", "System", "Stream", "StringBuilder", "LocalDate", "Model", "BindingResult"}

    def external_calls(self, node_id: str, max_lines: int = 40) -> list[str]:
        """Calls on receivers whose declared type is not a class in the graph (framework / library code).

        These never appear as call-graph steps, so surfacing them (with the receiver's type) lets a reader
        recognise repository, template, client and cache invocations.
        """
        f, line = self.file(node_id), self.line(node_id)
        _, sig = self.reader.declaration(f, line)
        _, end = self.reader.extent(f, sig, max_lines=max_lines)
        lines = self.reader.lines(f)
        graph_classes = {n["label"] for i, n in self.nodes.items() if self.kind(i) == "class"}
        out: list[str] = []
        for i in range(sig, min(end, len(lines)) + 1):
            for m in self._CALL_RE.finditer(lines[i - 1]):
                recv, meth = m.group(1), m.group(2)
                tm = next((re.search(rf"([A-Z]\w*(?:<[^;=()]*>)?)\s+(?:this\.)?{re.escape(recv)}", l) for l in lines
                           if re.search(rf"([A-Z]\w*(?:<[^;=()]*>)?)\s+(?:this\.)?{re.escape(recv)}", l)), None)
                rtype = tm.group(1).split("<")[0] if tm else None
                if rtype and rtype not in self._COMMON_TYPES:
                    tag = "in-repo class" if rtype in graph_classes else "framework/library type"
                    out.append(f"line {i}: {recv}.{meth}(...)  [{recv} is {rtype}: {tag}]")
        return list(dict.fromkeys(out))[:12]

    def method_source(self, node_id: str, max_lines: int = 40) -> str:
        f, line = self.file(node_id), self.line(node_id)
        annotations, sig = self.reader.declaration(f, line)
        start = annotations[0][0] if annotations else line
        _, end = self.reader.extent(f, sig, max_lines=max_lines)
        return self.reader.read(f, start, end, max_lines=max_lines + len(annotations))

    # ------------------------------------------------------------------ code search
    def search_code(self, pattern: str, max_results: int = 25) -> list[dict[str, Any]]:
        try:
            rx = re.compile(pattern)
        except re.error as exc:
            return [{"error": f"invalid regex: {exc}"}]
        hits: list[dict[str, Any]] = []
        for f in iter_files(self.root, suffixes=SOURCE_SUFFIXES + (".properties", ".yml", ".yaml", ".xml", ".json"),
                            include_tests=not self.exclude_tests):
            rp = rel(f, self.root)
            for i, text in enumerate(self.reader.lines(rp), 1):
                if rx.search(text):
                    hits.append({"file": rp, "line": i, "text": redact_line(text.strip()[:200])})
                    if len(hits) >= max_results:
                        return hits
        return hits

    def domain_entities(self, limit: int = 40) -> list[dict[str, Any]]:
        """Classes that look like persistent domain models (entity annotations, ORM bases, model packages)."""
        entity_ann = re.compile(r"^@(Entity|Document|Table|MappedSuperclass|Embeddable|Data|Aggregate\w*)\b")
        out: list[dict[str, Any]] = []
        for nid in self.nodes:
            if self.kind(nid) != "class" or self._excluded(nid):
                continue
            f = self.file(nid)
            anns = [a for _, a in self.reader.declaration(f, self.line(nid))[0]]
            in_model_pkg = bool(re.search(r"/(model|models|domain|entity|entities)/", "/" + f))
            bases = [self.nodes[e["target"]]["label"] for e in self.out_edges.get(nid, [])
                     if e.get("relation") in ("inherits", "implements") and e["target"] in self.nodes]
            if any(entity_ann.match(a) for a in anns) or in_model_pkg or any(b in ("Base", "BaseModel", "DbContext") for b in bases):
                out.append({"class": self.nodes[nid]["label"], "file": f, "line": self.line(nid),
                            "annotations": [a.split("(")[0] for a in anns][:4]})
        return out[:limit]
