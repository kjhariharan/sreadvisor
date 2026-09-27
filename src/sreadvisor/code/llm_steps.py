"""Orchestrates the LLM reasoning steps of Code Analysis.

Cost scales with the number of entry points and the judgment calls needed, not with lines of
code: entry points and call chains come from the graph, candidates come from a catalogue.
Every fact an agent returns is grounded (file exists, line in range) before it is accepted.
"""

from __future__ import annotations

import asyncio
import re
from collections import defaultdict

from sreadvisor.agents import outputs as out
from sreadvisor.agents.definitions import (
    build_business_agent,
    build_classifier,
    build_flow_tracer,
    build_reliability_agent,
)
from sreadvisor.agents.runner import AgentError, AgentRunner
from sreadvisor.code.reliability_candidates import Candidate
from sreadvisor.graph.code_graph import CodeGraph
from sreadvisor.model_provider import ModelSettings
from sreadvisor.registry import LlmSettings
from sreadvisor.schema.dataset import (
    BusinessContext,
    DependencyClassification,
    EntryPoint,
    FlowDependency,
    FlowStep,
    ReliabilityPattern,
    TechStackFingerprint,
    TransactionFlow,
)
from sreadvisor.util.files import evidence

_BATCH = 12
_PAREN = re.compile(r"\s*\([^)]*\)")


def grounded(graph: CodeGraph, file: str | None, line: int | None) -> bool:
    if not file or line is None:
        return False
    lines = graph.reader.lines(file)
    return bool(lines) and 1 <= line <= len(lines)


_INLINE_CITATION = re.compile(r"^\s*([\w./\\-]+):(\d+)\b")


def grounded_text(graph: CodeGraph, text: str) -> bool:
    """True if a narrative string's own leading ``file:line`` citation (the format asked of, for example,
    ``protecting_patterns``: ``"file:line ..."``) is a real location in the repository. A string with no such
    citation is not penalised here — it was never asked to cite one — so this returns True for it; the caller
    decides separately what to do when a field that is expected to justify itself has no evidence at all."""
    m = _INLINE_CITATION.match(text)
    return grounded(graph, m.group(1), int(m.group(2))) if m else True


def runtime_hints(fp: TechStackFingerprint) -> str:
    wanted = ("datastore", "cache", "messaging", "http_client")
    seen: dict[str, set[str]] = defaultdict(set)
    for d in fp.dependencies:
        for c in d.categories:
            if c in wanted:
                seen[c].add(f"{d.group + ':' if d.group else ''}{d.name}")
    return "; ".join(f"{c}: {', '.join(sorted(v))}" for c, v in sorted(seen.items())) or "none detected"


# ------------------------------------------------------------------------ flows


async def trace_flows(
    graph: CodeGraph, runner: AgentRunner, model_settings: ModelSettings, llm: LlmSettings,
    entry_points: list[EntryPoint], fp: TechStackFingerprint,
) -> tuple[list[TransactionFlow], list[str]]:
    agent = build_flow_tracer(graph, llm, model_settings)
    hints = runtime_hints(fp)
    problems: list[str] = []

    async def one(ep: EntryPoint) -> TransactionFlow | None:
        prompt = (
            f"Entry point id: {ep.id}\n"
            f"Kind: {ep.kind}   Route: {ep.http_method or ''} {ep.route or ''}\n"
            f"Symbol: {ep.symbol}   Defined at: {ep.evidence.file}:{ep.evidence.line}\n"
            f"Runtime dependencies declared in build manifests (use to name dependencies consistently): {hints}\n"
            "Trace this entry point now."
        )
        try:
            res = await runner.run(agent, prompt, out.FlowTraceOut)
        except AgentError as exc:
            problems.append(f"{ep.symbol}: {exc}")
            return None
        steps, deps, dropped = [], [], 0
        for s in res.steps:
            if grounded(graph, s.file, s.line):
                steps.append(FlowStep(order=s.order, layer=s.layer, symbol=s.symbol, action=s.action,
                                      target_type=s.target_type, target_name=s.target_name,
                                      evidence=evidence(s.file, s.line)))
            else:
                dropped += 1
        for d in res.dependencies:
            ev = evidence(d.file, d.line) if grounded(graph, d.file, d.line) else None
            if ev is None:  # ground it through a step that touches the same dependency
                step = next((s for s in steps if (s.target_name or "").lower() == d.name.lower()), None) or next(
                    (s for s in steps if s.target_type and s.target_type == d.kind), None)
                ev = step.evidence if step else None
            if ev is not None:
                deps.append(FlowDependency(name=d.name, kind=d.kind, evidence=ev))
            else:
                dropped += 1
        if dropped:
            problems.append(f"{ep.symbol}: dropped {dropped} ungrounded item(s) with no citable file/line")
        # Safety net: data-access / outbound steps present in the call graph must not be lost by the model.
        have = {(s.evidence.file, s.evidence.line) for s in steps}
        backfilled = 0
        for cs in graph.call_chain(ep.id, max_nodes=llm.max_chain_nodes):
            layer = graph.layer_hint(cs["id"])
            method = cs["symbol"].split(".")[-1].split("(")[0].lower()
            covered = (cs["file"], cs["line"]) in have or any(
                method and method in s.symbol.lower() and s.layer in ("repository", "client", "datastore") for s in steps)
            if layer in ("repository", "client") and not covered:
                steps.append(FlowStep(order=len(steps) + 1, layer=layer, symbol=cs["symbol"],
                                      action=f"{layer} step present in the call graph (added deterministically; model omitted it)",
                                      target_type="datastore" if layer == "repository" else "http_service",
                                      evidence=evidence(cs["file"], cs["line"])))
                backfilled += 1
        if backfilled:
            problems.append(f"{ep.symbol}: {backfilled} call-graph data-access/client step(s) missing from the model output were added")
        steps.sort(key=lambda s: s.order)
        return TransactionFlow(entry_point=ep, summary=res.summary, steps=steps, dependencies=deps)

    results = await asyncio.gather(*(one(ep) for ep in entry_points))
    return [r for r in results if r is not None], problems


# ------------------------------------------------------------------ reliability


async def detect_reliability(
    graph: CodeGraph, runner: AgentRunner, model_settings: ModelSettings, llm: LlmSettings,
    candidates: list[Candidate],
) -> tuple[list[ReliabilityPattern], list[str]]:
    if not candidates:
        return [], []
    agent = build_reliability_agent(graph, llm, model_settings)
    by_file: dict[str, list[Candidate]] = defaultdict(list)
    for c in candidates:
        by_file[c.file].append(c)
    batches: list[list[Candidate]] = []
    for group in by_file.values():
        batches += [group[i : i + _BATCH] for i in range(0, len(group), _BATCH)]
    problems: list[str] = []

    async def one(batch: list[Candidate]) -> list[ReliabilityPattern]:
        blocks = "\n\n".join(
            f"Candidate {n} [hint: {c.hint}] {c.file}:{c.line}\n{c.context}" for n, c in enumerate(batch, 1)
        )
        prompt = f"Candidates from {batch[0].file}:\n\n{blocks}\n\nJudge each candidate now."
        try:
            res = await runner.run(agent, prompt, out.ReliabilityOut)
        except AgentError as exc:
            problems.append(f"{batch[0].file}: {exc}")
            return []
        found = []
        for p in res.patterns:
            if not grounded(graph, p.file, p.line):
                problems.append(f"dropped ungrounded reliability pattern at {p.file}:{p.line}")
                continue
            found.append(ReliabilityPattern(
                pattern=p.pattern, mechanism=p.mechanism, protects=p.protects,
                parameters={k: str(v) for k, v in p.parameters.items()}, note=p.note,
                evidence=evidence(p.file, p.line, graph.reader.lines(p.file)[p.line - 1]),
            ))
        return found

    results = await asyncio.gather(*(one(b) for b in batches))
    seen: set[tuple[str, int, str]] = set()
    merged: list[ReliabilityPattern] = []
    for r in results:
        for p in r:
            key = (p.evidence.file, p.evidence.line or 0, p.pattern)
            if key not in seen:
                seen.add(key)
                merged.append(p)
    merged.sort(key=lambda p: (p.evidence.file, p.evidence.line or 0))
    return merged, problems


# ---------------------------------------------------------------- classification


def _dep_key(kind: str, name: str) -> tuple[str, str]:
    return kind.lower(), " ".join(_PAREN.sub("", name).lower().split())


async def classify_dependencies(
    graph: CodeGraph, runner: AgentRunner, model_settings: ModelSettings, llm: LlmSettings,
    flows: list[TransactionFlow], patterns: list[ReliabilityPattern],
) -> tuple[list[DependencyClassification], list[str]]:
    groups: dict[tuple[str, str], dict] = {}
    for fl in flows:
        for d in fl.dependencies:
            g = groups.setdefault(_dep_key(d.kind, d.name), {"name": d.name, "kind": d.kind, "flows": {}, "evidence": []})
            g["flows"].setdefault(fl.entry_point.symbol, (fl.entry_point, []))[1].append(d.evidence)
            g["evidence"].append(d.evidence)
    if not groups:
        return [], []

    agent = build_classifier(graph, llm, model_settings)
    pattern_lines = "\n".join(
        f"- {p.evidence.file}:{p.evidence.line} {p.pattern} via {p.mechanism}"
        + (f" protecting {p.protects}" if p.protects else "")
        for p in patterns[:30]
    ) or "(none found)"
    problems: list[str] = []

    async def one(key: tuple[str, str], g: dict) -> DependencyClassification | None:
        flow_lines = "\n".join(
            f"- {sym} ({ep.http_method or ''} {ep.route or ep.kind}) uses it at "
            + ", ".join(f"{e.file}:{e.line}" for e in evs[:3])
            for sym, (ep, evs) in g["flows"].items()
        )
        prompt = (
            f"Dependency: {g['name']} (kind: {g['kind']})\n\nFlows that use it:\n{flow_lines}\n\n"
            f"Reliability patterns found in the code:\n{pattern_lines}\n\nClassify this dependency now."
        )
        try:
            res = await runner.run(agent, prompt, out.ClassificationOut)
        except AgentError as exc:
            problems.append(f"{g['name']}: {exc}")
            return None
        cls = res.classification.strip().lower().replace(" ", "_").replace("-", "_")
        if cls not in ("hard_failure", "gracefully_degradable"):
            problems.append(f"{g['name']}: model returned unknown classification {res.classification!r}")
            return None
        known = set(g["flows"])
        degradable = sorted({d.entry_point for d in res.degradable_flows if d.entry_point in known})
        protecting = [p for p in res.protecting_patterns if grounded_text(graph, p)]
        if len(protecting) < len(res.protecting_patterns):
            problems.append(f"{g['name']}: dropped {len(res.protecting_patterns) - len(protecting)} "
                            "protecting_patterns citation(s) whose file:line does not exist in the repository")
        model_evidence = [evidence(e.file, e.line) for e in res.evidence if grounded(graph, e.file, e.line)]
        if res.evidence and not model_evidence:
            # Every citation the model gave for this claim was ungrounded: the classification, rationale and
            # blast_radius_description are kept (the judgment may still be right), but flagged rather than trusted
            # unconditionally, since nothing here actually points at real code.
            problems.append(f"{g['name']}: none of the model's evidence citations were grounded; "
                            "classification/rationale/blast_radius_description are not backed by a verified citation")
        return DependencyClassification(
            dependency=g["name"], kind=g["kind"], classification=cls, rationale=res.rationale,
            protecting_patterns=protecting, degradable_flows=degradable,
            # Blast radius is derived from the flow map: flows using it that cannot degrade.
            blast_radius=sorted(known - set(degradable)) if cls == "hard_failure" or degradable else [],
            blast_radius_description=res.blast_radius_description,
            evidence=model_evidence or g["evidence"][:3],
        )

    results = await asyncio.gather(*(one(k, g) for k, g in groups.items()))
    return [r for r in results if r is not None], problems


# -------------------------------------------------------------------- business


async def infer_business(
    graph: CodeGraph, runner: AgentRunner, model_settings: ModelSettings, llm: LlmSettings,
    repo_name: str, fp: TechStackFingerprint, entry_points: list[EntryPoint], flows: list[TransactionFlow],
) -> tuple[BusinessContext | None, list[str]]:
    agent = build_business_agent(graph, llm, model_settings)
    routes = "\n".join(f"- {e.http_method or e.kind} {e.route or ''} -> {e.symbol}" for e in entry_points[:40]) or "(none)"
    summaries = "\n".join(f"- {f.entry_point.symbol}: {f.summary}" for f in flows[:25]) or "(none)"
    deps = sorted({d.name for f in flows for d in f.dependencies})
    prompt = (
        f"Repository: {repo_name}\nFrameworks: {', '.join(f.name for f in fp.frameworks) or 'unknown'}\n\n"
        f"Entry points:\n{routes}\n\nFlow summaries:\n{summaries}\n\nExternal dependencies: {', '.join(deps) or 'none'}\n\n"
        "Infer the business purpose now."
    )
    try:
        res = await runner.run(agent, prompt, out.BusinessContextOut)
    except AgentError as exc:
        return None, [str(exc)]
    conf = res.confidence.lower() if res.confidence.lower() in ("high", "medium", "low") else "medium"
    grounded_evidence = [evidence(e.file, e.line) for e in res.evidence if grounded(graph, e.file, e.line)]
    problems: list[str] = []
    if res.evidence and not grounded_evidence:
        # The claim is kept (a business purpose can be correctly inferred even when the model cites it badly), but
        # never at whatever confidence the model itself asserted: every citation it gave was ungrounded, so nothing
        # here is actually verified against the repository.
        conf = "low"
        problems.append("every evidence citation was ungrounded; confidence forced to low")
    return BusinessContext(
        capability=res.capability, category=res.category, rationale=res.rationale,
        domain_entities=res.domain_entities, key_operations=res.key_operations, confidence=conf,
        evidence=grounded_evidence,
    ), problems
