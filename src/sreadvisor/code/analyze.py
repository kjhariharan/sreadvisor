"""Module one: Code Analysis for a single repository."""

from __future__ import annotations

from pathlib import Path

from sreadvisor.agents.runner import AgentRunner, check_backend
from sreadvisor.code import llm_steps
from sreadvisor.code.capacity import scan_capacity
from sreadvisor.code.configfiles import read_config_entries
from sreadvisor.code.encryption import scan_encryption_audit
from sreadvisor.code.fingerprint import fingerprint_repo
from sreadvisor.code.reliability_candidates import find_candidates
from sreadvisor.code.secrets import scan_secrets
from sreadvisor.code.telemetry import scan_telemetry
from sreadvisor.graph.code_graph import CodeGraph
from sreadvisor.model_provider import ModelSettings
from sreadvisor.registry import AnalysisSettings
from sreadvisor.schema.dataset import RepoAnalysis, StepStatus

Log = callable


def _status(step: str, items: list | None, *, detail: str | None = None) -> StepStatus:
    n = len(items) if items is not None else None
    return StepStatus(step=step, status="ok" if n else "no_findings", count=n, detail=detail)


async def analyze_repo(
    label: str, root: Path, state_dir: Path, settings: AnalysisSettings, model_settings: ModelSettings,
    *, use_llm: bool = True, refresh_graph: bool = False, log=print,
) -> RepoAnalysis:
    status: list[StepStatus] = []

    # 1. deterministic fingerprint (tech stack, dependencies)
    log(f"[{label}] fingerprinting tech stack")
    fp = fingerprint_repo(root)
    status.append(_status("tech_stack_fingerprint", fp.dependencies,
                          detail="; ".join(fp.parse_errors) or None))

    # 2. Graphify structural extraction (no LLM), cached per file
    log(f"[{label}] building structural code graph (Graphify, no LLM)")
    graph = CodeGraph(root, state_dir, exclude_tests=settings.graph.exclude_tests, parallel=settings.graph.parallel)
    stats = graph.build(refresh=refresh_graph)
    if "error" in stats:
        status.append(StepStatus(step="structural_graph", status="failed", detail=stats["error"]))
    else:
        status.append(StepStatus(step="structural_graph", status="ok", count=stats["nodes"],
                                 detail=f"{stats['nodes']} nodes, {stats['edges']} edges, {stats['cache_entries_added']} files newly parsed"))
    entry_points = graph.entry_points()
    status.append(_status("entry_point_detection", entry_points))
    log(f"[{label}] {len(entry_points)} entry points")

    # 3. deterministic scans
    entries = read_config_entries(root)
    capacity = scan_capacity(root, entries, fp)
    secrets = scan_secrets(root, entries, fp)
    enc = scan_encryption_audit(root, entries, fp)
    telemetry = scan_telemetry(root, entries, fp)
    status += [
        _status("application_capacity", capacity),
        _status("secrets_handling", secrets.hardcoded + secrets.sourced_from),
        _status("encryption_and_audit", enc.facts),
        _status("application_telemetry", telemetry.libraries),
    ]

    flows, patterns, classes, business = [], [], [], None
    if not use_llm:
        for s in ("transaction_flow_tracing", "reliability_patterns", "dependency_classification", "business_context"):
            status.append(StepStatus(step=s, status="skipped", detail="--no-llm"))
    else:
        problem = check_backend(model_settings)
        if problem:
            for s in ("transaction_flow_tracing", "reliability_patterns", "dependency_classification", "business_context"):
                status.append(StepStatus(step=s, status="failed", detail=problem))
            log(f"[{label}] LLM steps unavailable: {problem}")
        else:
            runner = AgentRunner(model_settings, settings.llm, state_dir / "llm_cache")
            llm = settings.llm

            log(f"[{label}] tracing {len(entry_points)} transaction flows (ADK flow_tracer agent)")
            flows, problems = await llm_steps.trace_flows(graph, runner, model_settings, llm, entry_points, fp)
            status.append(_status("transaction_flow_tracing", flows, detail="; ".join(problems) or None))

            candidates = find_candidates(graph)
            log(f"[{label}] adjudicating {len(candidates)} reliability-pattern candidates (ADK reliability agent)")
            patterns, problems = await llm_steps.detect_reliability(graph, runner, model_settings, llm, candidates)
            status.append(_status("reliability_patterns", patterns,
                                  detail="; ".join(problems) or f"{len(candidates)} candidates reviewed"))

            log(f"[{label}] classifying dependencies (ADK dependency_classifier agent)")
            classes, problems = await llm_steps.classify_dependencies(graph, runner, model_settings, llm, flows, patterns)
            status.append(_status("dependency_classification", classes, detail="; ".join(problems) or None))

            log(f"[{label}] inferring business context (ADK business_context agent)")
            business, problems = await llm_steps.infer_business(graph, runner, model_settings, llm, label, fp, entry_points, flows)
            status.append(StepStatus(step="business_context", status="ok" if business else "failed",
                                     detail="; ".join(problems) or None, count=1 if business else 0))
            log(f"[{label}] LLM calls: {runner.calls} made, {runner.cache_hits} served from cache")

    return RepoAnalysis(
        repo=label, path=str(root), fingerprint=fp, entry_points=entry_points, transaction_flows=flows,
        reliability_patterns=patterns, dependency_classification=classes, business_context=business,
        application_capacity=capacity, secrets=secrets, encryption_audit=enc, telemetry=telemetry,
        graph_stats=stats, status=status,
    )
