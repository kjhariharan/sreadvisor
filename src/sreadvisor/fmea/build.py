"""Builds the FMEA (Stage 6): one LLM call per major component (dependency), reasoning only from the architecture
and dependency facts already captured — Stage 1's ``DependencyClassification`` (blast radius, protecting patterns)
and, when given, Stage 5's runtime-only dependencies. Everything deterministic is decided here: which components are
"major" (deduplicated, one entry each), what context each gets, and how a failure mode is cross-referenced to an
existing Stage 6 gap; only "what could go wrong, how bad, why" is the model's judgment, and it never sees incident
history because there is none in this dataset.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sreadvisor.agents import outputs as out
from sreadvisor.agents.definitions import build_fmea_agent
from sreadvisor.agents.runner import AgentError, AgentRunner, check_backend
from sreadvisor.fmea.schema import FailureMode, FmeaReport
from sreadvisor.gap.schema import GapReport
from sreadvisor.model_provider import describe
from sreadvisor.registry import Registry
from sreadvisor.runtime.cross_validate import _tokens
from sreadvisor.runtime.schema import RuntimeCrossValidation
from sreadvisor.schema.common import Evidence
from sreadvisor.schema.dataset import ServiceDataset

_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


class FmeaError(RuntimeError):
    pass


@dataclass
class _Component:
    name: str
    kind: str
    origin: str  # "code_and_infra" | "runtime_only"
    classification: str  # "hard_failure" | "gracefully_degradable" | "unknown"
    blast_radius: list[str] = field(default_factory=list)
    blast_radius_description: str | None = None
    protecting_patterns: list[str] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)


def _code_components(dataset: ServiceDataset) -> list[_Component]:
    """``DependencyClassification`` when Stage 1 produced it (has blast radius and protecting patterns already
    worked out); falls back to the raw traced ``FlowDependency`` names, unclassified, when that step never ran
    (skipped, failed, or ``--no-llm``) — so a component list is still produced either way."""
    out_: list[_Component] = []
    seen: set[str] = set()
    for repo in dataset.repositories:
        for dc in repo.dependency_classification:
            key = dc.dependency.strip().lower()
            if key in seen:
                continue
            seen.add(key)
            out_.append(_Component(name=dc.dependency, kind=dc.kind, origin="code_and_infra", classification=dc.classification,
                                   blast_radius=list(dc.blast_radius), blast_radius_description=dc.blast_radius_description,
                                   protecting_patterns=list(dc.protecting_patterns), evidence=list(dc.evidence)))
    if out_:
        return out_
    for repo in dataset.repositories:
        for flow in repo.transaction_flows:
            for dep in flow.dependencies:
                key = f"{dep.kind}:{dep.name.strip().lower()}"
                if key in seen:
                    continue
                seen.add(key)
                out_.append(_Component(name=dep.name, kind=dep.kind, origin="code_and_infra", classification="unknown",
                                       evidence=[dep.evidence]))
    return out_


def _runtime_components(runtime: RuntimeCrossValidation | None) -> list[_Component]:
    if runtime is None:
        return []
    return [_Component(name=rod.node.name, kind=rod.node.kind, origin="runtime_only", classification="unknown")
           for rod in runtime.runtime_only]


def _flows_using(dataset: ServiceDataset, name: str) -> list[str]:
    toks = _tokens(name)
    out_: list[str] = []
    for repo in dataset.repositories:
        for flow in repo.transaction_flows:
            if toks and any(_tokens(d.name) & toks for d in flow.dependencies) and flow.entry_point.symbol not in out_:
                out_.append(flow.entry_point.symbol)
    return out_


def _related_gap_ids(gap_report: GapReport | None, name: str) -> list[str]:
    if gap_report is None:
        return []
    toks = _tokens(name)
    if not toks:
        return []
    return [g.id for g in gap_report.gaps if _tokens(g.why) & toks]


def _prompt(dataset: ServiceDataset, c: _Component) -> str:
    b = dataset.business_context
    flows = _flows_using(dataset, c.name) if c.origin == "code_and_infra" else []
    origin_note = ("found in Stage 1 code/infrastructure analysis" if c.origin == "code_and_infra" else
                  "found ONLY via live runtime observability (Stage 5); no repository's code declared this "
                  "dependency, so Stage 1 never classified or examined it")
    return (
        f"Service: {dataset.service_name}\n"
        f"Business purpose: {b.capability + ' (' + b.category + ')' if b else 'not inferred'}\n\n"
        f"Component: {c.name} (kind: {c.kind})\n"
        f"Origin: {origin_note}\n"
        f"Stage 1 classification: {c.classification}" + (f" — {c.blast_radius_description}" if c.blast_radius_description else "") + "\n"
        f"Flows that use it: {', '.join(flows or c.blast_radius) or 'not determined from the dataset'}\n"
        f"Existing protecting patterns: {', '.join(c.protecting_patterns) or 'none recorded'}\n\n"
        "Perform the FMEA for this one component now."
    )


async def build_fmea(dataset: ServiceDataset, gap_report: GapReport | None, runtime: RuntimeCrossValidation | None,
                     registry: Registry, state_dir: Path, runner: Any | None = None) -> FmeaReport:
    components = _code_components(dataset) + _runtime_components(runtime)
    b = dataset.business_context
    inputs: dict[str, Any] = {
        "dataset": {"service_name": dataset.service_name, "schema_version": dataset.schema_version,
                    "generated_at": dataset.generated_at.isoformat()},
        "gap_report": {"pass_name": gap_report.pass_name, "generated_at": gap_report.generated_at.isoformat()} if gap_report else None,
        "runtime_cross_validation": {"provider": runtime.provider, "generated_at": runtime.generated_at.isoformat()} if runtime else None,
        "sources_used": [s for s in ("stage1_dataset", "gap_report" if gap_report else None,
                                    "runtime_cross_validation" if runtime else None) if s],
    }
    if not components:
        return FmeaReport(service_name=dataset.service_name, generated_at=datetime.now(timezone.utc), inputs=inputs,
                          business_context=f"{b.capability} ({b.category})" if b else None, components_analyzed=0,
                          warnings=["no dependency or component was found in the dataset (or Stage 5 runtime data) to analyse"])

    model_settings = registry.model_settings()
    problem = None if runner else check_backend(model_settings)
    if problem:
        raise FmeaError(f"the FMEA analyst model is unavailable: {problem}")
    runner = runner or AgentRunner(model_settings, registry.analysis.llm, state_dir / "llm_cache")
    agent = build_fmea_agent(registry.analysis.llm, model_settings)

    warnings: list[str] = []

    async def one(c: _Component) -> list[FailureMode]:
        prompt = _prompt(dataset, c)
        try:
            res: out.FmeaComponentOut = await runner.run(agent, prompt, out.FmeaComponentOut)
        except AgentError as exc:
            warnings.append(f"{c.name}: FMEA assessment failed: {exc}")
            return []
        related = _related_gap_ids(gap_report, c.name)
        return [FailureMode(
            id="PENDING", component=c.name, component_kind=c.kind, origin=c.origin, classification=c.classification,
            failure_mode=fm.failure_mode, likely_cause=fm.likely_cause, effect_on_transaction_flow=fm.effect_on_transaction_flow,
            affected_flows=fm.affected_flows or c.blast_radius, severity=fm.severity, severity_rationale=fm.severity_rationale,
            existing_mitigations=fm.existing_mitigations or c.protecting_patterns, related_gap_ids=related, evidence=c.evidence,
        ) for fm in res.failure_modes]

    nested = await asyncio.gather(*(one(c) for c in components))
    modes = [fm for group in nested for fm in group]
    modes.sort(key=lambda m: (_SEVERITY_RANK[m.severity], m.component))
    for i, m in enumerate(modes, 1):
        m.id = f"FM-{i:03d}"

    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for m in modes:
        summary[m.severity] += 1
    inputs["assessor_model"] = describe(model_settings)
    return FmeaReport(service_name=dataset.service_name, generated_at=datetime.now(timezone.utc), inputs=inputs,
                      business_context=f"{b.capability} ({b.category})" if b else None, components_analyzed=len(components),
                      failure_modes=modes, summary_by_severity=summary, warnings=warnings)
