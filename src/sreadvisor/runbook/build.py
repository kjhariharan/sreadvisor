"""Builds the operations runbook (Stage 6) from the FMEA output plus the same architecture/dependency data and,
when available, Stage 4's SLI suggestions — reused as detection signals rather than re-derived, since Stage 4 already
worked out what telemetry exists for a given dependency. One LLM call per FMEA failure mode, asked only for what the
FMEA does not already determine: how an on-call engineer would notice this happening live, what to do about it, and
when to escalate. The failure mode, its effect and its severity are taken from the FMEA verbatim, never re-judged.
"""

from __future__ import annotations

import asyncio
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sreadvisor.agents import outputs as out
from sreadvisor.agents.definitions import build_runbook_agent
from sreadvisor.agents.runner import AgentError, AgentRunner, check_backend
from sreadvisor.fmea.schema import FailureMode, FmeaReport
from sreadvisor.model_provider import describe
from sreadvisor.registry import Registry
from sreadvisor.runtime.cross_validate import _tokens
from sreadvisor.runbook.schema import Runbook, RunbookEntry
from sreadvisor.schema.dataset import ServiceDataset

_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_LEADING_ORDINAL = re.compile(r"^\s*\d+[.)]\s+")


class RunbookError(RuntimeError):
    pass


def _strip_leading_number(step: str) -> str:
    """The renderer numbers immediate_actions itself; strips a model-added "1. " prefix so it is never doubled."""
    return _LEADING_ORDINAL.sub("", step)


def _known_detection_signals(component_name: str, sli_suggestions: list) -> list[str]:
    """SLIs Stage 4 already suggested for a dependency whose name overlaps this component: real, already-designed
    telemetry, preferred over asking the model to invent a signal from nothing."""
    toks = _tokens(component_name)
    if not toks:
        return []
    return [f"{s.name} ({s.tier_label}): {s.measurement_source}" for s in sli_suggestions if _tokens(s.subject) & toks]


def _prompt(dataset: ServiceDataset, fm: FailureMode, known_signals: list[str]) -> str:
    b = dataset.business_context
    return (
        f"Service: {dataset.service_name}\n"
        f"Business purpose: {b.capability + ' (' + b.category + ')' if b else 'not inferred'}\n\n"
        f"Component: {fm.component} (kind: {fm.component_kind}, Stage 1 classification: {fm.classification})\n"
        f"Failure mode (already determined — do not re-derive or contradict it): {fm.failure_mode}\n"
        f"Likely cause: {fm.likely_cause}\n"
        f"Effect on transaction flow: {fm.effect_on_transaction_flow}\n"
        f"Severity: {fm.severity} — {fm.severity_rationale}\n"
        f"Existing mitigations already in place: {', '.join(fm.existing_mitigations) or 'none recorded'}\n"
        f"Telemetry signals already known to exist for this component (prefer naming these over inventing a new "
        f"one): {'; '.join(known_signals) if known_signals else 'none found in the service SLI suggestions'}\n\n"
        "Write this runbook entry now."
    )


async def build_runbook(dataset: ServiceDataset, fmea_report: FmeaReport, sli_suggestions: list | None,
                        registry: Registry, state_dir: Path, runner: Any | None = None) -> Runbook:
    b = dataset.business_context
    inputs: dict[str, Any] = {
        "dataset": {"service_name": dataset.service_name, "schema_version": dataset.schema_version},
        "fmea": {"generated_at": fmea_report.generated_at.isoformat(), "failure_modes": len(fmea_report.failure_modes)},
        "sources_used": ["stage1_dataset", "fmea", "sli_suggestions" if sli_suggestions else None],
    }
    inputs["sources_used"] = [s for s in inputs["sources_used"] if s]
    if not fmea_report.failure_modes:
        return Runbook(service_name=dataset.service_name, generated_at=datetime.now(timezone.utc), inputs=inputs,
                       business_context=f"{b.capability} ({b.category})" if b else None,
                       warnings=["the FMEA report has no failure modes; nothing to build a runbook from"])

    model_settings = registry.model_settings()
    problem = None if runner else check_backend(model_settings)
    if problem:
        raise RunbookError(f"the runbook writer model is unavailable: {problem}")
    runner = runner or AgentRunner(model_settings, registry.analysis.llm, state_dir / "llm_cache")
    agent = build_runbook_agent(registry.analysis.llm, model_settings)
    sli_suggestions = sli_suggestions or []
    warnings: list[str] = []

    async def one(fm: FailureMode) -> RunbookEntry | None:
        known = _known_detection_signals(fm.component, sli_suggestions)
        prompt = _prompt(dataset, fm, known)
        try:
            res: out.RunbookStepsOut = await runner.run(agent, prompt, out.RunbookStepsOut)
        except AgentError as exc:
            warnings.append(f"{fm.component} ({fm.failure_mode}): runbook entry could not be generated: {exc}")
            return None
        detection = list(known)
        for s in res.detection_signals:
            if s not in detection:
                detection.append(s)
        return RunbookEntry(id="PENDING", fmea_id=fm.id, component=fm.component, component_kind=fm.component_kind,
                            origin=fm.origin, severity=fm.severity, failure_mode=fm.failure_mode,
                            effect_on_transaction_flow=fm.effect_on_transaction_flow, detection_signals=detection,
                            immediate_actions=[_strip_leading_number(a) for a in res.immediate_actions],
                            escalate_to=res.escalate_to, escalate_when=res.escalate_when, related_gap_ids=fm.related_gap_ids)

    nested = await asyncio.gather(*(one(fm) for fm in fmea_report.failure_modes))
    entries = [e for e in nested if e is not None]
    entries.sort(key=lambda e: (_SEVERITY_RANK[e.severity], e.component))
    for i, e in enumerate(entries, 1):
        e.id = f"RB-{i:03d}"
    inputs["writer_model"] = describe(model_settings)
    return Runbook(service_name=dataset.service_name, generated_at=datetime.now(timezone.utc), inputs=inputs,
                   business_context=f"{b.capability} ({b.category})" if b else None, entries=entries, warnings=warnings)
