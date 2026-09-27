"""Gap Analysis Pass 2.

Extends Pass 1 with Stage 5's runtime cross-validation (:class:`~sreadvisor.runtime.schema.RuntimeCrossValidation`).
Two things Pass 1 cannot do without it:

1. Re-examine an NFR entry whose ``verification.sources`` include ``runtime_telemetry`` and for which live evidence is
   actually available (see :mod:`sreadvisor.runtime.observed`), using the exact same assessor agent and prompt-building
   Pass 1 uses — the live evidence is appended to Pass 1's own prompt, not substituted for it, and the model still
   makes the call. A verdict only changes when the model itself changes it.
2. Add findings Pass 1 could never produce at all: a live dependency the code never declared, with no resilience
   pattern recorded protecting it (:func:`sreadvisor.runtime.observed.undocumented_dependency_gaps`).

Every :class:`~sreadvisor.gap.schema.Assessment` and :class:`~sreadvisor.gap.schema.Gap` in the merged
:class:`~sreadvisor.gap.schema.GapReport` carries ``detection_source``: ``"code_and_infra"`` when Pass 1 alone would
have produced it unchanged, or ``"runtime"`` when Stage 5's data changed the verdict or is the only reason the
finding exists at all. Called with no runtime data, Pass 2 degrades to exactly Pass 1's result (relabelled), so it is
always safe to run in place of Pass 1.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sreadvisor.agents.definitions import build_gap_assessor
from sreadvisor.agents.runner import AgentRunner, check_backend
from sreadvisor.gap import paths as dp
from sreadvisor.gap.pass1 import GapAnalysisError, GapAnalysisPass1, _assess, _prompt, _service_context
from sreadvisor.gap.schema import Assessment, Gap, GapReport, GapSummary, ModuleSummary
from sreadvisor.nfr.detect import applicable_modules, signals_from_dataset
from sreadvisor.nfr.loader import load_master
from sreadvisor.runtime import observed
from sreadvisor.runtime.schema import RuntimeCrossValidation
from sreadvisor.schema.dataset import ServiceDataset

_PRIORITY = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_STATUS_RANK = {"missing": 0, "partially_met": 1}


class GapAnalysisPass2(GapAnalysisPass1):
    """Registered in the registry as an NFR module, same as Pass 1; call :meth:`bind` before :meth:`evaluate`."""

    name = "gap_analysis_pass_2"

    async def evaluate(self, dataset: ServiceDataset, runtime: RuntimeCrossValidation | None = None) -> GapReport:
        pass1_report = await super().evaluate(dataset)
        if runtime is None:
            return pass1_report.model_copy(update={
                "pass_name": "gap_analysis_pass_2",
                "warnings": pass1_report.warnings + [
                    "no Stage 5 runtime cross-validation was given to Pass 2; this report is Pass 1's result, unchanged."],
            })
        if runtime.service_name != dataset.service_name:
            raise GapAnalysisError(
                f"the runtime cross-validation is for {runtime.service_name!r} but the dataset is for {dataset.service_name!r}")
        return await self._merge_with_runtime(dataset, pass1_report, runtime)

    async def _merge_with_runtime(self, dataset: ServiceDataset, pass1_report: GapReport,
                                  runtime: RuntimeCrossValidation) -> GapReport:
        kb = load_master(self.master_list)
        entry_by_id = {e.id: (m, e) for m in kb.modules.values() for e in m.entries}
        data = dataset.model_dump(mode="json")
        statuses = dp.step_statuses(data)
        locs, files = dp.locations(data)
        settings = self.registry.analysis.gap if self.registry else None
        max_items = settings.max_evidence_items if settings else 30
        max_chars = settings.max_evidence_chars if settings else 6000
        context = _service_context(dataset)

        to_recheck = [(a, ev) for a in pass1_report.assessments
                     if (ev := observed.runtime_evidence_for(a.nfr.id, dataset, runtime)) is not None]

        agent = runner = None
        if self.use_llm and to_recheck:
            if self.registry is None:
                raise GapAnalysisError("GapAnalysisPass2.bind(registry, state_dir) must be called before evaluate()")
            model_settings = self.registry.model_settings()
            problem = None if self.runner else check_backend(model_settings)
            if problem:
                raise GapAnalysisError(f"the assessor model is unavailable: {problem}")
            runner = self.runner or AgentRunner(model_settings, self.registry.analysis.llm, self.state_dir / "llm_cache")
            agent = build_gap_assessor(data, self.registry.analysis.llm, model_settings, max_items=max_items)

        updated: dict[str, Assessment] = {}
        for a, runtime_ev in to_recheck:
            if a.nfr.id not in entry_by_id:
                continue  # the Master NFR List changed between Pass 1 and this call; skip rather than guess
            _, entry = entry_by_id[a.nfr.id]
            if not self.use_llm:
                updated[a.nfr.id] = a.model_copy(update={"warnings": a.warnings + [
                    "runtime evidence is available for this requirement but --no-llm skipped re-assessment"]})
                continue
            prompt = f"{_prompt(context, a.nfr, entry, data, statuses, max_items, max_chars)}\n\n{runtime_ev}"
            result = await _assess(runner, agent, prompt, a.nfr, entry, data, statuses, locs, files, max_items,
                                   verify_met=bool(settings.verify_met) if settings else True)
            changed = result.status != a.status
            if changed:
                result.detection_source = "runtime"
                result.warnings = result.warnings + [f"revised from {a.status} after Stage 5 runtime evidence"]
            else:
                result.warnings = result.warnings + ["reassessed with Stage 5 runtime evidence; verdict unchanged"]
            updated[a.nfr.id] = result

        final_assessments = [updated.get(a.nfr.id, a) for a in pass1_report.assessments]

        extra_gaps: list[Gap] = []
        if "DC-001" in entry_by_id:
            from sreadvisor.gap.pass1 import _nfr_ref

            module, entry = entry_by_id["DC-001"]
            extra_gaps = observed.undocumented_dependency_gaps(dataset, runtime, _nfr_ref(module, entry))

        matched = applicable_modules(kb, signals_from_dataset(dataset))
        return _assemble2(dataset, kb, matched, pass1_report, final_assessments, extra_gaps, runtime)


def _assemble2(dataset: ServiceDataset, kb: Any, matched: list, pass1_report: GapReport,
              assessments: list[Assessment], extra_gaps: list[Gap], runtime: RuntimeCrossValidation) -> GapReport:
    order = {a.nfr.id: i for i, a in enumerate(assessments)}
    problems = [a for a in assessments if a.status in ("missing", "partially_met")]
    problems.sort(key=lambda a: (_PRIORITY[a.nfr.priority], _STATUS_RANK[a.status], order[a.nfr.id]))
    gaps = [Gap(id=f"GAP-{i:03d}", status=a.status, priority=a.nfr.priority, confidence=a.confidence, nfr=a.nfr,  # type: ignore[arg-type]
                why=a.rationale, evidence=a.evidence, warnings=a.warnings, detection_source=a.detection_source)
            for i, a in enumerate(problems, 1)]
    gaps += [g.model_copy(update={"id": f"GAP-{i:03d}"}) for i, g in enumerate(extra_gaps, len(gaps) + 1)]

    by_status: dict[str, int] = {"met": 0, "partially_met": 0, "missing": 0, "not_assessable": 0}
    for a in assessments:
        by_status[a.status] += 1
    modules: list[ModuleSummary] = []
    for m in matched:
        mine = [a for a in assessments if a.nfr.module_id == m.module.id]
        if not mine:
            continue
        ms = ModuleSummary(module_id=m.module.id, title=m.module.title, layer=m.module.layer, matched_by=m.reasons, assessed=len(mine))
        for a in mine:
            setattr(ms, a.status, getattr(ms, a.status) + 1)
        modules.append(ms)

    runtime_informed = sum(1 for g in gaps if g.detection_source == "runtime")
    s = runtime.summary
    warnings = list(pass1_report.warnings) + runtime.warnings + [
        f"Stage 5 runtime cross-validation incorporated (provider {runtime.provider}): {s.matched} dependency match(es), "
        f"{s.runtime_only} runtime-only, {s.code_only} code-only. {runtime_informed} of {len(gaps)} gap(s) in this "
        "report required runtime data to catch; the rest were already visible from code and infrastructure alone."]

    inputs = dict(pass1_report.inputs)
    inputs["sources_used"] = list(inputs.get("sources_used", [])) + ["runtime_cross_validation"]
    inputs["runtime_cross_validation"] = {"provider": runtime.provider, "service_id": runtime.service_id,
                                          "generated_at": runtime.generated_at.isoformat()}

    return GapReport(
        pass_name="gap_analysis_pass_2", service_name=dataset.service_name, generated_at=datetime.now(timezone.utc),
        inputs=inputs, business_context=pass1_report.business_context,
        summary=GapSummary(applicable_requirements=len(assessments), by_status=by_status,
                           gaps_by_priority={p: sum(1 for g in gaps if g.priority == p) for p in _PRIORITY},
                           gap_count=len(gaps), unrecognized_tech_gap_count=len(pass1_report.unrecognized_tech_gaps),
                           assessed_by_llm=sum(1 for a in assessments if a.method == "llm"),
                           failed_assessments=pass1_report.summary.failed_assessments),
        modules=modules, gaps=gaps, unrecognized_tech_gaps=pass1_report.unrecognized_tech_gaps,
        assessments=assessments, warnings=warnings)
