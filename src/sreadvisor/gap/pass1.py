"""Gap Analysis Pass 1.

Inputs: the Stage 1 dataset and the Master NFR List. Nothing else: no runtime data, no repository access.

For every NFR entry of every module that applies to the service (the same matching Stage 2 reports), an ADK ``LlmAgent`` judges
whether the dataset shows the requirement met, partially met or missing. Everything around the judgment is deterministic:

* which entries apply (Stage 2 module matching) and which dataset paths verify each (from the entry itself);
* the evidence slice given to the model (only those paths, with identities and file:line, nulls explicit);
* what cannot be judged from the dataset at all (runtime-only or manual-review entries, skipped Stage 1 steps) is
  ``not_assessable`` and never reported as a gap;
* every citation the model returns is checked against the dataset; a "met" without a valid citation is not accepted.

Unrecognized tech stack gaps come from the same comparison Stage 2 uses (fingerprint versus the modules in the Master NFR List)
and are recorded separately from NFR gaps.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from sreadvisor.agents import outputs as out
from sreadvisor.agents.outputs import GAP_STATUS_ALIASES
from sreadvisor.agents.definitions import build_gap_assessor
from sreadvisor.agents.runner import AgentError, AgentRunner, check_backend
from sreadvisor.gap import paths as dp
from sreadvisor.gap.schema import (
    Assessment,
    EvidenceRef,
    FindingEvidence,
    Gap,
    GapReport,
    GapSummary,
    ModuleSummary,
    NfrRef,
    UnrecognizedTechGap,
)
from sreadvisor.model_provider import describe
from sreadvisor.nfr.base import NFRModule
from sreadvisor.nfr.detect import applicable_modules, signals_from_dataset, unrecognized_technologies
from sreadvisor.nfr.loader import load_master
from sreadvisor.nfr.schema import MasterNfrList, NfrEntry, NfrModule as KbModule
from sreadvisor.schema.dataset import ServiceDataset

_PRIORITY = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_STATUS_RANK = {"missing": 0, "partially_met": 1}


class GapAnalysisError(RuntimeError):
    pass


def _norm_status(raw: str) -> str | None:
    return GAP_STATUS_ALIASES.get(raw.strip().lower().replace(" ", "_").replace("-", "_"))


def _nfr_ref(module: KbModule, entry: NfrEntry) -> NfrRef:
    return NfrRef(id=entry.id, module_id=module.id, module_title=module.title, layer=module.layer, title=entry.title,
                  priority=entry.priority, requirement=entry.requirement, best_practice=entry.best_practice,
                  audit_requirement=entry.audit_requirement, criteria=entry.verification.criteria, extends=entry.extends)


class GapAnalysisPass1(NFRModule):
    """Registered in the registry as an NFR module; call :meth:`bind` before :meth:`evaluate`."""

    name = "gap_analysis_pass_1"

    def __init__(self, master_list: str | None = None, only_modules: list[str] | None = None, limit: int | None = None,
                 use_llm: bool = True) -> None:
        self.master_list = master_list
        self.only_modules = only_modules
        self.limit = limit
        self.use_llm = use_llm
        self.registry: Any = None
        self.state_dir = Path(".sreadvisor")
        self.runner: Any = None
        self.log: Callable[[str], None] = print

    def bind(self, registry: Any, state_dir: Path, runner: Any | None = None, log: Callable[[str], None] = print) -> "GapAnalysisPass1":
        self.registry, self.state_dir, self.runner, self.log = registry, state_dir, runner, log
        return self

    # ---------------------------------------------------------------------------- evaluate

    async def evaluate(self, dataset: ServiceDataset, runtime: Any | None = None) -> GapReport:
        """Pass 1 uses only the dataset and the Master NFR List; ``runtime`` is accepted for the NFRModule contract and ignored."""
        kb = load_master(self.master_list)
        data = dataset.model_dump(mode="json")
        sig = signals_from_dataset(dataset)
        matched = applicable_modules(kb, sig)
        if self.only_modules:
            unknown = set(self.only_modules) - set(kb.modules)
            if unknown:
                raise GapAnalysisError(f"unknown module(s) {sorted(unknown)}; modules: {', '.join(kb.modules)}")
            matched = [m for m in matched if m.module.id in self.only_modules]

        work: list[tuple[KbModule, NfrEntry]] = [(m.module, e) for m in matched for e in m.module.entries]
        if self.limit:
            work = work[: self.limit]

        settings = self.registry.analysis.gap if self.registry else None
        max_items = settings.max_evidence_items if settings else 30
        max_chars = settings.max_evidence_chars if settings else 6000
        statuses = dp.step_statuses(data)
        locs, files = dp.locations(data)

        agent = runner = None
        if self.use_llm:
            if self.registry is None:
                raise GapAnalysisError("GapAnalysisPass1.bind(registry, state_dir) must be called before evaluate()")
            model_settings = self.registry.model_settings()
            problem = None if self.runner else check_backend(model_settings)
            if problem:
                raise GapAnalysisError(f"the assessor model is unavailable: {problem}")
            runner = self.runner or AgentRunner(model_settings, self.registry.analysis.llm, self.state_dir / "llm_cache")
            agent = build_gap_assessor(data, self.registry.analysis.llm, model_settings, max_items=max_items)
            model_label = describe(model_settings)
        else:
            model_label = "not used (--no-llm)"

        context = _service_context(dataset)
        total = len(work)
        done = 0

        async def one(module: KbModule, entry: NfrEntry) -> Assessment:
            nonlocal done
            ref = _nfr_ref(module, entry)
            pre = _precheck(ref, entry, statuses, use_llm=self.use_llm)
            if pre is not None:
                result = pre
            else:
                prompt = _prompt(context, ref, entry, data, statuses, max_items, max_chars)
                result = await _assess(runner, agent, prompt, ref, entry, data, statuses, locs, files, max_items,
                                       verify_met=bool(settings.verify_met) if settings else True)
            done += 1
            if self.use_llm and pre is None and (done % 10 == 0 or done == total):
                self.log(f"[gap] assessed {done}/{total}")
            return result

        assessments = list(await asyncio.gather(*(one(m, e) for m, e in work)))
        return _assemble(dataset, kb, matched, assessments, model_label, self.use_llm)


# ------------------------------------------------------------------------------- pre-checks


def _steps_for(entry: NfrEntry) -> dict[str, list[str]]:
    """Stage 1 steps behind each of the entry's dataset paths."""
    return {p: dp.steps_for_path(p) for p in entry.verification.stage1_paths}


def _relevant_status(entry: NfrEntry, statuses: dict[str, dict]) -> dict[str, str]:
    names = {s for steps in _steps_for(entry).values() for s in steps}
    return {n: statuses[n]["status"] + (f" ({statuses[n]['count']})" if statuses[n].get("count") is not None else "")
            for n in sorted(names) if n in statuses}


def _precheck(ref: NfrRef, entry: NfrEntry, statuses: dict[str, dict], *, use_llm: bool) -> Assessment | None:
    """Verdicts that need no model: what the dataset cannot answer is not_assessable, never a gap."""
    v = entry.verification
    relevant = _relevant_status(entry, statuses)
    base = dict(nfr=ref, method="deterministic", confidence="high")
    evidence = FindingEvidence(examined_paths=list(v.stage1_paths), stage1_steps=relevant)
    if "stage1_dataset" not in v.sources:
        return Assessment(status="not_assessable", evidence=evidence, rationale=(
            f"Verified from {', '.join(v.sources)}, not from the Stage 1 dataset. Pass 1 uses the dataset only; "
            "this is deferred to a later pass (runtime telemetry) or to manual review."), **base)
    if relevant and all(s.split(" ")[0] in ("skipped", "failed") for s in relevant.values()):
        return Assessment(status="not_assessable", evidence=evidence, rationale=(
            "The Stage 1 step(s) that would produce the evidence did not run: "
            + ", ".join(f"{k} {v}" for k, v in relevant.items()) + ". Absence cannot be inferred."), **base)
    if not use_llm:
        return Assessment(status="not_assessable", evidence=evidence, rationale="LLM assessment disabled (--no-llm).", **base)
    return None


# ----------------------------------------------------------------------------------- prompt


def _service_context(ds: ServiceDataset) -> str:
    fps = [r.fingerprint for r in ds.repositories]
    langs = sorted({lang for fp in fps for lang in fp.languages})
    fw = sorted({f"{f.name} {f.version or ''}".strip() for fp in fps for f in fp.frameworks})
    tools = sorted({t for fp in fps for t in fp.build_tools})
    b = ds.business_context
    return (f"Service: {ds.service_name}\n"
            f"Business context: {b.capability + ' (' + b.category + ')' if b else 'not inferred'}\n"
            f"Tech stack: languages {', '.join(langs) or 'none'}; frameworks {', '.join(fw) or 'none'}; build tools {', '.join(tools) or 'none'}")


def _prompt(context: str, ref: NfrRef, entry: NfrEntry, data: dict, statuses: dict[str, dict], max_items: int, max_chars: int) -> str:
    steps = _relevant_status(entry, statuses)
    evidence = dp.project(data, entry.verification.stage1_paths, max_items=max_items, max_chars=max_chars)
    return (
        f"{context}\n\n"
        f"NFR {ref.id} ({ref.module_title}, {ref.layer} module), priority {ref.priority}\n"
        f"Title: {ref.title}\n"
        f"Requirement: {ref.requirement}\n"
        f"Best practice: {ref.best_practice}\n"
        f"Audit requirement: {ref.audit_requirement or 'none'}\n"
        f"PASS CRITERIA: {ref.criteria}\n"
        f"Verification sources for this requirement: {', '.join(entry.verification.sources)}\n\n"
        f"Stage 1 steps behind this evidence: {', '.join(f'{k}={v}' for k, v in steps.items()) or 'n/a'}\n"
        f"Dataset paths examined: {', '.join(entry.verification.stage1_paths)}\n\n"
        f"Dataset evidence (only these paths; null or [] means the dataset records nothing; \"at\" is file:line):\n{evidence}\n"
        + ("NOTE: some lists above are truncated (\"+N more of M\"). Do not conclude that something is absent from a truncated list; "
           "use query_dataset to see the rest.\n" if dp.truncated(evidence) else "")
        + "\n"
        "Assess this requirement now."
    )


# --------------------------------------------------------------------------------- assessing


async def _assess(runner: Any, agent: Any, prompt: str, ref: NfrRef, entry: NfrEntry, data: dict, statuses: dict[str, dict],
                  locs: set[tuple[str, int]], files: set[str], max_items: int = 12, verify_met: bool = True) -> Assessment:
    steps = _relevant_status(entry, statuses)
    evidence = FindingEvidence(examined_paths=list(entry.verification.stage1_paths), stage1_steps=steps,
                               examined_locations=dp.at_locations(data, entry.verification.stage1_paths, max_items))
    try:
        res: out.GapAssessmentOut = await runner.run(agent, prompt, out.GapAssessmentOut)
    except AgentError as exc:
        return Assessment(nfr=ref, status="not_assessable", confidence="low", method="llm", evidence=evidence,
                          rationale="The assessment could not be completed.", warnings=[f"assessment failed: {exc}"])

    warnings: list[str] = []
    issue = _inconsistency(res)
    unresolved = False
    if issue:  # challenge the model once with the specific problem; do not override its judgment ourselves
        again = (f"{prompt}\n\nYour previous answer was:\n{res.model_dump_json()}\n\nProblem: {issue}\n"
                 "Reassess this requirement and reply with the corrected JSON object only.")
        try:
            second = await runner.run(agent, again, out.GapAssessmentOut)
        except AgentError:
            second = None
        if second is not None and _inconsistency(second) is None:
            res = second
            warnings.append(f"re-assessed after a consistency check ({issue})")
        else:
            unresolved = True
            warnings.append(f"verdict and citations disagree after a re-check: {issue}")
    status = _norm_status(res.status)
    if status is None:
        return Assessment(nfr=ref, status="not_assessable", confidence="low", method="llm", evidence=evidence,
                          rationale="The assessor returned an unusable status.", warnings=[f"unknown status {res.status!r}"])
    confidence = res.confidence.strip().lower() if res.confidence.strip().lower() in ("high", "medium", "low") else "medium"

    found: list[EvidenceRef] = []
    for r in res.found:
        g = _ground(r, data, locs, files)
        if g is None:
            warnings.append(f"dropped an ungrounded citation ({r.file or r.path}:{r.line})")
        else:
            found.append(g)

    rationale = res.rationale.strip()
    if unresolved:
        confidence = {"high": "medium", "medium": "low", "low": "low"}[confidence]
    if status == "met" and not found:
        warnings.append("assessor asserted met without a citation that exists in the dataset")
        status, confidence = "not_assessable", "low"
        rationale = f"Not accepted as met: no valid citation. Assessor said: {rationale}"
    if status in ("missing", "partially_met"):
        skipped = [k for k, v in steps.items() if v.split(" ")[0] in ("skipped", "failed")]
        if skipped:
            warnings.append("some Stage 1 steps behind this evidence did not run: " + ", ".join(skipped))
        if status == "partially_met" and not found:
            warnings.append("partially_met without any citation of what is satisfied")
    if dp.truncated(prompt.split("Dataset evidence", 1)[1]) and status in ("met", "missing", "partially_met"):
        warnings.append("evidence given to the assessor was truncated; verdict confidence capped at medium")
        confidence = "medium" if confidence == "high" else confidence
    evidence.found = found
    evidence.not_found = [n.strip() for n in res.not_found if n.strip()]
    if status == "met" and verify_met:
        status, confidence, rationale, found, not_found, warnings = await _verify_met(
            runner, agent, prompt, rationale, found, confidence, warnings, data, locs, files)
        evidence.found, evidence.not_found = found, not_found or evidence.not_found
    return Assessment(nfr=ref, status=status, confidence=confidence, method="llm", evidence=evidence,
                      rationale=rationale, warnings=warnings)


async def _verify_met(runner: Any, agent: Any, prompt: str, rationale: str, found: list[EvidenceRef], confidence: str,
                      warnings: list[str], data: dict, locs: set[tuple[str, int]], files: set[str]):
    """A false "met" hides a real gap, so a met verdict is challenged once: the model is asked to disprove it against every instance and
    every clause of the criteria. A concrete, cited shortfall downgrades the verdict; otherwise met stands."""
    again = (f"{prompt}\n\nVERIFICATION OF A 'MET' VERDICT. A previous assessment concluded this requirement is met: \"{rationale}\"\n"
             "Try to disprove it. Go through EVERY instance in the evidence and EVERY clause of the pass criteria, for example: is a tag or "
             "version present (an image with no tag is not pinned)? is the setting explicit rather than a framework default (check the origin "
             "field)? is the count at least the stated minimum? is every instance covered, not just some? If any instance or clause fails, answer "
             "partially_met (or missing if none satisfy) and cite the failing instance with shows=shortfall. Answer met only if every instance passes "
             "every clause.")
    try:
        second: out.GapAssessmentOut = await runner.run(agent, again, out.GapAssessmentOut)
    except AgentError as exc:
        return "met", confidence, rationale, found, [], warnings + [f"met verdict could not be re-checked: {str(exc)[:120]}"]
    new_status = _norm_status(second.status)
    refs = [g for r in second.found if (g := _ground(r, data, locs, files)) is not None]
    shortfalls = [r for r in refs if r.shows == "shortfall"]
    if new_status in ("partially_met", "missing") and shortfalls:
        return (new_status, "medium", second.rationale.strip(), refs, [n.strip() for n in second.not_found if n.strip()],
                warnings + [f"downgraded from met after an adversarial re-check: {rationale[:160]}"])
    note = "met confirmed by an adversarial re-check" if new_status == "met" else "re-check disagreed without a citable shortfall; kept met at lower confidence"
    return "met", confidence if new_status == "met" else "medium", rationale, found, [], warnings + [note]


def _inconsistency(res: out.GapAssessmentOut) -> str | None:
    """A verdict must agree with what the assessor itself cited as satisfied or falling short."""
    status = _norm_status(res.status)
    shows = {f.shows for f in res.found if f.shows}
    if status == "partially_met" and shows and "satisfied" not in shows:
        return ("you answered partially_met but tagged no citation as satisfied. Partially met means at least one instance or "
                "criterion is satisfied: cite it with shows=satisfied. If nothing satisfies the requirement, the status is missing.")
    if status == "met" and "shortfall" in shows:
        return ("you answered met but tagged a citation as a shortfall. Met means every instance satisfies the criteria; if any "
                "does not, the status is partially_met or missing.")
    if status == "missing" and "satisfied" in shows:
        return ("you answered missing but tagged a citation as satisfied. Missing means nothing in the evidence satisfies the "
                "requirement: if at least one instance or criterion is satisfied, the status is partially_met (or met if all are).")
    return None


def _ground(r: out.GapRefOut, data: dict, locs: set[tuple[str, int]], files: set[str]) -> EvidenceRef | None:
    """Keep only citations that exist in the dataset; an unverifiable line number is dropped, not trusted."""
    file, line, path, note = (r.file or None), r.line, (r.path or None), r.note.strip()
    if path and not dp.path_valid(data, path):
        path = None
    if file:
        if file not in files:
            file, line = None, None
        elif line is not None and (file, line) not in locs:
            line = None
            note = (note + " (line not verified against the dataset)").strip()
    if not file and not path:
        return None
    if path and not file:  # a dataset path: attach the file:line the dataset holds for it
        where = dp.locate(data, path)
        if where:
            file, line = where
    return EvidenceRef(file=file, line=line if file else None, path=path, note=note, shows=r.shows)  # type: ignore[arg-type]


# --------------------------------------------------------------------------------- assemble


def _assemble(ds: ServiceDataset, kb: MasterNfrList, matched: list, assessments: list[Assessment], model_label: str,
              use_llm: bool) -> GapReport:
    order = {e.nfr.id: i for i, e in enumerate(assessments)}
    problems = [a for a in assessments if a.status in ("missing", "partially_met")]
    problems.sort(key=lambda a: (_PRIORITY[a.nfr.priority], _STATUS_RANK[a.status], order[a.nfr.id]))
    gaps = [Gap(id=f"GAP-{i:03d}", status=a.status, priority=a.nfr.priority, confidence=a.confidence, nfr=a.nfr,  # type: ignore[arg-type]
                why=a.rationale, evidence=a.evidence, warnings=a.warnings) for i, a in enumerate(problems, 1)]

    tech = [UnrecognizedTechGap(id=f"UTG-{i:03d}", kind=u.kind, name=u.name, found_as=u.detail, evidence=u.evidence)
            for i, u in enumerate(unrecognized_technologies(kb, ds), 1)]

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

    warnings = [f"{a.nfr.id}: {w}" for a in assessments for w in a.warnings]
    failed = sum(1 for a in assessments if any(w.startswith("assessment failed") for w in a.warnings))
    llm_skipped = [s for r in ds.repositories for s in r.status if s.step in (
        "transaction_flow_tracing", "reliability_patterns", "dependency_classification") and s.status in ("skipped", "failed")]
    if llm_skipped:
        warnings.append("Stage 1 LLM steps were skipped or failed (" + ", ".join(sorted({s.step for s in llm_skipped}))
                        + "); requirements relying on them are not assessable.")
    b = ds.business_context
    return GapReport(
        service_name=ds.service_name, generated_at=datetime.now(timezone.utc),
        inputs={"dataset": {"service_name": ds.service_name, "schema_version": ds.schema_version,
                            "generated_at": ds.generated_at.isoformat(), "stage1_model_backend": ds.model_backend},
                "master_nfr_list": {"kb_schema_version": kb.kb_schema_version, "modules_total": len(kb.modules),
                                    "modules_applicable": len(matched)},
                "assessor_model": model_label, "sources_used": ["stage1_dataset", "master_nfr_list"]},
        business_context=f"{b.capability} ({b.category})" if b else None,
        summary=GapSummary(
            applicable_requirements=len(assessments), by_status=by_status,
            gaps_by_priority={p: sum(1 for g in gaps if g.priority == p) for p in _PRIORITY},
            gap_count=len(gaps), unrecognized_tech_gap_count=len(tech),
            assessed_by_llm=sum(1 for a in assessments if a.method == "llm"), failed_assessments=failed),
        modules=modules, gaps=gaps, unrecognized_tech_gaps=tech, assessments=assessments, warnings=warnings)
