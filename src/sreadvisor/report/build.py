"""Builds the Stage 4 unified report from a Stage 1 dataset and a Stage 3 gap report. Deterministic: every judgment
call (what the tech stack is, whether a requirement is met, what the service is for) was already made in an earlier
stage; this module only combines and reformats those facts. No LLM call, no network access.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from sreadvisor.gap.schema import Gap, GapReport
from sreadvisor.nfr.coverage import NfrCoverage, compute_coverage
from sreadvisor.report.schema import ActionItem, InfrastructureSummary, RepoSummary, UnifiedReport
from sreadvisor.report.sli import suggest_slis
from sreadvisor.schema.dataset import InfraAnalysis, RepoAnalysis, ServiceDataset

_HIGHLIGHT_CATEGORIES = ("datastore", "cache", "messaging", "http_client", "resilience", "telemetry", "security", "secrets")


# ------------------------------------------------------------------------------------- action items


def _locations(gap: Gap, limit: int = 4) -> list[str]:
    seen: list[str] = []
    for e in gap.evidence.found:
        if e.file and e.file not in seen:
            seen.append(e.file)
    return seen[:limit]


def action_from_gap(gap: Gap) -> str:
    """A single, always-grammatical instruction, regardless of how the requirement's own title is phrased (a few
    read as a positive requirement, "Resource requests and limits defined..."; a few read as a prohibition, "No
    secrets baked into..."). "Fix:"/"Complete:" as a label sidesteps having to reliably re-conjugate free text."""
    verb = "Complete" if gap.status == "partially_met" else "Fix"
    locs = _locations(gap)
    if not locs:
        return f"{verb}: {gap.nfr.title}."
    ellipsis = len(gap.evidence.found) > len(locs)
    where = f" — see {', '.join(locs)}" + (", ..." if ellipsis else "")
    return f"{verb}: {gap.nfr.title}{where}" + ("" if ellipsis else ".")


def action_item_from_gap(gap: Gap) -> ActionItem:
    return ActionItem(**gap.model_dump(), action=action_from_gap(gap))


# ------------------------------------------------------------------------------------------ tech stack


def _dependency_highlights(repo: RepoAnalysis) -> dict[str, list[str]]:
    out: dict[str, list[str]] = defaultdict(list)
    for d in repo.fingerprint.dependencies:
        if "test" in d.categories:
            continue
        coord = f"{d.group + ':' if d.group else ''}{d.name}"
        for cat in d.categories:
            if cat in _HIGHLIGHT_CATEGORIES and coord not in out[cat]:
                out[cat].append(coord)
    return dict(out)


def repo_summary(repo: RepoAnalysis) -> RepoSummary:
    return RepoSummary(repo=repo.repo, path=repo.path, fingerprint=repo.fingerprint, entry_points=repo.entry_points,
                       transaction_flows=repo.transaction_flows, dependency_highlights=_dependency_highlights(repo))


def infrastructure_summary(infra: InfraAnalysis) -> InfrastructureSummary:
    return InfrastructureSummary(
        workloads=len(infra.workloads), autoscalers=len(infra.autoscalers), disruption_budgets=len(infra.disruption_budgets),
        services=len(infra.services), ingresses=len(infra.ingresses), network_policies=len(infra.network_policies),
        compose_services=len(infra.compose_services), dockerfiles=len(infra.dockerfiles), helm_charts=len(infra.helm_charts),
        terraform_resources=len(infra.terraform_resources), pipelines=len(infra.pipelines), mesh_present=infra.mesh.present)


# ---------------------------------------------------------------------------------------------- assemble


def build_report(dataset: ServiceDataset, gap_report: GapReport, coverage: NfrCoverage | None = None) -> UnifiedReport:
    if dataset.service_name != gap_report.service_name:
        raise ValueError(f"dataset is for {dataset.service_name!r} but the gap report is for {gap_report.service_name!r}")
    coverage = coverage or compute_coverage(dataset)
    warnings = list(gap_report.warnings)
    if gap_report.inputs.get("dataset", {}).get("generated_at") != dataset.generated_at.isoformat():
        warnings.append("the gap report was generated from a different run of the dataset than the one given to this report; "
                        "re-run gap analysis if the dataset has changed since")

    inputs: dict[str, Any] = {
        "dataset": {"service_name": dataset.service_name, "schema_version": dataset.schema_version,
                    "generated_at": dataset.generated_at.isoformat(), "model_backend": dataset.model_backend},
        "gap_report": {"generated_at": gap_report.generated_at.isoformat(), "assessor_model": gap_report.inputs.get("assessor_model"),
                      "master_nfr_list": gap_report.inputs.get("master_nfr_list")},
        "sources_used": ["stage1_dataset", "gap_analysis_pass_1", "master_nfr_list", "oneagent_default_catalogue",
                         "app_instrumentation_catalogue"],
    }

    return UnifiedReport(
        service_name=dataset.service_name, generated_at=datetime.now(timezone.utc), inputs=inputs,
        business_context=dataset.business_context, completeness=dataset.completeness,
        tech_stack=[repo_summary(r) for r in dataset.repositories], infrastructure=infrastructure_summary(dataset.infrastructure),
        action_item_summary=gap_report.summary, action_items=[action_item_from_gap(g) for g in gap_report.gaps],
        unrecognized_tech_gaps=gap_report.unrecognized_tech_gaps, applicable_modules=coverage.applicable_modules,
        sli_suggestions=suggest_slis(dataset.repositories, dataset.business_context, coverage.telemetry_tiers),
        telemetry_tiers=coverage.telemetry_tiers, warnings=warnings)
