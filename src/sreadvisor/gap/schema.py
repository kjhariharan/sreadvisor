"""Output of Gap Analysis Pass 1: a structured gap list per service, ready for the Stage 4 report generator.

Two kinds of finding are kept apart on purpose:

* ``gaps``: ordinary NFR gaps (a requirement in the Master NFR List that the dataset shows is partially met or missing);
* ``unrecognized_tech_gaps``: technology found in the code or infrastructure that no module of the Master NFR List covers.
  These are a gap in the knowledge base, not in the service, and Stage 4 highlights them as their own item.

Pass 1 uses the Stage 1 dataset only. Requirements that can only be verified from runtime telemetry or manual review, or whose
Stage 1 evidence was not collected, are ``not_assessable`` (deferred), never reported as missing.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

from sreadvisor.schema.common import Evidence

GAP_SCHEMA_VERSION = "1.1"  # 1.1 adds Assessment/Gap.detection_source (Stage 6 Pass 2: code_and_infra vs runtime)

Status = Literal["met", "partially_met", "missing", "not_assessable"]
Priority = Literal["critical", "high", "medium", "low"]
Method = Literal["llm", "deterministic"]
# code_and_infra: Pass 1 alone (the Stage 1 dataset) could have produced this verdict.
# runtime: Stage 5's runtime cross-validation was needed — either it changed a dataset-only verdict (for example an
# encryption claim contradicted by an observed plaintext connection), or the finding has no code/infra counterpart at
# all (a dependency only the observability platform saw). Defaults to code_and_infra so Pass 1's own output, unchanged,
# still validates: only Pass 2 ever sets this to "runtime".
DetectionSource = Literal["code_and_infra", "runtime"]


class NfrRef(BaseModel):
    """The requirement as it stood in the Master NFR List when assessed (so Stage 4 needs no lookup)."""

    id: str
    module_id: str
    module_title: str
    layer: str
    title: str
    priority: Priority
    requirement: str
    best_practice: str
    audit_requirement: str | None = None
    criteria: str
    extends: str | None = None


class EvidenceRef(BaseModel):
    """Something the assessor pointed at in the dataset. Only citations verified to exist in the dataset are kept."""

    file: str | None = None
    line: int | None = None
    path: str | None = None  # dataset path, e.g. infrastructure.workloads[0].containers[0].readiness
    note: str = ""
    shows: Literal["satisfied", "shortfall"] | None = None  # does this citation show the requirement holding, or falling short?


class FindingEvidence(BaseModel):
    found: list[EvidenceRef] = Field(default_factory=list)  # what the dataset showed
    not_found: list[str] = Field(default_factory=list)  # what was expected and not present
    examined_paths: list[str] = Field(default_factory=list)  # dataset paths the check was made against (always recorded)
    examined_locations: list[str] = Field(default_factory=list)  # file:line of the items those paths covered (where "not found" was checked)
    stage1_steps: dict[str, str] = Field(default_factory=dict)  # relevant Stage 1 steps and their status


class Assessment(BaseModel):
    """The verdict on one applicable requirement (every applicable requirement gets one, gap or not)."""

    nfr: NfrRef
    status: Status
    confidence: Literal["high", "medium", "low"] = "medium"
    rationale: str
    evidence: FindingEvidence
    method: Method
    detection_source: DetectionSource = "code_and_infra"
    warnings: list[str] = Field(default_factory=list)


class Gap(BaseModel):
    """An ordinary NFR gap: an assessment whose status is partially_met or missing."""

    gap_type: Literal["nfr_gap"] = "nfr_gap"
    id: str
    status: Literal["partially_met", "missing"]
    priority: Priority
    confidence: Literal["high", "medium", "low"]
    nfr: NfrRef
    why: str  # why this is considered a gap
    evidence: FindingEvidence  # what was and was not found in the dataset
    detection_source: DetectionSource = "code_and_infra"
    warnings: list[str] = Field(default_factory=list)


class UnrecognizedTechGap(BaseModel):
    """Technology with no matching module in the Master NFR List. Carried to Stage 4 as its own highlighted item."""

    gap_type: Literal["unrecognized_tech_stack"] = "unrecognized_tech_stack"
    id: str
    highlight: bool = True
    kind: str  # language | framework | dependency | infrastructure | cloud_provider | manifest | api_style
    name: str
    found_as: str
    evidence: list[Evidence] = Field(default_factory=list)
    finding: str = "No module in the Master NFR List covers this technology."
    impact: str = (
        "Technology-specific requirements for it were not assessed; the service was checked against the baseline and "
        "cross-cutting modules only."
    )
    recommended_action: str = (
        "Review and add an NFR module for this technology to the Master NFR List (and entries in both telemetry catalogues), "
        "or add a `recognizes` rule if an existing module already covers it."
    )


class ModuleSummary(BaseModel):
    module_id: str
    title: str
    layer: str
    matched_by: list[str]
    assessed: int
    met: int = 0
    partially_met: int = 0
    missing: int = 0
    not_assessable: int = 0


class GapSummary(BaseModel):
    applicable_requirements: int
    by_status: dict[str, int]
    gaps_by_priority: dict[str, int]
    gap_count: int
    unrecognized_tech_gap_count: int
    assessed_by_llm: int
    failed_assessments: int = 0


class GapReport(BaseModel):
    schema_version: str = GAP_SCHEMA_VERSION
    pass_name: str = "gap_analysis_pass_1"
    service_name: str
    generated_at: datetime
    inputs: dict[str, Any]  # dataset schema/generation time, Master NFR List version, model backend: nothing else is used
    business_context: str | None = None
    summary: GapSummary
    modules: list[ModuleSummary]
    gaps: list[Gap]
    unrecognized_tech_gaps: list[UnrecognizedTechGap]
    assessments: list[Assessment]  # every applicable requirement incl. met and not_assessable, for traceability
    warnings: list[str] = Field(default_factory=list)
