"""The Stage 4 unified report: one JSON document per service that combines the tech stack summary and transaction
flow (Stage 1), the gap list rewritten as action items (Stage 3), SLI suggestions, and the three telemetry tiers
(Stage 2), all cross-referenced so nothing needs a second lookup.

Nothing here re-invents a shape that already exists elsewhere in the pipeline: ``ActionItem`` extends Stage 3's
``Gap`` by one field, and the tech stack, transaction flow, telemetry tier and business context sections embed the
exact pydantic types Stage 1 and Stage 2 already produce. This is deliberate — the brief asks for a report "consistent
with the JSON format already used for the consolidated dataset, the Master NFR List, and the gap list, so every stage
of the pipeline speaks the same format end to end" — so a JSON consumer that already understands those documents
understands this one too.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

from sreadvisor.gap.schema import Gap, GapSummary, UnrecognizedTechGap
from sreadvisor.nfr.coverage import ApplicableModule
from sreadvisor.nfr.tiers import TelemetryTiers
from sreadvisor.schema.dataset import BusinessContext, EntryPoint, TechStackFingerprint, TransactionFlow

REPORT_SCHEMA_VERSION = "1.0"

SliKind = Literal["latency", "error_rate", "throughput", "saturation", "availability", "business"]
SliTier = Literal[1, 2, 3]


class ActionItem(Gap):
    """A Stage 3 gap rewritten so a developer can act on it directly, not just read it as a finding.

    Everything a ``Gap`` already carries (the requirement, why it is a gap, the dataset evidence, priority,
    confidence) is unchanged; ``action`` is the one thing this stage adds: a single imperative sentence naming what
    to add or complete and where, generated deterministically from the gap's own ``not_found`` list and evidence
    locations (see :mod:`sreadvisor.report.build`). No new judgment is made — the gap has already been judged.
    """

    action: str


class RepoSummary(BaseModel):
    """The tech stack summary and transaction flow for one repository, straight from the Stage 1 dataset."""

    repo: str
    path: str
    fingerprint: TechStackFingerprint
    entry_points: list[EntryPoint] = Field(default_factory=list)
    transaction_flows: list[TransactionFlow] = Field(default_factory=list)
    dependency_highlights: dict[str, list[str]] = Field(default_factory=dict)  # category -> "group:name" coordinates


class InfrastructureSummary(BaseModel):
    """Counts, not full objects: the full infrastructure analysis is already in the Stage 1 dataset."""

    workloads: int = 0
    autoscalers: int = 0
    disruption_budgets: int = 0
    services: int = 0
    ingresses: int = 0
    network_policies: int = 0
    compose_services: int = 0
    dockerfiles: int = 0
    helm_charts: int = 0
    terraform_resources: int = 0
    pipelines: int = 0
    mesh_present: bool = False


class SliSuggestion(BaseModel):
    """One proposed service level indicator, sourced from whichever telemetry tier can already measure it."""

    id: str
    name: str
    description: str
    kind: SliKind
    subject: str  # what this measures: an entry point, a dependency, or a business capability
    tier: SliTier
    tier_label: str
    measurement_source: str  # human-readable: "OneAgent: builtin:service.response.time", "Micrometer: kafka.consumer...", ...
    metric_key: str | None = None  # a concrete Dynatrace metric key, when tier 1 has one
    signal_type: str | None = None  # metric | trace | event | counter | timer | gauge | ... from the source catalogue
    rationale: str


class UnifiedReport(BaseModel):
    schema_version: str = REPORT_SCHEMA_VERSION
    service_name: str
    generated_at: datetime
    inputs: dict[str, Any]  # dataset + gap report provenance: nothing else feeds this stage

    business_context: BusinessContext | None = None
    completeness: dict[str, Any] = Field(default_factory=dict)  # ds.completeness, unchanged

    tech_stack: list[RepoSummary] = Field(default_factory=list)
    infrastructure: InfrastructureSummary = Field(default_factory=InfrastructureSummary)

    action_item_summary: GapSummary
    action_items: list[ActionItem] = Field(default_factory=list)  # ordered as Stage 3 ordered its gaps
    unrecognized_tech_gaps: list[UnrecognizedTechGap] = Field(default_factory=list)  # highlighted, kept separate

    applicable_modules: list[ApplicableModule] = Field(default_factory=list)
    sli_suggestions: list[SliSuggestion] = Field(default_factory=list)
    telemetry_tiers: TelemetryTiers

    warnings: list[str] = Field(default_factory=list)
