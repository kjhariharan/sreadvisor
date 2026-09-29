"""FMEA (Failure Mode and Effects Analysis): reasoned from the service's architecture and dependencies as captured in
the Stage 1 consolidated dataset and, when available, Stage 5's runtime topology — never from incident history (this
version has none to reason from). One entry per plausible failure mode of one major dependency/component; a
component can have several distinct failure modes.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

from sreadvisor.schema.common import Evidence

FMEA_SCHEMA_VERSION = "1.0"

Severity = Literal["critical", "high", "medium", "low"]
Classification = Literal["hard_failure", "gracefully_degradable", "unknown"]
# code_and_infra: the component was found in the Stage 1 dataset (a traced dependency). runtime_only: found only via
# Stage 5's live topology (an undocumented dependency); Stage 1 never classified it, so its own resilience posture is
# unknown by definition.
ComponentOrigin = Literal["code_and_infra", "runtime_only"]


class FailureMode(BaseModel):
    id: str
    component: str
    component_kind: str
    origin: ComponentOrigin
    classification: Classification
    failure_mode: str
    likely_cause: str
    effect_on_transaction_flow: str
    affected_flows: list[str] = Field(default_factory=list)
    severity: Severity
    severity_rationale: str
    existing_mitigations: list[str] = Field(default_factory=list)
    related_gap_ids: list[str] = Field(default_factory=list)  # cross-referenced Stage 6 gap ids, when a name overlap is found
    evidence: list[Evidence] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class FmeaReport(BaseModel):
    schema_version: str = FMEA_SCHEMA_VERSION
    service_name: str
    generated_at: datetime
    inputs: dict[str, Any]
    business_context: str | None = None
    components_analyzed: int = 0
    failure_modes: list[FailureMode] = Field(default_factory=list)
    summary_by_severity: dict[str, int] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)
