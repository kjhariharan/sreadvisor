"""Pydantic contracts for what each LLM agent must return (validated after every call)."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, field_validator


class _Loc(BaseModel):
    file: str
    line: int


class _OptLoc(BaseModel):
    file: str | None = None
    line: int | None = None


class FlowStepOut(_OptLoc):
    order: int = 0
    layer: str
    symbol: str
    action: str
    target_type: str | None = None
    target_name: str | None = None


class FlowDependencyOut(_OptLoc):
    name: str
    kind: str


class FlowTraceOut(BaseModel):
    summary: str
    steps: list[FlowStepOut] = Field(default_factory=list)
    dependencies: list[FlowDependencyOut] = Field(default_factory=list)


class ReliabilityPatternOut(_OptLoc):
    pattern: str
    mechanism: str
    protects: str | None = None
    parameters: dict[str, Any] = Field(default_factory=dict)
    note: str | None = None


class ReliabilityOut(BaseModel):
    patterns: list[ReliabilityPatternOut] = Field(default_factory=list)


class DegradableFlowOut(BaseModel):
    entry_point: str
    reason: str
    file: str | None = None
    line: int | None = None


class ClassificationOut(BaseModel):
    classification: str  # hard_failure | gracefully_degradable
    rationale: str
    protecting_patterns: list[str] = Field(default_factory=list)
    degradable_flows: list[DegradableFlowOut] = Field(default_factory=list)
    blast_radius_description: str | None = None
    evidence: list[_Loc] = Field(default_factory=list)


class BusinessContextOut(BaseModel):
    capability: str
    category: str
    rationale: str
    domain_entities: list[str] = Field(default_factory=list)
    key_operations: list[str] = Field(default_factory=list)
    confidence: str = "medium"
    evidence: list[_Loc] = Field(default_factory=list)


_SHOWS = {"satisfied": "satisfied", "satisfies": "satisfied", "met": "satisfied", "pass": "satisfied", "ok": "satisfied",
          "shortfall": "shortfall", "gap": "shortfall", "missing": "shortfall", "not_met": "shortfall", "fail": "shortfall",
          "violation": "shortfall"}


class GapRefOut(BaseModel):
    file: str | None = None
    line: int | None = None
    path: str | None = None
    note: str = ""
    shows: str | None = None  # satisfied | shortfall: does this citation show the requirement holding, or falling short?

    @field_validator("shows")
    @classmethod
    def _norm_shows(cls, v: str | None) -> str | None:
        return None if v is None else _SHOWS.get(v.strip().lower().replace(" ", "_").replace("-", "_"))


GAP_STATUS_ALIASES = {
    "met": "met", "satisfied": "met", "fully_met": "met", "pass": "met",
    "partially_met": "partially_met", "partial": "partially_met", "partially_satisfied": "partially_met",
    "missing": "missing", "not_met": "missing", "unmet": "missing", "absent": "missing", "fail": "missing",
    "not_assessable": "not_assessable", "unknown": "not_assessable", "cannot_determine": "not_assessable",
    "not_determinable": "not_assessable", "insufficient_evidence": "not_assessable",
}


_SEVERITY_ALIASES = {"critical": "critical", "sev1": "critical", "p1": "critical",
                    "high": "high", "sev2": "high", "p2": "high",
                    "medium": "medium", "med": "medium", "sev3": "medium", "p3": "medium",
                    "low": "low", "sev4": "low", "p4": "low"}


class FailureModeOut(BaseModel):
    failure_mode: str
    likely_cause: str
    effect_on_transaction_flow: str
    affected_flows: list[str] = Field(default_factory=list)
    severity: str = "medium"
    severity_rationale: str
    existing_mitigations: list[str] = Field(default_factory=list)

    @field_validator("severity")
    @classmethod
    def _norm_severity(cls, v: str) -> str:
        norm = _SEVERITY_ALIASES.get(v.strip().lower().replace(" ", "_").replace("-", "_"))
        if norm is None:
            raise ValueError("severity must be one of: critical, high, medium, low")
        return norm

    @field_validator("failure_mode", "severity_rationale")
    @classmethod
    def _not_blank(cls, v: str) -> str:
        if len(v.strip()) < 4:
            raise ValueError("must not be blank")
        return v


class FmeaComponentOut(BaseModel):
    failure_modes: list[FailureModeOut] = Field(default_factory=list)


class RunbookStepsOut(BaseModel):
    detection_signals: list[str] = Field(default_factory=list)
    immediate_actions: list[str] = Field(default_factory=list)
    escalate_to: str
    escalate_when: str

    @field_validator("escalate_to", "escalate_when")
    @classmethod
    def _not_blank2(cls, v: str) -> str:
        if len(v.strip()) < 4:
            raise ValueError("must not be blank")
        return v


class GapAssessmentOut(BaseModel):
    status: str  # met | partially_met | missing | not_assessable
    confidence: str = "medium"
    rationale: str
    found: list[GapRefOut] = Field(default_factory=list)
    not_found: list[str] = Field(default_factory=list)

    @field_validator("status")
    @classmethod
    def _known_status(cls, v: str) -> str:
        norm = GAP_STATUS_ALIASES.get(v.strip().lower().replace(" ", "_").replace("-", "_"))
        if norm is None:
            raise ValueError("status must be one of: met, partially_met, missing, not_assessable")
        return norm

    @field_validator("rationale")
    @classmethod
    def _has_rationale(cls, v: str) -> str:
        if len(v.strip()) < 8 or v.strip() in ("...", "<one to three sentences>"):
            raise ValueError("rationale must explain the status in a sentence")
        return v
