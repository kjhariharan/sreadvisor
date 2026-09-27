"""Operations runbook (Stage 6): one entry per FMEA failure mode, structured for use during a live failure —
detection signals, immediate actions, and an escalation path. Built from the FMEA output plus the same architecture
and dependency data; never re-derives or contradicts the FMEA's own failure mode, effect or severity, only adds what
the FMEA does not already determine.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from sreadvisor.fmea.schema import ComponentOrigin, Severity

RUNBOOK_SCHEMA_VERSION = "1.0"


class RunbookEntry(BaseModel):
    id: str
    fmea_id: str  # the FailureMode this entry is for
    component: str
    component_kind: str
    origin: ComponentOrigin
    severity: Severity
    failure_mode: str
    effect_on_transaction_flow: str
    detection_signals: list[str] = Field(default_factory=list)
    immediate_actions: list[str] = Field(default_factory=list)
    escalate_to: str
    escalate_when: str
    related_gap_ids: list[str] = Field(default_factory=list)


class Runbook(BaseModel):
    schema_version: str = RUNBOOK_SCHEMA_VERSION
    service_name: str
    generated_at: datetime
    inputs: dict[str, Any]
    business_context: str | None = None
    entries: list[RunbookEntry] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
