"""Cross-validation of a live observability topology against the Stage 1 consolidated dataset.

Expressed in terms of the common runtime data schema (:mod:`sreadvisor.schema.runtime`): every dependency here, on
either side of the comparison, is represented as a :class:`TopologyNode`/:class:`TopologyEdge` pair (a code-only
dependency gets a synthetic node built from what Stage 1 found, so both sides of every finding share one shape).
Facts only, same as every other stage's dataset: this says what was and was not found on each side, not whether
either side is adequate — that is for Stage 6's gap analysis, which this is built to extend.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from sreadvisor.schema.common import Evidence
from sreadvisor.schema.runtime import ServiceMetrics, ServiceTopology, TopologyEdge, TopologyNode

CROSS_VALIDATION_SCHEMA_VERSION = "1.0"

MatchConfidence = Literal["high", "medium"]


class MatchedDependency(BaseModel):
    """A dependency both the code/infra analysis and the live topology agree on."""

    runtime_node: TopologyNode
    runtime_edge: TopologyEdge
    code_name: str
    code_kind: str
    code_evidence: list[Evidence] = Field(default_factory=list)
    matched_on: list[str]  # the name tokens shared by both sides
    confidence: MatchConfidence


class RuntimeOnlyDependency(BaseModel):
    """A topology neighbor the live provider shows that no Stage 1 dependency plausibly matches: an undeclared or
    transient dependency the code and infra analysis did not find."""

    node: TopologyNode
    edge: TopologyEdge
    reason: str = "no Stage 1 dependency with an overlapping name and a compatible kind was found"


class CodeOnlyDependency(BaseModel):
    """A dependency the Stage 1 transaction flows declared that has no corresponding live topology edge: not
    observed at runtime in the pulled window, or a naming mismatch the matcher could not bridge."""

    name: str
    kind: str
    evidence: list[Evidence] = Field(default_factory=list)
    reason: str = "no live topology edge with an overlapping name and a compatible kind was found"


class CrossValidationSummary(BaseModel):
    code_dependencies: int
    runtime_dependencies: int
    matched: int
    runtime_only: int
    code_only: int


class RuntimeCrossValidation(BaseModel):
    schema_version: str = CROSS_VALIDATION_SCHEMA_VERSION
    service_name: str
    provider: str
    service_id: str
    generated_at: datetime
    topology: ServiceTopology
    metrics: ServiceMetrics
    summary: CrossValidationSummary
    matched: list[MatchedDependency] = Field(default_factory=list)
    runtime_only: list[RuntimeOnlyDependency] = Field(default_factory=list)
    code_only: list[CodeOnlyDependency] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
