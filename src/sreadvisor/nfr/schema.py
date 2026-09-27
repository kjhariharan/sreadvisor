"""Schema of the Master NFR List and of the two telemetry catalogues.

The NFR schema deliberately does not freeze one field structure. A small required core exists so
Stage 3 can always rely on it (the requirement, the best practice it reflects, the audit requirement
tied to it, and the monitoring or telemetry that verifies it). Beyond that every entry model accepts
extra fields, and each module documents the extensions it uses in ``entry_extensions``. A module
that needs, say, ``kafka_property`` or ``sql_isolation_level`` simply adds it.

Three JSON files are produced from the YAML sources under ``nfr/data/src``:

* ``master_nfr_list.json``            flat, organised by module id (Stage 3 loads this)
* ``oneagent_default_catalogue.json`` tier 1: what Dynatrace OneAgent captures with zero configuration
* ``app_instrumentation_catalogue.json`` tier 2: what libraries inside the application emit
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

KB_SCHEMA_VERSION = "1.0"

Layer = Literal["baseline", "tech_stack", "cross_cutting"]
Priority = Literal["critical", "high", "medium", "low"]
SignalSource = Literal[
    "oneagent_default",  # tier 1: Dynatrace OneAgent, zero configuration
    "library_emitted",  # tier 2: metrics the application emits through library instrumentation
    "custom_instrumentation",  # tier 3: business-aware / new instrumentation
    "logs",
    "platform",  # Kubernetes / cloud provider / CI-CD platform signals
    "synthetic",
    "manual",  # verified by review, not by a signal
]
EvidenceSource = Literal["stage1_dataset", "runtime_telemetry", "manual_review"]
ModuleCategory = Literal[
    "baseline", "language", "framework", "architecture", "source_control", "cicd", "iac_container",
    "integration", "data", "security", "observability", "cross_cutting",
]

# Keys a detection rule may use. Values are a string or a list of strings (any of).
#   language / framework / entry_point / flow_dependency / infra / observability_provider : exact, case-insensitive
#   dependency (over "group:name") / image / terraform (resource type) : regular expression, case-insensitive
RULE_KEYS = ("language", "framework", "dependency", "infra", "image", "terraform", "observability_provider",
             "entry_point", "flow_dependency")
REGEX_KEYS = ("dependency", "image", "terraform")
# Vocabulary of the ``infra`` key (derived from the Stage 1 infrastructure section).
INFRA_SIGNALS = (
    "kubernetes", "openshift", "helm", "terraform", "docker", "docker_compose", "service_mesh", "mtls",
    "mesh_authorization", "network_policy", "github_actions", "gitlab_ci", "jenkins", "harness", "ucd",
    "azure_pipelines", "gcp",
)


class DetectRule(BaseModel):
    """All conditions in one rule must hold (AND). A module applies when any of its rules matches (OR)."""

    model_config = ConfigDict(extra="forbid")

    always: bool = False
    language: str | list[str] | None = None
    framework: str | list[str] | None = None
    dependency: str | list[str] | None = None
    infra: str | list[str] | None = None
    image: str | list[str] | None = None
    terraform: str | list[str] | None = None
    observability_provider: str | list[str] | None = None
    entry_point: str | list[str] | None = None
    flow_dependency: str | list[str] | None = None

    @model_validator(mode="after")
    def _non_empty(self) -> "DetectRule":
        if not self.always and not any(getattr(self, k) for k in RULE_KEYS):
            raise ValueError("a detect rule needs 'always: true' or at least one condition")
        infra = [self.infra] if isinstance(self.infra, str) else (self.infra or [])
        for value in infra:
            if value not in INFRA_SIGNALS:
                raise ValueError(f"unknown infra signal {value!r}; one of {', '.join(INFRA_SIGNALS)}")
        return self


class MonitoringSignal(BaseModel):
    """What to look at to verify the requirement holds in production."""

    model_config = ConfigDict(extra="forbid")

    source: SignalSource
    signal: str
    detail: str | None = None


class Verification(BaseModel):
    """How Stage 3 can check the entry. ``stage1_paths`` are dotted paths into the Stage 1 dataset
    (``[]`` marks a list); they are validated against the dataset schema at build time."""

    model_config = ConfigDict(extra="forbid")

    sources: list[EvidenceSource] = Field(min_length=1)
    stage1_paths: list[str] = Field(default_factory=list)
    criteria: str

    @model_validator(mode="after")
    def _paths_iff_dataset(self) -> "Verification":
        if "stage1_dataset" in self.sources and not self.stage1_paths:
            raise ValueError("sources include stage1_dataset but no stage1_paths are listed")
        return self


class NfrEntry(BaseModel):
    """One requirement. Extra keys are allowed so a module can extend the schema."""

    model_config = ConfigDict(extra="allow")

    id: str
    title: str
    requirement: str
    best_practice: str
    audit_requirement: str | None = None
    monitoring: list[MonitoringSignal] = Field(min_length=1)
    priority: Priority = "medium"
    verification: Verification
    extends: str | None = None  # id of the (usually baseline) entry this specialises
    tags: list[str] = Field(default_factory=list)

    @field_validator("title", "requirement", "best_practice")
    @classmethod
    def _not_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("must not be blank")
        return v.strip()


class NfrModule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    title: str
    layer: Layer
    category: ModuleCategory
    description: str
    extends: list[str] = Field(default_factory=list)  # tech-stack modules extend "baseline"
    detect: list[DetectRule] = Field(default_factory=list)  # applies when any rule matches
    recognizes: list[DetectRule] = Field(default_factory=list)  # covered by this module without triggering it
    entry_extensions: dict[str, str] = Field(default_factory=dict)  # documented extra entry fields
    catalogue_refs: list[str] = Field(default_factory=list)
    entries: list[NfrEntry] = Field(min_length=1)

    @model_validator(mode="after")
    def _shape(self) -> "NfrModule":
        if self.layer == "tech_stack" and "baseline" not in self.extends:
            raise ValueError("tech_stack modules must extend 'baseline'")
        if self.layer != "baseline" and not self.detect:
            raise ValueError("module needs at least one detect rule (cross-cutting modules use 'always: true')")
        prefix = self.entries[0].id.split("-", 1)[0]
        for e in self.entries:
            if not e.id.startswith(prefix + "-"):
                raise ValueError(f"entry id {e.id!r} does not share the module prefix {prefix!r}")
        return self


class MasterNfrList(BaseModel):
    """The flat JSON document Stage 3 loads: modules keyed by id, no further parsing needed."""

    model_config = ConfigDict(extra="forbid")

    kb_schema_version: str = KB_SCHEMA_VERSION
    description: str
    layers: dict[str, str]
    modules: dict[str, NfrModule]

    @model_validator(mode="after")
    def _consistent(self) -> "MasterNfrList":
        problems: list[str] = []
        seen: dict[str, str] = {}
        all_ids = {e.id for m in self.modules.values() for e in m.entries}
        for key, m in self.modules.items():
            if key != m.id:
                problems.append(f"module key {key!r} != module id {m.id!r}")
            for parent in m.extends:
                if parent not in self.modules:
                    problems.append(f"{m.id}: extends unknown module {parent!r}")
            for e in m.entries:
                if e.id in seen:
                    problems.append(f"duplicate entry id {e.id} in {m.id} and {seen[e.id]}")
                seen[e.id] = m.id
                if e.extends and e.extends not in all_ids:
                    problems.append(f"{e.id}: extends unknown entry {e.extends!r}")
        if not any(m.layer == "baseline" for m in self.modules.values()):
            problems.append("no baseline module")
        if problems:
            raise ValueError("; ".join(problems))
        return self

    def entries(self) -> list[tuple[NfrModule, NfrEntry]]:
        return [(m, e) for m in self.modules.values() for e in m.entries]


# ------------------------------------------------------------------- OneAgent default catalogue

SignalType = Literal["metric", "trace", "topology", "event", "log", "property"]


class OneAgentSignal(BaseModel):
    """Something OneAgent captures out of the box (default, zero-configuration monitoring)."""

    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    category: str  # throughput | latency | errors | runtime | resources | topology | tracing | database | messaging | availability
    signal_type: SignalType = "metric"
    metric_key: str | None = None  # Dynatrace metric key where one exists; verify against the tenant before relying on it (Stage 4 uses this to build a dashboard)
    description: str
    prerequisite: str | None = None  # platform-level deployment needed, never per-service configuration
    confidence: Literal["high", "medium"] = "high"


class NotCoveredByDefault(BaseModel):
    model_config = ConfigDict(extra="forbid")

    signal: str
    why: str
    likely_source: Literal["library_emitted", "custom_instrumentation", "extension", "other_integration"]


class OneAgentModule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    support_level: Literal["full", "partial", "limited", "none"]
    summary: str
    inherits: list[str] = Field(default_factory=list)  # signals of these modules also apply
    signals: list[OneAgentSignal] = Field(default_factory=list)
    not_covered_by_default: list[NotCoveredByDefault] = Field(default_factory=list)


class OneAgentCatalogue(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kb_schema_version: str = KB_SCHEMA_VERSION
    tier: Literal["oneagent_default"] = "oneagent_default"
    coverage: Literal["default_out_of_the_box"] = "default_out_of_the_box"
    description: str
    provenance: str
    modules: dict[str, OneAgentModule]

    @model_validator(mode="after")
    def _consistent(self) -> "OneAgentCatalogue":
        problems: list[str] = []
        ids: set[str] = set()
        for key, m in self.modules.items():
            for parent in m.inherits:
                if parent not in self.modules:
                    problems.append(f"{key}: inherits unknown module {parent!r}")
            for s in m.signals:
                if s.id in ids:
                    problems.append(f"duplicate OneAgent signal id {s.id}")
                ids.add(s.id)
            if m.support_level == "none" and m.signals:
                problems.append(f"{key}: support_level none but signals listed")
        if problems:
            raise ValueError("; ".join(problems))
        return self


# ----------------------------------------------------------- application-level instrumentation


class LibraryMetric(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    type: Literal["counter", "gauge", "timer", "histogram", "summary", "distribution", "span", "other"] = "other"
    unit: str | None = None
    description: str
    # The metric exists only when the service has this kind of dependency (Stage 1 dependency category) or this coordinate.
    requires_category: str | None = None
    requires_dependency: str | None = None
    enabled_by_default: bool = True
    note: str | None = None


class InstrumentationLibrary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    library: str
    stage1_kind: str | None = None  # kind used by Stage 1 telemetry detection (micrometer, opentelemetry, ...)
    detect: DetectRule  # how a service is recognised as using it (Stage 1 fingerprint)
    configuration: str  # how it is enabled / configured
    export: str  # how its metrics leave the process
    metrics: list[LibraryMetric] = Field(default_factory=list)
    confidence: Literal["high", "medium"] = "high"


class InstrumentationModule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    summary: str
    libraries: list[InstrumentationLibrary] = Field(default_factory=list)
    reason_none: str | None = None  # required when there are no libraries

    @model_validator(mode="after")
    def _explain_empty(self) -> "InstrumentationModule":
        if not self.libraries and not self.reason_none:
            raise ValueError("module lists no libraries, so reason_none must explain why")
        return self


class AppInstrumentationCatalogue(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kb_schema_version: str = KB_SCHEMA_VERSION
    tier: Literal["application_level_library_emitted"] = "application_level_library_emitted"
    coverage: Literal["application_level_library_emitted"] = "application_level_library_emitted"
    description: str
    provenance: str
    overlap_policy: str
    modules: dict[str, InstrumentationModule]

    @model_validator(mode="after")
    def _unique_libs(self) -> "AppInstrumentationCatalogue":
        seen: set[str] = set()
        dupes = {lib.id for m in self.modules.values() for lib in m.libraries if lib.id in seen or seen.add(lib.id)}
        if dupes:
            raise ValueError(f"library ids repeated across modules: {sorted(dupes)}")
        return self


def model_json(model: BaseModel) -> dict[str, Any]:
    return model.model_dump(mode="json", exclude_none=True, exclude_defaults=False)
