"""The three tiers of telemetry for one service, in the shape Stage 4's dashboard generator consumes.

Tier 1  OneAgent default        what Dynatrace OneAgent captures with zero configuration
Tier 2  application / library   what the application already emits (Micrometer, OpenTelemetry, Kafka client, ...)
Tier 3  custom instrumentation  business-aware metrics; concrete suggestions are proposed in Stage 4 (see report.sli)

The tiers are kept in separate structures and never merged: OneAgent's signals and a library's metrics
are not assumed to overlap. ``metric_index`` flattens them into one list with an explicit tier tag so a
dashboard can show tier 1 by default and let an SRE pick additions from tiers 2 and 3.
"""

from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, Field

from sreadvisor.nfr.detect import Signals, rule_match, signals_from_dataset
from sreadvisor.nfr.schema import (
    AppInstrumentationCatalogue,
    InstrumentationLibrary,
    LibraryMetric,
    NotCoveredByDefault,
    OneAgentCatalogue,
    OneAgentSignal,
)
from sreadvisor.schema.dataset import ServiceDataset

TIER1_TAG = "oneagent_default"
TIER2_TAG = "application_level_library_emitted"
TIER3_TAG = "custom_instrumentation"


# ------------------------------------------------------------------------- OneAgent (tier 1)


def resolve_oneagent(cat: OneAgentCatalogue, module_id: str) -> list[str]:
    """Module ids whose signals apply to ``module_id``: itself plus everything it inherits, depth first."""
    order: list[str] = []

    def walk(mid: str) -> None:
        if mid in order or mid not in cat.modules:
            return
        order.append(mid)
        for parent in cat.modules[mid].inherits:
            walk(parent)

    walk(module_id)
    return order


class Tier1Signal(BaseModel):
    signal: OneAgentSignal
    defined_in: str  # catalogue module that owns the signal
    applies_via: list[str]  # the service's matched modules that bring it in


class Tier1NotCovered(BaseModel):
    item: NotCoveredByDefault
    defined_in: str
    applies_via: list[str]


class Tier1Module(BaseModel):
    module: str
    support_level: str
    summary: str


class Tier1(BaseModel):
    tag: str = TIER1_TAG
    coverage: str = "default_out_of_the_box"
    modules: list[Tier1Module] = Field(default_factory=list)
    signals: list[Tier1Signal] = Field(default_factory=list)
    not_covered_by_default: list[Tier1NotCovered] = Field(default_factory=list)


def build_tier1(cat: OneAgentCatalogue, matched_modules: list[str]) -> Tier1:
    roots = ["oneagent_platform", *[m for m in matched_modules if m in cat.modules]]
    signals: dict[str, Tier1Signal] = {}
    gaps: dict[tuple[str, str], Tier1NotCovered] = {}
    mods: list[Tier1Module] = []
    for root in dict.fromkeys(roots):
        for mid in resolve_oneagent(cat, root):
            m = cat.modules[mid]
            for s in m.signals:
                entry = signals.setdefault(s.id, Tier1Signal(signal=s, defined_in=mid, applies_via=[]))
                if root not in entry.applies_via:
                    entry.applies_via.append(root)
            for g in m.not_covered_by_default:
                entry = gaps.setdefault((mid, g.signal), Tier1NotCovered(item=g, defined_in=mid, applies_via=[]))
                if root not in entry.applies_via:
                    entry.applies_via.append(root)
        m = cat.modules[root]
        mods.append(Tier1Module(module=root, support_level=m.support_level, summary=m.summary))
    return Tier1(modules=mods, signals=list(signals.values()), not_covered_by_default=list(gaps.values()))


# ----------------------------------------------------------------- application level (tier 2)


def applicable_metrics(lib: InstrumentationLibrary, categories: set[str], coords: list[str]) -> list[LibraryMetric]:
    """Metrics the library emits for this service: those with no precondition, or whose precondition holds."""
    out = []
    for m in lib.metrics:
        if m.requires_category and m.requires_category not in categories:
            continue
        if m.requires_dependency and not any(re.search(m.requires_dependency, c, re.I) for c in coords):
            continue
        out.append(m)
    return out


def documented_metrics(app: AppInstrumentationCatalogue, kind: str, coords: list[str], categories: set[str]) -> tuple[list[str], str]:
    """Metric names for a Stage 1 telemetry library ``kind``, chosen from the catalogue (single source of truth)."""
    libs = [lib for m in app.modules.values() for lib in m.libraries if lib.stage1_kind == kind]
    sig = Signals(dependencies=coords)
    chosen = [lib for lib in libs if rule_match(lib.detect, sig)] or libs
    names: list[str] = []
    for lib in chosen:
        for m in applicable_metrics(lib, categories, coords):
            if m.name not in names:
                names.append(m.name)
    return names, "application instrumentation catalogue: " + ", ".join(lib.library for lib in chosen) if chosen else ""


class DetectedLibrary(BaseModel):
    library_id: str
    library: str
    module: str
    detected_because: str
    configuration: str  # how the library is enabled (from the catalogue)
    export: str
    configuration_found: list[dict[str, Any]] = Field(default_factory=list)  # settings found in the service (Stage 1)
    metrics: list[LibraryMetric] = Field(default_factory=list)
    custom_metrics_found: list[dict[str, Any]] = Field(default_factory=list)  # instrumented in the service's own code
    confidence: str = "high"


class AvailableLibrary(BaseModel):
    library_id: str
    library: str
    module: str
    metric_names: list[str]
    note: str = "Not detected in this service; would emit these metrics if added."


class Tier2(BaseModel):
    tag: str = TIER2_TAG
    coverage: str = TIER2_TAG
    detected_in_service: list[DetectedLibrary] = Field(default_factory=list)
    available_not_detected: list[AvailableLibrary] = Field(default_factory=list)
    modules_without_library_metrics: dict[str, str] = Field(default_factory=dict)


def build_tier2(app: AppInstrumentationCatalogue, ds: ServiceDataset, sig: Signals, matched_modules: list[str]) -> Tier2:
    categories = {c for r in ds.repositories for d in r.fingerprint.dependencies if "test" not in d.categories for c in d.categories}
    stage1 = {lib.kind: lib for r in ds.repositories for lib in r.telemetry.libraries}
    detected: list[DetectedLibrary] = []
    available: list[AvailableLibrary] = []
    none: dict[str, str] = {}
    for mid, mod in app.modules.items():
        if not mod.libraries and mid in matched_modules and mod.reason_none:
            none[mid] = mod.reason_none
        for lib in mod.libraries:
            reason = rule_match(lib.detect, sig)
            if reason:
                s1 = stage1.get(lib.stage1_kind or "")
                detected.append(DetectedLibrary(
                    library_id=lib.id, library=lib.library, module=mid, detected_because=reason,
                    configuration=lib.configuration, export=lib.export,
                    configuration_found=list(s1.configuration) if s1 else [],
                    metrics=applicable_metrics(lib, categories, sig.dependencies),
                    custom_metrics_found=list(s1.custom_metrics) if s1 else [], confidence=lib.confidence))
            elif mid in matched_modules and lib.metrics:
                available.append(AvailableLibrary(library_id=lib.id, library=lib.library, module=mid,
                                                  metric_names=[m.name for m in lib.metrics]))
    return Tier2(detected_in_service=detected, available_not_detected=available, modules_without_library_metrics=none)


# ----------------------------------------------------------------------- custom (tier 3)


class Tier3(BaseModel):
    tag: str = TIER3_TAG
    status: str = "pending_stage5"
    note: str = (
        "Concrete business-aware custom metrics are suggested in Stage 4 (report.sli) from the business context below, for capabilities that neither "
        "OneAgent defaults (tier 1) nor library metrics (tier 2) express."
    )
    business_capability: str | None = None
    business_category: str | None = None
    key_operations: list[str] = Field(default_factory=list)
    domain_entities: list[str] = Field(default_factory=list)


def build_tier3(ds: ServiceDataset) -> Tier3:
    b = ds.business_context
    if not b:
        return Tier3()
    return Tier3(business_capability=b.capability, business_category=b.category,
                 key_operations=list(b.key_operations), domain_entities=list(b.domain_entities))


# ------------------------------------------------------------------------------ flat index


class MetricIndexEntry(BaseModel):
    name: str
    tier: int
    tier_tag: str
    module: str
    source: str  # "oneagent" or the library id
    metric_key: str | None = None
    category: str | None = None
    present_in_service: bool | None = None  # tier 2 only: the library was detected in the service
    default_on: bool | None = None  # tier 2 only: emitted without extra configuration


class TelemetryTiers(BaseModel):
    overlap_policy: str
    tier1_oneagent_default: Tier1
    tier2_application_library: Tier2
    tier3_custom_instrumentation: Tier3
    metric_index: list[MetricIndexEntry] = Field(default_factory=list)


def build_tiers(ds: ServiceDataset, oneagent: OneAgentCatalogue, app: AppInstrumentationCatalogue,
                matched_modules: list[str]) -> TelemetryTiers:
    sig = signals_from_dataset(ds)
    t1 = build_tier1(oneagent, matched_modules)
    t2 = build_tier2(app, ds, sig, matched_modules)
    t3 = build_tier3(ds)
    index: list[MetricIndexEntry] = []
    for s in t1.signals:
        if s.signal.signal_type == "metric":
            index.append(MetricIndexEntry(name=s.signal.name, tier=1, tier_tag=TIER1_TAG, module=s.defined_in, source="oneagent",
                                          metric_key=s.signal.metric_key, category=s.signal.category))
    seen_detected: set[str] = set()  # one entry per meter name even when two libraries can emit it (for example cache.gets)
    for d in t2.detected_in_service:
        for m in d.metrics:
            if m.name in seen_detected:
                continue
            seen_detected.add(m.name)
            index.append(MetricIndexEntry(name=m.name, tier=2, tier_tag=TIER2_TAG, module=d.module, source=d.library_id,
                                          present_in_service=True, default_on=m.enabled_by_default))
    for a in t2.available_not_detected:
        for n in a.metric_names:
            index.append(MetricIndexEntry(name=n, tier=2, tier_tag=TIER2_TAG, module=a.module, source=a.library_id,
                                          present_in_service=False))
    return TelemetryTiers(overlap_policy=app.overlap_policy, tier1_oneagent_default=t1, tier2_application_library=t2,
                          tier3_custom_instrumentation=t3, metric_index=index)
