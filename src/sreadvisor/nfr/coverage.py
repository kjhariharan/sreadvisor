"""NFR coverage of one service: which Master NFR List modules apply, which technologies have no module,
and the three telemetry tiers. Facts about coverage of the knowledge base only; no gap analysis (Stage 3).
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from pydantic import BaseModel, Field

from sreadvisor.nfr.detect import applicable_modules, signals_from_dataset, unrecognized_technologies
from sreadvisor.nfr.loader import load_app_catalogue, load_master, load_oneagent
from sreadvisor.nfr.schema import AppInstrumentationCatalogue, MasterNfrList, OneAgentCatalogue
from sreadvisor.nfr.tiers import TelemetryTiers, build_tiers
from sreadvisor.schema.common import Evidence
from sreadvisor.schema.dataset import ServiceDataset

_ACTION = (
    "No module in the Master NFR List covers this. Review it and add an NFR module "
    "(nfr/data/src/modules/<id>.yaml, then `sreadvisor nfr build`), plus entries in both telemetry catalogues, "
    "so the list stays current. Until then this technology is evaluated against the baseline and cross-cutting modules only."
)


class ApplicableModule(BaseModel):
    id: str
    title: str
    layer: str
    category: str
    matched_by: list[str]
    entry_count: int
    entries_by_priority: dict[str, int] = Field(default_factory=dict)


class UnrecognizedStack(BaseModel):
    kind: str  # language | framework | dependency | infrastructure | cloud_provider | manifest
    name: str
    detail: str
    evidence: list[Evidence] = Field(default_factory=list)
    action: str = _ACTION


class NfrCoverage(BaseModel):
    service_name: str
    generated_at: datetime
    kb_schema_version: str
    dataset_schema_version: str
    applicable_modules: list[ApplicableModule]
    modules_not_applicable: list[str]
    applicable_entry_count: int
    unrecognized_tech_stacks: list[UnrecognizedStack]
    telemetry_tiers: TelemetryTiers


def compute_coverage(
    ds: ServiceDataset,
    kb: MasterNfrList | None = None,
    oneagent: OneAgentCatalogue | None = None,
    app: AppInstrumentationCatalogue | None = None,
) -> NfrCoverage:
    kb = kb or load_master()
    oneagent = oneagent or load_oneagent()
    app = app or load_app_catalogue()
    sig = signals_from_dataset(ds)
    matched = applicable_modules(kb, sig)
    matched_ids = [m.module.id for m in matched]

    modules = [
        ApplicableModule(
            id=m.module.id, title=m.module.title, layer=m.module.layer, category=m.module.category, matched_by=m.reasons,
            entry_count=len(m.module.entries),
            entries_by_priority=dict(Counter(e.priority for e in m.module.entries)),
        )
        for m in matched
    ]
    return NfrCoverage(
        service_name=ds.service_name,
        generated_at=datetime.now(timezone.utc),
        kb_schema_version=kb.kb_schema_version,
        dataset_schema_version=ds.schema_version,
        applicable_modules=modules,
        modules_not_applicable=sorted(set(kb.modules) - set(matched_ids)),
        applicable_entry_count=sum(m.entry_count for m in modules),
        unrecognized_tech_stacks=[UnrecognizedStack(kind=u.kind, name=u.name, detail=u.detail, evidence=u.evidence)
                                  for u in unrecognized_technologies(kb, ds)],
        telemetry_tiers=build_tiers(ds, oneagent, app, matched_ids),
    )


def load_dataset(path: str | Path) -> ServiceDataset:
    return ServiceDataset.model_validate_json(Path(path).read_text(encoding="utf-8"))
