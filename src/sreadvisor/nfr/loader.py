"""Build, validate and load the knowledge base.

Authoring happens in YAML under ``nfr/data/src`` (comments, no quoting noise). ``build`` compiles it
into three flat JSON files next to it. Stage 3 and the report only ever read the JSON, so no parsing
logic is needed downstream; a test asserts the committed JSON is exactly what the sources compile to.
"""

from __future__ import annotations

import json
import types
import typing
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel

from sreadvisor.nfr.schema import AppInstrumentationCatalogue, MasterNfrList, OneAgentCatalogue
from sreadvisor.schema.dataset import ServiceDataset

DATA_DIR = Path(__file__).with_name("data")
SRC_DIR = DATA_DIR / "src"
MASTER_FILE = "master_nfr_list.json"
ONEAGENT_SHARED = {"oneagent_platform", "oneagent_service_layer"}  # signals shared by many modules via inherits
ONEAGENT_FILE = "oneagent_default_catalogue.json"
APP_FILE = "app_instrumentation_catalogue.json"


class KnowledgeBaseError(RuntimeError):
    pass


# ------------------------------------------------------------------------------------ build


def _yaml(path: Path) -> Any:
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise KnowledgeBaseError(f"{path.name}: invalid YAML: {exc}") from exc


def _dump(model: BaseModel) -> dict[str, Any]:
    doc = model.model_dump(mode="json", exclude_none=True)
    # The four core NFR fields are always present as keys so consumers never need a default.
    for module in doc.get("modules", {}).values():
        for entry in module.get("entries", []) if isinstance(module, dict) else []:
            entry.setdefault("audit_requirement", None)
    return doc


def build(src_dir: Path = SRC_DIR) -> dict[str, dict[str, Any]]:
    """Compile the YAML sources into the three JSON documents (validated, deterministic)."""
    header = _yaml(src_dir / "master.yaml")
    modules: dict[str, Any] = {}
    for f in sorted((src_dir / "modules").glob("*.yaml")):
        doc = _yaml(f)
        if not isinstance(doc, dict) or "id" not in doc:
            raise KnowledgeBaseError(f"{f.name}: a module file must be a mapping with an 'id'")
        if doc["id"] in modules:
            raise KnowledgeBaseError(f"{f.name}: duplicate module id {doc['id']!r}")
        modules[doc["id"]] = doc
    try:
        master = MasterNfrList(**header, modules=modules)
        oneagent = OneAgentCatalogue(**_yaml(src_dir / "oneagent.yaml"))
        app = AppInstrumentationCatalogue(**_yaml(src_dir / "instrumentation.yaml"))
    except Exception as exc:
        raise KnowledgeBaseError(f"knowledge base is invalid: {exc}") from exc
    problems = check_consistency(master, oneagent, app)
    if problems:
        raise KnowledgeBaseError("knowledge base is inconsistent:\n  - " + "\n  - ".join(problems))
    return {MASTER_FILE: _dump(master), ONEAGENT_FILE: _dump(oneagent), APP_FILE: _dump(app)}


def render(doc: dict[str, Any]) -> str:
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"


def write_built(out_dir: Path = DATA_DIR, src_dir: Path = SRC_DIR) -> list[Path]:
    out = []
    for name, doc in build(src_dir).items():
        p = out_dir / name
        p.write_text(render(doc), encoding="utf-8")
        out.append(p)
    load_master.cache_clear()
    load_oneagent.cache_clear()
    load_app_catalogue.cache_clear()
    return out


def is_up_to_date(out_dir: Path = DATA_DIR, src_dir: Path = SRC_DIR) -> list[str]:
    """Names of built files that are missing or differ from what the sources compile to."""
    stale = []
    for name, doc in build(src_dir).items():
        p = out_dir / name
        if not p.is_file() or p.read_text(encoding="utf-8") != render(doc):
            stale.append(name)
    return stale


# ---------------------------------------------------------------------------------- load


def _read(path: Path, model: type[BaseModel]):
    if not path.is_file():
        raise KnowledgeBaseError(f"{path} not found. Build it with: sreadvisor nfr build")
    try:
        return model.model_validate_json(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise KnowledgeBaseError(f"{path} is malformed: {exc}") from exc


@lru_cache(maxsize=4)
def load_master(path: str | None = None) -> MasterNfrList:
    return _read(Path(path) if path else DATA_DIR / MASTER_FILE, MasterNfrList)


@lru_cache(maxsize=4)
def load_oneagent(path: str | None = None) -> OneAgentCatalogue:
    return _read(Path(path) if path else DATA_DIR / ONEAGENT_FILE, OneAgentCatalogue)


@lru_cache(maxsize=4)
def load_app_catalogue(path: str | None = None) -> AppInstrumentationCatalogue:
    return _read(Path(path) if path else DATA_DIR / APP_FILE, AppInstrumentationCatalogue)


# ---------------------------------------------------------------------------- consistency


def _unwrap(tp: Any) -> Any:
    """Strip Optional / list / dict wrappers down to the model (or Any) a path segment continues into."""
    origin = typing.get_origin(tp)
    if origin in (typing.Union, types.UnionType):
        args = [a for a in typing.get_args(tp) if a is not type(None)]
        return _unwrap(args[0]) if len(args) == 1 else Any
    if origin is list:
        return _unwrap(typing.get_args(tp)[0])
    if origin is dict:
        return Any
    return tp


def path_exists(model: type[BaseModel], path: str) -> bool:
    """True if a dotted Stage 1 dataset path (``a.b[].c``) names a field of the dataset schema."""
    current: Any = model
    segments = path.split(".")
    for idx, segment in enumerate(segments):
        name = segment.removesuffix("[]")
        if current is Any or not (isinstance(current, type) and issubclass(current, BaseModel)):
            return True  # free-form dict / Any below this point: cannot be checked further
        field = current.model_fields.get(name)
        if field is None:
            return False
        is_list = typing.get_origin(field.annotation) is list or (
            typing.get_origin(field.annotation) in (typing.Union, types.UnionType)
            and any(typing.get_origin(a) is list for a in typing.get_args(field.annotation)))
        has_brackets = segment.endswith("[]")
        if has_brackets and not is_list:
            return False
        if is_list and not has_brackets and idx != len(segments) - 1:
            return False  # `[]` may only be omitted on the last segment (a list of plain values)
        current = _unwrap(field.annotation)
    return True


def check_consistency(master: MasterNfrList, oneagent: OneAgentCatalogue, app: AppInstrumentationCatalogue) -> list[str]:
    problems: list[str] = []
    for module, entry in master.entries():
        for p in entry.verification.stage1_paths:
            if not path_exists(ServiceDataset, p):
                problems.append(f"{entry.id}: stage1 path {p!r} does not exist in the Stage 1 dataset schema")
    tech = {m.id for m in master.modules.values() if m.layer != "baseline"}
    for label, cat in (("oneagent", oneagent.modules), ("instrumentation", app.modules)):
        for mid in cat:
            if mid not in master.modules and not (label == "oneagent" and mid in ONEAGENT_SHARED):
                problems.append(f"{label} catalogue lists module {mid!r} that is not in the Master NFR List")
        missing = sorted(m for m in tech if m not in cat and master.modules[m].layer == "tech_stack")
        if missing:
            problems.append(f"{label} catalogue has no entry (not even an explicit 'none') for tech-stack modules: {missing}")
    for m in master.modules.values():
        for ref in m.catalogue_refs:
            if ref not in ("oneagent_default", "application_level"):
                problems.append(f"{m.id}: unknown catalogue_ref {ref!r}")
    return problems
