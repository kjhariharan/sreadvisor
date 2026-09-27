"""Read and edit the Master NFR List from the UI.

The YAML sources under ``nfr/data/src`` stay the single source of truth; the JSON Stage 3 loads is rebuilt from them. An edit is applied only
after the *whole* knowledge base validates in a scratch copy (schema, cross references, catalogue coverage, every ``stage1_path``), the
previous file is backed up, and edits are protected by an etag so a hand edit made in between is never silently overwritten.
"""

from __future__ import annotations

import hashlib
import re
import shutil
import tempfile
import types
import typing
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ValidationError

from sreadvisor.nfr import loader
from sreadvisor.nfr import schema as S
from sreadvisor.schema.dataset import ServiceDataset

_ID = re.compile(r"^[a-z][a-z0-9_]{1,48}$")
_PREFIX = re.compile(r"^[A-Z][A-Z0-9]{1,7}$")
_FILE_PREFIX = {"baseline": "00", "tech_stack": "65", "cross_cutting": "96"}


class StoreError(Exception):
    """A request that cannot be applied. ``problems`` are shown to the user next to the form."""

    def __init__(self, message: str, problems: list[dict[str, str]] | None = None, status: int = 422) -> None:
        super().__init__(message)
        self.message, self.problems, self.status = message, problems or [], status


def _dump(data: Any) -> str:
    return yaml.safe_dump(data, sort_keys=False, allow_unicode=True, width=140, default_flow_style=False)


def _etag(path: Path) -> str:
    return hashlib.sha1(path.read_bytes()).hexdigest()[:16]


def _loc(loc: tuple) -> str:
    out = ""
    for part in loc:
        out += f"[{part}]" if isinstance(part, int) else (f".{part}" if out else str(part))
    return out


def _literal_values(tp: Any) -> list[str]:
    return [a for a in typing.get_args(tp) if isinstance(a, str)]


class NfrStore:
    def __init__(self, src_dir: Path = loader.SRC_DIR, data_dir: Path = loader.DATA_DIR, backup_dir: Path | None = None) -> None:
        self.src, self.data = Path(src_dir), Path(data_dir)
        self.backups = Path(backup_dir) if backup_dir else self.src.parent.parent.parent.parent.parent / ".sreadvisor" / "nfr_backups"

    # ------------------------------------------------------------------------------ reading

    def _files(self) -> dict[str, Path]:
        out: dict[str, Path] = {}
        for f in sorted((self.src / "modules").glob("*.yaml")):
            doc = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
            if isinstance(doc, dict) and doc.get("id"):
                out[str(doc["id"])] = f
        return out

    def list_modules(self) -> list[dict[str, Any]]:
        rows = []
        for mid, f in self._files().items():
            d = yaml.safe_load(f.read_text(encoding="utf-8"))
            entries = d.get("entries") or []
            rows.append({
                "id": mid, "title": d.get("title"), "layer": d.get("layer"), "category": d.get("category"),
                "description": d.get("description"), "entry_count": len(entries), "extends": d.get("extends") or [],
                "detect_rules": len(d.get("detect") or []), "file": f.name,
                "priorities": {p: sum(1 for e in entries if e.get("priority", "medium") == p) for p in _literal_values(S.Priority)},
            })
        return rows

    def get_module(self, module_id: str) -> dict[str, Any]:
        f = self._files().get(module_id)
        if f is None:
            raise StoreError(f"unknown module {module_id!r}", status=404)
        return {"module": yaml.safe_load(f.read_text(encoding="utf-8")), "etag": _etag(f), "file": f.name,
                "backups": self.history(module_id)}

    def hints(self) -> dict[str, Any]:
        return {
            "layers": _literal_values(S.Layer), "priorities": _literal_values(S.Priority),
            "signal_sources": _literal_values(S.SignalSource), "evidence_sources": _literal_values(S.EvidenceSource),
            "categories": _literal_values(S.ModuleCategory), "rule_keys": list(S.RULE_KEYS), "regex_keys": list(S.REGEX_KEYS),
            "infra_signals": list(S.INFRA_SIGNALS),
            "entry_ids": sorted(e.id for _m, e in loader.load_master(str(self.data / loader.MASTER_FILE)).entries()),
        }

    def dataset_paths(self) -> list[str]:
        """Every path an entry's ``stage1_paths`` may use, derived from the Stage 1 dataset schema (for autocomplete)."""
        out: list[str] = []

        def unwrap(tp: Any) -> tuple[Any, bool]:
            if typing.get_origin(tp) in (typing.Union, types.UnionType):
                args = [a for a in typing.get_args(tp) if a is not type(None)]
                return unwrap(args[0]) if len(args) == 1 else (Any, False)
            if typing.get_origin(tp) is list:
                inner, _ = unwrap(typing.get_args(tp)[0])
                return inner, True
            return tp, False

        def walk(model: type[BaseModel], prefix: str) -> None:
            for name, field in model.model_fields.items():
                tp, is_list = unwrap(field.annotation)
                path = f"{prefix}{name}" + ("[]" if is_list and isinstance(tp, type) and issubclass(tp, BaseModel) else "")
                if isinstance(tp, type) and issubclass(tp, BaseModel):
                    walk(tp, path + ".")
                else:
                    out.append(path)

        walk(ServiceDataset, "")
        return sorted(set(out))

    def catalogue(self, name: str) -> dict[str, Any]:
        files = {"oneagent": loader.ONEAGENT_FILE, "instrumentation": loader.APP_FILE}
        if name not in files:
            raise StoreError(f"unknown catalogue {name!r}", status=404)
        import json

        return json.loads((self.data / files[name]).read_text(encoding="utf-8"))

    # ---------------------------------------------------------------------------- validating

    def _problems(self, doc: dict[str, Any]) -> list[dict[str, str]]:
        try:
            S.NfrModule.model_validate(doc)
        except ValidationError as exc:
            return [{"path": _loc(e["loc"]), "message": e["msg"]} for e in exc.errors()]
        return []

    def _validate_tree(self, tmp_src: Path) -> list[dict[str, str]]:
        try:
            loader.build(tmp_src)
        except loader.KnowledgeBaseError as exc:
            out: list[dict[str, str]] = []
            for ln in (ln.strip(" -") for ln in str(exc).splitlines() if ln.strip()):
                if ln.endswith(":"):  # the "knowledge base is inconsistent:" header, not a problem
                    continue
                m = re.match(r"^([A-Z][A-Z0-9]*-\d+): (.*)$", ln)  # "CAP-001: stage1 path ..." names the requirement
                out.append({"path": "", "entry": m.group(1), "message": m.group(2)} if m else {"path": "", "message": ln})
            return out[:25]
        return []

    def _scratch(self) -> tuple[tempfile.TemporaryDirectory, Path]:
        tmp = tempfile.TemporaryDirectory(prefix="sreadvisor-nfr-")
        dst = Path(tmp.name) / "src"
        shutil.copytree(self.src, dst)
        return tmp, dst

    def validate(self, doc: dict[str, Any], module_id: str | None = None) -> list[dict[str, str]]:
        """Dry run: every problem the save would hit, without writing anything."""
        problems = self._problems(doc)
        if problems:
            return problems
        tmp, dst = self._scratch()
        with tmp:
            files = self._files()
            target = dst / "modules" / (files[module_id].name if module_id in files else f"{_FILE_PREFIX[doc['layer']]}_{doc['id']}.yaml")
            target.write_text(_dump(doc), encoding="utf-8")
            self._sync_catalogue_stubs(dst, doc, module_id)
            return self._validate_tree(dst)

    # ---------------------------------------------------------------------------- writing

    def _backup(self, path: Path) -> Path:
        self.backups.mkdir(parents=True, exist_ok=True)
        dest = self.backups / f"{path.stem}.{datetime.now():%Y%m%d-%H%M%S-%f}{path.suffix}"
        shutil.copy2(path, dest)
        return dest

    def history(self, module_id: str) -> list[dict[str, str]]:
        f = self._files().get(module_id)
        if f is None or not self.backups.is_dir():
            return []
        return [{"name": b.name, "saved_at": datetime.fromtimestamp(b.stat().st_mtime).isoformat(timespec="seconds")}
                for b in sorted(self.backups.glob(f"{f.stem}.*{f.suffix}"), reverse=True)]

    def _rebuild(self) -> None:
        loader.write_built(self.data, self.src)

    def save_module(self, module_id: str, doc: dict[str, Any], etag: str | None) -> dict[str, Any]:
        files = self._files()
        f = files.get(module_id)
        if f is None:
            raise StoreError(f"unknown module {module_id!r}", status=404)
        if doc.get("id") != module_id:
            raise StoreError("a module's id cannot be changed", [{"path": "id", "message": "renaming would break references"}])
        if etag and etag != _etag(f):
            raise StoreError("the module changed on disk since you opened it; reload and re-apply your edit",
                             status=409)
        problems = self.validate(doc, module_id)
        if problems:
            raise StoreError("the module does not validate; nothing was saved", problems)
        self._backup(f)
        f.write_text(_dump(doc), encoding="utf-8")
        self._rebuild()
        return self.get_module(module_id)

    def create_module(self, doc: dict[str, Any]) -> dict[str, Any]:
        mid = str(doc.get("id", ""))
        problems: list[dict[str, str]] = []
        if not _ID.match(mid):
            problems.append({"path": "id", "message": "use lower-case letters, digits and underscores (start with a letter)"})
        if mid in self._files():
            problems.append({"path": "id", "message": f"module {mid!r} already exists"})
        if doc.get("layer") == "baseline":
            problems.append({"path": "layer", "message": "there is exactly one baseline module"})
        entries = doc.get("entries") or []
        if entries and not _PREFIX.match(str(entries[0].get("id", "")).split("-")[0]):
            problems.append({"path": "entries[0].id", "message": "entry ids look like ABC-001 (upper-case prefix, unique per module)"})
        if problems:
            raise StoreError("the module cannot be created", problems)
        problems = self.validate(doc, None)
        if problems:
            raise StoreError("the module does not validate; nothing was saved", problems)
        dest = self.src / "modules" / f"{_FILE_PREFIX[doc['layer']]}_{mid}.yaml"
        dest.write_text(_dump(doc), encoding="utf-8")
        self._sync_catalogue_stubs(self.src, doc, None, backup=True)
        self._rebuild()
        return self.get_module(mid)

    def delete_module(self, module_id: str) -> None:
        f = self._files().get(module_id)
        if f is None:
            raise StoreError(f"unknown module {module_id!r}", status=404)
        doc = yaml.safe_load(f.read_text(encoding="utf-8"))
        if doc.get("layer") == "baseline":
            raise StoreError("the baseline module cannot be deleted")
        tmp, dst = self._scratch()
        with tmp:
            (dst / "modules" / f.name).unlink()
            self._drop_catalogue_entries(dst, module_id)
            problems = self._validate_tree(dst)
        if problems:
            raise StoreError("other modules still depend on this one; nothing was deleted", problems)
        self._backup(f)
        f.unlink()
        self._drop_catalogue_entries(self.src, module_id, backup=True)
        self._rebuild()

    def restore(self, module_id: str, backup_name: str, etag: str | None) -> dict[str, Any]:
        f = self._files().get(module_id)
        if f is None:
            raise StoreError(f"unknown module {module_id!r}", status=404)
        if not any(h["name"] == backup_name for h in self.history(module_id)):  # also stops path tricks: only listed backups
            raise StoreError("no such backup for this module", status=404)
        doc = yaml.safe_load((self.backups / backup_name).read_text(encoding="utf-8"))
        return self.save_module(module_id, doc, etag)

    # --------------------------------------------------------------------- catalogue stubs

    def _sync_catalogue_stubs(self, src: Path, doc: dict[str, Any], existing_id: str | None, backup: bool = False) -> None:
        """A new tech-stack module needs an entry in both telemetry catalogues (the build requires it). Add an honest placeholder."""
        if doc.get("layer") != "tech_stack" or existing_id:
            return
        mid = doc["id"]
        for fname, stub in (
            ("oneagent.yaml", {"support_level": "none", "inherits": ["oneagent_platform"], "signals": [], "not_covered_by_default": [],
                               "summary": "Not yet catalogued: review against the Dynatrace technology support matrix before relying on this."}),
            ("instrumentation.yaml", {"summary": "Not yet catalogued.",
                                      "reason_none": "Not yet catalogued: no library metric catalogue exists for this technology; add one when it is reviewed."}),
        ):
            p = src / fname
            data = yaml.safe_load(p.read_text(encoding="utf-8"))
            if mid not in data["modules"]:
                if backup:
                    self._backup(p)
                data["modules"][mid] = stub
                p.write_text(_dump(data), encoding="utf-8")

    def _drop_catalogue_entries(self, src: Path, module_id: str, backup: bool = False) -> None:
        for fname in ("oneagent.yaml", "instrumentation.yaml"):
            p = src / fname
            data = yaml.safe_load(p.read_text(encoding="utf-8"))
            if module_id in data["modules"]:
                if backup:
                    self._backup(p)
                del data["modules"][module_id]
                for m in data["modules"].values():  # anything that inherited from it no longer does
                    if isinstance(m, dict) and module_id in (m.get("inherits") or []):
                        m["inherits"].remove(module_id)
                p.write_text(_dump(data), encoding="utf-8")
