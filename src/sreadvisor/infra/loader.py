"""Discovers and loads infrastructure-as-code files from one or more roots."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from sreadvisor.util.files import is_test_path, iter_files, read_text, rel
from sreadvisor.util.yamlx import YamlDoc, load_yaml_docs

_HELM_TEMPLATE_MARK = re.compile(r"\{\{")


@dataclass
class KDoc:
    """One YAML document that looks like a Kubernetes-style resource (has apiVersion + kind)."""

    file: str
    doc: YamlDoc
    templated: bool = False

    @property
    def data(self) -> dict:
        return self.doc.data

    @property
    def kind(self) -> str:
        return str(self.data.get("kind", ""))

    @property
    def api(self) -> str:
        return str(self.data.get("apiVersion", ""))

    @property
    def name(self) -> str:
        return str((self.data.get("metadata") or {}).get("name", ""))

    def line(self, *path) -> int:
        return self.doc.line(*path)


@dataclass
class IacFiles:
    roots: list[str] = field(default_factory=list)
    kdocs: list[KDoc] = field(default_factory=list)
    yaml_files: list[tuple[str, str, list[YamlDoc]]] = field(default_factory=list)  # (rel, text, docs) non-k8s yaml/json
    terraform: list[tuple[str, str]] = field(default_factory=list)
    dockerfiles: list[tuple[str, str]] = field(default_factory=list)
    jenkinsfiles: list[tuple[str, str]] = field(default_factory=list)
    helm_dirs: list[tuple[str, Path]] = field(default_factory=list)  # (rel dir, absolute dir)
    files_scanned: int = 0
    errors: list[str] = field(default_factory=list)


def _label(root: Path, multi: bool, rp: str) -> str:
    return f"{root.name}/{rp}" if multi else rp


def load_iac(roots: list[Path]) -> IacFiles:
    out = IacFiles(roots=[str(r) for r in roots])
    multi = len(roots) > 1
    for root in roots:
        if root.is_file():
            files, base = [root], root.parent
        else:
            files, base = list(iter_files(root, include_tests=False)), root
        helm_roots = {p.parent for p in files if p.name == "Chart.yaml"}
        for h in helm_roots:
            out.helm_dirs.append((_label(base, multi, rel(h, base)), h))
        for f in files:
            rp = _label(base, multi, rel(f, base))
            lname = f.name.lower()
            if any(h == f.parent or h in f.parents for h in helm_roots):
                out.files_scanned += 1
                continue  # Helm chart internals are handled by the helm parser
            if is_test_path(rel(f, base)) or ".devcontainer" in f.parts:
                continue
            if lname.endswith(".tf"):
                out.terraform.append((rp, read_text(f)))
            elif lname == "dockerfile" or lname.startswith("dockerfile.") or lname.endswith(".dockerfile"):
                out.dockerfiles.append((rp, read_text(f)))
            elif lname.startswith("jenkinsfile"):
                out.jenkinsfiles.append((rp, read_text(f)))
            elif lname.endswith((".yml", ".yaml", ".json")):
                text = read_text(f)
                if lname.endswith(".json") and not re.search(r'"(rootActivity|applicationProcess|componentProcess|pipeline)"', text):
                    continue
                try:
                    docs = load_yaml_docs(text) if not lname.endswith(".json") else [_json_doc(text)]
                except (yaml.YAMLError, json.JSONDecodeError) as exc:
                    out.errors.append(f"{rp}: not parseable ({str(exc).splitlines()[0]})")
                    continue
                out.files_scanned += 1
                k8s = [d for d in docs if isinstance(d.data, dict) and "apiVersion" in d.data and "kind" in d.data]
                for d in k8s:
                    out.kdocs.append(KDoc(rp, d))
                rest = [d for d in docs if d not in k8s and isinstance(d.data, (dict, list))]
                if rest:
                    out.yaml_files.append((rp, text, rest))
    return out


def _json_doc(text: str) -> YamlDoc:
    """JSON is valid YAML; reuse the YAML loader so line numbers work."""
    docs = load_yaml_docs(text)
    if not docs:
        raise json.JSONDecodeError("empty", text, 0)
    return docs[0]


def looks_templated(text: str) -> bool:
    return bool(_HELM_TEMPLATE_MARK.search(text))
