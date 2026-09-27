"""Read application configuration files into ``(file, key, value, line)`` entries."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

import yaml

from sreadvisor.util.files import iter_files, read_text, rel
from sreadvisor.util.yamlx import flatten, load_yaml_docs

CONFIG_SUFFIXES = (".properties", ".yml", ".yaml", ".env", ".toml", ".json", ".conf", ".ini", ".cfg")
_INFRA_DIR_PARTS = {".github", ".gitlab", "k8s", "kubernetes", "helm", "charts", "deploy", "deployment", "manifests",
                    "terraform", "infra", "infrastructure", "ansible", ".circleci", ".harness"}
_INFRA_NAME = re.compile(r"^(docker-)?compose[\w.\-]*\.ya?ml$|^\.gitlab-ci\.ya?ml$|^azure-pipelines\.ya?ml$|"
                         r"^(chart|values)[\w.\-]*\.ya?ml$|^skaffold\.ya?ml$|^\.gitpod\.ya?ml$|^dco\.ya?ml$")
_K8S_MARK = re.compile(r"^\s*apiVersion\s*:", re.M)
_SKIP_JSON = {"package.json", "package-lock.json", "tsconfig.json", "composer.json", "launchsettings.json", "renovate.json"}
_SKIP_NAMES_PREFIX = ("messages",)  # i18n bundles


@dataclass
class ConfigEntry:
    file: str
    key: str
    value: str
    line: int
    raw: str = ""


_NOISE_PARTS = {"wrapper", ".devcontainer"}


def is_noise_config(rel_path: str) -> bool:
    """Tooling files that are neither application config nor infrastructure (build wrappers, dev containers)."""
    return any(p in _NOISE_PARTS for p in rel_path.lower().split("/")[:-1])


def is_infra_file(rel_path: str, text: str) -> bool:
    parts = rel_path.lower().split("/")
    name = parts[-1]
    if any(p in _INFRA_DIR_PARTS for p in parts[:-1]) or _INFRA_NAME.match(name):
        return True
    return name.endswith((".yml", ".yaml")) and bool(_K8S_MARK.search(text)) and "kind:" in text


def _properties(text: str, rp: str) -> Iterator[ConfigEntry]:
    for i, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line[0] in "#!;[":
            continue
        m = re.match(r"^([^=:\s]+)\s*[=:]\s*(.*)$", line)
        if m:
            yield ConfigEntry(rp, m.group(1), m.group(2).strip(), i, raw)


def _yaml(text: str, rp: str) -> Iterator[ConfigEntry]:
    try:
        docs = load_yaml_docs(text)
    except yaml.YAMLError:
        return
    lines_text = text.splitlines()
    for doc in docs:
        for key, (value, path) in flatten(doc.data).items():
            if value is None or isinstance(value, (dict, list)):
                continue
            ln = doc.line(*path)
            yield ConfigEntry(rp, key, str(value), ln, lines_text[ln - 1] if 0 < ln <= len(lines_text) else "")


def _json(text: str, rp: str) -> Iterator[ConfigEntry]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return
    lines = text.splitlines()
    for key, (value, _path) in flatten(data).items():
        if value is None or isinstance(value, (dict, list)):
            continue
        leaf = re.sub(r"\[\d+\]", "", key.split(".")[-1])
        ln = next((i for i, t in enumerate(lines, 1) if f'"{leaf}"' in t), 1)
        yield ConfigEntry(rp, key, str(value), ln, lines[ln - 1] if ln <= len(lines) else "")


def _dotenv(text: str, rp: str) -> Iterator[ConfigEntry]:
    for i, raw in enumerate(text.splitlines(), 1):
        m = re.match(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.]*)\s*=\s*(.*)$", raw)
        if m and not raw.strip().startswith("#"):
            yield ConfigEntry(rp, m.group(1), m.group(2).strip().strip("\"'"), i, raw)


def read_config_entries(root: Path, *, include_tests: bool = False) -> list[ConfigEntry]:
    """Application config only: Kubernetes/CI/compose YAML is an infrastructure concern."""
    entries: list[ConfigEntry] = []
    for f in iter_files(root, suffixes=CONFIG_SUFFIXES, names=[".env"], include_tests=include_tests):
        rp = rel(f, root)
        name = f.name.lower()
        if name in _SKIP_JSON or name.startswith(_SKIP_NAMES_PREFIX) or name.endswith((".lock", ".min.json")):
            continue
        text = read_text(f)
        if is_noise_config(rp) or is_infra_file(rp, text):
            continue
        if name.endswith((".properties", ".ini", ".cfg", ".conf")):
            entries += _properties(text, rp)
        elif name.endswith((".yml", ".yaml")):
            entries += _yaml(text, rp)
        elif name.endswith(".json"):
            entries += _json(text, rp)
        elif name.endswith(".env") or name.startswith(".env"):
            entries += _dotenv(text, rp)
    return entries
