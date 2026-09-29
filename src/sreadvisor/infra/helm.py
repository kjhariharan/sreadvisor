"""Helm charts: values of interest, and resource manifests (rendered with `helm template` when the
binary exists, otherwise a best-effort resolution of simple ``.Values`` references)."""

from __future__ import annotations

import re
import shutil
import subprocess
import textwrap
from pathlib import Path

import yaml

from sreadvisor.infra.loader import KDoc
from sreadvisor.schema.dataset import HelmChart, InfraAnalysis
from sreadvisor.util.files import evidence, read_text
from sreadvisor.util.yamlx import flatten, load_yaml_docs

INTEREST = re.compile(r"(replica|resources|autoscaling|disruption|pdb|probe|strategy|affinity|topology|tls|ingress|persistence|"
                      r"encrypt|secret|limits|requests|maxsurge|maxunavailable|terminationgrace|image\.tag)", re.I)
_TOYAML = re.compile(r"\{\{-?\s*toYaml\s+\.Values\.([\w.]+)\s*\|\s*(?:n)?indent\s+(\d+)\s*-?\}\}")
_VALUE = re.compile(r"\{\{-?\s*\.Values\.([\w.]+)\s*(?:\|[^}]*)?-?\}\}")
_CONTROL_LINE = re.compile(r"^\s*\{\{-?\s*(if|else|end|range|with|define|include|template|/\*|-)[^}]*\}\}\s*$", re.M)
_ANY = re.compile(r"\{\{.*?\}\}", re.S)


def _lookup(values: dict, dotted: str):
    cur = values
    for part in dotted.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _resolve_template(text: str, values: dict) -> str:
    def to_yaml(m: re.Match[str]) -> str:
        v = _lookup(values, m.group(1))
        if v is None:
            return "__TPL__"
        dumped = yaml.safe_dump(v, default_flow_style=False).rstrip()
        return "\n" + textwrap.indent(dumped, " " * int(m.group(2)))

    def scalar(m: re.Match[str]) -> str:
        v = _lookup(values, m.group(1))
        return "__TPL__" if v is None or isinstance(v, (dict, list)) else str(v)

    text = _TOYAML.sub(to_yaml, text)
    text = _CONTROL_LINE.sub("", text)
    text = _VALUE.sub(scalar, text)
    return _ANY.sub("__TPL__", text)


def parse_helm(ia: InfraAnalysis, helm_dirs: list[tuple[str, Path]]) -> list[KDoc]:
    """Return the resource documents to feed to the Kubernetes parser."""
    kdocs: list[KDoc] = []
    helm_bin = shutil.which("helm")
    for rel_dir, d in helm_dirs:
        try:
            chart = yaml.safe_load(read_text(d / "Chart.yaml")) or {}
        except yaml.YAMLError as exc:
            ia.parse_errors.append(f"{rel_dir}/Chart.yaml: {exc}")
            continue
        values_file = next((d / n for n in ("values.yaml", "values.yml") if (d / n).is_file()), None)
        values: dict = {}
        if values_file:
            try:
                values = yaml.safe_load(read_text(values_file)) or {}
            except yaml.YAMLError as exc:
                ia.parse_errors.append(f"{rel_dir}/{values_file.name}: {exc}")
        interesting = {k: v for k, (v, _) in flatten(values).items() if INTEREST.search(k)}
        templates = sorted(p.name for p in (d / "templates").glob("*.y*ml")) if (d / "templates").is_dir() else []

        rendered = False
        if helm_bin:
            try:
                res = subprocess.run([helm_bin, "template", str(chart.get("name", d.name)), str(d)], capture_output=True, text=True, timeout=60)
                if res.returncode == 0:
                    for doc in load_yaml_docs(res.stdout):
                        if isinstance(doc.data, dict) and "kind" in doc.data:
                            kdocs.append(KDoc(f"{rel_dir}/(helm template)", doc, templated=False))
                    rendered = True
                else:
                    ia.parse_errors.append(f"{rel_dir}: helm template failed: {res.stderr.strip()[:200]}")
            except (OSError, subprocess.SubprocessError, yaml.YAMLError) as exc:
                ia.parse_errors.append(f"{rel_dir}: helm template error: {exc}")
        if not rendered:
            for tpl in (d / "templates").glob("*.y*ml") if (d / "templates").is_dir() else []:
                text = _resolve_template(read_text(tpl), values)
                try:
                    for doc in load_yaml_docs(text):
                        if isinstance(doc.data, dict) and "kind" in doc.data:
                            kdocs.append(KDoc(f"{rel_dir}/templates/{tpl.name}", doc, templated=True))
                except yaml.YAMLError:
                    ia.parse_errors.append(f"{rel_dir}/templates/{tpl.name}: template not resolvable without the helm binary")
        ia.helm_charts.append(HelmChart(
            name=str(chart.get("name", d.name)), version=str(chart.get("version")) if chart.get("version") else None, path=rel_dir,
            rendered_with_helm=rendered, values_of_interest={k: v for k, v in list(interesting.items())[:40]}, templates=templates,
            evidence=evidence(f"{rel_dir}/Chart.yaml", 1, f"chart {chart.get('name', d.name)}")))
    return kdocs
