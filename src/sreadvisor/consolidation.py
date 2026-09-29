"""Module three: Dataset Consolidation.

Merges Code Analysis and Infra Analysis into one dataset per service. Content is facts only: the
cross-references below link findings from different modules (for example a dependency and the
mesh-level policies that name its host) without saying whether the result is adequate; that is for
later stages, run against an evolving requirements list.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from sreadvisor.config import ServiceConfig
from sreadvisor.providers.base import ObservabilityProvider
from sreadvisor.schema.dataset import (
    CapacityPosture,
    CrossReference,
    InfraAnalysis,
    ObservabilityBinding,
    RepoAnalysis,
    ServiceDataset,
)

REPO_STEPS = ["tech_stack_fingerprint", "structural_graph", "entry_point_detection", "application_capacity", "secrets_handling",
              "encryption_and_audit", "application_telemetry", "transaction_flow_tracing", "reliability_patterns",
              "dependency_classification", "business_context"]
INFRA_STEPS = ["kubernetes", "helm", "terraform", "compose_and_docker", "cicd_pipelines", "service_mesh"]
_TOKEN = re.compile(r"[a-z0-9]{4,}")


def _tokens(s: str) -> set[str]:
    return set(_TOKEN.findall(s.lower())) - {"database", "service", "spring", "data", "relational", "cache", "with", "from"}


# ----------------------------------------------------------------------- cross references


def _resilience_layers(repos: list[RepoAnalysis], infra: InfraAnalysis) -> list[CrossReference]:
    out = []
    for kind in ("retry", "timeout", "circuit_breaker"):
        app = [p for r in repos for p in r.reliability_patterns if p.pattern == kind]
        mesh = [m for m in infra.mesh.traffic_policies if m.kind == kind]
        if app or mesh:
            out.append(CrossReference(
                kind="resilience_by_layer", subject=kind,
                facts={"application_code": len(app), "mesh": len(mesh), "mesh_hosts": sorted({m.host for m in mesh})},
                evidence=[p.evidence for p in app[:3]] + [m.evidence for m in mesh[:3]]))
    return out


def _dependency_mesh(repos: list[RepoAnalysis], infra: InfraAnalysis) -> list[CrossReference]:
    if not infra.mesh.present:
        return []
    out = []
    for r in repos:
        for dc in r.dependency_classification:
            toks = _tokens(dc.dependency)
            matched = [m for m in infra.mesh.traffic_policies if toks & _tokens(m.host)]
            out.append(CrossReference(
                kind="dependency_mesh_policies", subject=dc.dependency,
                facts={"classification": dc.classification, "mesh": infra.mesh.mesh,
                       "matched_mesh_policy_kinds": sorted({m.kind for m in matched}),
                       "matched_mesh_hosts": sorted({m.host for m in matched}),
                       "application_level_patterns": dc.protecting_patterns},
                evidence=[m.evidence for m in matched[:4]] + dc.evidence[:2]))
    return out


def _transport(repos: list[RepoAnalysis], infra: InfraAnalysis) -> list[CrossReference]:
    if not infra.mesh.mtls:
        return []
    code_facts = [f for r in repos for f in r.encryption_audit.facts if f.domain == "in_transit"]
    return [CrossReference(
        kind="transport_encryption_mesh_and_code", subject="service-to-service traffic",
        facts={"mesh_mtls": [f"{m.scope}: {m.mode}" for m in infra.mesh.mtls],
               "application_level_in_transit_facts": len(code_facts),
               "application_level_plaintext_or_disabled": [f"{f.evidence.file}:{f.evidence.line} {f.setting}" for f in code_facts
                                                            if f.status in ("plaintext", "disabled")][:10]},
        evidence=[m.evidence for m in infra.mesh.mtls[:3]])]


def _secrets(repos: list[RepoAnalysis], infra: InfraAnalysis) -> list[CrossReference]:
    out: list[CrossReference] = []
    env_names: dict[str, list[str]] = {}  # env var name -> ["workload/container <- secret/x:y"]
    for w in infra.workloads:
        for c in w.containers:
            for s in c.env_from_secrets:
                name = s.split(" <- ")[0]
                env_names.setdefault(name, []).append(f"{w.name}/{c.name} <- {s.split(' <- ')[1]}")
    for r in repos:
        keys = {s.name: s for s in r.secrets.sourced_from if s.mechanism == "environment_variable" and s.name}
        for h in r.secrets.hardcoded:
            if h.kind == "hardcoded_credential" and h.key and "." in h.key:  # a literal may be overridden by relaxed-binding env
                relaxed = h.key.upper().replace(".", "_").replace("-", "")
                keys.setdefault(relaxed, None)  # type: ignore[arg-type]
        for name, src in keys.items():
            supplied = env_names.get(name) or env_names.get(name.upper())
            out.append(CrossReference(
                kind="secret_env_var_supply", subject=f"{r.repo}: ${name}",
                facts={"env_var": name, "supplied_by_iac_secret_ref": supplied or [], "code_reference": bool(src)},
                evidence=[src.evidence] if src else []))
    for name_keys in infra.kubernetes_secret_definitions:
        sname = name_keys.split(":")[0]
        refs = [f"{w.name}/{c.name}" for w in infra.workloads for c in w.containers if any(f"secret/{sname}" in s for s in c.env_from_secrets)]
        refs += [f"{s.detail}" for s in infra.secrets.sourced_from if s.mechanism == "kubernetes_secret" and s.name == sname and s.detail and "volume" in s.detail]
        ev = next((h.evidence for h in infra.secrets.hardcoded if h.key == f"Secret/{sname}"), None)
        out.append(CrossReference(
            kind="kubernetes_secret_definition", subject=f"Secret/{sname}",
            facts={"keys": name_keys.split(": ", 1)[1].split(", "), "inline_values_committed": ev is not None, "referenced_by": sorted(set(refs))},
            evidence=[ev] if ev else []))
    return out


def _health(repos: list[RepoAnalysis], infra: InfraAnalysis) -> list[CrossReference]:
    out = []
    for w in infra.workloads:
        for c in w.containers:
            probes = {n: p for n, p in (("liveness", c.liveness), ("readiness", c.readiness), ("startup", c.startup)) if p}
            if not probes:
                continue
            # Only HTTP probes can be served by the application's own health endpoints.
            http = any(p.type == "http" for p in probes.values())
            actuator = [d.evidence for r in repos for d in r.fingerprint.dependencies if d.name == "spring-boot-starter-actuator"] if http else []
            out.append(CrossReference(
                kind="health_probes_and_application_health", subject=f"{w.name}/{c.name}",
                facts={"probes": {n: f"{p.type} {p.target}" for n, p in probes.items()}, "actuator_dependency_present": bool(actuator) if http else None},
                evidence=[w.evidence] + actuator[:1]))
    return out


def _migrations(repos: list[RepoAnalysis], infra: InfraAnalysis) -> list[CrossReference]:
    embedded = [d for r in repos for d in r.fingerprint.dependencies if "schema_migration" in d.categories and "test" not in d.categories]
    steps = [(p.file, p.db_migration) for p in infra.pipelines if p.db_migration.present]
    if not embedded and not steps:
        return []
    return [CrossReference(
        kind="database_migration_coupling", subject="schema migrations",
        facts={"migration_library_in_application": sorted({f"{d.group or ''}:{d.name}".strip(":") for d in embedded}),
               "pipeline_migration_steps": [f"{f}: tool={m.tool} separate_step={m.separate_step}" for f, m in steps]},
        evidence=[d.evidence for d in embedded[:2]] + [e for _, m in steps for e in m.evidence[:1]])]


# ---------------------------------------------------------------------------- completeness


def completeness(repos: list[RepoAnalysis], infra: InfraAnalysis, extra_warnings: list[str]) -> dict:
    sections: dict[str, str] = {}
    warnings = list(extra_warnings)
    counts = {"ok": 0, "no_findings": 0, "skipped": 0, "failed": 0}

    def tally(prefix: str, statuses, expected: list[str]) -> None:
        by = {s.step: s for s in statuses}
        for name in expected:
            s = by.get(name)
            key = f"{prefix}.{name}"
            if s is None:
                sections[key] = "missing"
                warnings.append(f"{key}: step did not report a status")
                continue
            sections[key] = f"{s.status}" + (f" ({s.count})" if s.count is not None else "")
            counts[s.status] += 1
            if s.status == "failed":
                warnings.append(f"{key}: FAILED - {s.detail}")
            elif s.status == "skipped":
                warnings.append(f"{key}: skipped - {s.detail}")
            elif s.detail and s.status != "ok":
                warnings.append(f"{key}: {s.detail}")

    for r in repos:
        tally(f"code[{r.repo}]", r.status, REPO_STEPS)
        warnings += [f"code[{r.repo}]: {e}" for e in r.fingerprint.parse_errors]
    tally("infra", infra.status, INFRA_STEPS)
    warnings += [f"infra: {e}" for e in infra.parse_errors]
    total = sum(counts.values())
    return {
        "summary": f"{counts['ok']}/{total} steps produced findings, {counts['no_findings']} ran with no findings, "
                   f"{counts['skipped']} skipped, {counts['failed']} failed",
        "steps": counts, "sections": sections, "warnings": warnings,
        "structurally_complete": all(v != "missing" for v in sections.values()) and counts["failed"] == 0,
    }


# --------------------------------------------------------------------------------- build


def build_dataset(cfg: ServiceConfig, provider: ObservabilityProvider, repos: list[RepoAnalysis], infra: InfraAnalysis,
                  model_backend: str | None, extra_warnings: list[str] | None = None) -> ServiceDataset:
    business = next((r.business_context for r in repos if r.business_context), None)
    xrefs = (_resilience_layers(repos, infra) + _dependency_mesh(repos, infra) + _transport(repos, infra)
             + _secrets(repos, infra) + _health(repos, infra) + _migrations(repos, infra))
    return ServiceDataset(
        service_name=cfg.service_name,
        generated_at=datetime.now(timezone.utc),
        model_backend=model_backend,
        observability=ObservabilityBinding(provider=provider.name, service_id=cfg.observability.service_id, options=provider.public_options()),
        business_context=business,
        repositories=repos,
        infrastructure=infra,
        capacity_posture=CapacityPosture(application=[c for r in repos for c in r.application_capacity], infrastructure=infra.capacity),
        cross_references=xrefs,
        completeness=completeness(repos, infra, extra_warnings or []),
    )
