"""Module two: Infra Analysis over one or more infrastructure-as-code paths."""

from __future__ import annotations

from pathlib import Path

from sreadvisor.infra.cicd import parse_pipelines
from sreadvisor.infra.compose import is_compose, parse_compose, parse_dockerfile
from sreadvisor.infra.helm import parse_helm
from sreadvisor.infra.k8s import parse_k8s
from sreadvisor.infra.loader import load_iac
from sreadvisor.infra.mesh import parse_mesh
from sreadvisor.infra.terraform import parse_terraform
from sreadvisor.schema.dataset import InfraAnalysis, StepStatus


def _st(step: str, items) -> StepStatus:
    n = len(items)
    return StepStatus(step=step, status="ok" if n else "no_findings", count=n)


def analyze_infra(roots: list[Path], log=print) -> InfraAnalysis:
    ia = InfraAnalysis(roots=[str(r) for r in roots])
    if not roots:
        ia.status = [StepStatus(step=s, status="skipped", detail="no iac_paths configured") for s in
                     ("kubernetes", "helm", "terraform", "compose_and_docker", "cicd_pipelines", "service_mesh")]
        return ia
    log(f"[infra] scanning {len(roots)} infrastructure path(s)")
    files = load_iac(roots)
    ia.files_scanned = files.files_scanned + len(files.terraform) + len(files.dockerfiles) + len(files.jenkinsfiles)
    ia.parse_errors += files.errors

    helm_docs = parse_helm(ia, files.helm_dirs)
    kdocs = files.kdocs + helm_docs
    parse_k8s(ia, kdocs)
    parse_mesh(ia, kdocs)
    parse_terraform(ia, files.terraform)

    pipeline_candidates = []
    for rp, text, docs in files.yaml_files:
        composed = [d for d in docs if is_compose(rp, d)]
        for d in composed:
            parse_compose(ia, rp, d)
        rest = [d for d in docs if d not in composed]
        if rest:
            pipeline_candidates.append((rp, text, rest))
    for rp, text in files.dockerfiles:
        parse_dockerfile(ia, rp, text)
    parse_pipelines(ia, pipeline_candidates, files.jenkinsfiles)

    ia.status = [
        _st("kubernetes", ia.workloads + ia.services + ia.autoscalers + ia.disruption_budgets + ia.ingresses),
        _st("helm", ia.helm_charts),
        _st("terraform", ia.terraform_resources),
        _st("compose_and_docker", ia.compose_services + ia.dockerfiles),
        _st("cicd_pipelines", ia.pipelines),
        StepStatus(step="service_mesh", status="ok" if ia.mesh.present else "no_findings",
                   count=len(ia.mesh.traffic_policies) + len(ia.mesh.mtls),
                   detail=None if ia.mesh.present else "no Istio/Linkerd resources or injection markers found"),
    ]
    return ia
