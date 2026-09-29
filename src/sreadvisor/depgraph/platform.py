"""Hosting platform classification: deterministic, from facts Stage 1's infra analysis already collected. No
existing part of the pipeline distinguishes a managed platform (GKE, EKS, AKS, OpenShift) from generic Kubernetes —
`infra/k8s.py` already recognizes OpenShift-specific workload kinds (``DeploymentConfig``) and
`infra/terraform.py` already extracts a cloud provider prefix per resource, but neither rolls those signals up
into one classification. This module is that roll-up, and the one genuinely new piece of detection this feature
needs; everything else it uses already exists.
"""

from __future__ import annotations

from sreadvisor.depgraph.schema import HostingPlatform
from sreadvisor.schema.dataset import InfraAnalysis

# Kinds only OpenShift defines (never plain upstream Kubernetes) — infra/k8s.py's WORKLOAD_KINDS already includes
# DeploymentConfig for exactly this reason; Route/BuildConfig/ImageStream are OpenShift-only API kinds too, though
# this project does not currently parse them into their own model, so only the workload kind is checked here.
_OPENSHIFT_WORKLOAD_KINDS = {"DeploymentConfig"}

_PROVIDER_TO_PLATFORM = {"google": "gke", "aws": "eks", "azurerm": "aks"}
_PLATFORM_LABEL = {"gke": "Google Kubernetes Engine (GKE)", "eks": "Amazon EKS", "aks": "Azure AKS",
                   "openshift": "OpenShift", "kubernetes": "Kubernetes (generic/unspecified distribution)",
                   "docker_compose": "Docker Compose", "unknown": "unknown"}


def classify_hosting_platform(infra: InfraAnalysis) -> HostingPlatform:
    """Priority: OpenShift-specific workload kind > cloud-managed Kubernetes (from a Terraform provider prefix) >
    generic Kubernetes (any workload, no more specific signal) > Docker Compose only > unknown. Never guessed when
    there is genuinely nothing to go on."""
    for w in infra.workloads:
        if w.kind in _OPENSHIFT_WORKLOAD_KINDS:
            return HostingPlatform(kind="openshift", detail=f"{w.kind} (OpenShift-specific workload kind)",
                                   evidence=[w.evidence])

    for tr in infra.terraform_resources:
        platform = _PROVIDER_TO_PLATFORM.get(tr.provider)
        if platform:
            return HostingPlatform(kind=platform, detail=f"{tr.type} (Terraform, provider {tr.provider!r})",
                                   evidence=[tr.evidence])

    if infra.workloads:
        return HostingPlatform(kind="kubernetes", detail=f"{len(infra.workloads)} Kubernetes workload(s), "
                               "no cloud-managed-platform or OpenShift-specific signal found",
                               evidence=[infra.workloads[0].evidence])

    if infra.compose_services:
        return HostingPlatform(kind="docker_compose", detail=f"{len(infra.compose_services)} Docker Compose service(s)",
                               evidence=[infra.compose_services[0].evidence])

    return HostingPlatform(kind="unknown", detail=None, evidence=[])


def platform_label(kind: str) -> str:
    return _PLATFORM_LABEL.get(kind, kind)
