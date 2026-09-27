"""Kubernetes manifests: replicas, probes, resources, autoscaling, disruption budgets, secrets, TLS."""

from __future__ import annotations

from typing import Any

from sreadvisor.code.secrets import FAKE, ENV_PLACEHOLDER, is_credential_key
from sreadvisor.infra.loader import KDoc
from sreadvisor.schema.dataset import (
    Autoscaler,
    CapacitySetting,
    DisruptionBudget,
    EncryptionAuditFact,
    InfraAnalysis,
    K8sContainer,
    K8sIngress,
    K8sService,
    K8sWorkload,
    NetworkPolicyFact,
    Probe,
    SecretFinding,
    SecretSource,
)
from sreadvisor.util.files import evidence
from sreadvisor.util.redact import redact

WORKLOAD_KINDS = {"Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "ReplicaSet", "Pod", "Rollout", "DeploymentConfig"}


def dig(d: Any, *path: Any, default: Any = None) -> Any:
    for p in path:
        if isinstance(d, dict):
            d = d.get(p)
        elif isinstance(d, list) and isinstance(p, int) and p < len(d):
            d = d[p]
        else:
            return default
        if d is None:
            return default
    return d


def _s(v: Any) -> str | None:
    return None if v is None else str(v)


def _int(v: Any) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def pod_spec_path(kind: str) -> tuple[str, ...]:
    return {"Pod": ("spec",), "CronJob": ("spec", "jobTemplate", "spec", "template", "spec")}.get(kind, ("spec", "template", "spec"))


def _probe(raw: Any) -> Probe | None:
    if not isinstance(raw, dict):
        return None
    if "httpGet" in raw:
        ptype, target = "http", f"{raw['httpGet'].get('path', '/')}:{raw['httpGet'].get('port', '')}"
    elif "tcpSocket" in raw:
        ptype, target = "tcp", str(raw["tcpSocket"].get("port", ""))
    elif "grpc" in raw:
        ptype, target = "grpc", str(raw["grpc"].get("port", ""))
    elif "exec" in raw:
        ptype, target = "exec", " ".join(map(str, raw["exec"].get("command", [])))[:120]
    else:
        ptype, target = "unknown", None
    return Probe(type=ptype, target=target, initial_delay_seconds=_int(raw.get("initialDelaySeconds")),
                 period_seconds=_int(raw.get("periodSeconds")), timeout_seconds=_int(raw.get("timeoutSeconds")),
                 failure_threshold=_int(raw.get("failureThreshold")))


def parse_k8s(ia: InfraAnalysis, kdocs: list[KDoc]) -> None:
    secrets_defs: dict[str, list[str]] = {}
    for kd in kdocs:
        kind = kd.kind
        if kind in WORKLOAD_KINDS:
            _workload(ia, kd)
        elif kind in ("HorizontalPodAutoscaler", "VerticalPodAutoscaler") or (kind == "ScaledObject" and "keda" in kd.api):
            _autoscaler(ia, kd)
        elif kind == "PodDisruptionBudget":
            spec = kd.data.get("spec") or {}
            sel = dig(spec, "selector", "matchLabels")
            ia.disruption_budgets.append(DisruptionBudget(
                name=kd.name, selector=_s(sel), min_available=_s(spec.get("minAvailable")),
                max_unavailable=_s(spec.get("maxUnavailable")), evidence=evidence(kd.file, kd.line(), f"PodDisruptionBudget {kd.name}")))
        elif kind == "Service":
            spec = kd.data.get("spec") or {}
            ports = [f"{p.get('port')}->{p.get('targetPort', p.get('port'))}" for p in spec.get("ports", []) if isinstance(p, dict)]
            ia.services.append(K8sService(name=kd.name, type=spec.get("type", "ClusterIP"), ports=ports,
                                          selector=_s(spec.get("selector")), evidence=evidence(kd.file, kd.line(), f"Service {kd.name}")))
        elif kind == "Ingress":
            _ingress(ia, kd)
        elif kind == "NetworkPolicy":
            ia.network_policies.append(NetworkPolicyFact(
                name=kd.name, policy_types=list(dig(kd.data, "spec", "policyTypes", default=[])),
                evidence=evidence(kd.file, kd.line(), f"NetworkPolicy {kd.name}")))
        elif kind == "Secret":
            _secret(ia, kd, secrets_defs)
        elif kind == "ConfigMap":
            for k, v in (kd.data.get("data") or {}).items():
                if isinstance(v, str) and is_credential_key(k) and v and not FAKE.match(v) and not ENV_PLACEHOLDER.search(v):
                    ia.secrets.hardcoded.append(SecretFinding(
                        kind="hardcoded_credential", key=f"ConfigMap/{kd.name}:{k}", value_redacted=redact(v), location_type="iac",
                        evidence=evidence(kd.file, kd.line("data", k), f"{k}: <value>")))
            ia.secrets.sourced_from.append(SecretSource(
                mechanism="kubernetes_configmap", name=kd.name, detail="ConfigMap definition", location_type="iac",
                evidence=evidence(kd.file, kd.line(), f"ConfigMap {kd.name}")))
        elif kind == "StorageClass":
            for k, v in (kd.data.get("parameters") or {}).items():
                if any(t in k.lower() for t in ("encrypt", "kms", "diskencryption")):
                    ia.encryption_audit.facts.append(EncryptionAuditFact(
                        domain="at_rest", subject=f"StorageClass/{kd.name}", setting=f"parameters.{k}", value=str(v),
                        status="disabled" if str(v).lower() == "false" else "enabled" if str(v).lower() == "true" else "configured",
                        layer="iac", evidence=evidence(kd.file, kd.line("parameters", k), f"{k}: {v}")))
        elif kind in ("ExternalSecret", "SecretProviderClass", "SealedSecret", "ClusterExternalSecret"):
            mech = "external_secrets" if kind in ("ExternalSecret", "ClusterExternalSecret", "SealedSecret") else (
                "vault" if "vault" in str(kd.data.get("spec", {}).get("provider", "")).lower() else "secrets_manager")
            ia.secrets.sourced_from.append(SecretSource(mechanism=mech, name=kd.name, detail=f"{kind} resource", location_type="iac",
                                                        evidence=evidence(kd.file, kd.line(), f"{kind} {kd.name}")))
    ia.kubernetes_secret_definitions += [f"{n}: {', '.join(sorted(ks))}" for n, ks in secrets_defs.items()]


# ------------------------------------------------------------------------------ pieces


def _workload(ia: InfraAnalysis, kd: KDoc) -> None:
    kind, spec = kd.kind, kd.data.get("spec") or {}
    base = pod_spec_path(kind)
    pod = dig(kd.data, *base, default={}) or {}
    tmeta_path = base[:-1] + ("metadata",)
    tmeta = dig(kd.data, *tmeta_path, default={}) or {}
    ann = {**(tmeta.get("annotations") or {})}
    labels = tmeta.get("labels") or {}

    strategy = dig(spec, "strategy", "type") or dig(spec, "updateStrategy", "type")
    if kind == "Rollout":
        strategy = "canary" if "canary" in (spec.get("strategy") or {}) else "blueGreen" if "blueGreen" in (spec.get("strategy") or {}) else strategy
    mesh = None
    if any(k.startswith("sidecar.istio.io/") for k in ann) or "istio.io/rev" in labels or "istio-injection" in labels:
        mesh = f"istio ({ann.get('sidecar.istio.io/inject', labels.get('istio-injection', 'labelled'))})"
    if "linkerd.io/inject" in ann:
        mesh = f"linkerd ({ann['linkerd.io/inject']})"

    security_pod = dig(pod, "securityContext", "runAsNonRoot")
    containers: list[K8sContainer] = []
    for c in pod.get("containers", []) or []:
        if not isinstance(c, dict):
            continue
        env_secrets, env_cms = [], []
        for e in c.get("env", []) or []:
            if not isinstance(e, dict):
                continue
            ref = dig(e, "valueFrom", "secretKeyRef")
            if ref:
                env_secrets.append(f"{e.get('name')} <- secret/{ref.get('name')}:{ref.get('key')}")
                ia.secrets.sourced_from.append(SecretSource(
                    mechanism="kubernetes_secret", name=f"{ref.get('name')}:{ref.get('key')}",
                    detail=f"env {e.get('name')} of {kd.name}/{c.get('name')}", location_type="iac",
                    evidence=evidence(kd.file, kd.line(*base, "containers"), f"{e.get('name')} <- secretKeyRef")))
            cref = dig(e, "valueFrom", "configMapKeyRef")
            if cref:
                env_cms.append(f"{e.get('name')} <- configmap/{cref.get('name')}:{cref.get('key')}")
            if "value" in e and isinstance(e["value"], (str, int)) and is_credential_key(str(e.get("name"))):
                v = str(e["value"])
                if v and not FAKE.match(v) and not ENV_PLACEHOLDER.search(v):
                    ia.secrets.hardcoded.append(SecretFinding(
                        kind="hardcoded_credential", key=f"{kd.name}/{c.get('name')} env {e.get('name')}", value_redacted=redact(v),
                        location_type="iac", evidence=evidence(kd.file, kd.line(*base, "containers"), f"env {e.get('name')}: <literal>")))
        for ef in c.get("envFrom", []) or []:
            if isinstance(ef, dict) and "secretRef" in ef:
                env_secrets.append(f"envFrom <- secret/{ef['secretRef'].get('name')}")
                ia.secrets.sourced_from.append(SecretSource(
                    mechanism="kubernetes_secret", name=str(ef["secretRef"].get("name")), detail=f"envFrom of {kd.name}",
                    location_type="iac", evidence=evidence(kd.file, kd.line(*base, "containers"), "envFrom secretRef")))
            elif isinstance(ef, dict) and "configMapRef" in ef:
                env_cms.append(f"envFrom <- configmap/{ef['configMapRef'].get('name')}")
        res = c.get("resources") or {}
        run_non_root = dig(c, "securityContext", "runAsNonRoot", default=security_pod)
        cont = K8sContainer(
            name=str(c.get("name")), image=_s(c.get("image")),
            ports=[p["containerPort"] for p in c.get("ports", []) or [] if isinstance(p, dict) and "containerPort" in p],
            requests={k: str(v) for k, v in (res.get("requests") or {}).items()},
            limits={k: str(v) for k, v in (res.get("limits") or {}).items()},
            liveness=_probe(c.get("livenessProbe")), readiness=_probe(c.get("readinessProbe")), startup=_probe(c.get("startupProbe")),
            env_from_secrets=env_secrets, env_from_configmaps=env_cms, run_as_non_root=run_non_root)
        containers.append(cont)
        for kind_, vals in (("requests", cont.requests), ("limits", cont.limits)):
            for rname, val in vals.items():
                ia.capacity.append(CapacitySetting(
                    layer="infrastructure", category="resources", key=f"{kind_}.{rname}", value=val, subject=f"{kd.name}/{cont.name}",
                    evidence=evidence(kd.file, kd.line(*base, "containers"), f"{kind_}.{rname}: {val}")))

    for vol in pod.get("volumes", []) or []:
        if not isinstance(vol, dict):
            continue
        secret_names = [vol["secret"].get("secretName")] if "secret" in vol else [
            src["secret"].get("name") for src in dig(vol, "projected", "sources", default=[]) or []
            if isinstance(src, dict) and isinstance(src.get("secret"), dict)]
        for sname in secret_names:
            ia.secrets.sourced_from.append(SecretSource(
                mechanism="kubernetes_secret", name=str(sname), detail=f"volume '{vol.get('name')}' of {kd.name}",
                location_type="iac", evidence=evidence(kd.file, kd.line(*base, "volumes"), f"secret volume {vol.get('name')}")))
        if "csi" in vol and "secrets-store" in str(dig(vol, "csi", "driver", default="")):
            ia.secrets.sourced_from.append(SecretSource(
                mechanism="secrets_manager", name=str(vol.get("name")), detail="Secrets Store CSI driver volume", location_type="iac",
                evidence=evidence(kd.file, kd.line(*base, "volumes"), "csi secrets-store volume")))
    if any(k.startswith("vault.hashicorp.com/agent-inject") for k in ann):
        ia.secrets.sourced_from.append(SecretSource(
            mechanism="vault", name=kd.name, detail="Vault agent injector annotations", location_type="iac",
            evidence=evidence(kd.file, kd.line(*tmeta_path, "annotations"), "vault.hashicorp.com/agent-inject")))

    replicas = _s(spec.get("replicas"))
    wl = K8sWorkload(
        kind=kind, name=kd.name, namespace=_s(dig(kd.data, "metadata", "namespace")), replicas=replicas, strategy=_s(strategy),
        max_surge=_s(dig(spec, "strategy", "rollingUpdate", "maxSurge")), max_unavailable=_s(dig(spec, "strategy", "rollingUpdate", "maxUnavailable")),
        termination_grace_period_seconds=_int(pod.get("terminationGracePeriodSeconds")), containers=containers,
        has_pod_anti_affinity="podAntiAffinity" in (pod.get("affinity") or {}), has_topology_spread=bool(pod.get("topologySpreadConstraints")),
        service_account=_s(pod.get("serviceAccountName")), mesh_injection=mesh, templated=kd.templated,
        evidence=evidence(kd.file, kd.line(), f"{kind} {kd.name}"))
    ia.workloads.append(wl)
    if replicas is not None:
        ia.capacity.append(CapacitySetting(layer="infrastructure", category="replicas", key="replicas", value=replicas, subject=kd.name,
                                           evidence=evidence(kd.file, kd.line("spec", "replicas"), f"replicas: {replicas}")))


def _autoscaler(ia: InfraAnalysis, kd: KDoc) -> None:
    spec = kd.data.get("spec") or {}
    kind = kd.kind
    metrics: list[str] = []
    if kind == "HorizontalPodAutoscaler":
        mn, mx = spec.get("minReplicas"), spec.get("maxReplicas")
        target = dig(spec, "scaleTargetRef", "name")
        if spec.get("targetCPUUtilizationPercentage") is not None:
            metrics.append(f"cpu:{spec['targetCPUUtilizationPercentage']}%")
        for m in spec.get("metrics", []) or []:
            if isinstance(m, dict):
                r = m.get("resource") or {}
                metrics.append(f"{m.get('type')}:{r.get('name', dig(m, 'pods', 'metric', 'name', default=''))}:"
                               f"{dig(r, 'target', 'averageUtilization', default=dig(r, 'target', 'averageValue', default=''))}")
    elif kind == "ScaledObject":
        mn, mx, target = spec.get("minReplicaCount"), spec.get("maxReplicaCount"), dig(spec, "scaleTargetRef", "name")
        metrics = [str(t.get("type")) for t in spec.get("triggers", []) or [] if isinstance(t, dict)]
    else:  # VPA
        mn = mx = None
        target = dig(spec, "targetRef", "name")
        metrics = [f"updateMode:{dig(spec, 'updatePolicy', 'updateMode', default='Auto')}"]
    ia.autoscalers.append(Autoscaler(kind=kind, name=kd.name, target=_s(target), min_replicas=_s(mn), max_replicas=_s(mx), metrics=metrics,
                                     evidence=evidence(kd.file, kd.line(), f"{kind} {kd.name}")))
    for key, val in (("minReplicas", mn), ("maxReplicas", mx)):
        if val is not None:
            ia.capacity.append(CapacitySetting(layer="infrastructure", category="autoscaling", key=key, value=str(val), subject=f"{kind}/{kd.name}",
                                               evidence=evidence(kd.file, kd.line("spec"), f"{key}: {val}")))


def _ingress(ia: InfraAnalysis, kd: KDoc) -> None:
    spec = kd.data.get("spec") or {}
    hosts = [r.get("host") for r in spec.get("rules", []) or [] if isinstance(r, dict) and r.get("host")]
    tls_hosts = [h for t in spec.get("tls", []) or [] if isinstance(t, dict) for h in (t.get("hosts") or [])]
    ia.ingresses.append(K8sIngress(name=kd.name, hosts=hosts, tls_hosts=tls_hosts, evidence=evidence(kd.file, kd.line(), f"Ingress {kd.name}")))
    has_tls = bool(spec.get("tls"))
    ia.encryption_audit.facts.append(EncryptionAuditFact(
        domain="in_transit", subject=f"Ingress/{kd.name}", setting="spec.tls",
        value=", ".join(tls_hosts) if has_tls else "no TLS section", status="enabled" if has_tls else "detected", layer="iac",
        evidence=evidence(kd.file, kd.line("spec", "tls") if has_tls else kd.line("spec"), "Ingress TLS")))


def _secret(ia: InfraAnalysis, kd: KDoc, defs: dict[str, list[str]]) -> None:
    keys = list((kd.data.get("data") or {}).keys()) + list((kd.data.get("stringData") or {}).keys())
    if not keys:
        return
    defs[kd.name] = keys
    inline = "stringData" if kd.data.get("stringData") else "data"
    ia.secrets.hardcoded.append(SecretFinding(
        kind="plaintext_secret_manifest", key=f"Secret/{kd.name}", value_redacted=redact(",".join(keys)), location_type="iac",
        evidence=evidence(kd.file, kd.line(inline), f"Secret {kd.name} carries inline values for keys: {', '.join(keys)}")))
    ia.secrets.sourced_from.append(SecretSource(
        mechanism="kubernetes_secret", name=kd.name, detail=f"Secret definition ({kd.data.get('type', 'Opaque')})", location_type="iac",
        evidence=evidence(kd.file, kd.line(), f"Secret {kd.name}")))
