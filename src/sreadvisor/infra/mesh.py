"""Service-mesh configuration (Istio, Linkerd): mTLS, mesh-level retries/timeouts, circuit breaking, routing.

These policies are applied at the mesh layer, not in application code, so they are recorded here and
cross-referenced against application-level findings during consolidation.
"""

from __future__ import annotations

from typing import Any

from sreadvisor.infra.k8s import dig
from sreadvisor.infra.loader import KDoc
from sreadvisor.schema.dataset import InfraAnalysis, MeshMtls, MeshTrafficPolicy
from sreadvisor.util.files import evidence

ISTIO = ("networking.istio.io", "security.istio.io")
LINKERD = ("linkerd.io", "policy.linkerd.io")


def parse_mesh(ia: InfraAnalysis, kdocs: list[KDoc]) -> None:
    m = ia.mesh
    kinds: set[str] = set()

    def policy(host: str, kind: str, settings: dict[str, Any], kd: KDoc, *path: Any) -> None:
        m.traffic_policies.append(MeshTrafficPolicy(host=host, kind=kind, settings=settings, resource=f"{kd.kind}/{kd.name}",
                                                    evidence=evidence(kd.file, kd.line(*path), f"{kd.kind} {kd.name}")))

    for kd in kdocs:
        api, kind, spec = kd.api, kd.kind, kd.data.get("spec") or {}
        if any(api.startswith(a) for a in ISTIO):
            kinds.add("istio")
            if kind == "VirtualService":
                hosts = ", ".join(spec.get("hosts", []) or ["*"])
                for i, r in enumerate(spec.get("http", []) or []):
                    if not isinstance(r, dict):
                        continue
                    if r.get("retries"):
                        policy(hosts, "retry", {k: v for k, v in r["retries"].items()}, kd, "spec", "http", i, "retries")
                    if r.get("timeout"):
                        policy(hosts, "timeout", {"timeout": r["timeout"]}, kd, "spec", "http", i, "timeout")
                    if r.get("fault"):
                        policy(hosts, "fault_injection", r["fault"], kd, "spec", "http", i, "fault")
                    if r.get("mirror"):
                        policy(hosts, "mirror", {"mirror": r["mirror"]}, kd, "spec", "http", i, "mirror")
                    routes = r.get("route") or []
                    if len(routes) > 1 or any("weight" in x for x in routes if isinstance(x, dict)):
                        policy(hosts, "routing", {"weighted_routes": [{"host": dig(x, "destination", "host"), "weight": x.get("weight")}
                                                                       for x in routes if isinstance(x, dict)]}, kd, "spec", "http", i, "route")
            elif kind == "DestinationRule":
                host = str(spec.get("host", "*"))
                tp = spec.get("trafficPolicy") or {}
                if tp.get("outlierDetection"):
                    policy(host, "circuit_breaker", tp["outlierDetection"], kd, "spec", "trafficPolicy", "outlierDetection")
                if tp.get("connectionPool"):
                    policy(host, "connection_pool", tp["connectionPool"], kd, "spec", "trafficPolicy", "connectionPool")
                if tp.get("loadBalancer"):
                    policy(host, "load_balancing", tp["loadBalancer"], kd, "spec", "trafficPolicy", "loadBalancer")
                if dig(tp, "tls", "mode"):
                    m.mtls.append(MeshMtls(scope=f"client-side to {host}", mode=str(tp["tls"]["mode"]),
                                           evidence=evidence(kd.file, kd.line("spec", "trafficPolicy", "tls"), f"DestinationRule {kd.name} tls.mode")))
            elif kind == "PeerAuthentication":
                mode = dig(spec, "mtls", "mode", default="UNSET")
                scope = f"namespace {dig(kd.data, 'metadata', 'namespace', default='<default>')}" if not spec.get("selector") \
                    else f"workload {dig(spec, 'selector', 'matchLabels')}"
                m.mtls.append(MeshMtls(scope=scope, mode=str(mode), evidence=evidence(kd.file, kd.line("spec", "mtls"), f"PeerAuthentication {kd.name}")))
            elif kind == "AuthorizationPolicy":
                m.authorization_policies.append(f"istio AuthorizationPolicy/{kd.name} action={spec.get('action', 'ALLOW')}")
            elif kind == "Gateway":
                for s in spec.get("servers", []) or []:
                    if isinstance(s, dict) and dig(s, "tls", "mode"):
                        m.mtls.append(MeshMtls(scope=f"gateway {kd.name} port {dig(s, 'port', 'number')}", mode=f"gateway-tls:{s['tls']['mode']}",
                                               evidence=evidence(kd.file, kd.line("spec", "servers"), f"Gateway {kd.name} tls")))
        elif any(api.startswith(a) for a in LINKERD):
            kinds.add("linkerd")
            if kind == "ServiceProfile":
                host = kd.name
                for i, r in enumerate(spec.get("routes", []) or []):
                    if not isinstance(r, dict):
                        continue
                    if r.get("isRetryable"):
                        policy(host, "retry", {"route": r.get("name"), "isRetryable": True, "retryBudget": spec.get("retryBudget")}, kd, "spec", "routes", i)
                    if r.get("timeout"):
                        policy(host, "timeout", {"route": r.get("name"), "timeout": r["timeout"]}, kd, "spec", "routes", i, "timeout")
            elif kind in ("Server", "AuthorizationPolicy", "MeshTLSAuthentication", "ServerAuthorization"):
                m.authorization_policies.append(f"linkerd {kind}/{kd.name}")
            elif kind == "HTTPRoute":
                policy(kd.name, "routing", {"rules": len(spec.get("rules", []) or [])}, kd, "spec")
        if kind == "Namespace":
            labels = dig(kd.data, "metadata", "labels", default={}) or {}
            ann = dig(kd.data, "metadata", "annotations", default={}) or {}
            if labels.get("istio-injection") or "istio.io/rev" in labels:
                kinds.add("istio")
                m.injection.append(f"namespace/{kd.name}: istio-injection={labels.get('istio-injection', labels.get('istio.io/rev'))} ({kd.file}:{kd.line()})")
            if ann.get("linkerd.io/inject"):
                kinds.add("linkerd")
                m.injection.append(f"namespace/{kd.name}: linkerd.io/inject={ann['linkerd.io/inject']} ({kd.file}:{kd.line()})")

    for w in ia.workloads:
        if w.mesh_injection:
            kinds.add(w.mesh_injection.split(" ")[0])
            m.injection.append(f"{w.kind}/{w.name}: {w.mesh_injection} ({w.evidence.file}:{w.evidence.line})")
    if kinds:
        m.present = True
        m.mesh = "+".join(sorted(kinds))
        if "linkerd" in kinds and not any(x.scope.startswith("linkerd") for x in m.mtls):
            m.mtls.append(MeshMtls(scope="all meshed pods", mode="automatic mTLS (Linkerd default for meshed traffic)",
                                   evidence=next((w.evidence for w in ia.workloads if w.mesh_injection and "linkerd" in w.mesh_injection),
                                                 evidence("(mesh)", None))))
