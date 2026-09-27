"""docker-compose files and Dockerfiles."""

from __future__ import annotations

import re
from typing import Any

from sreadvisor.code.secrets import ENV_PLACEHOLDER, FAKE, is_credential_key
from sreadvisor.infra.k8s import dig
from sreadvisor.schema.dataset import ComposeService, DockerfileFact, InfraAnalysis, SecretFinding
from sreadvisor.util.files import evidence
from sreadvisor.util.redact import redact
from sreadvisor.util.yamlx import YamlDoc


def is_compose(rp: str, doc: YamlDoc) -> bool:
    name = rp.lower().split("/")[-1]
    return isinstance(doc.data, dict) and "services" in doc.data and (name.startswith(("docker-compose", "compose")) or "version" in doc.data
                                                                        or all(isinstance(v, dict) for v in doc.data["services"].values()))


def parse_compose(ia: InfraAnalysis, rp: str, doc: YamlDoc) -> None:
    for name, svc in (doc.data.get("services") or {}).items():
        if not isinstance(svc, dict):
            continue
        env = svc.get("environment") or {}
        pairs = [(k, v) for k, v in env.items()] if isinstance(env, dict) else [tuple(str(e).split("=", 1)) for e in env if "=" in str(e)]
        for k, v in pairs:
            v = "" if v is None else str(v)
            if is_credential_key(k) and v and not FAKE.match(v) and not ENV_PLACEHOLDER.search(v):
                ia.secrets.hardcoded.append(SecretFinding(
                    kind="hardcoded_credential", key=f"compose service {name} env {k}", value_redacted=redact(v), location_type="iac",
                    evidence=evidence(rp, doc.line("services", name, "environment"), f"{k}=<literal>")))
        ia.compose_services.append(ComposeService(
            name=name, image=svc.get("image"), replicas=None if dig(svc, "deploy", "replicas") is None else str(svc["deploy"]["replicas"]),
            restart=svc.get("restart") or dig(svc, "deploy", "restart_policy", "condition"), healthcheck="healthcheck" in svc,
            limits={k: str(v) for k, v in (dig(svc, "deploy", "resources", "limits", default={}) or {}).items()},
            ports=[str(p) for p in svc.get("ports", []) or []],
            depends_on=list(svc.get("depends_on", {}).keys()) if isinstance(svc.get("depends_on"), dict) else [str(d) for d in svc.get("depends_on", []) or []],
            evidence=evidence(rp, doc.line("services", name), f"service {name}")))


def parse_dockerfile(ia: InfraAnalysis, rp: str, text: str) -> None:
    bases, user, health, exposed, first = [], None, False, [], None
    for i, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        first = first or i
        m = re.match(r"(?i)^(FROM|USER|HEALTHCHECK|EXPOSE)\s+(.*)$", line)
        if not m:
            continue
        op, arg = m.group(1).upper(), m.group(2)
        if op == "FROM":
            bases.append(arg.split()[0])
        elif op == "USER":
            user = arg.split()[0]
        elif op == "HEALTHCHECK" and not arg.upper().startswith("NONE"):
            health = True
        elif op == "EXPOSE":
            exposed += arg.split()
    ia.dockerfiles.append(DockerfileFact(file=rp, base_images=bases, user=user, has_healthcheck=health, exposed_ports=exposed,
                                         evidence=evidence(rp, first or 1, "Dockerfile")))
