"""Terraform: resource definitions with replica, resilience, capacity and encryption attributes."""

from __future__ import annotations

import re
from typing import Any

import hcl2

from sreadvisor.code.secrets import FAKE, ENV_PLACEHOLDER, is_credential_key
from sreadvisor.schema.dataset import (
    CapacitySetting,
    EncryptionAuditFact,
    InfraAnalysis,
    SecretFinding,
    SecretSource,
    TerraformResource,
    Autoscaler,
)
from sreadvisor.util.files import evidence
from sreadvisor.util.redact import redact

INTEREST = re.compile(
    r"(replica|count|desired|min_size|max_size|min_capacity|max_capacity|multi_az|availability|backup|retention|encrypt|kms|tls|ssl|https|"
    r"protocol|deletion_protection|autoscal|health|failover|versioning|allocated_storage|instance_class|instance_type|machine_type|"
    r"cpu|memory|node_count|zone|snapshot|logging|audit|ttl|expir|lifecycle|port$|minimum_tls|min_tls|ssl_enforcement|require_ssl|"
    r"performance_insights|storage_type|iops)", re.I)
SECRET_MANAGER_TYPES = re.compile(r"^(aws_secretsmanager_secret|aws_ssm_parameter|google_secret_manager_secret|azurerm_key_vault(_secret)?|vault_\w+)$")
AUTOSCALING_TYPES = re.compile(r"^(aws_appautoscaling_(target|policy)|aws_autoscaling_(group|policy)|google_compute_(region_)?autoscaler|"
                               r"azurerm_monitor_autoscale_setting|kubernetes_horizontal_pod_autoscaler(_v2)?)$")
UNQUOTE = re.compile(r'^"(.*)"$', re.S)


def _u(v: Any) -> Any:
    return UNQUOTE.sub(r"\1", v) if isinstance(v, str) else v


def _flatten(attrs: dict[str, Any], prefix: str = "", depth: int = 0) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in attrs.items():
        if k.startswith("__"):
            continue
        key = f"{prefix}{k}"
        if isinstance(v, dict) and depth < 2:
            out.update(_flatten(v, key + ".", depth + 1))
        elif isinstance(v, list) and v and all(isinstance(i, dict) for i in v) and depth < 2:
            for i in v:
                out.update(_flatten(i, key + ".", depth + 1))
        elif not isinstance(v, (dict, list)):
            out[key] = _u(v)
        elif isinstance(v, list) and len(v) <= 6:
            out[key] = ", ".join(str(_u(i)) for i in v)
    return out


def _line(text: str, header: str) -> int:
    m = re.search(header, text)
    return text.count("\n", 0, m.start()) + 1 if m else 1


def parse_terraform(ia: InfraAnalysis, files: list[tuple[str, str]]) -> None:
    for rp, text in files:
        try:
            data = hcl2.loads(text)
        except Exception as exc:  # hcl2 raises several parser error types
            ia.parse_errors.append(f"{rp}: HCL not parseable ({str(exc).splitlines()[0][:120]})")
            continue
        blocks: list[tuple[str, str, dict[str, Any], str]] = []  # (type, name, attrs, header-regex)
        for entry in data.get("resource", []) or []:
            for rtype, named in entry.items():
                rtype = _u(rtype)
                for rname, attrs in named.items():
                    rname = _u(rname)
                    blocks.append((rtype, rname, attrs, rf'resource\s+"{re.escape(rtype)}"\s+"{re.escape(rname)}"'))
        for entry in data.get("module", []) or []:
            for mname, attrs in entry.items():
                mname = _u(mname)
                blocks.append((f"module:{_u(attrs.get('source', ''))}", mname, attrs, rf'module\s+"{re.escape(mname)}"'))

        for rtype, rname, attrs, header in blocks:
            flat = _flatten(attrs)
            ln = _line(text, header)
            picked = {k: v for k, v in flat.items() if INTEREST.search(k) and not is_credential_key(k)}
            provider = rtype.split(":")[0].split("_")[0] if not rtype.startswith("module:") else "module"
            ia.terraform_resources.append(TerraformResource(
                type=rtype, name=rname, provider=provider, attributes=picked, evidence=evidence(rp, ln, f"{rtype}.{rname}")))
            for k, v in picked.items():
                if re.search(r"encrypt|kms|tls|ssl|https", k, re.I):
                    domain = "at_rest" if re.search(r"encrypt|kms", k, re.I) and not re.search(r"transit|tls|ssl", k, re.I) else "in_transit"
                    sv = str(v).lower()
                    ia.encryption_audit.facts.append(EncryptionAuditFact(
                        domain=domain, subject=f"{rtype}.{rname}", setting=k, value=str(v)[:100],
                        status="enabled" if sv == "true" else "disabled" if sv == "false" else "configured", layer="iac",
                        evidence=evidence(rp, ln, f"{k} = {v}")))
                elif re.search(r"retention|ttl|expir|snapshot", k, re.I):
                    ia.encryption_audit.facts.append(EncryptionAuditFact(
                        domain="retention", subject=f"{rtype}.{rname}", setting=k, value=str(v)[:100], status="configured", layer="iac",
                        evidence=evidence(rp, ln, f"{k} = {v}")))
                elif re.search(r"replica|count|desired|min_|max_|node_count|multi_az|availability|failover|instance_(class|type)|machine_type|"
                               r"allocated_storage|cpu|memory", k, re.I):
                    ia.capacity.append(CapacitySetting(layer="infrastructure", category="autoscaling" if AUTOSCALING_TYPES.match(rtype) else "resources",
                                                       key=k, value=str(v), subject=f"{rtype}.{rname}", evidence=evidence(rp, ln, f"{k} = {v}")))
            if AUTOSCALING_TYPES.match(rtype):
                mn = next((v for k, v in flat.items() if re.search(r"min_(size|capacity|replicas)|minimum", k)), None)
                mx = next((v for k, v in flat.items() if re.search(r"max_(size|capacity|replicas)|maximum", k)), None)
                ia.autoscalers.append(Autoscaler(kind=f"terraform:{rtype}", name=rname, min_replicas=None if mn is None else str(mn),
                                                 max_replicas=None if mx is None else str(mx), evidence=evidence(rp, ln, f"{rtype}.{rname}")))
            if SECRET_MANAGER_TYPES.match(rtype):
                ia.secrets.sourced_from.append(SecretSource(
                    mechanism="vault" if rtype.startswith("vault_") else "secrets_manager", name=f"{rtype}.{rname}",
                    detail="secret store resource in Terraform", location_type="iac", evidence=evidence(rp, ln, f"{rtype}.{rname}")))
            for k, v in flat.items():
                if is_credential_key(k) and isinstance(v, str) and v and not FAKE.match(v) and not ENV_PLACEHOLDER.search(v) \
                        and not v.startswith(("var.", "data.", "local.", "aws_", "random_", "module.", "${")) and "(" not in v:
                    ia.secrets.hardcoded.append(SecretFinding(
                        kind="hardcoded_credential", key=f"{rtype}.{rname}.{k}", value_redacted=redact(v), location_type="iac",
                        evidence=evidence(rp, ln, f"{k} = <literal>")))
