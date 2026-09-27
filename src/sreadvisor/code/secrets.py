"""Secrets and sensitive-configuration handling: hardcoded credentials vs. externally sourced ones.

Values are never stored: findings carry a redacted placeholder and a file:line reference.
"""

from __future__ import annotations

import re
from pathlib import Path

from sreadvisor.code.configfiles import ConfigEntry
from sreadvisor.graph.code_graph import SOURCE_SUFFIXES
from sreadvisor.schema.dataset import SecretFinding, SecretSource, SecretsAnalysis, TechStackFingerprint
from sreadvisor.util.files import evidence, iter_files, read_text, rel
from sreadvisor.util.redact import DOTNET_CONN, JDBC_PASSWORD, SOURCE_ASSIGN, TOKEN_PATTERNS, URL_CREDS, redact  # noqa: F401

CRED_KEY = re.compile(
    r"(pass(word|wd|phrase)?|pwd|secret|api[-_.]?key|apikey|access[-_.]?key|private[-_.]?key|client[-_.]?secret|"
    r"credentials?|auth[-_.]?token|(^|[._-])token($|[._-])|connection[-_.]?string|conn[-_.]?str)", re.I)
BENIGN_SUFFIX = re.compile(r"[-_.](name|url|uri|path|file|location|enabled|type|header|prefix|expiry|expiration|ttl|length|"
                           r"algorithm|alias|min|max|policy|pattern|encoder|validity|strategy|field|param|label|message)$", re.I)
ENV_PLACEHOLDER = re.compile(r"\$\{([A-Za-z0-9_.\-]+)(?::([^}]*))?\}")
TEMPLATE = re.compile(r"^(\{\{.*\}\}|<.*>|%\(.*\)s|@[\w.]+@|#\{.*\}|\$\(.*\))$")
FAKE = re.compile(r"^(changeme|change-me|change_me|x{3,}|\*+|todo|tbd|none|null|true|false|password|passwd|secret|example|"
                  r"your[-_ ].*|dummy|sample|placeholder|redacted|\.{3})$", re.I)

ENV_READS = [
    re.compile(r"""System\.getenv\(\s*"([^"]+)"\s*\)"""),
    re.compile(r"""os\.(?:environ(?:\.get)?[\[(]|getenv\()\s*['"]([^'"]+)['"]"""),
    re.compile(r"""process\.env\.([A-Za-z_][A-Za-z0-9_]*)|process\.env\[\s*['"]([^'"]+)['"]\s*\]"""),
    re.compile(r"""Environment\.GetEnvironmentVariable\(\s*"([^"]+)"\s*\)"""),
    re.compile(r"""@Value\(\s*"\$\{([A-Za-z0-9_.\-]+)"""),
]
VAULT_CODE = re.compile(r"VaultTemplate|@VaultPropertySource|VaultOperations|hvac\.Client|import hvac|node-vault|VaultSharp|@Vault\b")
SM_CODE = re.compile(r"SecretsManagerClient|secretsmanager|GetSecretValue|SecretManagerServiceClient|SecretClient\b|"
                     r"KeyVaultClient|DefaultAzureCredential|AWSSecretsManager|boto3\.client\(\s*['\"]secretsmanager")
MOUNT_CODE = re.compile(r"/var/run/secrets|/etc/secrets|/mnt/secrets|configtree:|SERVICE_BINDING_ROOT|/bindings/")
VAULT_KEY = re.compile(r"(^|\.)(vault)(\.|$)|spring\.config\.import.*(vault|configserver)|spring\.cloud\.(vault|azure\.keyvault|aws\.secretsmanager|gcp\.secretmanager)", re.I)
SM_KEY = re.compile(r"secretsmanager|keyvault|secret-?manager|aws\.secrets", re.I)


def is_credential_key(key: str) -> bool:
    last = re.split(r"[.\[]", key.strip())[-1]
    if BENIGN_SUFFIX.search(key.split(".")[-1]) and not re.search(r"password|secret|key$|token$", last, re.I):
        return False
    return bool(CRED_KEY.search(key))


def _loc_type(rp: str) -> str:
    return "config" if rp.lower().endswith((".properties", ".yml", ".yaml", ".env", ".json", ".toml", ".ini", ".cfg", ".conf")) or rp.split("/")[-1].startswith(".env") else "source"


def scan_secrets(root: Path, entries: list[ConfigEntry], fp: TechStackFingerprint) -> SecretsAnalysis:
    res = SecretsAnalysis()
    seen: set[tuple] = set()

    def add_finding(kind, key, value, loc, rp, line, snippet):
        k = (kind, key, rp, line)
        if k not in seen:
            seen.add(k)
            res.hardcoded.append(SecretFinding(kind=kind, key=key, value_redacted=redact(value), location_type=loc,
                                               evidence=evidence(rp, line, snippet)))

    def add_source(mech, name, detail, loc, rp, line, snippet):
        k = (mech, name, rp, line)
        if k not in seen:
            seen.add(k)
            res.sourced_from.append(SecretSource(mechanism=mech, name=name, detail=detail, location_type=loc,
                                                 evidence=evidence(rp, line, snippet)))

    # ---- configuration files
    for e in entries:
        loc = "config"
        snippet = f"{e.key}=<value>"  # never echo the raw line: it may contain the secret
        m_jdbc, m_url = JDBC_PASSWORD.search(e.value), URL_CREDS.search(e.value)
        if m_jdbc and not ENV_PLACEHOLDER.fullmatch(m_jdbc.group(1)):
            add_finding("credentials_in_connection_string", e.key, m_jdbc.group(1), loc, e.file, e.line, snippet)
        elif m_url and not ENV_PLACEHOLDER.search(m_url.group(2)):
            add_finding("credentials_in_connection_string", e.key, m_url.group(2), loc, e.file, e.line, snippet)
        for label, rx in TOKEN_PATTERNS:
            if rx.search(e.value):
                add_finding("private_key" if "private" in label else "hardcoded_credential", label, e.value, loc, e.file, e.line, snippet)

        if VAULT_KEY.search(e.key) or VAULT_KEY.search(e.value):
            add_source("vault", e.key, "vault / config-server integration setting", loc, e.file, e.line, f"{e.key}=<value>")
        if SM_KEY.search(e.key):
            add_source("secrets_manager", e.key, "secrets manager integration setting", loc, e.file, e.line, f"{e.key}=<value>")
        if MOUNT_CODE.search(e.value):
            add_source("kubernetes_secret", e.key, "mounted secret / service-binding path", loc, e.file, e.line, f"{e.key}=<value>")

        if not is_credential_key(e.key):
            continue
        v = e.value.strip()
        if not v or FAKE.match(v) or TEMPLATE.match(v) or v.startswith("ENC("):
            continue
        ph = ENV_PLACEHOLDER.search(v)
        if ph:
            add_source("environment_variable", ph.group(1), f"config placeholder for {e.key}", loc, e.file, e.line,
                       f"{e.key}=${{{ph.group(1)}...}}")
            default = ph.group(2)
            if default and not FAKE.match(default):
                add_finding("default_value_in_placeholder", e.key, default, loc, e.file, e.line, snippet)
            continue
        add_finding("hardcoded_credential", e.key, v, loc, e.file, e.line, snippet)

    # ---- source code and other text files
    for f in iter_files(root, suffixes=SOURCE_SUFFIXES + (".xml", ".sh", ".gradle", ".kts", ".tf"), include_tests=False):
        rp = rel(f, root)
        loc = "source"
        if f.name in ("pom.xml",) or f.name.endswith(".csproj"):
            continue
        for i, line in enumerate(read_text(f).splitlines(), 1):
            s = line.strip()
            if s.startswith(("//", "*", "/*", "#")) and not TOKEN_PATTERNS[1][1].search(s):
                continue
            for label, rx in TOKEN_PATTERNS:
                if rx.search(line):
                    add_finding("private_key" if "private" in label else "hardcoded_credential", label, "x", loc, rp, i, f"<{label}>")
            m = SOURCE_ASSIGN.search(line)
            if m:
                key, val = m.group(1), m.group(2)
                if (not ENV_PLACEHOLDER.search(val) and not FAKE.match(val) and " " not in val
                        and val.lower() != key.lower() and not re.fullmatch(r"[a-z]+([._-][a-z]+)+", val)):
                    add_finding("hardcoded_credential", key, val, loc, rp, i, f"{key} = <string literal>")
            m2 = JDBC_PASSWORD.search(line) or URL_CREDS.search(line)
            if m2 and "${" not in line[m2.start():m2.end() + 20]:
                add_finding("credentials_in_connection_string", None, "x", loc, rp, i, "<connection string with credentials>")
            for rx in ENV_READS:
                for mm in rx.finditer(line):
                    name = next((g for g in mm.groups() if g), None)
                    if name and re.search(CRED_KEY.pattern + r"|url|dsn|conn|key", name, re.I):
                        add_source("environment_variable", name, "read from environment in code", loc, rp, i, s)
            if VAULT_CODE.search(line):
                add_source("vault", None, "vault client usage", loc, rp, i, s)
            if SM_CODE.search(line):
                add_source("secrets_manager", None, "cloud secrets manager client usage", loc, rp, i, s)
            if MOUNT_CODE.search(line):
                add_source("kubernetes_secret", None, "reads mounted secret path", loc, rp, i, s)

    for d in fp.dependencies:
        if "secrets" in d.categories and "test" not in d.categories:
            mech = "vault" if "vault" in d.name.lower() else "secrets_manager"
            add_source(mech, f"{d.group or ''}:{d.name}".strip(":"), "dependency for external secret retrieval", "config",
                       d.evidence.file, d.evidence.line, d.evidence.snippet)
    return res
