"""Encryption (at rest / in transit) and audit/retention evidence found in application code and config."""

from __future__ import annotations

import re
from pathlib import Path

from sreadvisor.code.configfiles import ConfigEntry
from sreadvisor.graph.code_graph import SOURCE_SUFFIXES
from sreadvisor.schema.dataset import EncryptionAuditAnalysis, EncryptionAuditFact, TechStackFingerprint
from sreadvisor.util.files import evidence, iter_files, read_text, rel

TLS_KEY = re.compile(r"(^|[.\-_\[])(ssl|tls|https|mtls|trust-?store|key-?store|certificate|require-ssl|insecure-requests)([.\-_\]]|$)", re.I)
SECRET_VALUE_KEY = re.compile(r"password|secret|passphrase", re.I)
RETENTION_KEY = re.compile(r"(retention|max-?history|total-?size-?cap|time-?to-?live|(^|[.\-_])ttl($|[.\-_])|expir|purge|archiv)", re.I)
AUDIT_KEY = re.compile(r"(audit|envers)", re.I)
AT_REST_KEY = re.compile(r"(encrypt|kms|cipher|jasypt|transparent-?data|sse[.\-_]|column-?encryption)", re.I)
DB_URL_KEY = re.compile(r"(datasource|jdbc|mongodb|redis|rabbitmq|amqp|kafka|bootstrap).*(url|uri|address|servers|host)", re.I)
TLS_IN_URL = re.compile(r"(ssl(mode)?=(true|require|verify-(ca|full)|required|preferred)|useSSL=true|encrypt=true|sslmode=(require|verify)|"
                        r"tls=true|rediss://|amqps://|mongodb\+srv://|:9093|https://)", re.I)
TLS_OFF_IN_URL = re.compile(r"(useSSL=false|ssl=false|sslmode=disable|sslMode=DISABLED|encrypt=false|tls=false)", re.I)
TRUTHY, FALSY = {"true", "yes", "on", "required", "1"}, {"false", "no", "off", "disabled", "0"}

PLAIN_HTTP = re.compile(r"http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|\$\{|\{)[A-Za-z0-9._\-]+(?::\d+)?[^\s\"'<>)\]]*")
NAMESPACE_HOSTS = re.compile(r"http://(www\.w3\.org|www\.springframework\.org|maven\.apache\.org|java\.sun\.com|xmlns\.jcp\.org|"
                             r"www\.apache\.org|www\.eclipse\.org|schemas?\.|www\.thymeleaf\.org|www\.opensource\.org|"
                             r"www\.gnu\.org|xml\.apache\.org|www\.hibernate\.org|jakarta\.ee|www\.slf4j\.org|logback\.qos\.ch|"
                             r"json-schema\.org|docs\.oracle\.com|opensource\.org|www\.mozilla\.org|purl\.org)", re.I)
INSECURE_CODE = re.compile(r"TrustAllStrategy|NoopHostnameVerifier|ALLOW_ALL_HOSTNAME_VERIFIER|InsecureSkipVerify|"
                           r"rejectUnauthorized\s*:\s*false|verify\s*=\s*False|ServerCertificateCustomValidationCallback\s*=.*true|"
                           r"DangerousAcceptAnyServerCertificateValidator|TrustManager\b.*\{\s*\}|checkServerTrusted\([^)]*\)\s*\{\s*\}")
AUDIT_CODE = [
    ("authentication events", re.compile(r"AuthenticationSuccessEvent|AuthenticationFailure\w*Event|AbstractAuthenticationAuditListener|"
                                         r"AuthenticationEventPublisher|LogoutSuccessEvent|AuditEventRepository|AuditApplicationEvent|AuditEvent\b|"
                                         r"signInManager|SignInResult|ILogger.*(login|sign-?in)", re.I)),
    ("data change auditing", re.compile(r"@Audited\b|@EnableJpaAuditing|@EntityListeners\(\s*AuditingEntityListener|@CreatedBy|@LastModifiedBy|"
                                        r"@CreatedDate|@LastModifiedDate|AuditorAware|Envers|javers|SaveChangesInterceptor|IAuditable", re.I)),
    ("audit logging", re.compile(r"audit[_.\-]?log|auditLogger|getLogger\(\s*[\"']audit|logger\.\w+\(\s*[\"']AUDIT|LoggerFactory\.getLogger\(\s*[\"'].*audit", re.I)),
    ("administrative actions", re.compile(r"@PreAuthorize\(\s*\"hasRole\('ADMIN'\)|@RolesAllowed\(\s*\"admin|\[Authorize\(Roles\s*=\s*\"Admin", re.I)),
]


def _status_for(value: str) -> str:
    v = value.strip().lower()
    return "enabled" if v in TRUTHY else "disabled" if v in FALSY else "configured"


def scan_encryption_audit(root: Path, entries: list[ConfigEntry], fp: TechStackFingerprint) -> EncryptionAuditAnalysis:
    facts: list[EncryptionAuditFact] = []
    seen: set[tuple] = set()

    def add(domain, subject, setting, value, status, layer, rp, line, snippet):
        k = (domain, setting, rp, line)
        if k not in seen:
            seen.add(k)
            facts.append(EncryptionAuditFact(domain=domain, subject=subject, setting=setting, value=value, status=status,
                                             layer=layer, evidence=evidence(rp, line, snippet)))

    for e in entries:
        red = "<redacted>" if SECRET_VALUE_KEY.search(e.key) else e.value[:120]
        snip = f"{e.key}={red}"
        if DB_URL_KEY.search(e.key) and re.match(r"^\s*(\$\{[^}]*:)?\s*(jdbc|mongodb|redis|amqp|kafka|[\w.\-]+:\d+|https?)", e.value, re.I):
            m_off, m_on = TLS_OFF_IN_URL.search(e.value), TLS_IN_URL.search(e.value)
            subject = re.split(r"[.\[]", e.key)[1] if "." in e.key else e.key
            if m_off:
                add("in_transit", f"{subject} connection", e.key, m_off.group(0), "disabled", "config", e.file, e.line, snip)
            elif m_on:
                add("in_transit", f"{subject} connection", e.key, m_on.group(0), "enabled", "config", e.file, e.line, snip)
            elif re.match(r"^\s*(\$\{[^}]*:)?\s*(jdbc|mongodb|redis|amqp)", e.value, re.I):
                add("in_transit", f"{subject} connection", e.key, "no explicit TLS parameter in URL", "detected", "config", e.file, e.line, snip)
        if TLS_KEY.search(e.key):
            add("in_transit", "application endpoint / client", e.key, red, _status_for(e.value), "config", e.file, e.line, snip)
        if AT_REST_KEY.search(e.key):
            add("at_rest", "configured encryption setting", e.key, red, _status_for(e.value), "config", e.file, e.line, snip)
        if AUDIT_KEY.search(e.key):
            add("audit", "audit configuration", e.key, red, _status_for(e.value), "config", e.file, e.line, snip)
        if RETENTION_KEY.search(e.key):
            add("retention", "retention / expiry configuration", e.key, red, "configured", "config", e.file, e.line, snip)
        if e.value.startswith("ENC("):
            add("at_rest", "config value encrypted with Jasypt", e.key, "ENC(...)", "enabled", "config", e.file, e.line, f"{e.key}=ENC(...)")
        for m in PLAIN_HTTP.finditer(e.value):
            if not NAMESPACE_HOSTS.match(m.group(0)):
                add("in_transit", "plain HTTP endpoint", e.key, m.group(0)[:120], "plaintext", "config", e.file, e.line, snip)

    for f in iter_files(root, suffixes=SOURCE_SUFFIXES, include_tests=False):
        rp = rel(f, root)
        for i, line in enumerate(read_text(f).splitlines(), 1):
            s = line.strip()
            if s.startswith(("//", "*", "/*", "#")):
                continue
            if INSECURE_CODE.search(line):
                add("in_transit", "TLS certificate / hostname validation", "validation bypass in code", s[:120], "disabled", "code", rp, i, s)
            for m in PLAIN_HTTP.finditer(line):
                if not NAMESPACE_HOSTS.match(m.group(0)) and "xmlns" not in line:
                    add("in_transit", "plain HTTP endpoint", "http:// literal in code", m.group(0)[:120], "plaintext", "code", rp, i, s)
            for subject, rx in AUDIT_CODE:
                if rx.search(line):
                    add("audit", subject, "audit-related code", s[:120], "detected", "code", rp, i, s)
                    break
            if re.search(r"@Convert\(.*(Crypt|Encrypt|Cipher)|@ColumnTransformer|AES/|Cipher\.getInstance|pgcrypto|EncryptedType|Fernet\(", line):
                add("at_rest", "application-level data encryption", "encryption in code", s[:120], "detected", "code", rp, i, s)

    for d in fp.dependencies:
        if "test" in d.categories:
            continue
        if "audit" in d.categories or re.search(r"envers|javers|jasypt|bouncycastle|tink|cryptography", d.name, re.I):
            domain = "audit" if "audit" in d.categories else "at_rest"
            add(domain, "dependency", f"{d.group or ''}:{d.name}".strip(":"), d.version or "", "detected", "config",
                d.evidence.file, d.evidence.line, d.evidence.snippet)
        if d.name == "spring-boot-starter-actuator":
            add("audit", "actuator auditevents endpoint available", "spring-boot-starter-actuator", "", "detected", "config",
                d.evidence.file, d.evidence.line, d.evidence.snippet)
    return EncryptionAuditAnalysis(facts=facts)
