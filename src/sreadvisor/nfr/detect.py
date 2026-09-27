"""Turn a Stage 1 dataset into detection signals, match them to Master NFR List modules, and find
technologies that no module covers.

Nothing here judges the service; it only answers "which NFR modules apply" and "what did we find
that the list has no module for". The second answer is the feedback loop: an unrecognized tech
stack is flagged in the report, never silently skipped.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from sreadvisor.nfr.schema import REGEX_KEYS, RULE_KEYS, DetectRule, MasterNfrList, NfrModule
from sreadvisor.schema.common import Evidence
from sreadvisor.schema.dataset import ServiceDataset

# Dependency categories worth asking "is there an NFR module for this?" about. Test-only and plain
# web-templating libraries are skipped: the framework itself is checked instead.
CANDIDATE_CATEGORIES = {"datastore", "messaging", "cache", "security", "secrets", "resilience", "telemetry",
                        "schema_migration", "audit", "http_client"}
# Terraform providers that name a cloud platform (utility providers such as random or null are ignored).
CLOUD_PROVIDERS = {"google", "google-beta", "aws", "azurerm", "azuread", "oci", "alicloud", "ibm", "digitalocean"}
INFRA_LABELS = {
    "github_actions": "GitHub Actions", "gitlab_ci": "GitLab CI", "jenkins": "Jenkins", "harness": "Harness",
    "ucd": "UrbanCode Deploy", "azure_pipelines": "Azure Pipelines",
}


@dataclass
class Signals:
    """Everything the detection rules can look at."""

    languages: set[str] = field(default_factory=set)
    frameworks: set[str] = field(default_factory=set)
    dependencies: list[str] = field(default_factory=list)  # lower-case "group:name"
    infra: set[str] = field(default_factory=set)
    images: list[str] = field(default_factory=list)
    terraform_types: list[str] = field(default_factory=list)
    observability_provider: str | None = None
    entry_point_kinds: set[str] = field(default_factory=set)
    flow_dependency_kinds: set[str] = field(default_factory=set)


def coordinate(group: str | None, name: str) -> str:
    return f"{group or ''}:{name}".lower()


def signals_from_dataset(ds: ServiceDataset) -> Signals:
    s = Signals(observability_provider=ds.observability.provider.lower())
    for repo in ds.repositories:
        fp = repo.fingerprint
        s.languages |= {lang.lower() for lang in fp.languages}
        s.frameworks |= {f.name.lower() for f in fp.frameworks}
        s.dependencies += [coordinate(d.group, d.name) for d in fp.dependencies if "test" not in d.categories]
        s.entry_point_kinds |= {e.kind for e in repo.entry_points}
        for flow in repo.transaction_flows:
            s.flow_dependency_kinds |= {d.kind for d in flow.dependencies}
        s.flow_dependency_kinds |= {c.kind for c in repo.dependency_classification}

    infra = ds.infrastructure
    kinds = {w.kind for w in infra.workloads}
    if infra.workloads or infra.services or infra.ingresses:
        s.infra.add("kubernetes")
    if kinds & {"DeploymentConfig", "BuildConfig", "Route"} or any(
            re.search(r"\boc\s+(apply|rollout|new-app|start-build)", step) for p in infra.pipelines for step in p.deploy_steps):
        s.infra.add("openshift")
    if infra.helm_charts:
        s.infra.add("helm")
    if infra.terraform_resources:
        s.infra.add("terraform")
    if infra.dockerfiles or infra.compose_services:
        s.infra.add("docker")
    if infra.compose_services:
        s.infra.add("docker_compose")
    if infra.mesh.present or any(w.mesh_injection for w in infra.workloads):
        s.infra.add("service_mesh")
    if infra.mesh.mtls:
        s.infra.add("mtls")
    if infra.mesh.authorization_policies:
        s.infra.add("mesh_authorization")
    if infra.network_policies:
        s.infra.add("network_policy")
    for p in infra.pipelines:
        if p.system in INFRA_LABELS:
            s.infra.add(p.system)
    s.images = [c.image for w in infra.workloads for c in w.containers if c.image] + [
        c.image for c in infra.compose_services if c.image] + [b for d in infra.dockerfiles for b in d.base_images]
    s.terraform_types = [r.type for r in infra.terraform_resources]
    if any(r.provider.startswith("google") for r in infra.terraform_resources) or any(
            re.search(r"(gcr\.io|pkg\.dev)/", img) for img in s.images):
        s.infra.add("gcp")
    return s


# --------------------------------------------------------------------------------- matching


def _values(v: str | list[str] | None) -> list[str]:
    return [] if v is None else [v] if isinstance(v, str) else list(v)


def _any_regex(patterns: list[str], haystack: list[str]) -> str | None:
    for p in patterns:
        rx = re.compile(p, re.I)
        for h in haystack:
            if rx.search(h):
                return h
    return None


def rule_match(rule: DetectRule, s: Signals) -> str | None:
    """Return a human-readable reason if every condition of the rule holds, else None."""
    if rule.always:
        return "applies to every service"
    reasons: list[str] = []
    for key in RULE_KEYS:
        wanted = _values(getattr(rule, key))
        if not wanted:
            continue
        if key in REGEX_KEYS:
            haystack = {"dependency": s.dependencies, "image": s.images, "terraform": s.terraform_types}[key]
            hit = _any_regex(wanted, haystack)
            if hit is None:
                return None
            reasons.append(f"{key} '{hit}'")
        else:
            pool = {
                "language": s.languages, "framework": s.frameworks, "infra": s.infra,
                "entry_point": s.entry_point_kinds, "flow_dependency": s.flow_dependency_kinds,
                "observability_provider": {s.observability_provider} if s.observability_provider else set(),
            }[key]
            hit = next((w for w in wanted if w.lower() in pool), None)
            if hit is None:
                return None
            reasons.append(f"{key} '{hit}'")
    return " + ".join(reasons)


def match_reasons(module: NfrModule, s: Signals) -> list[str]:
    return [r for rule in module.detect if (r := rule_match(rule, s))]


@dataclass
class ModuleMatch:
    module: NfrModule
    reasons: list[str]


def applicable_modules(kb: MasterNfrList, s: Signals) -> list[ModuleMatch]:
    """Baseline and cross-cutting modules always apply; tech-stack modules when a rule matches."""
    out = []
    for m in kb.modules.values():
        reasons = match_reasons(m, s)
        if reasons or m.layer == "baseline":
            out.append(ModuleMatch(m, reasons or ["applies to every service"]))
    order = {"baseline": 0, "tech_stack": 1, "cross_cutting": 2}
    return sorted(out, key=lambda mm: (order[mm.module.layer], mm.module.id))


# ------------------------------------------------------------------------------ unrecognized


@dataclass
class Candidate:
    kind: str  # language | framework | dependency | infrastructure | cloud_provider | manifest | api_style
    name: str
    detail: str
    signals: Signals
    evidence: list[Evidence] = field(default_factory=list)


def candidates_from_dataset(ds: ServiceDataset) -> list[Candidate]:
    out: dict[tuple[str, str], Candidate] = {}

    def add(kind: str, name: str, detail: str, sig: Signals, ev: list[Evidence]) -> None:
        key = (kind, name.lower())
        if key not in out:
            out[key] = Candidate(kind, name, detail, sig, ev[:3])

    for repo in ds.repositories:
        fp = repo.fingerprint
        for lang in fp.languages:
            add("language", lang, f"language of repository {repo.repo}", Signals(languages={lang.lower()}), [])
        for f in fp.frameworks:
            add("framework", f.name, f"framework {f.name} {f.version or ''}".strip(), Signals(frameworks={f.name.lower()}), f.evidence)
        for d in fp.dependencies:
            cats = set(d.categories)
            if "test" in cats or not cats & CANDIDATE_CATEGORIES:
                continue
            coord = coordinate(d.group, d.name)
            label = f"{d.group + ':' if d.group else ''}{d.name}"
            kinds = "/".join(sorted(cats & CANDIDATE_CATEGORIES))
            add("dependency", label, f"{kinds} dependency ({d.ecosystem})", Signals(dependencies=[coord]), [d.evidence])
        for kind in sorted({e.kind for e in repo.entry_points} & {"grpc", "graphql"}):
            label = {"grpc": "gRPC", "graphql": "GraphQL"}[kind]
            add("api_style", label, f"{label} entry points in repository {repo.repo}", Signals(entry_point_kinds={kind}),
                [e.evidence for e in repo.entry_points if e.kind == kind])
        for um in fp.unparsed_manifests:
            add("manifest", um.stack, f"{um.file} present but Stage 1 has no parser for this stack",
                Signals(languages={um.stack.lower()}), [Evidence(file=um.file)])

    infra = ds.infrastructure
    seen_pipe: set[str] = set()
    for p in infra.pipelines:
        if p.system in seen_pipe:
            continue
        seen_pipe.add(p.system)
        label = INFRA_LABELS.get(p.system, p.system)
        add("infrastructure", label, f"CI/CD system found in {p.file}",
            Signals(infra={p.system} if p.system in INFRA_LABELS else set()), [Evidence(file=p.file)])
    if infra.mesh.present and infra.mesh.mesh:
        add("infrastructure", f"service mesh ({infra.mesh.mesh})", "mesh configuration found", Signals(infra={"service_mesh"}), [])
    for r in infra.terraform_resources:
        if r.provider in CLOUD_PROVIDERS or r.provider.split("/")[-1] in CLOUD_PROVIDERS:
            add("cloud_provider", r.provider, f"Terraform resources for provider {r.provider}",
                Signals(terraform_types=[r.type], infra={"terraform"} | ({"gcp"} if r.provider.startswith("google") else set())),
                [r.evidence])
    return list(out.values())


def is_recognized(kb: MasterNfrList, c: Candidate) -> bool:
    """A candidate is covered if some module would detect it (or explicitly recognises it) on its own."""
    for m in kb.modules.values():
        # `entry_point` and `flow_dependency` rules are applicability heuristics (a gRPC entry point suggests a microservice) and do not
        # mean the module covers that technology; only `recognizes` rules may name those.
        detect = [r for r in m.detect if r.entry_point is None and r.flow_dependency is None]
        if any(rule_match(r, c.signals) for r in [*detect, *m.recognizes] if not r.always):
            return True
    return False


@dataclass
class Unrecognized:
    kind: str
    name: str
    detail: str
    evidence: list[Evidence]


def unrecognized_technologies(kb: MasterNfrList, ds: ServiceDataset) -> list[Unrecognized]:
    out = [Unrecognized(c.kind, c.name, c.detail, c.evidence)
           for c in candidates_from_dataset(ds) if not is_recognized(kb, c)]
    return sorted(out, key=lambda u: (u.kind, u.name.lower()))
