from __future__ import annotations

from pathlib import Path

from sreadvisor.code.fingerprint.parsers import MANIFEST_PARSERS, UNPARSED_MANIFESTS, ParsedManifest
from sreadvisor.code.fingerprint.signatures import frameworks_for
from sreadvisor.schema.dataset import Framework, TechStackFingerprint, UnparsedManifest
from sreadvisor.util.files import iter_files, rel


def fingerprint_repo(root: Path) -> TechStackFingerprint:
    """Deterministic tech-stack fingerprint: parse every recognised manifest, then match signatures."""
    manifests: list[ParsedManifest] = []
    unparsed: dict[str, UnparsedManifest] = {}
    for f in iter_files(root, include_tests=False):
        lname = f.name.lower()
        for pred, parser in MANIFEST_PARSERS:
            if pred(lname):
                manifests.append(parser(f, rel(f, root)))
                break
        else:
            if lname in UNPARSED_MANIFESTS:
                stack = UNPARSED_MANIFESTS[lname]
                unparsed.setdefault(stack, UnparsedManifest(file=rel(f, root), stack=stack))

    fp = TechStackFingerprint(unparsed_manifests=sorted(unparsed.values(), key=lambda u: u.stack))
    seen_deps: set[tuple] = set()
    fw: dict[str, Framework] = {}

    def note_framework(name: str, version: str | None, ev) -> None:
        cur = fw.setdefault(name, Framework(name=name))
        if version and not cur.version and not version.startswith("${"):
            cur.version = version
        if len(cur.evidence) < 3:
            cur.evidence.append(ev)

    for pm in manifests:
        fp.manifests.append(pm.file)
        fp.parse_errors += pm.errors
        for lang in pm.languages:
            if lang not in fp.languages:
                fp.languages.append(lang)
        if pm.build_tool not in fp.build_tools:
            fp.build_tools.append(pm.build_tool)
        for k, v in pm.runtime_versions.items():
            fp.runtime_versions.setdefault(k, v)
        for h in pm.hints:  # parent / plugin / BOM first: they carry the authoritative framework version
            for name in frameworks_for(f"{h.group}:{h.name}") or frameworks_for(f":{h.name}"):
                note_framework(name, h.version, h.evidence)
        for d in pm.dependencies:
            key = (d.ecosystem, d.group, d.name, d.version, d.scope, d.evidence.file)
            if key not in seen_deps:
                seen_deps.add(key)
                fp.dependencies.append(d)
            if "test" in d.categories:
                continue
            for name in frameworks_for(f"{d.group or ''}:{d.name}"):
                note_framework(name, d.version, d.evidence)

    fp.frameworks = sorted(fw.values(), key=lambda f: (f.name != "Spring Boot", f.name))
    # A Maven/Gradle project that carries Kotlin sources is already flagged above; otherwise Java.
    return fp
