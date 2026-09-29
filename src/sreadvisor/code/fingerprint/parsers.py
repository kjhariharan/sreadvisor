"""One parser per manifest format. Add a parser here when a new stack is encountered.

Each parser turns one manifest file into a :class:`ParsedManifest`; the fingerprint step
merges them. Parsers never call an LLM.
"""

from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable
from xml.parsers.expat import ExpatError

from sreadvisor.code.fingerprint.signatures import categories_for
from sreadvisor.schema.common import Evidence
from sreadvisor.schema.dataset import Dependency
from sreadvisor.util.files import evidence, read_text
from sreadvisor.util.xmlx import XNode, parse_xml


@dataclass
class Hint:
    """A coordinate that signals a framework but is not itself a runtime dependency
    (Maven parent, BOM import, build plugin)."""

    group: str
    name: str
    version: str | None
    evidence: Evidence


@dataclass
class ParsedManifest:
    file: str
    ecosystem: str
    build_tool: str
    languages: list[str] = field(default_factory=list)
    runtime_versions: dict[str, str] = field(default_factory=dict)
    dependencies: list[Dependency] = field(default_factory=list)
    hints: list[Hint] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


_TEST_SCOPES = {"test", "testimplementation", "testcompileonly", "testruntimeonly", "testcompile", "dev"}


def _dep(ecosystem: str, group: str | None, name: str, version: str | None, scope: str | None, ev: Evidence) -> Dependency:
    coordinate = f"{group or ''}:{name}"
    # Test/dev-only dependencies are not part of the running service, so they carry no runtime categories.
    categories = ["test"] if (scope or "").lower() in _TEST_SCOPES else categories_for(coordinate)
    return Dependency(
        ecosystem=ecosystem, group=group, name=name, version=version, scope=scope,
        categories=categories, evidence=ev,
    )


# ------------------------------------------------------------------------------ Maven


def _resolve(value: str | None, props: dict[str, str]) -> str | None:
    if value is None:
        return None
    for _ in range(5):
        new = re.sub(r"\$\{([^}]+)\}", lambda m: props.get(m.group(1), m.group(0)), value)
        if new == value:
            break
        value = new
    return value


def parse_maven(path: Path, rel: str) -> ParsedManifest:
    pm = ParsedManifest(file=rel, ecosystem="maven", build_tool="maven", languages=["Java"])
    try:
        root = parse_xml(read_text(path))
    except ExpatError as exc:
        pm.errors.append(f"{rel}: malformed XML ({exc})")
        return pm

    props: dict[str, str] = {}
    props_node = root.find("properties")
    if props_node is not None:
        for c in props_node.children:
            props[c.tag] = c.text.strip()
    for key in ("java.version", "maven.compiler.release", "maven.compiler.source", "maven.compiler.target"):
        if props.get(key):
            pm.runtime_versions["java"] = _resolve(props[key], props) or props[key]
            break

    parent = root.find("parent")
    if parent is not None:
        pm.hints.append(Hint(
            parent.child_text("groupId") or "", parent.child_text("artifactId") or "",
            _resolve(parent.child_text("version"), props), evidence(rel, parent.line, "<parent>")))

    def read_dep(node: XNode) -> tuple[str, str, str | None, str | None]:
        return (
            _resolve(node.child_text("groupId"), props) or "",
            _resolve(node.child_text("artifactId"), props) or "",
            _resolve(node.child_text("version"), props),
            node.child_text("scope"),
        )

    deps_node = root.find("dependencies")
    for d in (deps_node.findall("dependency") if deps_node is not None else []):
        g, a, v, s = read_dep(d)
        if a:
            pm.dependencies.append(_dep("maven", g, a, v, s, evidence(rel, d.line, f"{g}:{a}")))

    mgmt = root.find("dependencyManagement")
    if mgmt is not None and mgmt.find("dependencies") is not None:
        for d in mgmt.find("dependencies").findall("dependency"):
            g, a, v, _ = read_dep(d)
            if d.child_text("scope") == "import":  # BOM import
                pm.hints.append(Hint(g, a, v, evidence(rel, d.line, f"BOM {g}:{a}")))

    build = root.find("build")
    plugins = build.find("plugins") if build is not None else None
    for p in (plugins.findall("plugin") if plugins is not None else []):
        g, a, v, _ = read_dep(p)
        if a:
            pm.hints.append(Hint(g or "org.apache.maven.plugins", a, v, evidence(rel, p.line, f"plugin {g}:{a}")))
            if "kotlin" in a and "Kotlin" not in pm.languages:
                pm.languages.append("Kotlin")
    return pm


# ----------------------------------------------------------------------------- Gradle

_GRADLE_CONFIGS = (
    "implementation|api|compileOnly|runtimeOnly|testImplementation|testCompileOnly|testRuntimeOnly|annotationProcessor|"
    "developmentOnly|compile|runtime|testCompile|kapt|providedRuntime"
)
_GRADLE_DEP = re.compile(rf"^\s*({_GRADLE_CONFIGS})\s*\(?\s*['\"]([^'\":\s]+):([^'\":\s]+)(?::([^'\"\s]+))?['\"]", re.M)
_GRADLE_PLUGIN = re.compile(r"""^\s*id\s*\(?\s*['"]([^'"]+)['"]\)?(?:\s*\)?\s+version\s+['"]([^'"]+)['"])?""", re.M)
_GRADLE_JAVA = re.compile(r"(?:JavaLanguageVersion\.of\(\s*(\d+)\s*\)|sourceCompatibility\s*=\s*['\"]?(?:JavaVersion\.VERSION_)?([\d._]+))")


def parse_gradle(path: Path, rel: str) -> ParsedManifest:
    text = read_text(path)
    pm = ParsedManifest(file=rel, ecosystem="gradle", build_tool="gradle", languages=["Java"])
    if path.suffix == ".kts" or "org.jetbrains.kotlin" in text:
        pm.languages.append("Kotlin")

    def ln(m: re.Match[str]) -> int:
        return text.count("\n", 0, m.start()) + 1

    for m in _GRADLE_DEP.finditer(text):
        conf, g, a, v = m.groups()
        pm.dependencies.append(_dep("gradle", g, a, v, conf, evidence(rel, ln(m), m.group(0))))
    for m in _GRADLE_PLUGIN.finditer(text):
        pid, ver = m.groups()
        pm.hints.append(Hint(pid, pid, ver, evidence(rel, ln(m), m.group(0))))
    jm = _GRADLE_JAVA.search(text)
    if jm:
        pm.runtime_versions["java"] = (jm.group(1) or jm.group(2)).replace("_", ".")
    return pm


# -------------------------------------------------------------------------------- npm


def _json_line(text: str, needle: str) -> int | None:
    idx = text.find(f'"{needle}"')
    return None if idx < 0 else text.count("\n", 0, idx) + 1


def parse_npm(path: Path, rel: str) -> ParsedManifest:
    text = read_text(path)
    pm = ParsedManifest(file=rel, ecosystem="npm", build_tool="npm", languages=["JavaScript"])
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        pm.errors.append(f"{rel}: malformed JSON ({exc})")
        return pm
    if not isinstance(data, dict):
        pm.errors.append(f"{rel}: expected a JSON object")
        return pm
    if (data.get("engines") or {}).get("node"):
        pm.runtime_versions["node"] = str(data["engines"]["node"])
    for section, scope in (("dependencies", "runtime"), ("devDependencies", "dev"), ("peerDependencies", "peer"),
                           ("optionalDependencies", "optional")):
        for name, ver in (data.get(section) or {}).items():
            pm.dependencies.append(_dep("npm", None, name, str(ver), scope, evidence(rel, _json_line(text, name), f"{name}@{ver}")))
    if any(d.name == "typescript" for d in pm.dependencies):
        pm.languages.append("TypeScript")
    return pm


# ---------------------------------------------------------------------------- Python

_REQ = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9_.\-]*)\s*(?:\[[^\]]*\])?\s*([<>=!~][^;#\s]*(?:\s*,\s*[<>=!~][^;#\s]*)*)?")


def _py_dep(spec: str, rel: str, line: int | None, scope: str) -> Dependency | None:
    m = _REQ.match(spec)
    if not m:
        return None
    return _dep("pypi", None, m.group(1).lower(), (m.group(2) or "").strip() or None, scope, evidence(rel, line, spec))


def parse_pyproject(path: Path, rel: str) -> ParsedManifest:
    text = read_text(path)
    pm = ParsedManifest(file=rel, ecosystem="pypi", build_tool="pyproject", languages=["Python"])
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        pm.errors.append(f"{rel}: malformed TOML ({exc})")
        return pm

    def line_of(needle: str) -> int | None:
        idx = text.find(needle)
        return None if idx < 0 else text.count("\n", 0, idx) + 1

    project = data.get("project") or {}
    if project.get("requires-python"):
        pm.runtime_versions["python"] = project["requires-python"]
    for spec in project.get("dependencies") or []:
        d = _py_dep(spec, rel, line_of(spec), "runtime")
        if d:
            pm.dependencies.append(d)
    for group, specs in (project.get("optional-dependencies") or {}).items():
        for spec in specs:
            d = _py_dep(spec, rel, line_of(spec), f"optional:{group}")
            if d:
                pm.dependencies.append(d)
    poetry = (data.get("tool") or {}).get("poetry") or {}
    for name, spec in (poetry.get("dependencies") or {}).items():
        if name.lower() == "python":
            pm.runtime_versions["python"] = str(spec)
            continue
        ver = spec if isinstance(spec, str) else (spec.get("version") if isinstance(spec, dict) else None)
        pm.dependencies.append(_dep("pypi", None, name.lower(), ver, "runtime", evidence(rel, line_of(name), f"{name} = {ver}")))
    for spec in (data.get("dependency-groups") or {}).get("dev", []) or []:
        if isinstance(spec, str):
            d = _py_dep(spec, rel, line_of(spec), "dev")
            if d:
                pm.dependencies.append(d)
    return pm


def parse_requirements(path: Path, rel: str) -> ParsedManifest:
    pm = ParsedManifest(file=rel, ecosystem="pypi", build_tool="pip", languages=["Python"])
    for i, raw in enumerate(read_text(path).splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "git+", "http")):
            continue
        d = _py_dep(line, rel, i, "runtime")
        if d:
            pm.dependencies.append(d)
    return pm


# ---------------------------------------------------------------------------- .NET


def parse_csproj(path: Path, rel: str) -> ParsedManifest:
    pm = ParsedManifest(file=rel, ecosystem="nuget", build_tool="dotnet", languages=["C#"])
    try:
        root = parse_xml(read_text(path))
    except ExpatError as exc:
        pm.errors.append(f"{rel}: malformed XML ({exc})")
        return pm
    sdk = root.attrs.get("Sdk", "")
    if sdk:
        pm.hints.append(Hint("", "Microsoft.AspNetCore" if sdk.endswith(".Web") else sdk, None,
                             evidence(rel, root.line, f"Sdk={sdk}")))
    for node in root.iter():
        if node.tag in ("TargetFramework", "TargetFrameworks") and node.text.strip():
            pm.runtime_versions["dotnet"] = node.text.strip()
        elif node.tag == "PackageReference":
            name = node.attrs.get("Include") or node.attrs.get("Update")
            if name:
                ver = node.attrs.get("Version") or node.child_text("Version")
                pm.dependencies.append(_dep("nuget", None, name, ver, None, evidence(rel, node.line, f"{name} {ver or ''}")))
    return pm


# ------------------------------------------------------------------------------ Go

_GO_REQ = re.compile(r"^\s*(?:require\s+)?([\w.\-~]+(?:/[\w.\-~]+)+)\s+(v[\w.\-+]+)(\s*//\s*indirect)?")


def parse_gomod(path: Path, rel: str) -> ParsedManifest:
    pm = ParsedManifest(file=rel, ecosystem="gomod", build_tool="go", languages=["Go"])
    in_block = False
    for i, raw in enumerate(read_text(path).splitlines(), 1):
        line = raw.strip()
        if re.fullmatch(r"go\s+[\d.]+", line):
            pm.runtime_versions["go"] = line.split()[1]
        elif line.startswith("require ("):
            in_block = True
        elif in_block and line == ")":
            in_block = False
        elif in_block or line.startswith("require "):
            m = _GO_REQ.match(raw)
            if not m:
                continue
            name, version, indirect = m.groups()
            if indirect:  # transitive: kept without categories so it does not read as a direct choice
                pm.dependencies.append(Dependency(ecosystem="gomod", group=None, name=name, version=version,
                                                  scope="indirect", categories=[], evidence=evidence(rel, i, line)))
            else:
                pm.dependencies.append(_dep("gomod", None, name, version, "runtime", evidence(rel, i, line)))
    return pm


# ---------------------------------------------------------------------------- Rust


def parse_cargo(path: Path, rel: str) -> ParsedManifest:
    text = read_text(path)
    pm = ParsedManifest(file=rel, ecosystem="cargo", build_tool="cargo", languages=["Rust"])
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        pm.errors.append(f"{rel}: malformed TOML ({exc})")
        return pm

    def line_of(needle: str) -> int | None:
        m = re.search(rf"^\s*{re.escape(needle)}\s*[=.{{]", text, re.M)
        return None if not m else text.count("\n", 0, m.start()) + 1

    package = data.get("package") or {}
    if package.get("rust-version"):
        pm.runtime_versions["rust"] = str(package["rust-version"])
    if package.get("edition"):
        pm.runtime_versions["rust_edition"] = str(package["edition"])
    tables = [("dependencies", "runtime", data), ("dev-dependencies", "dev", data), ("build-dependencies", "build", data),
              ("dependencies", "runtime", data.get("workspace") or {})]
    for key, scope, table in tables:
        for name, spec in (table.get(key) or {}).items():
            ver = spec if isinstance(spec, str) else (spec.get("version") if isinstance(spec, dict) else None)
            pm.dependencies.append(_dep("cargo", None, name.lower(), ver, scope,
                                        evidence(rel, line_of(name), f"{name} = {ver or '...'}")))
    return pm


# Manifests of stacks that have no parser yet. Finding one records the stack instead of skipping it silently.
UNPARSED_MANIFESTS: dict[str, str] = {
    "gemfile": "Ruby", "composer.json": "PHP", "build.sbt": "Scala", "mix.exs": "Elixir", "pubspec.yaml": "Dart",
    "package.swift": "Swift", "project.clj": "Clojure", "deps.edn": "Clojure", "stack.yaml": "Haskell",
    "package.yaml": "Haskell", "cmakelists.txt": "C/C++", "rebar.config": "Erlang",
}


# ------------------------------------------------------------------------- registry

Parser = Callable[[Path, str], ParsedManifest]

# (predicate over lower-case file name, parser). Append here to support a new format.
MANIFEST_PARSERS: list[tuple[Callable[[str], bool], Parser]] = [
    (lambda n: n == "pom.xml", parse_maven),
    (lambda n: n in ("build.gradle", "build.gradle.kts"), parse_gradle),
    (lambda n: n == "package.json", parse_npm),
    (lambda n: n == "pyproject.toml", parse_pyproject),
    (lambda n: re.fullmatch(r"requirements[\w.\-]*\.txt", n) is not None, parse_requirements),
    (lambda n: n.endswith(".csproj"), parse_csproj),
    (lambda n: n == "go.mod", parse_gomod),
    (lambda n: n == "cargo.toml", parse_cargo),
]
