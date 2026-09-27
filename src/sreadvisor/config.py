"""Per-service configuration: load from a YAML/JSON file or build from CLI flags, then validate.

Validation collects *every* problem and names each offending field, e.g.
``observability.service_id: missing required field``.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from sreadvisor.registry import Registry, RegistryError

_URL_RE = re.compile(r"^(https?://|git@|ssh://)")


class ConfigError(Exception):
    def __init__(self, problems: list[str], source: str | None = None) -> None:
        self.problems = problems
        self.source = source
        head = f"Invalid configuration{f' ({source})' if source else ''}:"
        super().__init__(head + "".join(f"\n  - {p}" for p in problems))


class RepoRef(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str | None = None
    url: str | None = None
    ref: str | None = None
    name: str | None = None

    @model_validator(mode="after")
    def _one_source(self) -> "RepoRef":
        if bool(self.path) == bool(self.url):
            raise ValueError("give exactly one of 'path' or 'url'")
        return self

    @property
    def label(self) -> str:
        if self.name:
            return self.name
        src = (self.path or self.url or "repo").rstrip("/\\")
        return re.split(r"[/\\]", src)[-1].removesuffix(".git") or "repo"


class ObservabilityConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provider: str
    service_id: str
    options: dict[str, Any] = Field(default_factory=dict)


class ServiceConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    service_name: str
    code_repos: list[RepoRef] = Field(min_length=1)
    iac_paths: list[str] = Field(default_factory=list)
    observability: ObservabilityConfig
    output_dir: str | None = None

    config_dir: Path = Field(default=Path("."), exclude=True)


def _loc(err: dict[str, Any]) -> str:
    return ".".join(str(p) for p in err["loc"] if p != "config_dir") or "(root)"


def _friendly(err: dict[str, Any]) -> str:
    loc, kind, msg = _loc(err), err["type"], err["msg"]
    if kind == "missing":
        return f"{loc}: missing required field"
    if kind == "extra_forbidden":
        return f"{loc}: unknown field (check spelling)"
    if kind == "too_short":
        return f"{loc}: must contain at least one entry"
    return f"{loc}: {msg}"


def _normalize_repos(raw: Any) -> Any:
    if not isinstance(raw, list):
        return raw
    out: list[Any] = []
    for item in raw:
        if isinstance(item, str):
            out.append({"url": item} if _URL_RE.match(item) else {"path": item})
        else:
            out.append(item)
    return out


def _load_raw(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise ConfigError([f"config file not found: {path}"])
    text = path.read_text(encoding="utf-8")
    try:
        data = json.loads(text) if path.suffix.lower() == ".json" else yaml.safe_load(text)
    except (json.JSONDecodeError, yaml.YAMLError) as exc:
        raise ConfigError([f"file is not valid {'JSON' if path.suffix.lower() == '.json' else 'YAML'}: {exc}"], str(path)) from exc
    if not isinstance(data, dict):
        raise ConfigError(["top level must be a mapping/object with the service settings"], str(path))
    return data


def load_config_file(path: str | Path, registry: Registry | None = None) -> ServiceConfig:
    p = Path(path)
    return build_config(_load_raw(p), base_dir=p.resolve().parent, registry=registry, source=str(p))


def build_config(
    raw: dict[str, Any], *, base_dir: Path, registry: Registry | None = None, source: str | None = None
) -> ServiceConfig:
    raw = dict(raw)
    if "code_repos" in raw:
        raw["code_repos"] = _normalize_repos(raw["code_repos"])
    if isinstance(raw.get("iac_paths"), str):
        raw["iac_paths"] = [raw["iac_paths"]]
    problems: list[str] = []
    try:
        cfg = ServiceConfig(**raw)
    except ValidationError as exc:
        raise ConfigError([_friendly(e) for e in exc.errors()], source) from exc

    cfg.config_dir = base_dir
    problems += _check_paths(cfg)
    problems += _check_provider(cfg, registry or Registry.load())
    if problems:
        raise ConfigError(problems, source)
    return cfg


def resolve_path(cfg: ServiceConfig, value: str) -> Path:
    p = Path(value).expanduser()
    return p if p.is_absolute() else (cfg.config_dir / p).resolve()


def _check_paths(cfg: ServiceConfig) -> list[str]:
    problems: list[str] = []
    for i, repo in enumerate(cfg.code_repos):
        if repo.path and not resolve_path(cfg, repo.path).is_dir():
            problems.append(f"code_repos[{i}].path: directory does not exist: {resolve_path(cfg, repo.path)}")
    for i, iac in enumerate(cfg.iac_paths):
        if not resolve_path(cfg, iac).exists():
            problems.append(f"iac_paths[{i}]: path does not exist: {resolve_path(cfg, iac)}")
    return problems


def _check_provider(cfg: ServiceConfig, registry: Registry) -> list[str]:
    prefix = "observability"
    try:
        cls = registry.provider_class(cfg.observability.provider)
    except RegistryError as exc:
        return [f"{prefix}.provider: {exc}"]
    problems: list[str] = []
    sid = cfg.observability.service_id.strip()
    if not sid:
        problems.append(f"{prefix}.service_id: must not be empty")
    pattern = getattr(cls, "SERVICE_ID_RE", None)
    if sid and pattern is not None and not pattern.match(sid):
        problems.append(f"{prefix}.service_id: '{sid}' does not look like a {cls.name} service id")
    try:
        cls.validate_options(cfg.observability.options)
    except ValidationError as exc:
        for e in exc.errors():
            e = {**e, "loc": (prefix, "options", *e["loc"])}
            problems.append(_friendly(e))
    except ValueError as exc:
        problems.append(f"{prefix}.options.{exc}" if re.match(r"^\w+:", str(exc)) else f"{prefix}.options: {exc}")
    return problems


def config_from_flags(
    *,
    repos: list[str],
    iac: list[str],
    provider: str | None,
    service_id: str | None,
    service_name: str | None,
    provider_options: dict[str, Any],
    output_dir: str | None,
    registry: Registry | None = None,
    base_dir: Path | None = None,
) -> ServiceConfig:
    raw: dict[str, Any] = {
        "service_name": service_name or (re.split(r"[/\\]", repos[0].rstrip("/\\"))[-1] if repos else None),
        "code_repos": repos,
        "iac_paths": iac,
        "observability": {"provider": provider, "service_id": service_id, "options": provider_options},
    }
    if output_dir:
        raw["output_dir"] = output_dir
    raw["observability"] = {k: v for k, v in raw["observability"].items() if v is not None}
    raw = {k: v for k, v in raw.items() if v is not None}
    return build_config(raw, base_dir=base_dir or Path.cwd(), registry=registry, source="command-line flags")
