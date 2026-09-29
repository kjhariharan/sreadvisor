"""Configuration registry: providers, NFR modules, output sinks, model and analysis settings."""

from __future__ import annotations

import importlib
import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field

from sreadvisor.model_provider import ModelSettings

DEFAULT_REGISTRY = Path(__file__).with_name("default_registry.yaml")


class RegistryError(RuntimeError):
    pass


class RegistryEntry(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    class_path: str = Field(alias="class")
    enabled: bool = True
    options: dict[str, Any] = Field(default_factory=dict)


class GraphSettings(BaseModel):
    parallel: bool = False
    exclude_tests: bool = True


class LlmSettings(BaseModel):
    concurrency: int = 1
    max_chain_nodes: int = 30
    max_body_lines: int = 40
    cache: bool = True
    max_retries: int = 1
    # Generation settings for every agent call (agents/definitions.py's _agent()); 0.0 keeps findings reproducible
    # across a re-run with the same dataset, which is why every agent shared one hardcoded value before this was
    # a config property. Raise it only if a backend/model needs it to follow instructions reliably.
    temperature: float = 0.0
    max_output_tokens: int = 8192


class GapSettings(BaseModel):
    max_evidence_items: int = 30  # list items shown per dataset path in an assessor prompt
    max_evidence_chars: int = 6000  # cap on the projected dataset evidence per requirement
    verify_met: bool = True  # re-check every "met" verdict by trying to disprove it (a false met hides a real gap)


class AnalysisSettings(BaseModel):
    graph: GraphSettings = Field(default_factory=GraphSettings)
    llm: LlmSettings = Field(default_factory=LlmSettings)
    gap: GapSettings = Field(default_factory=GapSettings)


def import_class(dotted: str) -> type:
    module_name, _, cls_name = dotted.rpartition(".")
    if not module_name:
        raise RegistryError(f"'{dotted}' is not a dotted class path")
    try:
        return getattr(importlib.import_module(module_name), cls_name)
    except (ImportError, AttributeError) as exc:
        raise RegistryError(f"Cannot import '{dotted}': {exc}") from exc


class Registry(BaseModel):
    model: dict[str, Any] = Field(default_factory=dict)
    providers: dict[str, RegistryEntry] = Field(default_factory=dict)
    nfr_modules: dict[str, RegistryEntry] = Field(default_factory=dict)
    output_sinks: dict[str, RegistryEntry] = Field(default_factory=dict)
    analysis: AnalysisSettings = Field(default_factory=AnalysisSettings)
    source: str = ""

    @classmethod
    def load(cls, path: str | Path | None = None) -> "Registry":
        chosen = Path(path) if path else Path(os.environ["SREADVISOR_REGISTRY"]) if os.environ.get(
            "SREADVISOR_REGISTRY"
        ) else DEFAULT_REGISTRY
        if not chosen.is_file():
            raise RegistryError(f"Registry file not found: {chosen}")
        try:
            raw = yaml.safe_load(chosen.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            raise RegistryError(f"Registry file {chosen} is not valid YAML: {exc}") from exc
        try:
            return cls(**raw, source=str(chosen))
        except Exception as exc:
            raise RegistryError(f"Registry file {chosen} is malformed: {exc}") from exc

    def model_settings(self) -> ModelSettings:
        return ModelSettings.from_config(self.model)

    # -- providers ---------------------------------------------------------------
    def provider_names(self) -> list[str]:
        return [n for n, e in self.providers.items() if e.enabled]

    def provider_class(self, name: str):
        entry = self.providers.get(name)
        if entry is None or not entry.enabled:
            raise RegistryError(
                f"Observability provider '{name}' is not enabled in the registry. "
                f"Enabled providers: {', '.join(self.provider_names()) or '(none)'}."
            )
        return import_class(entry.class_path)

    # -- sinks / nfr modules -----------------------------------------------------
    def active_sinks(self) -> list[Any]:
        return [import_class(e.class_path)(**e.options) for e in self.output_sinks.values() if e.enabled]

    def active_nfr_modules(self) -> list[Any]:
        return [import_class(e.class_path)(**e.options) for e in self.nfr_modules.values() if e.enabled]
