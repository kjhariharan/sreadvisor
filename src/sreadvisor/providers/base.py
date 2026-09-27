"""ObservabilityProvider: the seam that keeps the pipeline vendor-neutral.

A provider fetches topology and metrics from one observability platform and returns them
in the common runtime schema (:mod:`sreadvisor.schema.runtime`). The pipeline, the
cross-validation stage and gap analysis only ever see that schema. To add New Relic,
Datadog or an internal monitoring system, write one subclass and register it in the
registry file; nothing else changes.

Integrations should be exposed as MCP tools (via ADK's ``MCPToolset``) where practical;
:meth:`ObservabilityProvider.mcp_toolset` is the hook for that.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, ClassVar

from pydantic import BaseModel, ConfigDict

from sreadvisor.schema.runtime import ServiceMetrics, ServiceTopology


class ProviderOptions(BaseModel):
    """Base for provider-specific options. Unknown keys are rejected so typos surface early."""

    model_config = ConfigDict(extra="forbid")


class ObservabilityError(RuntimeError):
    """A provider could not fetch topology or metrics (auth, network, or the platform itself). Every provider raises
    this (or a subclass of it), never its own unrelated exception type, so a caller such as the ``runtime`` CLI
    command can handle any provider without importing that provider's own module."""


class ObservabilityProvider(ABC):
    name: ClassVar[str]
    OptionsModel: ClassVar[type[ProviderOptions]] = ProviderOptions

    def __init__(self, service_id: str, options: ProviderOptions | None = None) -> None:
        self.service_id = service_id
        self.options = options if options is not None else self.OptionsModel()

    @classmethod
    def validate_options(cls, raw: dict[str, Any]) -> ProviderOptions:
        """Validate raw option values; raises ``pydantic.ValidationError`` naming bad fields."""
        return cls.OptionsModel(**raw)

    def public_options(self) -> dict[str, Any]:
        """Options that are safe to write to the dataset (secrets excluded)."""
        return {}

    def mcp_toolset(self) -> Any | None:
        """Optional ADK ``MCPToolset`` exposing this integration to agents."""
        return None

    @abstractmethod
    async def get_topology(self, service_id: str) -> ServiceTopology: ...

    @abstractmethod
    async def get_metrics(self, service_id: str) -> ServiceMetrics: ...
