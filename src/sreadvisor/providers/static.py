"""A file-backed provider that already speaks the common runtime schema.

Useful for offline runs and tests, and it demonstrates the extension contract: a provider
is one small class registered in the registry file.
"""

from __future__ import annotations

import json
from pathlib import Path

from sreadvisor.providers.base import ObservabilityProvider, ProviderOptions
from sreadvisor.schema.runtime import ServiceMetrics, ServiceTopology


class StaticOptions(ProviderOptions):
    topology_file: str
    metrics_file: str


class StaticProvider(ObservabilityProvider):
    name = "static"
    OptionsModel = StaticOptions
    options: StaticOptions

    def public_options(self) -> dict[str, str]:
        return {"topology_file": self.options.topology_file, "metrics_file": self.options.metrics_file}

    async def get_topology(self, service_id: str) -> ServiceTopology:
        return ServiceTopology(**json.loads(Path(self.options.topology_file).read_text(encoding="utf-8")))

    async def get_metrics(self, service_id: str, metric_keys: list[str] | None = None, from_time: str = "now-2h",
                          resolution: str = "Inf") -> ServiceMetrics:
        # A file already holds one fixed answer, so a requested window/resolution/metric selection is accepted (for
        # interface parity with a live provider such as DynatraceProvider) but has nothing to act on.
        return ServiceMetrics(**json.loads(Path(self.options.metrics_file).read_text(encoding="utf-8")))
