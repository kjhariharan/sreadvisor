"""NFR module contract (used from Stage 2 onward).

An NFR module evaluates the objective Stage 1 dataset (and, later, the common runtime
schema) against its own requirements list. Modules are registered in the registry file;
the Stage 1 dataset deliberately contains no judgment so it can be reused against an
evolving set of these modules.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from sreadvisor.schema.dataset import ServiceDataset


class NFRModule(ABC):
    name: str

    def bind(self, registry: Any, state_dir: Any, runner: Any | None = None, log: Any = print) -> "NFRModule":
        """Give the module what it needs to run (model settings from the registry, cache directory). Default: nothing."""
        return self

    @abstractmethod
    async def evaluate(self, dataset: ServiceDataset, runtime: Any | None = None) -> Any: ...
