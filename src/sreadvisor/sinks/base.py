from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from sreadvisor.schema.dataset import ServiceDataset


class OutputSink(ABC):
    """Consumes a finished dataset. Register new sinks (Markdown, Confluence, ...) in the registry."""

    name: str

    @abstractmethod
    def emit(self, dataset: ServiceDataset, out_dir: Path) -> str | None:
        """Write/print the dataset. Return a human-readable location, if any."""
