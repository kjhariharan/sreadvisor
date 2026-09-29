from __future__ import annotations

import re
from pathlib import Path

from sreadvisor.schema.dataset import ServiceDataset
from sreadvisor.sinks.base import OutputSink


class JsonFileSink(OutputSink):
    name = "json_file"

    def emit(self, dataset: ServiceDataset, out_dir: Path) -> str:
        out_dir.mkdir(parents=True, exist_ok=True)
        safe = re.sub(r"[^A-Za-z0-9_.-]+", "-", dataset.service_name).strip("-") or "service"
        path = out_dir / f"{safe}.dataset.json"
        path.write_text(dataset.model_dump_json(indent=2, exclude_none=True), encoding="utf-8")
        return str(path)
