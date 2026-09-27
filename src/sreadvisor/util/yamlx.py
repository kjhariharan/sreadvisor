"""YAML loading that keeps line numbers, so every fact can cite file:line."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import yaml

Path_ = tuple[Any, ...]


@dataclass
class YamlDoc:
    data: Any
    lines: dict[Path_, int] = field(default_factory=dict)
    start_line: int = 1

    def line(self, *path: Any) -> int:
        """Line of ``path``, falling back to the nearest ancestor that has one."""
        p = tuple(path)
        while p:
            if p in self.lines:
                return self.lines[p]
            p = p[:-1]
        return self.start_line


def _walk(node: yaml.Node, path: Path_, out: dict[Path_, int]) -> None:
    out[path] = node.start_mark.line + 1
    if isinstance(node, yaml.MappingNode):
        for k, v in node.value:
            key = getattr(k, "value", None)
            if not isinstance(key, str):
                continue
            kp = path + (key,)
            out[kp] = k.start_mark.line + 1
            _walk(v, kp, out)
            out[kp] = k.start_mark.line + 1  # key line wins over value line
    elif isinstance(node, yaml.SequenceNode):
        for i, item in enumerate(node.value):
            _walk(item, path + (i,), out)


def load_yaml_docs(text: str) -> list[YamlDoc]:
    """Parse a (possibly multi-document) YAML string. Raises ``yaml.YAMLError`` on bad input."""
    loader = yaml.SafeLoader(text)
    docs: list[YamlDoc] = []
    try:
        while loader.check_node():
            node = loader.get_node()
            if node is None:
                continue
            lines: dict[Path_, int] = {}
            _walk(node, (), lines)
            data = loader.construct_document(node)
            if data is None:
                continue
            docs.append(YamlDoc(data=data, lines=lines, start_line=node.start_mark.line + 1))
    finally:
        loader.dispose()
    return docs


def flatten(data: Any, prefix: str = "") -> dict[str, tuple[Any, Path_]]:
    """Flatten nested mappings/lists to ``dotted.key -> (value, path)``."""
    out: dict[str, tuple[Any, Path_]] = {}

    def rec(node: Any, dotted: str, path: Path_) -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                rec(v, f"{dotted}.{k}" if dotted else str(k), path + (k,))
        elif isinstance(node, list):
            for i, v in enumerate(node):
                rec(v, f"{dotted}[{i}]", path + (i,))
        else:
            out[dotted] = (node, path)

    rec(data, prefix, ())
    return out
