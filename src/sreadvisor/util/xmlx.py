"""Minimal XML tree with line numbers (ElementTree drops them). Namespaces are ignored."""

from __future__ import annotations

from dataclasses import dataclass, field
from xml.parsers import expat


@dataclass
class XNode:
    tag: str
    attrs: dict[str, str]
    line: int
    text: str = ""
    children: list["XNode"] = field(default_factory=list)

    def find(self, tag: str) -> "XNode | None":
        return next((c for c in self.children if c.tag == tag), None)

    def findall(self, tag: str) -> list["XNode"]:
        return [c for c in self.children if c.tag == tag]

    def child_text(self, tag: str) -> str | None:
        c = self.find(tag)
        return c.text.strip() if c is not None and c.text.strip() else None

    def iter(self):
        yield self
        for c in self.children:
            yield from c.iter()


def parse_xml(text: str) -> XNode:
    """Parse XML text. Raises ``xml.parsers.expat.ExpatError`` on malformed input."""
    parser = expat.ParserCreate()
    stack: list[XNode] = []
    root: list[XNode] = []

    def start(name: str, attrs: dict[str, str]) -> None:
        node = XNode(tag=name.split(":")[-1], attrs=dict(attrs), line=parser.CurrentLineNumber)
        if stack:
            stack[-1].children.append(node)
        else:
            root.append(node)
        stack.append(node)

    def end(_name: str) -> None:
        stack.pop()

    def chars(data: str) -> None:
        if stack:
            stack[-1].text += data

    parser.StartElementHandler = start
    parser.EndElementHandler = end
    parser.CharacterDataHandler = chars
    parser.Parse(text.lstrip("﻿"), True)
    return root[0]
