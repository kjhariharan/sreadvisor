"""Source-reading helpers: annotations above a definition, method extents, safe line reads."""

from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path

from sreadvisor.util.redact import redact_line

_STRING_RE = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'')


class SourceReader:
    """Reads repository files with path-safety and a small line cache."""

    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self._lines = lru_cache(maxsize=256)(self._read_lines)

    def _read_lines(self, rel_path: str) -> tuple[str, ...]:
        p = (self.root / rel_path).resolve()
        if self.root not in p.parents and p != self.root:
            raise ValueError(f"path escapes repository root: {rel_path}")
        return tuple(p.read_text(encoding="utf-8", errors="replace").splitlines())

    def lines(self, rel_path: str) -> tuple[str, ...]:
        try:
            return self._lines(rel_path)
        except (OSError, ValueError):
            return ()

    def read(self, rel_path: str, start: int, end: int, max_lines: int = 80) -> str:
        """Numbered lines ``start..end`` (1-based, inclusive), capped at ``max_lines``.

        This is the text that ends up interpolated directly into an LLM prompt (via ``read_code``/``get_call_chain``),
        so any credential-shaped substring is masked here, at the boundary, before it ever leaves this reader —
        never in :meth:`lines`, whose untouched text other methods still need for structural parsing.
        """
        ls = self.lines(rel_path)
        if not ls:
            return f"<cannot read {rel_path}>"
        start = max(1, start)
        end = min(len(ls), max(start, end), start + max_lines - 1)
        return "\n".join(f"{i}: {redact_line(ls[i - 1])}" for i in range(start, end + 1))

    def annotations_above(self, rel_path: str, line: int, max_scan: int = 14) -> list[tuple[int, str]]:
        """Annotation / decorator / attribute lines immediately above a definition (1-based ``line``).

        Returns ``(line_number, text)`` in source order. Multi-line annotations are returned as
        their individual lines; use :meth:`annotation_text` to join them.
        """
        ls = self.lines(rel_path)
        out: list[tuple[int, str]] = []
        i = line - 2
        pending_tail = False  # inside a multi-line annotation, scanning up towards its '@' line
        for _ in range(max_scan):
            if i < 0:
                break
            text = ls[i].strip()
            if not text:
                break
            if text.startswith(("//", "/*", "*", "///", "#")) and not text.startswith("#["):
                i -= 1
                continue  # comment between annotations
            if text.startswith(("@", "[")):
                out.append((i + 1, text))
                pending_tail = False
            elif text.count(")") > text.count("(") or pending_tail:
                out.append((i + 1, text))  # tail of a multi-line annotation
                pending_tail = True
            else:
                break
            i -= 1
        out.reverse()
        return out

    def declaration(self, rel_path: str, line: int) -> tuple[list[tuple[int, str]], int]:
        """Annotations of the definition whose graph node starts at ``line``, and its signature line.

        Graphify anchors a Java/Kotlin/C# declaration at its first annotation line, while Python
        decorators may sit above the anchor; both directions are scanned and merged.
        """
        ls = self.lines(rel_path)
        up = self.annotations_above(rel_path, line)
        down: list[tuple[int, str]] = []
        i, depth = line - 1, 0
        while 0 <= i < len(ls):
            t = ls[i].strip()
            is_start = t.startswith(("@", "[")) and not t.startswith("@interface")
            if depth > 0 or is_start:
                down.append((i + 1, t))
                depth = max(0, depth + t.count("(") - t.count(")"))
                i += 1
                continue
            if t.startswith(("//", "/*", "*")) and down:
                i += 1
                continue
            break
        seen = {n for n, _ in down}
        return [a for a in up if a[0] not in seen] + down, i + 1

    def annotation_text(self, rel_path: str, line: int, max_lines: int = 4) -> str:
        """Annotation starting at ``line`` joined across continuation lines until parentheses balance."""
        ls = self.lines(rel_path)
        buf, depth = "", 0
        for i in range(line - 1, min(len(ls), line - 1 + max_lines)):
            buf += " " + ls[i].strip()
            depth += ls[i].count("(") - ls[i].count(")")
            if depth <= 0:
                break
        return buf.strip()

    def extent(self, rel_path: str, start: int, max_lines: int = 60) -> tuple[int, int]:
        """Best-effort end line of the definition starting at ``start`` (brace or indentation based)."""
        ls = self.lines(rel_path)
        if not ls or start > len(ls):
            return start, start
        if rel_path.endswith(".py"):
            base = len(ls[start - 1]) - len(ls[start - 1].lstrip())
            end = start
            for j in range(start, len(ls)):
                t = ls[j]
                if t.strip() and (len(t) - len(t.lstrip())) <= base:
                    break
                if t.strip():
                    end = j + 1
                if end - start >= max_lines:
                    break
            return start, end
        depth, seen_open = 0, False
        for j in range(start - 1, min(len(ls), start - 1 + max_lines)):
            code = _STRING_RE.sub('""', re.sub(r"//.*$", "", ls[j]))
            for ch in code:
                if ch == "{":
                    depth += 1
                    seen_open = True
                elif ch == "}":
                    depth -= 1
            if seen_open and depth <= 0:
                return start, j + 1
            if not seen_open and code.rstrip().endswith(";"):
                return start, j + 1  # abstract / interface method
        return start, min(len(ls), start + max_lines - 1)
