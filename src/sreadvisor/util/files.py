"""File-system helpers shared by every scanner."""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from pathlib import Path

from sreadvisor.schema.common import Evidence

SKIP_DIRS = {
    ".git", "node_modules", "target", "build", "dist", "out", ".gradle", ".idea", ".vscode",
    ".venv", "venv", "__pycache__", "bin", "obj", ".terraform", "vendor", ".mvn", ".sreadvisor",
    "graphify-out", ".pytest_cache", ".mypy_cache", ".tox", ".next",
}
TEST_DIR_PARTS = {"test", "tests", "__tests__", "testing", "spec", "specs", "e2e", "integration-test"}
_TEST_FILE_RE = re.compile(
    r"(Tests?\.(java|kt|cs|groovy|scala)$|IT\.java$|\.(test|spec)\.[jt]sx?$|(^|/)test_[^/]*\.py$|_test\.(py|go)$)"
)
MAX_BYTES = 2_000_000


def is_test_path(rel_path: str) -> bool:
    parts = rel_path.lower().split("/")
    return any(p in TEST_DIR_PARTS for p in parts[:-1]) or bool(_TEST_FILE_RE.search(rel_path))


def rel(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def iter_files(
    root: Path,
    *,
    suffixes: Iterable[str] | None = None,
    names: Iterable[str] | None = None,
    include_tests: bool = True,
) -> Iterator[Path]:
    """Walk ``root`` skipping build/vendor directories; filter by suffix and/or exact name."""
    suffixes_t = tuple(s.lower() for s in suffixes) if suffixes else None
    names_l = {n.lower() for n in names} if names else None
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            entries = sorted(current.iterdir())
        except OSError:
            continue
        for entry in entries:
            if entry.is_dir():
                if entry.name in SKIP_DIRS:
                    continue
                stack.append(entry)
                continue
            if not entry.is_file():
                continue
            lname = entry.name.lower()
            if suffixes_t is None and names_l is None:
                pass
            elif not ((suffixes_t and lname.endswith(suffixes_t)) or (names_l and lname in names_l)):
                continue
            if not include_tests and is_test_path(rel(entry, root)):
                continue
            try:
                if entry.stat().st_size > MAX_BYTES:
                    continue
            except OSError:
                continue
            yield entry


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def evidence(file: str, line: int | None, snippet: str | None = None) -> Evidence:
    if snippet is not None:
        snippet = " ".join(snippet.strip().split())[:200]
    return Evidence(file=file, line=line, snippet=snippet)


def line_of(text: str, pattern: str | re.Pattern[str], start: int = 0) -> int | None:
    """1-based line number of the first regex match at/after character offset ``start``."""
    m = re.compile(pattern).search(text, start) if isinstance(pattern, str) else pattern.search(text, start)
    if not m:
        return None
    return text.count("\n", 0, m.start()) + 1
