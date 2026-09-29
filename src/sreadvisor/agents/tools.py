"""Scoped tools handed to the agents. Each is a plain function ADK wraps as a FunctionTool
(the docstring and type hints become the tool schema the model sees)."""

from __future__ import annotations

from sreadvisor.graph.code_graph import CodeGraph
from sreadvisor.registry import LlmSettings

_CHAIN_CHAR_BUDGET = 9000


def make_tools(graph: CodeGraph, llm: LlmSettings) -> dict[str, object]:
    def get_call_chain(entry_point_id: str) -> dict:
        """Return the deterministic call graph reachable from an entry point.

        Each step has its symbol, file, line, the line of the call site that reached it, a
        layer_hint (controller/service/repository/client/other, derived from annotations and naming),
        external_calls (calls into framework or library objects, with the receiver's declared type),
        and a source excerpt. Framework-inherited calls (for example repository.save) are not graph
        steps; look for them inside the excerpts.

        Args:
            entry_point_id: the entry point id given in the task.
        """
        chain = graph.call_chain(entry_point_id, max_nodes=llm.max_chain_nodes)
        if not chain:
            return {"error": f"unknown entry point id {entry_point_id!r}"}
        budget = _CHAIN_CHAR_BUDGET
        for step in chain:
            step["layer_hint"] = graph.layer_hint(step["id"])
            step["external_calls"] = graph.external_calls(step["id"], max_lines=llm.max_body_lines)
            src = graph.method_source(step["id"], max_lines=llm.max_body_lines)
            if budget - len(src) < 0:
                step["source"] = "<omitted to save space; call read_code for this step>"
            else:
                step["source"] = src
                budget -= len(src)
            del step["id"]
        return {"steps": chain}

    def read_code(file: str, start_line: int, end_line: int) -> str:
        """Read numbered source lines from the repository.

        Args:
            file: repository-relative path, exactly as given in tool results.
            start_line: first line (1-based).
            end_line: last line (inclusive). At most 80 lines are returned.
        """
        return graph.reader.read(file, start_line, end_line, max_lines=80)

    def search_code(regex: str) -> list:
        """Search source and config files in the repository for a regular expression.

        Args:
            regex: a Python regular expression. At most 25 hits are returned.
        """
        return graph.search_code(regex, max_results=25)

    def list_domain_entities() -> list:
        """List classes that look like persistent domain models, with file and line."""
        return graph.domain_entities()

    def read_readme() -> str:
        """Return the first 60 lines of the repository README, if there is one."""
        for name in ("README.md", "readme.md", "README.rst", "README.txt", "README"):
            if graph.reader.lines(name):
                return graph.reader.read(name, 1, 60, max_lines=60)
        return "<no README found>"

    return {f.__name__: f for f in (get_call_chain, read_code, search_code, list_domain_entities, read_readme)}


def make_dataset_tools(data: dict, max_items: int = 12, max_chars: int = 4000) -> dict[str, object]:
    """Tools for agents that reason over the Stage 1 dataset only (no repository, no runtime data)."""
    from sreadvisor.gap.paths import PathError, path_valid, project

    def query_dataset(path: str) -> str:
        """Return the part of the Stage 1 dataset at a dotted path, for evidence not already in your prompt.

        Use ``[]`` for every list, for example ``infrastructure.workloads[].containers[].readiness`` or
        ``repositories[].secrets.hardcoded``. List items are shown with their name, kind and file:line.
        A null value means the dataset records nothing there. Only the dataset can be queried.

        Args:
            path: dotted dataset path such as ``cross_references`` or ``repositories[].entry_points[].route``.
        """
        try:
            if not path_valid(data, path):
                return f"error: no such path {path!r} in the dataset"
            return project(data, [path], max_items=max_items, max_chars=max_chars)
        except PathError as exc:
            return f"error: {exc}"

    return {"query_dataset": query_dataset}
