from __future__ import annotations

from pydantic import BaseModel


class Evidence(BaseModel):
    """A pointer to where a fact was found. Every finding in the dataset carries one."""

    file: str
    line: int | None = None
    snippet: str | None = None
