"""Secrets must never be copied into the dataset, or sent to an LLM. ``redact`` replaces a whole known value with
its shape only; ``redact_line`` finds and masks credential-shaped substrings within an otherwise-useful line of
source (used before that line is interpolated into an LLM prompt, where the surrounding code is still wanted)."""

from __future__ import annotations

import re

TOKEN_PATTERNS = [
    ("AWS access key id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("private key block", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("API secret key (sk-...)", re.compile(r"\bsk-[A-Za-z0-9]{24,}\b")),
]
SOURCE_ASSIGN = re.compile(
    r"""\b(\w*(?:password|passwd|pwd|secret|api_?key|apikey|token|credential)\w*)\s*(?:=|:|=>)\s*["']([^"'\n]{4,})["']""", re.I)
JDBC_PASSWORD = re.compile(r"jdbc:[\w:]+//[^\s\"']*?[?&;](?:password|pwd)=([^&;\s\"']+)", re.I)
URL_CREDS = re.compile(r"\b[a-z][a-z0-9+.\-]*://([^/\s:@\"'$]+):([^/\s@\"']+)@")
DOTNET_CONN = re.compile(r"(?:Password|Pwd)\s*=\s*([^;\"'\s]+)", re.I)


def redact(value: str | None) -> str:
    if value is None:
        return "<none>"
    return f"<redacted:len={len(value)}>"


def _mask_group(rx: re.Pattern, group: int, line: str) -> str:
    """Replace one captured group of every match with a placeholder, keeping the rest of each match (and the line)
    untouched. Uses a single ``re.sub`` pass (not a re-search-and-replace loop): the placeholder text must never be
    re-scanned against the same pattern, since "<redacted-secret>" itself satisfies several of these patterns'
    "any non-quote/non-space characters" value groups and would otherwise match again forever."""

    def repl(m: re.Match) -> str:
        whole = m.group(0)
        ms = m.start(0)
        gs, ge = m.span(group)
        return whole[: gs - ms] + "<redacted-secret>" + whole[ge - ms :]

    return rx.sub(repl, line)


def redact_line(line: str) -> str:
    """Mask a credential-shaped substring in one line of source, keeping the rest of the line intact so it stays
    useful context for an LLM prompt. Whole-token patterns are masked outright; patterns that capture just the
    secret value (an assignment, a jdbc/url password, a .NET connection-string password) keep the key/prefix and
    replace only the captured value."""
    for _, rx in TOKEN_PATTERNS:
        line = rx.sub("<redacted-secret>", line)
    line = _mask_group(SOURCE_ASSIGN, 2, line)
    line = _mask_group(JDBC_PASSWORD, 1, line)
    line = _mask_group(URL_CREDS, 2, line)
    line = _mask_group(DOTNET_CONN, 1, line)
    return line
