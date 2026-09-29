"""Runs an ADK agent to a validated JSON result, with caching and a repair turn.

The agents themselves are ordinary ``LlmAgent`` objects whose model comes from
``model_provider.get_model``. This module only supplies the plumbing around them:
a session, JSON extraction, pydantic validation, one repair attempt, and a result cache
keyed by (model, agent instruction, prompt) so unchanged inputs are never re-asked.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import urllib.error
import urllib.request
import uuid
import warnings
from pathlib import Path
from typing import TypeVar

from pydantic import BaseModel, ValidationError

from sreadvisor.model_provider import ModelSettings, describe
from sreadvisor.registry import LlmSettings

warnings.filterwarnings("ignore")
logging.getLogger("google_adk").setLevel(logging.ERROR)
logging.getLogger("LiteLLM").setLevel(logging.ERROR)

T = TypeVar("T", bound=BaseModel)
_FENCE = re.compile(r"^```(?:json)?\s*|\s*```$", re.M)

_LLM_TRANSPORT_RETRIES = 3  # attempts for a transient failure, not for a JSON-repair retry (a separate concept)
_RETRYABLE_ERROR_RE = re.compile(
    r"\b(429|500|502|503|504)\b|time(d)?[\s_-]*out|connection reset|connection refused|connection aborted|"
    r"rate limit|too many requests|temporarily unavailable|service unavailable", re.I)


class AgentError(RuntimeError):
    pass


def _is_retryable_llm_error(exc: Exception) -> bool:
    """Transient failures (timeout, connection reset, 429, 5xx) are worth retrying; anything else (bad auth, an
    unknown model, a malformed request) is not, and should fail fast rather than retry a request that will never
    succeed."""
    if isinstance(exc, (TimeoutError, ConnectionError)):
        return True
    return bool(_RETRYABLE_ERROR_RE.search(str(exc)))


def extract_json_objects(text: str) -> list[dict]:
    """Every complete top-level JSON object in a reply, in order (models sometimes echo input JSON before the answer)."""
    cleaned = _FENCE.sub("", text.strip())
    decoder = json.JSONDecoder()
    found: list[dict] = []
    pos = cleaned.find("{")
    while pos >= 0:
        try:
            obj, end = decoder.raw_decode(cleaned, pos)
        except json.JSONDecodeError:
            pos = cleaned.find("{", pos + 1)
            continue
        if isinstance(obj, dict):
            found.append(obj)
        pos = cleaned.find("{", end)
    return found


def extract_json(text: str) -> dict:
    """Pull the first complete JSON object out of a model reply (tolerates fences, chatter, trailing text)."""
    cleaned = _FENCE.sub("", text.strip())
    decoder = json.JSONDecoder()
    error: Exception | None = None
    pos = cleaned.find("{")
    while pos >= 0:
        try:
            obj, _end = decoder.raw_decode(cleaned, pos)
            if isinstance(obj, dict):
                return obj
        except json.JSONDecodeError as exc:
            error = exc
        pos = cleaned.find("{", pos + 1)
    raise ValueError(f"no valid JSON object found in reply ({error})" if error else "no JSON object found in reply")


def check_backend(settings: ModelSettings) -> str | None:
    """Cheap pre-flight so a missing model fails fast with an actionable message."""
    if settings.backend != "ollama":
        return None
    import os

    base = (settings.ollama_api_base or os.environ.get("OLLAMA_API_BASE") or "http://localhost:11434").rstrip("/")
    try:
        with urllib.request.urlopen(f"{base}/api/tags", timeout=5) as r:
            names = {m["name"] for m in json.load(r).get("models", [])}
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return f"Ollama is not reachable at {base} ({exc}). Start it with `ollama serve`."
    want = settings.ollama_model
    if want not in names and f"{want}:latest" not in names:
        return f"Ollama model '{want}' is not pulled. Available: {', '.join(sorted(names)) or '(none)'}. Run `ollama pull {want}`."
    return None


class AgentRunner:
    def __init__(self, settings: ModelSettings, llm: LlmSettings, cache_dir: Path) -> None:
        self.settings = settings
        self.llm = llm
        self.cache_dir = cache_dir
        self._sem = asyncio.Semaphore(max(1, llm.concurrency))
        self.calls = 0
        self.cache_hits = 0

    def _cache_path(self, agent, prompt: str) -> Path:
        key = hashlib.sha256(
            "\x00".join([describe(self.settings), agent.name, str(agent.instruction), prompt]).encode()
        ).hexdigest()
        return self.cache_dir / f"{agent.name}-{key[:24]}.json"

    async def run(self, agent, prompt: str, schema: type[T]) -> T:
        cache_file = self._cache_path(agent, prompt)
        if self.llm.cache and cache_file.exists():
            try:
                result = schema.model_validate_json(cache_file.read_text(encoding="utf-8"))
                self.cache_hits += 1
                return result
            except ValidationError:
                pass
        async with self._sem:
            result = await self._run_uncached(agent, prompt, schema)
        if self.llm.cache:
            cache_file.parent.mkdir(parents=True, exist_ok=True)
            cache_file.write_text(result.model_dump_json(), encoding="utf-8")
        return result

    async def _call_model(self, runner, session_id: str, message: str, agent, types) -> list[str]:
        """One model turn, retried with exponential backoff on a transient transport failure (timeout, connection
        reset, 429, 5xx). A non-retryable failure (bad auth, an unknown model, ...) still raises immediately, on
        the first attempt, exactly as before."""
        for retry in range(_LLM_TRANSPORT_RETRIES):
            texts: list[str] = []
            try:
                async for event in runner.run_async(
                    user_id="analyst", session_id=session_id,
                    new_message=types.Content(role="user", parts=[types.Part(text=message)]),
                ):
                    if event.is_final_response() and event.content and event.content.parts:
                        texts.append("".join(p.text or "" for p in event.content.parts))
                return texts
            except Exception as exc:
                if not _is_retryable_llm_error(exc) or retry == _LLM_TRANSPORT_RETRIES - 1:
                    raise AgentError(f"{agent.name}: model call failed: {exc}") from exc
                await asyncio.sleep(2**retry)
        return []  # unreachable: the loop above always returns or raises

    async def _run_uncached(self, agent, prompt: str, schema: type[T]) -> T:
        from google.adk.runners import Runner
        from google.adk.sessions import InMemorySessionService
        from google.genai import types

        service = InMemorySessionService()
        runner = Runner(agent=agent, app_name="sreadvisor", session_service=service)
        session_id = uuid.uuid4().hex
        await service.create_session(app_name="sreadvisor", user_id="analyst", session_id=session_id)

        message = prompt
        last_error = "unknown"
        for attempt in range(self.llm.max_retries + 1):
            self.calls += 1
            texts = await self._call_model(runner, session_id, message, agent, types)
            text = "\n".join(texts)
            last_error = "no JSON object found in reply"
            for candidate in reversed(extract_json_objects(text)):  # the answer is normally the last object
                try:
                    return schema.model_validate(candidate)
                except ValidationError as exc:
                    last_error = str(exc)[:600]
            message = (
                f"Your previous reply could not be used: {last_error}\n"
                "Reply again with ONLY the corrected JSON object, no commentary."
            )
        raise AgentError(f"{agent.name}: no valid JSON after {self.llm.max_retries + 1} attempt(s): {last_error}")
