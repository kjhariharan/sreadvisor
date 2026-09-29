"""Retry/backoff on a transient LLM transport failure (AgentRunner._call_model), and the classifier that decides
what counts as transient. No real ADK Runner or model call: run_async is a small fake async generator.
"""

import asyncio

import pytest
from google.genai import types

from sreadvisor.agents.runner import AgentError, AgentRunner, _is_retryable_llm_error


@pytest.mark.parametrize("exc", [
    TimeoutError("timed out"), ConnectionError("connection reset"),
    RuntimeError("429 Too Many Requests"), RuntimeError("503 Service Unavailable"),
    RuntimeError("upstream connection reset by peer"),
])
def test_transient_failures_are_retryable(exc):
    assert _is_retryable_llm_error(exc)


@pytest.mark.parametrize("exc", [ValueError("invalid api key"), RuntimeError("404 model not found"),
                                 RuntimeError("400 bad request: missing field")])
def test_permanent_failures_are_not_retryable(exc):
    assert not _is_retryable_llm_error(exc)


class _Part:
    def __init__(self, text):
        self.text = text


class _Content:
    def __init__(self, text):
        self.parts = [_Part(text)]


class _Event:
    def __init__(self, text):
        self.content = _Content(text)

    def is_final_response(self):
        return True


class _FlakyRunner:
    """Fails transiently ``fail_times`` times, then succeeds; or raises a permanent error immediately."""

    def __init__(self, fail_times=0, exc=None, final_text='{"ok": true}'):
        self.calls = 0
        self.fail_times = fail_times
        self.exc = exc or ConnectionError("connection reset")
        self.final_text = final_text

    async def run_async(self, user_id, session_id, new_message):
        self.calls += 1
        if self.calls <= self.fail_times:
            raise self.exc
        yield _Event(self.final_text)


class _Agent:
    name = "test_agent"


def _runner_instance() -> AgentRunner:
    from sreadvisor.registry import LlmSettings

    return AgentRunner(settings=None, llm=LlmSettings(), cache_dir=None)  # _call_model touches neither


@pytest.fixture(autouse=True)
def _no_real_sleep(monkeypatch):
    async def instant(_seconds):
        return None

    monkeypatch.setattr(asyncio, "sleep", instant)


def test_transient_failure_is_retried_and_eventually_succeeds():
    fake = _FlakyRunner(fail_times=2, exc=TimeoutError("timed out"))
    ar = _runner_instance()
    texts = asyncio.run(ar._call_model(fake, "sess", "hello", _Agent(), types))
    assert texts == ['{"ok": true}'] and fake.calls == 3  # failed twice, succeeded on the 3rd (final) attempt


def test_transient_failure_that_never_recovers_raises_after_the_last_attempt():
    fake = _FlakyRunner(fail_times=99, exc=ConnectionError("connection reset"))
    ar = _runner_instance()
    with pytest.raises(AgentError, match="model call failed"):
        asyncio.run(ar._call_model(fake, "sess", "hello", _Agent(), types))
    assert fake.calls == 3  # exactly _LLM_TRANSPORT_RETRIES attempts, not more


def test_permanent_failure_raises_on_the_first_attempt_no_retry():
    fake = _FlakyRunner(fail_times=99, exc=ValueError("invalid api key"))
    ar = _runner_instance()
    with pytest.raises(AgentError, match="model call failed"):
        asyncio.run(ar._call_model(fake, "sess", "hello", _Agent(), types))
    assert fake.calls == 1  # no retry spent on a permanent failure
