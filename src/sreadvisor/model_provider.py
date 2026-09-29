"""The single place a model object is created.

Every ADK agent in this codebase gets its model from :func:`get_model`. Switching the
backend is a config change (``model.backend`` in the registry file, or the
``SREADVISOR_MODEL_BACKEND`` environment variable), never a code change:

* ``ollama``  -> ``LiteLlm(model="ollama_chat/<model>")``, local development
* ``gemini``  -> ADK's native ``Gemini`` class with a Gemini API key (production-parity check)
* ``vertex``  -> the same ``Gemini`` class against a Google Cloud project via Application
                 Default Credentials (eventual production deployment)
* ``gateway`` -> ``LiteLlm`` pointed at an internal AI gateway instead of a named provider's own API.
                 ``model.gateway.model`` names the underlying model in LiteLLM's own "<provider>/<name>"
                 form (for example "openai/gpt-4o", "anthropic/claude-sonnet-4-5", "gemini/gemini-2.5-flash"),
                 so the SAME gateway backend serves whichever provider the gateway itself routes that model
                 name to — switching models is a config change, never a code change here either.
"""

from __future__ import annotations

import os
from typing import Any, Literal

from pydantic import BaseModel, Field

Backend = Literal["ollama", "gemini", "vertex", "gateway"]
BACKENDS: tuple[str, ...] = ("ollama", "gemini", "vertex", "gateway")


class ModelConfigError(RuntimeError):
    pass


class ModelSettings(BaseModel):
    backend: Backend = "ollama"
    # Ollama: default matches the local mapping in the brief. The brief also names
    # qwen3-coder:30b as a prerequisite; switch to it by setting model.ollama.model.
    ollama_model: str = "gemma4:latest"
    ollama_api_base: str | None = None
    # Ollama's default context window (4k) is too small for tool-using agents with a thinking model.
    ollama_num_ctx: int = 16384
    gemini_model: str = "gemini-2.5-flash"
    gemini_api_key_env: str = "GEMINI_API_KEY"
    vertex_model: str = "gemini-2.5-flash"
    vertex_project: str | None = None
    vertex_location: str = "us-central1"

    # Generic internal AI gateway: any model the gateway can route to (Anthropic, Gemini, OpenAI, ...), addressed
    # through one LiteLLM-compatible endpoint. The api key is resolved the same way as the Dynatrace token
    # elsewhere in this project: an inline value or, preferably, a named environment variable, never hardcoded.
    gateway_model: str = "openai/gpt-4o"
    gateway_api_base: str | None = None
    gateway_api_key_env: str = "AI_GATEWAY_API_KEY"
    # TLS, for a gateway behind a corporate proxy or an internal CA the system trust store does not already have.
    # ssl_verify=False and a ca_cert_path are mutually exclusive in effect: a given path always wins (LiteLLM
    # treats a ssl_verify string as "verify using this CA bundle"), so only turn verification off when you have no
    # CA bundle to point at, e.g. for a trusted internal endpoint with a self-signed certificate.
    gateway_ssl_verify: bool = True
    gateway_ca_cert_path: str | None = None

    @classmethod
    def from_config(cls, section: dict[str, Any] | None) -> "ModelSettings":
        """Build from the ``model:`` section of the registry, then apply env overrides."""
        section = section or {}
        flat: dict[str, Any] = {"backend": section.get("backend", "ollama")}
        for backend in BACKENDS:
            for key, value in (section.get(backend) or {}).items():
                flat[f"{backend}_{key}"] = value
        env = os.environ
        if env.get("SREADVISOR_MODEL_BACKEND"):
            flat["backend"] = env["SREADVISOR_MODEL_BACKEND"].strip().lower()
        if env.get("SREADVISOR_OLLAMA_MODEL"):
            flat["ollama_model"] = env["SREADVISOR_OLLAMA_MODEL"]
        if env.get("OLLAMA_API_BASE"):
            flat["ollama_api_base"] = env["OLLAMA_API_BASE"]
        if env.get("GOOGLE_CLOUD_PROJECT") and not flat.get("vertex_project"):
            flat["vertex_project"] = env["GOOGLE_CLOUD_PROJECT"]
        if env.get("GOOGLE_CLOUD_LOCATION") and "vertex_location" not in flat:
            flat["vertex_location"] = env["GOOGLE_CLOUD_LOCATION"]
        if env.get("SREADVISOR_GATEWAY_MODEL"):
            flat["gateway_model"] = env["SREADVISOR_GATEWAY_MODEL"]
        if env.get("AI_GATEWAY_API_BASE"):
            flat["gateway_api_base"] = env["AI_GATEWAY_API_BASE"]
        try:
            return cls(**flat)
        except Exception as exc:  # pydantic validation error -> readable message
            raise ModelConfigError(
                f"Invalid model settings ({exc}). model.backend must be one of {', '.join(BACKENDS)}."
            ) from exc


def describe(settings: ModelSettings) -> str:
    if settings.backend == "ollama":
        return f"ollama:{settings.ollama_model}"
    if settings.backend == "gemini":
        return f"gemini:{settings.gemini_model}"
    if settings.backend == "gateway":
        return f"gateway:{settings.gateway_model}"
    return f"vertex:{settings.vertex_project or '<project?>'}/{settings.vertex_model}"


def get_model(settings: ModelSettings | None = None) -> Any:
    """Return the ADK model object for the configured backend."""
    if settings is None:
        from sreadvisor.registry import Registry  # local import avoids a cycle

        settings = Registry.load().model_settings()

    if settings.backend == "ollama":
        from google.adk.models.lite_llm import LiteLlm

        kwargs: dict[str, Any] = {}
        if settings.ollama_api_base:
            kwargs["api_base"] = settings.ollama_api_base
        kwargs["num_ctx"] = settings.ollama_num_ctx
        return LiteLlm(model=f"ollama_chat/{settings.ollama_model}", **kwargs)

    if settings.backend == "gateway":
        from google.adk.models.lite_llm import LiteLlm

        if not settings.gateway_api_base:
            raise ModelConfigError(
                "model.backend is 'gateway' but no gateway URL is set. Set model.gateway.api_base in the registry "
                "or export AI_GATEWAY_API_BASE."
            )
        kwargs = {"api_base": settings.gateway_api_base}
        api_key = os.environ.get(settings.gateway_api_key_env)
        if api_key:
            kwargs["api_key"] = api_key
        # A CA bundle path, when given, IS the verification setting (LiteLLM's ssl_verify accepts either a bool or
        # a path to verify against); gateway_ssl_verify only matters when no path is given.
        kwargs["ssl_verify"] = settings.gateway_ca_cert_path or settings.gateway_ssl_verify
        return LiteLlm(model=settings.gateway_model, **kwargs)

    from google import genai
    from google.adk.models.google_llm import Gemini

    if settings.backend == "gemini":
        api_key = os.environ.get(settings.gemini_api_key_env) or os.environ.get("GOOGLE_API_KEY")
        if not api_key:
            raise ModelConfigError(
                f"model.backend is 'gemini' but no API key was found in ${settings.gemini_api_key_env} "
                "(or $GOOGLE_API_KEY)."
            )
        return Gemini(model=settings.gemini_model, client=genai.Client(api_key=api_key))

    if settings.backend == "vertex":
        if not settings.vertex_project:
            raise ModelConfigError(
                "model.backend is 'vertex' but no Google Cloud project is set. Set model.vertex.project in the "
                "registry or export GOOGLE_CLOUD_PROJECT. Authentication uses Application Default Credentials "
                "(run: gcloud auth application-default login)."
            )
        client = genai.Client(vertexai=True, project=settings.vertex_project, location=settings.vertex_location)
        return Gemini(model=settings.vertex_model, client=client)

    raise ModelConfigError(f"Unknown model backend {settings.backend!r}")  # pragma: no cover
