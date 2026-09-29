"""End-to-end Stage 1 pipeline: resolve inputs -> code analysis -> infra analysis -> consolidation -> sinks."""

from __future__ import annotations

import subprocess
from pathlib import Path

from sreadvisor.code.analyze import analyze_repo
from sreadvisor.config import RepoRef, ServiceConfig, resolve_path
from sreadvisor.consolidation import build_dataset
from sreadvisor.infra.analyze import analyze_infra
from sreadvisor.model_provider import describe
from sreadvisor.registry import Registry
from sreadvisor.schema.dataset import RepoAnalysis, ServiceDataset, StepStatus, TechStackFingerprint


class InputError(RuntimeError):
    pass


def resolve_repo(cfg: ServiceConfig, ref: RepoRef, state_dir: Path, log=print) -> Path:
    if ref.path:
        return resolve_path(cfg, ref.path)
    dest = state_dir / "repos" / ref.label
    try:
        if dest.exists():
            log(f"[{ref.label}] updating cached clone")
            subprocess.run(["git", "-C", str(dest), "pull", "--ff-only", "-q"], check=True, capture_output=True, timeout=300)
        else:
            dest.parent.mkdir(parents=True, exist_ok=True)
            log(f"[{ref.label}] cloning {ref.url}")
            cmd = ["git", "clone", "--depth", "1", "-q"] + (["--branch", ref.ref] if ref.ref else []) + [str(ref.url), str(dest)]
            subprocess.run(cmd, check=True, capture_output=True, timeout=600)
    except (subprocess.SubprocessError, OSError) as exc:
        detail = getattr(exc, "stderr", b"")
        raise InputError(f"code_repos: could not fetch {ref.url}: {(detail or b'').decode(errors='replace').strip() or exc}") from exc
    return dest


async def run_pipeline(cfg: ServiceConfig, registry: Registry, *, state_dir: Path, use_llm: bool = True,
                       refresh_graph: bool = False, log=print) -> ServiceDataset:
    model_settings = registry.model_settings()
    provider_cls = registry.provider_class(cfg.observability.provider)
    provider = provider_cls(cfg.observability.service_id, provider_cls.validate_options(cfg.observability.options))

    repos = []
    for ref in cfg.code_repos:
        try:
            root = resolve_repo(cfg, ref, state_dir, log)
            repos.append(await analyze_repo(ref.label, root, state_dir, registry.analysis, model_settings,
                                            use_llm=use_llm, refresh_graph=refresh_graph, log=log))
        except Exception as exc:
            # One repo failing (a bad git ref, a network error, an unexpected crash mid-analysis) must not discard
            # the other repos' completed work, including expensive LLM analysis already done for them; it is
            # recorded as a failed step instead, and the dataset comes out partial (structurally_complete=False)
            # rather than not coming out at all. See consolidation.py's completeness computation.
            log(f"[{ref.label}] repo analysis failed: {exc}")
            repos.append(RepoAnalysis(repo=ref.label, path=ref.path or ref.url or ref.label, fingerprint=TechStackFingerprint(),
                                      status=[StepStatus(step="repo_analysis", status="failed", detail=str(exc)[:500])]))

    infra = analyze_infra([resolve_path(cfg, p) for p in cfg.iac_paths], log=log)
    log("[consolidate] merging into the per-service dataset")
    return build_dataset(cfg, provider, repos, infra, describe(model_settings) if use_llm else "not used (--no-llm)")


def emit(dataset: ServiceDataset, registry: Registry, out_dir: Path) -> list[str]:
    return [loc for sink in registry.active_sinks() if (loc := sink.emit(dataset, out_dir))]
