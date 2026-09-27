"""Workspace-facing services for the UI: per-service configs, background jobs, and the report files the pipeline writes.

Everything here stays inside the workspace directory. Jobs run the same CLI a person would (``python -m sreadvisor ...``), as an argument
list (never through a shell), so the UI adds no second code path through the pipeline.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from sreadvisor.config import ConfigError, build_config, load_config_file
from sreadvisor.registry import Registry, RegistryError

_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,80}$")
_ENV_LOCK = threading.Lock()


class WorkspaceError(Exception):
    def __init__(self, message: str, problems: list[str] | None = None, status: int = 422) -> None:
        super().__init__(message)
        self.message, self.problems, self.status = message, problems or [], status


def slug(name: str) -> str:
    s = re.sub(r"[^A-Za-z0-9_.-]+", "-", name.strip()).strip("-.")
    if not s:
        raise WorkspaceError("a name is required")
    return s[:80]


# ------------------------------------------------------------------------------------ configs


class Configs:
    def __init__(self, workspace: Path, registry_path: str | None = None) -> None:
        self.ws = workspace
        self.dir = workspace / "config"
        self.registry_path = registry_path

    def registry(self) -> Registry:
        return Registry.load(self.registry_path)

    def _path(self, name: str) -> Path:
        if not _NAME.match(name):
            raise WorkspaceError("invalid config name", status=400)
        for ext in (".yaml", ".yml", ".json"):
            p = self.dir / f"{name}{ext}"
            if p.is_file():
                return p
        return self.dir / f"{name}.yaml"

    def list(self) -> list[dict[str, Any]]:
        rows = []
        for p in sorted(self.dir.glob("*")) if self.dir.is_dir() else []:
            if p.suffix.lower() not in (".yaml", ".yml", ".json") or not p.is_file():
                continue
            try:
                raw = self._read(p)
            except WorkspaceError:
                raw = {}
            rows.append({"name": p.stem, "file": p.name, "service_name": raw.get("service_name"),
                         "provider": (raw.get("observability") or {}).get("provider"),
                         "repos": len(raw.get("code_repos") or []), "iac": len(raw.get("iac_paths") or [])})
        return rows

    def _read(self, p: Path) -> dict[str, Any]:
        try:
            data = json.loads(p.read_text(encoding="utf-8")) if p.suffix.lower() == ".json" else yaml.safe_load(p.read_text(encoding="utf-8"))
        except (ValueError, yaml.YAMLError) as exc:
            raise WorkspaceError(f"{p.name} is not valid: {exc}") from exc
        if not isinstance(data, dict):
            raise WorkspaceError(f"{p.name}: top level must be a mapping")
        return data

    def get(self, name: str) -> dict[str, Any]:
        p = self._path(name)
        if not p.is_file():
            raise WorkspaceError(f"no config named {name!r}", status=404)
        # Relative paths in a config file are relative to that file (as the CLI reads it); show them resolved so the form is unambiguous.
        return {"name": p.stem, "file": p.name, "config": self.normalise(self._read(p), base=p.parent)}

    def normalise(self, raw: dict[str, Any], base: Path | None = None) -> dict[str, Any]:
        """Relative paths are made absolute (typed ones against the workspace, a loaded file's against its own folder) so a saved file
        means the same from anywhere."""
        raw = json.loads(json.dumps(raw))
        base = base or self.ws

        def fix(v: str) -> str:
            if re.match(r"^(https?://|git@|ssh://)", v) or Path(v).expanduser().is_absolute():
                return v
            return str((base / v).resolve())

        repos = []
        for r in raw.get("code_repos") or []:
            if isinstance(r, str):
                r = {"url": r} if re.match(r"^(https?://|git@|ssh://)", r) else {"path": r}
            if r.get("path"):
                r["path"] = fix(r["path"])
            repos.append({k: v for k, v in r.items() if v not in (None, "")})
        raw["code_repos"] = repos
        raw["iac_paths"] = [fix(p) for p in (raw.get("iac_paths") or []) if str(p).strip()]
        if raw.get("output_dir"):
            raw["output_dir"] = fix(raw["output_dir"])
        else:
            raw.pop("output_dir", None)
        obs = raw.get("observability") or {}
        obs["options"] = {k: v for k, v in (obs.get("options") or {}).items() if v not in (None, "")}
        obs["options"].pop("api_token", None)  # a token is never written to a config file
        raw["observability"] = obs
        return raw

    def validate(self, raw: dict[str, Any], token: str | None = None) -> list[str]:
        """Problems with a config, named by field; empty when it is valid. ``token`` is used for this check only."""
        raw = self.normalise(raw)
        env_name = ((raw.get("observability") or {}).get("options") or {}).get("api_token_env", "DT_API_TOKEN")
        try:
            registry = self.registry()
            with _ENV_LOCK:
                old = os.environ.get(env_name)
                if token:
                    os.environ[env_name] = token
                try:
                    build_config(raw, base_dir=self.dir, registry=registry, source="the form")
                finally:
                    if token:
                        if old is None:
                            os.environ.pop(env_name, None)
                        else:
                            os.environ[env_name] = old
        except ConfigError as exc:
            return list(exc.problems)
        except RegistryError as exc:
            return [str(exc)]
        return []

    def save(self, name: str, raw: dict[str, Any], token: str | None, force: bool) -> dict[str, Any]:
        name = slug(name)
        raw = self.normalise(raw)
        problems = self.validate(raw, token)
        token_only = problems and all("api_token" in p for p in problems)
        if problems and not (force and token_only):
            raise WorkspaceError("the configuration is not valid; nothing was saved", problems)
        self.dir.mkdir(parents=True, exist_ok=True)
        p = self._path(name)
        p.write_text("# Written by the sreadvisor UI. The API token is never stored here; name the environment variable that holds it.\n"
                     + yaml.safe_dump(raw, sort_keys=False, allow_unicode=True), encoding="utf-8")
        return {"name": p.stem, "file": p.name, "problems": problems}

    def providers(self) -> list[dict[str, Any]]:
        registry = self.registry()
        out = []
        for name in registry.provider_names():
            cls = registry.provider_class(name)
            fields = list(getattr(cls.OptionsModel, "model_fields", {}).keys())
            out.append({"name": name, "options": fields, "service_id_pattern": getattr(getattr(cls, "SERVICE_ID_RE", None), "pattern", None)})
        return out

    def load_service(self, name: str):
        return load_config_file(self._path(name), self.registry())


# ---------------------------------------------------------------------------------------- jobs


@dataclass
class Job:
    id: str
    kind: str
    label: str
    argv: list[str]
    started: float = field(default_factory=time.time)
    finished: float | None = None
    status: str = "running"  # running | succeeded | failed | cancelled
    returncode: int | None = None
    log: list[str] = field(default_factory=list)
    proc: subprocess.Popen | None = field(default=None, repr=False)

    def public(self, since: int = 0) -> dict[str, Any]:
        return {"id": self.id, "kind": self.kind, "label": self.label, "status": self.status, "returncode": self.returncode,
                "started": self.started, "finished": self.finished, "command": "sreadvisor " + " ".join(self.argv),
                "log": self.log[since:], "log_size": len(self.log)}


class Jobs:
    def __init__(self, workspace: Path) -> None:
        self.ws = workspace
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()

    def running(self) -> Job | None:
        return next((j for j in self._jobs.values() if j.status == "running"), None)

    def start(self, kind: str, label: str, argv: list[str], env_extra: dict[str, str] | None = None) -> Job:
        with self._lock:
            active = self.running()
            if active:
                raise WorkspaceError(f"a job is already running ({active.label}); wait for it or cancel it", status=409)
            env = {**os.environ, "PYTHONUNBUFFERED": "1", "PYTHONIOENCODING": "utf-8", **(env_extra or {})}
            flags = subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0
            job = Job(id=uuid.uuid4().hex[:10], kind=kind, label=label, argv=argv)
            job.proc = subprocess.Popen([sys.executable, "-m", "sreadvisor", *argv], cwd=self.ws, env=env, stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace", creationflags=flags)
            self._jobs[job.id] = job
            for old in sorted(self._jobs.values(), key=lambda j: j.started)[:-30]:
                if old.status != "running":
                    del self._jobs[old.id]
        threading.Thread(target=self._pump, args=(job,), daemon=True).start()
        return job

    def _pump(self, job: Job) -> None:
        assert job.proc and job.proc.stdout
        for line in job.proc.stdout:
            job.log.append(line.rstrip("\n"))
        job.returncode = job.proc.wait()
        job.finished = time.time()
        if job.status == "running":
            job.status = "succeeded" if job.returncode == 0 else "failed"

    def get(self, job_id: str) -> Job:
        job = self._jobs.get(job_id)
        if job is None:
            raise WorkspaceError("no such job", status=404)
        return job

    def list(self) -> list[dict[str, Any]]:
        return [j.public() | {"log": [], "log_size": len(j.log)} for j in sorted(self._jobs.values(), key=lambda j: -j.started)]

    def cancel(self, job_id: str) -> Job:
        job = self.get(job_id)
        if job.status == "running" and job.proc:
            job.status = "cancelled"
            if sys.platform == "win32":
                subprocess.run(["taskkill", "/PID", str(job.proc.pid), "/T", "/F"], capture_output=True)
            else:
                job.proc.terminate()
        return job


# ------------------------------------------------------------------------------------- reports

_SUFFIXES = {".dataset.json": "dataset", ".gaps.json": "gaps", ".nfr-coverage.json": "coverage", ".report.md": "report"}


class Reports:
    def __init__(self, workspace: Path, extra_dirs: list[Path] | None = None) -> None:
        self.dirs = [workspace / "output", *(extra_dirs or [])]

    def _scan(self) -> dict[str, dict[str, Path]]:
        found: dict[str, dict[str, Path]] = {}
        for d in dict.fromkeys(self.dirs):
            if not d.is_dir():
                continue
            for f in d.iterdir():
                for suffix, kind in _SUFFIXES.items():
                    if f.name.endswith(suffix):
                        found.setdefault(f.name[: -len(suffix)], {})[kind] = f
        return found

    def list(self) -> list[dict[str, Any]]:
        rows = []
        for service, files in sorted(self._scan().items()):
            row: dict[str, Any] = {"service": service, "files": {k: {"name": p.name, "modified": p.stat().st_mtime, "bytes": p.stat().st_size}
                                                                 for k, p in files.items()}}
            if "gaps" in files:
                try:
                    g = json.loads(files["gaps"].read_text(encoding="utf-8"))
                    row["gap_summary"] = g.get("summary")
                    row["generated_at"] = g.get("generated_at")
                    row["assessor_model"] = (g.get("inputs") or {}).get("assessor_model")
                except ValueError:
                    row["gap_summary"] = None
            rows.append(row)
        return rows

    def path(self, service: str, kind: str) -> Path:
        p = self._scan().get(service, {}).get(kind)
        if p is None:
            raise WorkspaceError(f"no {kind} file for {service!r}", status=404)
        return p

    def json(self, service: str, kind: str) -> Any:
        return json.loads(self.path(service, kind).read_text(encoding="utf-8"))

    def dataset_facts(self, service: str) -> dict[str, Any]:
        d = self.json(service, "dataset")
        repos = d.get("repositories") or []
        infra = d.get("infrastructure") or {}
        return {
            "service": d.get("service_name"), "generated_at": d.get("generated_at"), "schema_version": d.get("schema_version"),
            "model_backend": d.get("model_backend"), "observability": d.get("observability"),
            "business_context": d.get("business_context"), "completeness": d.get("completeness"),
            "repositories": [{
                "repo": r.get("repo"), "languages": r["fingerprint"].get("languages"), "frameworks": [f["name"] + (" " + f["version"] if f.get("version") else "") for f in r["fingerprint"].get("frameworks", [])],
                "build_tools": r["fingerprint"].get("build_tools"), "dependencies": len(r["fingerprint"].get("dependencies", [])),
                "entry_points": len(r.get("entry_points", [])), "flows": len(r.get("transaction_flows", [])),
                "reliability_patterns": len(r.get("reliability_patterns", [])), "dependency_classifications": len(r.get("dependency_classification", [])),
            } for r in repos],
            "infrastructure": {k: len(infra.get(k) or []) for k in ("workloads", "autoscalers", "disruption_budgets", "services", "ingresses",
                                                                    "network_policies", "compose_services", "dockerfiles", "helm_charts",
                                                                    "terraform_resources", "pipelines")} | {"mesh": bool((infra.get("mesh") or {}).get("present"))},
        }
