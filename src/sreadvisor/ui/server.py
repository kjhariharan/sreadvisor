"""The local web UI: a small FastAPI app plus static pages. Start it with ``sreadvisor ui``.

It has no authentication and can start analyses and edit the knowledge base, so it binds to the loopback interface by default.
"""

from __future__ import annotations

import os
import re
import sys
import time
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from sreadvisor.agents.runner import check_backend
from sreadvisor.model_provider import describe
from sreadvisor.nfr import loader
from sreadvisor.ui.nfr_store import NfrStore, StoreError
from sreadvisor.ui.workspace import Configs, Jobs, Reports, WorkspaceError, slug

STATIC = Path(__file__).with_name("static")
_ID = re.compile(r"^[A-Za-z0-9_]+$")


def create_app(workspace: Path, *, src_dir: Path | None = None, data_dir: Path | None = None, registry_path: str | None = None) -> FastAPI:
    workspace = Path(workspace).resolve()
    app = FastAPI(title="sreadvisor UI", docs_url=None, redoc_url=None)
    configs = Configs(workspace, registry_path)
    jobs = Jobs(workspace)
    model_cache: dict[str, Any] = {"at": 0.0, "problem": None}
    store = NfrStore(src_dir or loader.SRC_DIR, data_dir or loader.DATA_DIR, workspace / ".sreadvisor" / "nfr_backups")

    def reports() -> Reports:
        extra: list[Path] = []
        for c in configs.list():  # also look where each config writes its output
            try:
                svc = configs.load_service(c["name"])
                if svc.output_dir:
                    extra.append(Path(svc.output_dir) if Path(svc.output_dir).is_absolute() else (svc.config_dir / svc.output_dir).resolve())
            except Exception:
                continue
        return Reports(workspace, extra)

    # ------------------------------------------------------------------------ error mapping
    @app.exception_handler(StoreError)
    async def _store_err(_r: Request, exc: StoreError):
        return JSONResponse({"error": exc.message, "problems": exc.problems}, status_code=exc.status)

    @app.exception_handler(WorkspaceError)
    async def _ws_err(_r: Request, exc: WorkspaceError):
        return JSONResponse({"error": exc.message, "problems": [{"path": "", "message": p} for p in exc.problems]}, status_code=exc.status)

    # ---------------------------------------------------------------------------------- pages
    @app.get("/")
    async def index():
        return FileResponse(STATIC / "index.html", headers={"Cache-Control": "no-store"})

    app.mount("/static", StaticFiles(directory=STATIC), name="static")

    # ---------------------------------------------------------------------------------- meta
    @app.get("/api/meta")
    async def meta():
        registry = configs.registry()
        ms = registry.model_settings()
        now = time.time()
        if now - model_cache["at"] > 20:  # pinging Ollama takes a moment; the header polls this endpoint
            model_cache.update(at=now, problem=check_backend(ms))
        problem = model_cache["problem"]
        env_names = {"DT_API_TOKEN"}
        for c in configs.list():
            try:
                env_names.add(configs.load_service(c["name"]).observability.options.get("api_token_env", "DT_API_TOKEN"))
            except Exception:
                pass
        running = jobs.running()
        return {"workspace": str(workspace), "providers": configs.providers(), "configs": configs.list(),
                "model": {"backend": ms.backend, "label": describe(ms), "problem": problem},
                "env": {n: bool(os.environ.get(n)) for n in sorted(env_names)}, "running_job": running.id if running else None,
                "python": sys.version.split()[0]}

    # --------------------------------------------------------------------------------- configs
    @app.get("/api/configs/{name}")
    async def get_config(name: str):
        return configs.get(name)

    @app.post("/api/configs/validate")
    async def validate_config(body: dict[str, Any]):
        problems = configs.validate(body.get("config") or {}, body.get("token") or None)
        return {"valid": not problems, "problems": problems, "normalised": configs.normalise(body.get("config") or {})}

    @app.put("/api/configs/{name}")
    async def save_config(name: str, body: dict[str, Any]):
        return configs.save(name, body.get("config") or {}, body.get("token") or None, bool(body.get("force")))

    # ------------------------------------------------------------------------------------ jobs
    @app.get("/api/jobs")
    async def list_jobs():
        return jobs.list()

    @app.get("/api/jobs/{job_id}")
    async def get_job(job_id: str, since: int = 0):
        return jobs.get(job_id).public(since)

    @app.post("/api/jobs/{job_id}/cancel")
    async def cancel_job(job_id: str):
        return jobs.cancel(job_id).public()

    @app.post("/api/jobs/analyze")
    async def start_analyze(body: dict[str, Any]):
        name = str(body.get("config") or "")
        svc = configs.load_service(name)  # re-validated here: a job never starts from an invalid config
        path = configs._path(name)
        argv = ["analyze", "--config", str(path)]
        env: dict[str, str] = {}
        if body.get("no_llm"):
            argv.append("--no-llm")
        if body.get("refresh_graph"):
            argv.append("--refresh-graph")
        if body.get("gaps"):
            argv.append("--gaps")
        _common_model_args(body, argv)
        if body.get("token"):
            env[svc.observability.options.get("api_token_env", "DT_API_TOKEN")] = str(body["token"])
        return jobs.start("analyze", f"analyze {svc.service_name}", argv, env).public()

    @app.post("/api/jobs/gaps")
    async def start_gaps(body: dict[str, Any]):
        service = str(body.get("service") or "")
        dataset = reports().path(service, "dataset")
        argv = ["gaps", "--dataset", str(dataset), "--out", str(dataset.parent)]
        if body.get("no_llm"):
            argv.append("--no-llm")
        if body.get("limit"):
            argv += ["--limit", str(int(body["limit"]))]
        for m in body.get("modules") or []:
            if not _ID.match(str(m)):
                raise WorkspaceError(f"invalid module id {m!r}", status=400)
            argv += ["--module", str(m)]
        _common_model_args(body, argv)
        return jobs.start("gaps", f"gap analysis {service}", argv).public()

    def _common_model_args(body: dict[str, Any], argv: list[str]) -> None:
        if body.get("model_backend") in ("ollama", "gemini", "vertex"):
            argv += ["--model-backend", body["model_backend"]]
        if body.get("ollama_model"):
            if not re.match(r"^[A-Za-z0-9_.:/-]+$", str(body["ollama_model"])):
                raise WorkspaceError("invalid model name", status=400)
            argv += ["--ollama-model", str(body["ollama_model"])]

    # ---------------------------------------------------------------------------------- reports
    @app.get("/api/reports")
    async def list_reports():
        return reports().list()

    @app.get("/api/reports/{service}/gaps")
    async def report_gaps(service: str):
        return reports().json(service, "gaps")

    @app.get("/api/reports/{service}/coverage")
    async def report_coverage(service: str):
        return reports().json(service, "coverage")

    @app.get("/api/reports/{service}/dataset-facts")
    async def report_dataset(service: str):
        return reports().dataset_facts(service)

    @app.get("/api/reports/{service}/download/{kind}")
    async def report_download(service: str, kind: str):
        p = reports().path(service, kind)
        return FileResponse(p, filename=p.name)

    @app.get("/api/reports/{service}/markdown")
    async def report_markdown(service: str):
        return PlainTextResponse(reports().path(service, "report").read_text(encoding="utf-8"))

    # ---------------------------------------------------------------------------- NFR catalogue
    @app.get("/api/nfr/modules")
    async def nfr_modules():
        return store.list_modules()

    @app.get("/api/nfr/hints")
    async def nfr_hints():
        return store.hints()

    @app.get("/api/nfr/dataset-paths")
    async def nfr_paths():
        return store.dataset_paths()

    @app.get("/api/nfr/catalogues/{name}")
    async def nfr_catalogue(name: str):
        return store.catalogue(name)

    @app.get("/api/nfr/modules/{module_id}")
    async def nfr_get(module_id: str):
        return store.get_module(module_id)

    @app.post("/api/nfr/validate")
    async def nfr_validate(body: dict[str, Any]):
        problems = store.validate(body.get("module") or {}, body.get("module_id"))
        return {"valid": not problems, "problems": problems}

    @app.put("/api/nfr/modules/{module_id}")
    async def nfr_save(module_id: str, body: dict[str, Any]):
        return store.save_module(module_id, body.get("module") or {}, body.get("etag"))

    @app.post("/api/nfr/modules")
    async def nfr_create(body: dict[str, Any]):
        return store.create_module(body.get("module") or {})

    @app.delete("/api/nfr/modules/{module_id}")
    async def nfr_delete(module_id: str):
        store.delete_module(module_id)
        return {"deleted": module_id}

    @app.post("/api/nfr/modules/{module_id}/restore")
    async def nfr_restore(module_id: str, body: dict[str, Any]):
        return store.restore(module_id, str(body.get("backup") or ""), body.get("etag"))

    return app


def serve(host: str, port: int, workspace: Path, open_browser: bool = True, registry_path: str | None = None) -> None:
    import threading
    import webbrowser

    import uvicorn

    if host not in ("127.0.0.1", "localhost", "::1"):
        print(f"warning: the UI has no authentication and can run analyses and edit the knowledge base; binding to {host} exposes it.")
    app = create_app(workspace, registry_path=registry_path)
    url = f"http://{'127.0.0.1' if host in ('localhost', '') else host}:{port}/"
    print(f"sreadvisor UI: {url}   (workspace {Path(workspace).resolve()})   Ctrl+C to stop")
    if open_browser:
        threading.Timer(1.2, lambda: webbrowser.open(url)).start()
    uvicorn.run(app, host=host, port=port, log_level="warning")
