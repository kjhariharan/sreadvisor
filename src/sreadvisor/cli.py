"""Command-line entry point.

Two ways to give inputs: flags for a one-off run, or (preferred for repeated use) a per-service
YAML/JSON config file that is validated on load, with every bad field named.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

from sreadvisor.config import ConfigError, config_from_flags, load_config_file
from sreadvisor.pipeline import InputError, emit, run_pipeline
from sreadvisor.registry import Registry, RegistryError
from sreadvisor.schema.dataset import ServiceDataset


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sreadvisor", description="SRE readiness advisor: Stage 1 code + infra analysis.")
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("analyze", help="analyse a service and write the consolidated dataset")
    a.add_argument("--config", "-c", help="per-service YAML/JSON config file (preferred for repeated use)")
    a.add_argument("--repo", action="append", default=[], help="code repository path or git URL (repeatable)")
    a.add_argument("--iac", action="append", default=[], help="infrastructure-as-code path (repeatable)")
    a.add_argument("--service-name", help="service name (default: first repo directory name)")
    a.add_argument("--provider", help="active observability provider, e.g. dynatrace")
    a.add_argument("--service-id", help="the provider's service id, e.g. SERVICE-0123456789ABCDEF")
    a.add_argument("--dt-environment-url", help="Dynatrace environment URL (when provider is dynatrace)")
    a.add_argument("--dt-auth-mode", choices=["api_token", "oauth2"], help="Dynatrace auth mode (default: api_token)")
    a.add_argument("--dt-api-token", help="Dynatrace API token (prefer exporting DT_API_TOKEN); auth_mode api_token")
    a.add_argument("--dt-oauth-client-id", help="Dynatrace OAuth2 client id (prefer exporting DT_OAUTH_CLIENT_ID); auth_mode oauth2")
    a.add_argument("--dt-oauth-client-secret", help="Dynatrace OAuth2 client secret (prefer exporting DT_OAUTH_CLIENT_SECRET); auth_mode oauth2")
    a.add_argument("--dt-oauth-url", help="Dynatrace OAuth2 token endpoint (default: Dynatrace SSO); auth_mode oauth2")
    a.add_argument("--provider-option", action="append", default=[], metavar="KEY=VALUE", help="other provider option (repeatable)")
    a.add_argument("--out", help="output directory (default: ./output)")
    a.add_argument("--registry", help="registry file (default: built-in)")
    a.add_argument("--state-dir", default=".sreadvisor", help="graph/LLM cache and clone directory (default: .sreadvisor)")
    a.add_argument("--no-llm", action="store_true", help="skip the LLM reasoning steps (deterministic findings only)")
    a.add_argument("--refresh-graph", action="store_true", help="discard the cached Graphify graph and rebuild it")
    a.add_argument("--model-backend", choices=["ollama", "gemini", "vertex", "gateway"], help="override model.backend for this run")
    a.add_argument("--ollama-model", help="override the Ollama model name for this run")
    a.add_argument("--gaps", action="store_true", help="after the dataset is written, run Gap Analysis Pass 1 on it")
    a.add_argument("--report", action="store_true", help="also build the Stage 4 unified report, HTML render and Dynatrace "
                                                          "dashboard (implies --gaps)")
    a.add_argument("--graph", action="store_true", help="also build the dependency graph (JSON + HTML); makes no LLM call")

    v = sub.add_parser("validate-config", help="validate a per-service config file and exit")
    v.add_argument("--config", "-c", required=True)
    v.add_argument("--registry")

    g = sub.add_parser("gaps", help="Gap Analysis: assess a Stage 1 dataset against the Master NFR List "
                                    "(Pass 1, or Pass 2 when --runtime is given)")
    g.add_argument("--dataset", required=True, help="path to a <service>.dataset.json")
    g.add_argument("--runtime", help="path to a <service>.runtime-cross-validation.json (from `sreadvisor runtime`); "
                                     "when given, runs Gap Analysis Pass 2 instead of Pass 1")
    g.add_argument("--out", help="output directory (default: next to the dataset)")
    g.add_argument("--registry", help="registry file (default: built-in)")
    g.add_argument("--state-dir", default=".sreadvisor", help="LLM cache directory (default: .sreadvisor)")
    g.add_argument("--module", action="append", default=[], help="only assess this Master NFR List module id (repeatable)")
    g.add_argument("--limit", type=int, help="assess only the first N applicable requirements (for a quick trial)")
    g.add_argument("--no-llm", action="store_true", help="deterministic parts only: unrecognized tech gaps, not_assessable verdicts")
    g.add_argument("--model-backend", choices=["ollama", "gemini", "vertex", "gateway"], help="override model.backend for this run")
    g.add_argument("--ollama-model", help="override the Ollama model name for this run")

    r = sub.add_parser("report", help="Stage 4: unified JSON report, HTML render and Dynatrace dashboard from a dataset + gap report")
    r.add_argument("--dataset", required=True, help="path to a <service>.dataset.json")
    r.add_argument("--gaps", required=True, help="path to the matching <service>.gaps.json (from `sreadvisor gaps`)")
    r.add_argument("--out", help="output directory (default: next to the dataset)")

    rt = sub.add_parser("runtime", help="Stage 5: pull live topology and metrics from the observability provider, "
                                        "cross-validate against a Stage 1 dataset")
    rt.add_argument("--dataset", required=True, help="path to a <service>.dataset.json (its observability binding names the provider)")
    rt.add_argument("--service-id", help="override the dataset's own observability.service_id (for example when the pilot "
                                         "service is not the exact one available in a trial tenant)")
    rt.add_argument("--from-time", default="now-2h", help="start of the metrics window, in Dynatrace relative time syntax (default now-2h)")
    rt.add_argument("--out", help="output directory (default: next to the dataset)")
    rt.add_argument("--registry", help="registry file (default: built-in)")

    f = sub.add_parser("fmea", help="Stage 6: Failure Mode and Effects Analysis from a dataset (and, optionally, runtime cross-validation)")
    f.add_argument("--dataset", required=True, help="path to a <service>.dataset.json")
    f.add_argument("--gaps", help="path to a <service>.gaps.json, to cross-reference each failure mode with related gaps")
    f.add_argument("--runtime", help="path to a <service>.runtime-cross-validation.json, to include runtime-only dependencies")
    f.add_argument("--out", help="output directory (default: next to the dataset)")
    f.add_argument("--registry", help="registry file (default: built-in)")
    f.add_argument("--state-dir", default=".sreadvisor", help="LLM cache directory (default: .sreadvisor)")
    f.add_argument("--model-backend", choices=["ollama", "gemini", "vertex", "gateway"], help="override model.backend for this run")
    f.add_argument("--ollama-model", help="override the Ollama model name for this run")

    rb = sub.add_parser("runbook", help="Stage 6: operations runbook (JSON + Markdown) from an FMEA report")
    rb.add_argument("--dataset", required=True, help="path to a <service>.dataset.json")
    rb.add_argument("--fmea", required=True, help="path to a <service>.fmea.json (from `sreadvisor fmea`)")
    rb.add_argument("--report", help="path to a <service>.report.json (from `sreadvisor report`), to reuse its SLI suggestions "
                                     "as detection signals")
    rb.add_argument("--out", help="output directory (default: next to the dataset)")
    rb.add_argument("--registry", help="registry file (default: built-in)")
    rb.add_argument("--state-dir", default=".sreadvisor", help="LLM cache directory (default: .sreadvisor)")
    rb.add_argument("--model-backend", choices=["ollama", "gemini", "vertex", "gateway"], help="override model.backend for this run")
    rb.add_argument("--ollama-model", help="override the Ollama model name for this run")

    dg = sub.add_parser("graph", help="dependency graph (JSON + interactive HTML) from a dataset, no LLM call; "
                                      "optionally enriched with runtime cross-validation")
    dg.add_argument("--dataset", required=True, help="path to a <service>.dataset.json")
    dg.add_argument("--runtime", help="path to a <service>.runtime-cross-validation.json, to add runtime-only "
                                      "dependencies and tag edges with what's confirmed live")
    dg.add_argument("--out", help="output directory (default: next to the dataset)")

    u = sub.add_parser("ui", help="start the local web UI (inputs, gap reports, Master NFR List editor)")
    u.add_argument("--host", default="127.0.0.1", help="interface to bind (default: 127.0.0.1; the UI has no authentication)")
    u.add_argument("--port", type=int, default=8765)
    u.add_argument("--workspace", default=".", help="directory holding config/ and output/ (default: current directory)")
    u.add_argument("--registry", help="registry file (default: built-in)")
    u.add_argument("--no-browser", action="store_true", help="do not open a browser window")

    n = sub.add_parser("nfr", help="work with the Master NFR List and the telemetry catalogues")
    ns = n.add_subparsers(dest="nfr_cmd", required=True)
    ns.add_parser("build", help="compile nfr/data/src/*.yaml into the JSON files Stage 3 loads")
    ns.add_parser("check", help="validate the sources and confirm the committed JSON is up to date")
    nl = ns.add_parser("list", help="list modules, or the requirements of one module")
    nl.add_argument("--module", help="module id to show in detail")
    nc = ns.add_parser("coverage", help="NFR coverage report for an existing Stage 1 dataset")
    nc.add_argument("--dataset", required=True, help="path to a <service>.dataset.json")
    nc.add_argument("--out", help="output directory (default: next to the dataset)")

    s = sub.add_parser("schema", help="print the JSON Schema of the consolidated dataset")
    s.add_argument("--out", help="write to a file instead of stdout")
    return p


def _provider_options(args: argparse.Namespace) -> dict:
    opts: dict = {}
    if args.dt_environment_url:
        opts["environment_url"] = args.dt_environment_url
    if args.dt_auth_mode:
        opts["auth_mode"] = args.dt_auth_mode
    if args.dt_api_token:
        opts["api_token"] = args.dt_api_token
    if args.dt_oauth_client_id:
        opts["oauth_client_id"] = args.dt_oauth_client_id
    if args.dt_oauth_client_secret:
        opts["oauth_client_secret"] = args.dt_oauth_client_secret
    if args.dt_oauth_url:
        opts["oauth_url"] = args.dt_oauth_url
    for kv in args.provider_option:
        if "=" not in kv:
            raise ConfigError([f"--provider-option '{kv}': expected KEY=VALUE"])
        k, v = kv.split("=", 1)
        opts[k.strip()] = v.strip()
    return opts


def _load_cfg(args: argparse.Namespace, registry: Registry):
    if args.config:
        cfg = load_config_file(args.config, registry)
        return cfg
    if not args.repo:
        raise ConfigError(["give --config FILE, or at least --repo PATH_OR_URL"])
    return config_from_flags(repos=args.repo, iac=args.iac, provider=args.provider, service_id=args.service_id,
                             service_name=args.service_name, provider_options=_provider_options(args), output_dir=args.out,
                             registry=registry)


def _run_gaps(dataset: ServiceDataset, registry: Registry, out_dir: Path, state_dir: Path, *, only_modules: list[str] | None = None,
              limit: int | None = None, use_llm: bool = True, runtime=None):
    from sreadvisor.gap.output import console_summary, write_report
    from sreadvisor.gap.pass1 import GapAnalysisError

    module_name = "gap_analysis_pass_2" if runtime is not None else "gap_analysis_pass_1"
    module = next((m for m in registry.active_nfr_modules() if m.name == module_name), None)
    if module is None:
        print(f"error: {module_name} is not enabled under nfr_modules in the registry", file=sys.stderr)
        return 2, None
    module.only_modules, module.limit, module.use_llm = only_modules or None, limit, use_llm
    module.bind(registry, state_dir)
    try:
        gap_report = asyncio.run(module.evaluate(dataset, runtime))
    except GapAnalysisError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2, None
    print(console_summary(gap_report))
    print(f"\nWrote {write_report(gap_report, out_dir)}")
    return 0, gap_report


def _gaps(args: argparse.Namespace) -> int:
    from sreadvisor.nfr.coverage import load_dataset
    from sreadvisor.runtime.schema import RuntimeCrossValidation

    if args.model_backend:
        os.environ["SREADVISOR_MODEL_BACKEND"] = args.model_backend
    if args.ollama_model:
        os.environ["SREADVISOR_OLLAMA_MODEL"] = args.ollama_model
    try:
        registry = Registry.load(args.registry)
        dataset = load_dataset(args.dataset)
        runtime = RuntimeCrossValidation.model_validate_json(Path(args.runtime).read_text(encoding="utf-8")) if args.runtime else None
    except (RegistryError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    out_dir = Path(args.out) if args.out else Path(args.dataset).resolve().parent
    rc, _ = _run_gaps(dataset, registry, out_dir.resolve(), Path(args.state_dir).resolve(), only_modules=args.module,
                      limit=args.limit, use_llm=not args.no_llm, runtime=runtime)
    return rc


def _run_report(dataset: ServiceDataset, gap_report, out_dir: Path) -> int:
    from sreadvisor.report.build import build_report
    from sreadvisor.report.output import console_summary, write_report

    try:
        unified = build_report(dataset, gap_report)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    written = write_report(unified, out_dir)
    print(console_summary(unified, written))
    return 0


def _report(args: argparse.Namespace) -> int:
    from sreadvisor.gap.schema import GapReport
    from sreadvisor.nfr.coverage import load_dataset

    try:
        dataset = load_dataset(args.dataset)
        gap_report = GapReport.model_validate_json(Path(args.gaps).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    out_dir = Path(args.out) if args.out else Path(args.dataset).resolve().parent
    return _run_report(dataset, gap_report, out_dir.resolve())


def _runtime(args: argparse.Namespace) -> int:
    import asyncio as _asyncio

    from sreadvisor.nfr.coverage import load_dataset
    from sreadvisor.providers.base import ObservabilityError
    from sreadvisor.runtime.cross_validate import cross_validate
    from sreadvisor.runtime.output import console_summary, write_report

    try:
        registry = Registry.load(args.registry)
        dataset = load_dataset(args.dataset)
        obs = dataset.observability
        provider_cls = registry.provider_class(obs.provider)
        options = provider_cls.validate_options(obs.options)  # re-resolves the token from its env var, never from the dataset
        provider = provider_cls(args.service_id or obs.service_id, options)
    except (RegistryError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    async def pull():
        topology = await provider.get_topology(provider.service_id)
        metrics = await provider.get_metrics(provider.service_id, from_time=args.from_time)
        return topology, metrics

    try:
        topology, metrics = _asyncio.run(pull())
    except ObservabilityError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    result = cross_validate(dataset, topology, metrics)
    out_dir = Path(args.out) if args.out else Path(args.dataset).resolve().parent
    print(console_summary(result))
    print(f"\nWrote {write_report(result, out_dir.resolve())}")
    return 0


def _fmea(args: argparse.Namespace) -> int:
    from sreadvisor.fmea.build import FmeaError, build_fmea
    from sreadvisor.fmea.output import console_summary, write_report
    from sreadvisor.gap.schema import GapReport
    from sreadvisor.nfr.coverage import load_dataset
    from sreadvisor.runtime.schema import RuntimeCrossValidation

    if args.model_backend:
        os.environ["SREADVISOR_MODEL_BACKEND"] = args.model_backend
    if args.ollama_model:
        os.environ["SREADVISOR_OLLAMA_MODEL"] = args.ollama_model
    try:
        registry = Registry.load(args.registry)
        dataset = load_dataset(args.dataset)
        gap_report = GapReport.model_validate_json(Path(args.gaps).read_text(encoding="utf-8")) if args.gaps else None
        runtime = RuntimeCrossValidation.model_validate_json(Path(args.runtime).read_text(encoding="utf-8")) if args.runtime else None
    except (RegistryError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    out_dir = Path(args.out) if args.out else Path(args.dataset).resolve().parent
    try:
        fmea_report = asyncio.run(build_fmea(dataset, gap_report, runtime, registry, Path(args.state_dir).resolve()))
    except FmeaError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(console_summary(fmea_report))
    print(f"\nWrote {write_report(fmea_report, out_dir.resolve())}")
    return 0


def _runbook(args: argparse.Namespace) -> int:
    from sreadvisor.fmea.schema import FmeaReport
    from sreadvisor.nfr.coverage import load_dataset
    from sreadvisor.report.schema import UnifiedReport
    from sreadvisor.runbook.build import RunbookError, build_runbook
    from sreadvisor.runbook.output import console_summary, write_markdown, write_report

    if args.model_backend:
        os.environ["SREADVISOR_MODEL_BACKEND"] = args.model_backend
    if args.ollama_model:
        os.environ["SREADVISOR_OLLAMA_MODEL"] = args.ollama_model
    try:
        registry = Registry.load(args.registry)
        dataset = load_dataset(args.dataset)
        fmea_report = FmeaReport.model_validate_json(Path(args.fmea).read_text(encoding="utf-8"))
        sli_suggestions = (UnifiedReport.model_validate_json(Path(args.report).read_text(encoding="utf-8")).sli_suggestions
                           if args.report else None)
    except (RegistryError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    out_dir = Path(args.out) if args.out else Path(args.dataset).resolve().parent
    try:
        runbook = asyncio.run(build_runbook(dataset, fmea_report, sli_suggestions, registry, Path(args.state_dir).resolve()))
    except RunbookError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(console_summary(runbook))
    print(f"\nWrote {write_report(runbook, out_dir.resolve())}")
    print(f"Wrote {write_markdown(runbook, out_dir.resolve())}")
    return 0


def _run_graph(dataset: ServiceDataset, runtime, out_dir: Path) -> int:
    from sreadvisor.depgraph.build import DepGraphError, build_dependency_graph
    from sreadvisor.depgraph.output import console_summary, write_html, write_report

    try:
        graph = build_dependency_graph(dataset, runtime)
    except DepGraphError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(console_summary(graph))
    print(f"\nWrote {write_report(graph, out_dir)}")
    print(f"Wrote {write_html(graph, out_dir)}")
    return 0


def _graph(args: argparse.Namespace) -> int:
    from sreadvisor.nfr.coverage import load_dataset
    from sreadvisor.runtime.schema import RuntimeCrossValidation

    try:
        dataset = load_dataset(args.dataset)
        runtime = RuntimeCrossValidation.model_validate_json(Path(args.runtime).read_text(encoding="utf-8")) if args.runtime else None
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    out_dir = Path(args.out) if args.out else Path(args.dataset).resolve().parent
    return _run_graph(dataset, runtime, out_dir.resolve())


def _nfr(args: argparse.Namespace) -> int:
    from sreadvisor.nfr import loader
    from sreadvisor.nfr.coverage import compute_coverage, load_dataset
    from sreadvisor.sinks.nfr_report import NfrReportSink

    try:
        if args.nfr_cmd == "build":
            for p in loader.write_built():
                print(f"wrote {p}")
            return 0
        if args.nfr_cmd == "check":
            stale = loader.is_up_to_date()
            if stale:
                print("stale (run `sreadvisor nfr build`): " + ", ".join(stale), file=sys.stderr)
                return 1
            kb = loader.load_master()
            print(f"OK: {len(kb.modules)} modules, {len(kb.entries())} requirements; catalogues consistent; JSON up to date.")
            return 0
        if args.nfr_cmd == "list":
            kb = loader.load_master()
            if args.module:
                m = kb.modules.get(args.module)
                if m is None:
                    print(f"error: unknown module {args.module!r}. Modules: {', '.join(kb.modules)}", file=sys.stderr)
                    return 2
                print(f"{m.title} [{m.layer}/{m.category}]: {m.description}\n")
                for e in m.entries:
                    print(f"  {e.id} ({e.priority}) {e.title}")
                return 0
            for m in kb.modules.values():
                print(f"{m.id:32} {m.layer:14} {len(m.entries):3} requirements  {m.title}")
            return 0
        if args.nfr_cmd == "coverage":
            ds = load_dataset(args.dataset)
            out = Path(args.out) if args.out else Path(args.dataset).resolve().parent
            print(NfrReportSink().emit(ds, out))
            return 0
    except loader.KnowledgeBaseError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 2


def main(argv: list[str] | None = None) -> int:
    # A .env file (see .env.example), if present anywhere from the current directory upward, is loaded into the
    # process environment before anything else reads it — every setting below this point that reads os.environ
    # (the model backend, Ollama/Gemini/Vertex settings, DT_API_TOKEN, SREADVISOR_REGISTRY, SREADVISOR_OUTPUT_DIR,
    # ...) picks it up with no further wiring. An already-exported real environment variable always wins:
    # load_dotenv() never overwrites one that is already set.
    load_dotenv()
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    args = _parser().parse_args(argv)

    if args.cmd == "schema":
        text = json.dumps(ServiceDataset.model_json_schema(), indent=2)
        if args.out:
            Path(args.out).write_text(text, encoding="utf-8")
            print(f"wrote {args.out}")
        else:
            print(text)
        return 0

    if args.cmd == "ui":
        from sreadvisor.ui.server import serve

        serve(args.host, args.port, Path(args.workspace), open_browser=not args.no_browser, registry_path=args.registry)
        return 0
    if args.cmd == "nfr":
        return _nfr(args)
    if args.cmd == "gaps":
        return _gaps(args)
    if args.cmd == "report":
        return _report(args)
    if args.cmd == "runtime":
        return _runtime(args)
    if args.cmd == "fmea":
        return _fmea(args)
    if args.cmd == "runbook":
        return _runbook(args)
    if args.cmd == "graph":
        return _graph(args)

    try:
        registry = Registry.load(args.registry)
        if args.cmd == "validate-config":
            cfg = load_config_file(args.config, registry)
            print(f"OK: {args.config} is valid (service '{cfg.service_name}', {len(cfg.code_repos)} repo(s), "
                  f"{len(cfg.iac_paths)} iac path(s), provider '{cfg.observability.provider}').")
            return 0

        if args.model_backend:
            os.environ["SREADVISOR_MODEL_BACKEND"] = args.model_backend
        if args.ollama_model:
            os.environ["SREADVISOR_OLLAMA_MODEL"] = args.ollama_model
        cfg = _load_cfg(args, registry)
        state_dir = Path(args.state_dir).resolve()
        # Precedence: --out flag > output_dir in the per-service config > $SREADVISOR_OUTPUT_DIR > "output".
        out_dir = Path(args.out or cfg.output_dir or os.environ.get("SREADVISOR_OUTPUT_DIR") or "output")
        if not out_dir.is_absolute() and not args.out and cfg.output_dir:
            out_dir = (cfg.config_dir / cfg.output_dir).resolve()
        dataset = asyncio.run(run_pipeline(cfg, registry, state_dir=state_dir, use_llm=not args.no_llm, refresh_graph=args.refresh_graph))
    except (ConfigError, RegistryError, InputError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    locations = emit(dataset, registry, out_dir.resolve())
    for loc in locations:
        print(f"\nWrote {loc}")
    rc = 0 if dataset.completeness.get("structurally_complete") else 1
    if args.gaps or args.report:
        gap_rc, gap_report = _run_gaps(dataset, registry, out_dir.resolve(), state_dir, use_llm=not args.no_llm)
        rc = gap_rc or rc
        if args.report and gap_report is not None:
            rc = _run_report(dataset, gap_report, out_dir.resolve()) or rc
    if args.graph:
        rc = _run_graph(dataset, None, out_dir.resolve()) or rc
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
