"""CI/CD pipeline definitions: deployment strategy, rollback, and database-migration steps.

Every supported system (GitHub Actions, GitLab CI, Jenkins, Azure Pipelines, Harness, UrbanCode
Deploy) is first normalised into ``Step`` records; one evaluator then derives the facts, so adding a
system means writing one extractor.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Callable

from sreadvisor.infra.k8s import dig
from sreadvisor.schema.common import Evidence
from sreadvisor.schema.dataset import InfraAnalysis, MigrationFact, PipelineAnalysis, RollbackFact
from sreadvisor.util.files import evidence
from sreadvisor.util.yamlx import YamlDoc

DEPLOY = re.compile(
    r"kubectl\s+(apply|set\s+image|rollout|replace|create)|helm\s+(upgrade|install)|terraform\s+apply|ecs\s+(update-service|deploy)|"
    r"cf\s+push|az\s+(webapp|containerapp|aks)|gcloud\s+(run|app)\s+deploy|argocd\s+app\s+sync|docker\s+(stack\s+deploy|service\s+update|compose\s+up)|"
    r"k8s\w*(deploy|apply)|kustomize\s+build|serverless\s+deploy|sam\s+deploy|cdk\s+deploy|\bdeploy(ing|ment)?\b|codedeploy", re.I)
BLUE_GREEN = re.compile(r"blue[-_ ]?green|bluegreen|k8sbluegreen|bgswap|slot\s+swap|swap[-_ ]slots?|--blue-green", re.I)
CANARY = re.compile(r"canary|k8scanary|traffic[-_ ]split|flagger|argo[-_ ]?rollouts?.*canary", re.I)
ROLLING = re.compile(r"rolling[-_ ]?update|rollingupdate|k8srollingdeploy|strategy:\s*rolling|rolling deploy", re.I)
RECREATE = re.compile(r"\brecreate\b", re.I)
AUTO_ROLLBACK = re.compile(r"--atomic|--rollback-on-failure|auto[-_]?rollback|automatic(ally)? roll|rollback[-_]on[-_]failure|"
                           r"flagger|argo.*rollouts?.*abort|autoRollbackConfiguration|--auto-rollback-configuration", re.I)
ROLLBACK_ACTION = re.compile(r"rollout\s+undo|helm\s+rollback|argocd\s+app\s+rollback|rollback|roll\s+back|revert\s+deploy", re.I)
MIGRATION = re.compile(r"flyway|liquibase|alembic\s+upgrade|prisma\s+migrate|dotnet\s+ef\s+database\s+update|rails\s+db:migrate|"
                       r"knex\s+migrate|sequelize.*db:migrate|manage\.py\s+migrate|migrate\s+(up|-path)|sqitch|dbmate|db[-_ ]migrat|schema[-_ ]migrat|"
                       r"\bmigrat(e|ion)s?\b", re.I)
MIG_TOOL = re.compile(r"(flyway|liquibase|alembic|prisma|dotnet\s+ef|rails\s+db:migrate|knex|sequelize|manage\.py\s+migrate|sqitch|dbmate)", re.I)


@dataclass
class Step:
    unit: str
    name: str
    text: str
    line: int
    manual: bool = False
    on_failure: bool = False


def _text(*parts: Any) -> str:
    return " ".join(str(p) for p in parts if p not in (None, "", {}, []))


# ------------------------------------------------------------------------- extractors


def _github(rp: str, doc: YamlDoc) -> tuple[str | None, list[Step], dict]:
    d = doc.data
    triggers = d.get("on", d.get(True)) or {}
    trig = set(triggers) if isinstance(triggers, (dict, list)) else {triggers}
    manual_only = trig == {"workflow_dispatch"}
    steps: list[Step] = []
    for jid, job in (d.get("jobs") or {}).items():
        if not isinstance(job, dict):
            continue
        jfail = "failure()" in str(job.get("if", ""))
        env = job.get("environment")
        env_name = env.get("name") if isinstance(env, dict) else env
        if job.get("uses"):
            steps.append(Step(jid, jid, _text(job["uses"]), doc.line("jobs", jid), manual_only, jfail))
        for i, s in enumerate(job.get("steps") or []):
            if isinstance(s, dict):
                steps.append(Step(jid, str(s.get("name", s.get("uses", f"step {i + 1}"))),
                                  _text(s.get("name"), s.get("uses"), s.get("run"), s.get("with"), env_name),
                                  doc.line("jobs", jid, "steps", i), manual_only, jfail or "failure()" in str(s.get("if", ""))))
    return d.get("name"), steps, {}


def _gitlab(rp: str, doc: YamlDoc) -> tuple[str | None, list[Step], dict]:
    steps = []
    for jid, job in doc.data.items():
        if isinstance(job, dict) and ("script" in job or "trigger" in job):
            when = str(job.get("when", ""))
            steps.append(Step(jid, jid, _text(jid, job.get("stage"), job.get("script"), job.get("environment"), job.get("before_script")),
                              doc.line(jid), when == "manual" or any("manual" in str(r) for r in job.get("rules", []) or []), when == "on_failure"))
    return None, steps, {}


def _azure(rp: str, doc: YamlDoc) -> tuple[str | None, list[Step], dict]:
    steps: list[Step] = []
    explicit: dict = {}
    blob = json.dumps(doc.data, default=str)

    def walk(node: Any, unit: str, path: tuple) -> None:
        if isinstance(node, dict):
            if "strategy" in node and isinstance(node["strategy"], dict):
                for k in node["strategy"]:
                    if k in ("canary", "rolling", "runOnce"):
                        explicit["strategy"] = {"canary": "canary", "rolling": "rolling", "runOnce": "recreate"}[k]
                        explicit["line"] = doc.line(*path, "strategy", k)
                        explicit["text"] = f"strategy: {k}"
            if "on" in node and isinstance(node["on"], dict) and "failure" in node["on"]:
                explicit["rollback"] = "automated"
                explicit["rollback_line"] = doc.line(*path, "on", "failure")
            for k, v in node.items():
                nu = str(node.get("stage") or node.get("job") or node.get("deployment") or unit)
                if k in ("script", "bash", "powershell", "task", "displayName", "pwsh"):
                    steps.append(Step(nu, str(node.get("displayName", k)), _text(node.get("displayName"), node.get("script"), node.get("task"), node.get("bash")),
                                      doc.line(*path, k)))
                walk(v, nu, path + (k,))
        elif isinstance(node, list):
            for i, v in enumerate(node):
                walk(v, unit, path + (i,))

    walk(doc.data, "pipeline", ())
    return doc.data.get("name"), steps, explicit


def _harness(rp: str, doc: YamlDoc) -> tuple[str | None, list[Step], dict]:
    pipe = doc.data.get("pipeline") or {}
    steps: list[Step] = []
    explicit: dict = {}
    pipe_strats = pipe.get("failureStrategies") or []
    for si, st in enumerate(pipe.get("stages") or []):
        stage = (st or {}).get("stage") or {}
        sname = str(stage.get("name", f"stage {si + 1}"))
        base = ("pipeline", "stages", si, "stage")
        stype = str(stage.get("type", ""))
        if stype.lower() == "approval":
            steps.append(Step(sname, sname, "approval", doc.line(*base), manual=True))
        ex = dig(stage, "spec", "execution", default={}) or {}
        for kind, on_fail in (("steps", False), ("rollbackSteps", True)):
            for i, s in enumerate(ex.get(kind) or []):
                step = (s or {}).get("step") or (s or {}).get("stepGroup") or {}
                stype2 = str(step.get("type", ""))
                steps.append(Step(sname, str(step.get("name", stype2)), _text(step.get("name"), stype2, step.get("spec")),
                                  doc.line(*base, "spec", "execution", kind, i), stype2.lower() == "harnessapproval", on_fail))
                if re.search(r"BlueGreen|BGSwap", stype2):
                    explicit.setdefault("strategy", "blue_green"); explicit.setdefault("line", doc.line(*base, "spec", "execution", kind, i)); explicit.setdefault("text", stype2)
                elif "Canary" in stype2:
                    explicit.setdefault("strategy", "canary"); explicit.setdefault("line", doc.line(*base, "spec", "execution", kind, i)); explicit.setdefault("text", stype2)
                elif "Rolling" in stype2 and not on_fail:
                    explicit.setdefault("strategy", "rolling"); explicit.setdefault("line", doc.line(*base, "spec", "execution", kind, i)); explicit.setdefault("text", stype2)
        strategies = (stage.get("failureStrategies") or []) + pipe_strats
        actions = [str(dig(fs, "onFailure", "action", "type", default="")) for fs in strategies if isinstance(fs, dict)]
        if ex.get("rollbackSteps") or "StageRollback" in actions or "PipelineRollback" in actions:
            if "StageRollback" in actions or "PipelineRollback" in actions:
                explicit["rollback"] = "automated"
                explicit["rollback_line"] = doc.line(*base, "failureStrategies") if stage.get("failureStrategies") else doc.line("pipeline", "failureStrategies")
            elif "ManualIntervention" in actions:
                explicit.setdefault("rollback", "manual")
                explicit.setdefault("rollback_line", doc.line(*base, "failureStrategies"))
            else:
                explicit.setdefault("rollback", "manual")
                explicit.setdefault("rollback_line", doc.line(*base, "spec", "execution", "rollbackSteps"))
    return pipe.get("name"), steps, explicit


def _ucd(rp: str, doc: YamlDoc) -> tuple[str | None, list[Step], dict]:
    steps: list[Step] = []
    name = str(doc.data.get("name", "")) if isinstance(doc.data, dict) else None

    def walk(node: Any, path: tuple) -> None:
        if isinstance(node, dict):
            if "name" in node and any(k in node for k in ("pluginName", "type", "properties", "children")):
                steps.append(Step(name or rp, str(node["name"]), _text(node.get("name"), node.get("pluginName"), node.get("type"),
                                                                          json.dumps(node.get("properties", ""), default=str)[:400]),
                                  doc.line(*path), "manual" in str(node.get("type", "")).lower() or "approval" in str(node.get("name", "")).lower()))
            for k, v in node.items():
                walk(v, path + (k,))
        elif isinstance(node, list):
            for i, v in enumerate(node):
                walk(v, path + (i,))

    walk(doc.data, ())
    return name, steps, ({"rollback": "manual", "rollback_line": 1} if name and "rollback" in name.lower() else {})


def _jenkins(rp: str, text: str) -> tuple[str | None, list[Step], dict]:
    steps: list[Step] = []
    unit, in_failure = "pipeline", False
    for i, line in enumerate(text.splitlines(), 1):
        m = re.search(r"stage\s*\(\s*['\"]([^'\"]+)['\"]", line)
        if m:
            unit, in_failure = m.group(1), False
        if re.search(r"\bfailure\s*\{", line):
            in_failure = True
        if line.strip() and not line.strip().startswith("//"):
            steps.append(Step(unit, line.strip()[:60], line.strip(), i, manual="input" in line and ("message" in line or "input(" in line), on_failure=in_failure))
    return None, steps, {}


# ------------------------------------------------------------------------- evaluation


def _evaluate(system: str, rp: str, name: str | None, steps: list[Step], explicit: dict) -> PipelineAnalysis:
    deploy_steps = [s for s in steps if DEPLOY.search(s.text) or DEPLOY.search(s.name)]
    if system == "jenkins":  # Jenkins records are raw lines: keep only command-looking deploy lines
        deploy_steps = [s for s in deploy_steps if re.search(r"\b(sh|bat|kubectl|helm|terraform|docker)\b", s.text)]
    pa = PipelineAnalysis(system=system, file=rp, name=name, deploys=bool(deploy_steps),
                          deploy_steps=[f"{s.unit}: {s.name}"[:100] for s in deploy_steps][:8])

    if explicit.get("strategy"):
        pa.deployment_strategy = explicit["strategy"]
        pa.strategy_evidence = [evidence(rp, explicit.get("line"), explicit.get("text"))]
    elif deploy_steps:
        for label, rx in (("blue_green", BLUE_GREEN), ("canary", CANARY), ("rolling", ROLLING), ("recreate", RECREATE)):
            hit = next((s for s in steps if rx.search(s.text) or rx.search(s.name)), None)
            if hit:
                pa.deployment_strategy = label
                pa.strategy_evidence = [evidence(rp, hit.line, hit.text)]
                break
        else:
            pa.deployment_strategy = "unknown"
    else:
        pa.deployment_strategy = "none"

    if deploy_steps:
        auto = next((s for s in steps if AUTO_ROLLBACK.search(s.text)), None) or next(
            (s for s in steps if s.on_failure and ROLLBACK_ACTION.search(s.text)), None) or next(
            (s for s in steps if re.search(r"\|\|\s*(kubectl\s+rollout\s+undo|helm\s+rollback)", s.text)), None)
        manual = next((s for s in steps if ROLLBACK_ACTION.search(s.text + " " + s.name) and not s.on_failure), None)
        if explicit.get("rollback") == "automated" or auto:
            line = explicit.get("rollback_line") if explicit.get("rollback") == "automated" else auto.line
            pa.rollback = RollbackFact(mode="automated", evidence=[evidence(rp, line, "automated rollback trigger")])
        elif explicit.get("rollback") == "manual" or manual:
            line = explicit.get("rollback_line") if explicit.get("rollback") == "manual" else manual.line
            pa.rollback = RollbackFact(mode="manual", evidence=[evidence(rp, line, "rollback step / manual rollback defined")])

    mig = [s for s in steps if MIGRATION.search(s.text) and not re.search(r"^\s*(name|on):", s.text)]
    mig = [s for s in mig if not s.on_failure and re.search(r"flyway|liquibase|alembic|prisma|ef\s+database|db:migrate|knex|sequelize|manage\.py|sqitch|dbmate|"
                                                            r"migrate|migration", s.text, re.I)]
    if mig:
        tool = MIG_TOOL.search(" ".join(s.text for s in mig))
        both = [s for s in mig if s in deploy_steps]
        if not deploy_steps:
            sep: bool | None = None
        else:
            sep = not (both and len(both) == len(mig))
        pa.db_migration = MigrationFact(present=True, tool=tool.group(1) if tool else None, separate_step=sep,
                                        evidence=[evidence(rp, s.line, s.name) for s in mig[:3]])
    return pa


def parse_pipelines(ia: InfraAnalysis, yaml_files: list[tuple[str, str, list[YamlDoc]]], jenkinsfiles: list[tuple[str, str]]) -> None:
    for rp, text, docs in yaml_files:
        low = rp.lower()
        name = low.split("/")[-1]
        for doc in docs:
            d = doc.data
            if not isinstance(d, dict):
                continue
            extractor: Callable | None = None
            system = ""
            if ".github/workflows/" in low and "jobs" in d:
                extractor, system = _github, "github_actions"
            elif name == ".gitlab-ci.yml" or name == ".gitlab-ci.yaml":
                extractor, system = _gitlab, "gitlab_ci"
            elif name.startswith("azure-pipelines") or ("stages" in d and ("pool" in d or "trigger" in d) and "pipeline" not in d):
                extractor, system = _azure, "azure_pipelines"
            elif "pipeline" in d and isinstance(d["pipeline"], dict) and "stages" in d["pipeline"]:
                extractor, system = _harness, "harness"
            elif "rootActivity" in text or "componentProcess" in text or "applicationProcess" in text:
                extractor, system = _ucd, "ucd"
            if extractor:
                pname, steps, explicit = extractor(rp, doc)
                ia.pipelines.append(_evaluate(system, rp, pname, steps, explicit))
    for rp, text in jenkinsfiles:
        pname, steps, explicit = _jenkins(rp, text)
        ia.pipelines.append(_evaluate("jenkins", rp, pname, steps, explicit))
