# sreadvisor

Stage 1: code analysis and infra analysis, consolidated into a facts-only dataset per service.
Stage 2: Master NFR List and telemetry catalogues. Stage 3: Gap Analysis Pass 1. Stage 4: unified report,
SLI suggestions and the Dynatrace dashboard generator. Stage 5: observability provider integration (Dynatrace,
via MCP) and runtime cross-validation. Stage 6: Gap Analysis Pass 2 (runtime-aware), FMEA and the operations
runbook generator (all below).

## Setup

```
uv sync                                  # Python 3.12 venv (pinned in .python-version), all dependencies
ollama pull gemma4:latest                # local model (set model.ollama.model to use qwen3-coder:30b once pulled)
                                         # model.ollama.num_ctx (default 16384) must stay well above Ollama's 4k default
gcloud auth application-default login    # only needed later, for the `vertex` backend
cp .env.example .env                     # optional: fill in the model backend, tokens, output dir, ... (see below)
```

`sreadvisor` loads `.env` automatically on every run (searching from the current directory upward), so anything in
it is equivalent to exporting it as a real environment variable — which always takes precedence if already set.
See `.env.example` for the full, documented list: `SREADVISOR_OUTPUT_DIR` (default output directory, when neither
`--out` nor a config's `output_dir` is given), `SREADVISOR_MODEL_BACKEND`/`SREADVISOR_OLLAMA_MODEL`/`OLLAMA_API_BASE`,
`GEMINI_API_KEY`/`GOOGLE_API_KEY`, `GOOGLE_CLOUD_PROJECT`/`GOOGLE_CLOUD_LOCATION`, `DT_API_TOKEN`, and
`SREADVISOR_REGISTRY`. The Dynatrace environment URL is deliberately *not* one of these (see the comment in
`.env.example`): it always comes from `--dt-environment-url` or a service's own config file.

## Run

Preferred: a per-service config file (validated on load; bad fields are named).

```
uv run sreadvisor validate-config --config config/petclinic.yaml
uv run sreadvisor analyze --config config/petclinic.yaml
```

One-off, with flags:

```
uv run sreadvisor analyze --repo path/or/git-url --iac path/to/iac \
    --provider dynatrace --dt-environment-url https://abc.live.dynatrace.com \
    --service-id SERVICE-0123456789ABCDEF          # token from $DT_API_TOKEN (or --dt-api-token)
```

Useful flags: `--no-llm` (deterministic findings only), `--refresh-graph`, `--model-backend ollama|gemini|vertex`,
`--registry FILE`, `--out DIR`. `uv run sreadvisor schema` prints the dataset's JSON Schema.
Output: `output/<service>.dataset.json`.

## Design

| Concern | Where |
|---|---|
| Model backend switch (ollama / gemini / vertex) | `model_provider.py`; every agent gets its model from `get_model()` |
| Provider / NFR module / output sink registry | `default_registry.yaml`, `registry.py` |
| Observability abstraction | `providers/base.py` (`ObservabilityProvider`), `schema/runtime.py` (common runtime schema), `providers/dynatrace.py` (first implementation, MCP-based) |
| Deterministic fingerprinting (per-stack parsers) | `code/fingerprint/parsers.py` (add a parser per new manifest format) |
| Structural graph (Graphify, tree-sitter, no LLM, cached per file) | `graph/code_graph.py` |
| LLM reasoning (ADK `LlmAgent`s with scoped tools) | `agents/definitions.py`, orchestration in `code/llm_steps.py` |
| Deterministic scans: capacity, secrets, encryption/audit, telemetry | `code/capacity.py`, `secrets.py`, `encryption.py`, `telemetry.py` |
| Infra: Kubernetes, Helm, Terraform, compose/Docker, CI/CD, service mesh | `infra/` |
| Consolidation, cross-references, completeness report | `consolidation.py` |

How the LLM is kept honest: Graphify supplies entry points (annotation catalogue) and call chains; agents only judge on top of
that structure. Every fact an agent returns must cite an existing file and line or it is dropped, and data-access steps present
in the call graph are backfilled if the model omits them. Results are cached by (model, agent, prompt).

Secrets are never copied into the dataset (values are redacted to their length).

## Stage 2: Master NFR List and telemetry catalogues

A knowledge base, not an analysis component. It is authored as YAML under `src/sreadvisor/nfr/data/src/` and compiled to three flat JSON
files in `src/sreadvisor/nfr/data/` (Stage 3 loads these; no parsing logic needed):

| File | Contents |
|---|---|
| `master_nfr_list.json` | Modules keyed by id, each with `entries`. Layer one `baseline`; layer two `tech_stack` modules (extend the baseline); `cross_cutting` modules that apply to every service |
| `oneagent_default_catalogue.json` | Tier 1, tagged `oneagent_default`: what Dynatrace OneAgent captures with zero configuration, per module, plus `not_covered_by_default` |
| `app_instrumentation_catalogue.json` | Tier 2, tagged `application_level_library_emitted`: what Micrometer, OpenTelemetry, Kafka clients, pools and caches emit, per module |

Every requirement has `requirement`, `best_practice`, `audit_requirement`, `monitoring` (signals that verify it, each tagged with its tier)
and `verification` (`stage1_paths` into the Stage 1 dataset plus pass `criteria`; the paths are validated against the dataset schema at build time).
Modules add their own fields freely (for example `kafka_property`), documented under `entry_extensions`.

```
uv run sreadvisor nfr build          # compile the YAML sources into the JSON files
uv run sreadvisor nfr check          # validate everything and confirm the committed JSON is current
uv run sreadvisor nfr list [--module spring_boot_kafka]
uv run sreadvisor nfr coverage --dataset output/spring-petclinic.dataset.json
```

`analyze` also writes, next to the dataset, `<service>.report.md` and `<service>.nfr-coverage.json`: which modules apply and why, the
**unrecognized tech stacks** (technologies with no module, never silently skipped), and the three telemetry tiers. The coverage JSON's
`telemetry_tiers.metric_index` is the input for Stage 5's dashboard generator (tier 1 default, tier 2 already emitted, tier 3 pending).

Adding coverage: create `nfr/data/src/modules/<id>.yaml` (copy an existing module), add the module to `oneagent.yaml` and `instrumentation.yaml`
(an explicit "none" with a reason is fine), run `nfr build`. A technology already covered by a module but reported as unrecognized needs a `recognizes` rule.
Modules apply through `detect` rules (language, framework, dependency regex, infra signal, image, terraform type, observability provider,
entry point kind); rules that are only heuristics (`entry_point`, `flow_dependency`) never count as recognising a technology.
Metric keys and OneAgent behaviour in the catalogues are curated, not read from a tenant: entries marked `confidence: medium` and every
`metric_key` must be validated against the target tenant in Stage 5.

## Stage 3: Gap Analysis Pass 1

Inputs are the Stage 1 dataset and the Master NFR List; nothing else (no runtime data, no repository access).

```
uv run sreadvisor gaps --dataset output/spring-petclinic.dataset.json          # writes output/spring-petclinic.gaps.json
uv run sreadvisor gaps --dataset ... --module capacity_scaling --limit 5       # quick trial
uv run sreadvisor gaps --dataset ... --no-llm                                  # deterministic parts only
uv run sreadvisor analyze --config config/petclinic.yaml --gaps                # Stage 1 + 2 + 3 in one run
```

For every requirement of every module that applies to the service (the same matching as the Stage 2 report), an ADK agent
(`gap_assessor`, model via `model_provider`) judges **met / partially_met / missing** against the dataset. Around that judgment everything is deterministic:

* the model sees only the slice of the dataset named by the entry's `stage1_paths` (list items keep name, kind and `file:line`; absence is shown as null or `[]`), so cost scales with the number of requirements, not dataset size; its one tool queries the dataset, nothing else;
* **`not_assessable`** is a fourth status and is never a gap: requirements verified only from runtime telemetry or manual review, and requirements whose Stage 1 step was skipped or failed (absence cannot be inferred from a step that did not run);
* every citation is checked against the dataset (unknown files, lines and paths are dropped; a dataset path is resolved to its `file:line`); a "met" without a valid citation is not accepted; the verdict must agree with what the model cited as satisfied or falling short (a contradiction is put back to the model once, naming the exact problem, rather than silently overridden);
* every **met** verdict is re-checked once more, adversarially: the model is asked to try to disprove its own answer against every instance and every clause of the pass criteria (`registry.analysis.gap.verify_met`, on by default). A cited, groundable shortfall downgrades the verdict; a disagreement with no citation leaves it met but lowers confidence and is recorded as a warning. This exists because a false "met" hides a real gap, which is worse than a false "missing".

Output (`<service>.gaps.json`, ready for the Stage 4 report generator):

| Section | Contents |
|---|---|
| `gaps` | Ordinary NFR gaps, ordered by priority then missing before partial. Each has the NFR (requirement, best practice, audit requirement, pass criteria), `why`, and `evidence`: `found` (with `file:line`, and whether each citation shows the requirement `satisfied` or a `shortfall`), `not_found`, `examined_paths`, `examined_locations`, and the Stage 1 steps behind it |
| `unrecognized_tech_gaps` | Technology in the code or infrastructure with no matching module in the Master NFR List (`gap_type: unrecognized_tech_stack`, `highlight: true`), kept separate from `gaps` for Stage 4 to show as its own item |
| `assessments` | The verdict on every applicable requirement, including met and not_assessable, for traceability |
| `summary`, `modules`, `warnings`, `inputs` | Counts, per-module results, anything the model got wrong or could not do, and exactly what was used as input |

## Stage 4: unified report, SLI suggestions and the Dynatrace dashboard

Inputs are the Stage 1 dataset and the Stage 3 gap report; nothing else (no LLM call, no network access — Stage 4 only recombines
facts the earlier stages already judged).

```
uv run sreadvisor report --dataset output/spring-petclinic.dataset.json --gaps output/spring-petclinic.gaps.json
uv run sreadvisor analyze --config config/petclinic.yaml --report          # Stage 1 + 3 + 4 in one run (implies --gaps)
```

Output, next to the dataset:

| File | Contents |
|---|---|
| `<service>.unified-report.json` | The combined document: `schema.UnifiedReport`, in the same pydantic/JSON style as every other stage's output, so a consumer that already reads the dataset or the gap report reads this one too |
| `<service>.unified-report.html` | The same report rendered as one self-contained page (inline CSS only, no external requests) that an SRE or developer opens directly in a browser |
| `<service>.dynatrace-dashboard.json` | An importable Dynatrace dashboard (classic Dashboards config schema: `dashboardMetadata` + `tiles`) covering the tier 1 SLIs |

What the unified report combines:

* **tech stack and transaction flow** — the Stage 1 fingerprint and traced flows, embedded directly (`schema.dataset.TechStackFingerprint`, `TransactionFlow`), plus dependency highlights by category and an infrastructure-object count;
* **action items** — every Stage 3 gap, unchanged, plus one new field: `action`, a single always-grammatical instruction ("Fix: ..." / "Complete: ..." — never a re-conjugated finding, since a few requirement titles are phrased as prohibitions) naming the affected files. `ActionItem` is literally `Gap` plus that field, so nothing about the evidence, rationale or NFR context is duplicated or reshaped;
* **unrecognized tech stack gaps** — carried through unchanged from Stage 3 and rendered as their own highlighted section in the HTML, never mixed into the ordinary action items;
* **SLI suggestions** — deterministic, table-driven (`report/sli.py`): latency and error rate for every entry point (tier 1), plus one dependency-driven SLI per distinct dependency seen in a traced flow (datastore call latency, cache hit ratio or call latency, **Kafka consumer lag** when the client library exposes it — tier 2, never a OneAgent default), plus business-aware metrics (tier 3) from a lookup table keyed by the inferred business category (shopping cart, order management, notification, ...), with a generic fallback built from the service's own key operations when the category has no table entry;
* **the three telemetry tiers**, unchanged from Stage 2, so the report can show — separately labelled — what OneAgent already gives for free, what the application's own libraries already emit, and what still needs new instrumentation.

The Dynatrace dashboard only turns a tier 1 SLI into a chart tile when the OneAgent catalogue gives it a real `builtin:` metric key;
everything else (tier 2, tier 3, and the handful of tier 1 signals whose key is not yet confirmed) becomes a Markdown tile naming the
metric and its source instead of fabricating a selector that would either be wrong or permanently empty. **Not validated against a
live tenant:** confirm every metric key against the target environment before relying on the generated dashboard, the same caveat the
OneAgent catalogue itself carries.

## Stage 5: observability provider integration (Dynatrace first)

Pulls a service's live Smartscape topology and already-collected metrics from Dynatrace, normalizes both into the
common runtime schema (`schema/runtime.py`), and cross-validates the topology against the dependencies Stage 1 found
in code and infra: any dependency the platform shows that the code/infra analysis did not find (and vice versa) is
flagged as structured data, ready to extend Stage 6's gap analysis.

```
uv run sreadvisor runtime --dataset output/<service>.dataset.json                 # writes <service>.runtime-cross-validation.json
uv run sreadvisor runtime --dataset ... --service-id SERVICE-XXXX --from-time now-7d --out DIR
```

The dataset's own `observability` binding names the provider and service id (`--service-id` overrides just the id,
for example to point at whichever real service happens to exist in a trial tenant); the API token is resolved fresh
from its named environment variable at call time (never read from, or written to, the dataset).

**Retrieval goes through an MCP server, not a hand-rolled REST client**, per the brief: no usable Dynatrace MCP
server could run in this environment (the official one is an npm package, and this project has no Node.js/npx), so,
following the project's own fallback rule ("if a suitable MCP server does not already exist, build a thin one"),
`mcp_servers/dynatrace_server.py` is a small Python MCP server (built on the `mcp` SDK already declared as a
dependency) with two tools, `get_smartscape_topology` and `get_service_metrics`; every Dynatrace REST call in the
whole codebase happens inside it. `DynatraceProvider.get_topology()`/`get_metrics()` are an ordinary MCP client
calling that same server directly (no LLM judgment is needed to fetch one named service's data); `mcp_toolset()`
registers the identical server so an ADK `LlmAgent` can call it the same way later (Stage 6).

Cross-validation (`runtime/cross_validate.py`) compares Stage 1's traced `FlowDependency` list against the
topology's **outbound** dependency-like edges only (the pilot service is the caller) — an inbound caller is never
something the service's own code could have declared as "a dependency of mine", so it is excluded from the
comparison entirely rather than reported as a guaranteed, meaningless mismatch. A dependency-like edge is one to a
neighbor whose kind is a service, database, cache, queue or external service; a structural relationship (runs on
this host, is an instance of this process group, ...) is still returned in the full topology but never compared.
Matching is by shared name tokens, with a kind-compatible match (for example a `datastore` code dependency against a
`database` topology node) recorded at higher confidence than a name-only one.

**Tested against a real Dynatrace SaaS trial tenant** (`playground.live.dynatrace.com`), live, before moving on.
Neither Pet Clinic nor the earlier `adservice` sample exists there, so the pilot service for this stage is
`astroshop-cart` from the OpenTelemetry Astronomy Shop demo, which the tenant does have deployed; a small hand-built
Stage 1-like dataset stands in for a real Stage 1 run against that service's own repository. Two live runs, against
the real API with a real personal token, produced all three outcomes: a genuine **runtime-only** dependency
(`astroshop-flagd`, a feature-flag service call the hand-built dataset never declared — precisely the "transient or
undocumented dependency" scenario the brief describes), a **code-only** dependency (a fictional
`legacy-inventory-service` the live topology correctly shows nothing about), and, once the dataset declared `flagd`
correctly, a **matched** dependency at high confidence. The live tenant also exercised the graceful-degradation path
for real: four structural neighbor entities (a `CLOUD_APPLICATION`, a `KUBERNETES_CLUSTER`, and others) returned 400
from the entity-detail endpoint, and came back as nodes with a recorded `resolution_error` instead of failing the
whole pull.

## Stage 6: Gap Analysis Pass 2, FMEA and the operations runbook

Three generators, each building on the last: Pass 2 folds Stage 5's runtime cross-validation into Gap Analysis;
FMEA reasons about failure modes from the architecture Stage 1 and Stage 5 already captured; the runbook turns
each FMEA finding into something an on-call engineer can act on.

```
uv run sreadvisor gaps --dataset output/<service>.dataset.json --runtime output/<service>.runtime-cross-validation.json
                                                                    # Pass 2 instead of Pass 1; same output path/shape
uv run sreadvisor fmea --dataset output/<service>.dataset.json --gaps output/<service>.gaps.json \
    --runtime output/<service>.runtime-cross-validation.json       # --gaps and --runtime are both optional
uv run sreadvisor runbook --dataset output/<service>.dataset.json --fmea output/<service>.fmea.json \
    --report output/<service>.unified-report.json                 # --report is optional, reuses its SLIs as detection signals
```

### Gap Analysis Pass 2 (`gap/pass2.py`, `runtime/observed.py`)

`GapAnalysisPass2` subclasses `GapAnalysisPass1` and calls it first, unchanged — Pass 2 is Pass 1 plus two things
only runtime data makes possible, merged into one `GapReport` (`gap_analysis_pass_2`) with every `Assessment` and
`Gap` carrying a new field, `detection_source`: `code_and_infra` (Pass 1 alone would have produced this) or
`runtime` (Stage 5's data changed the verdict, or the finding has no code/infra counterpart at all).

1. **Re-examining a requirement with live evidence added.** A handful of Master NFR List entries have a genuine
   *runtime-observable dimension* — a claim code/config makes that a live platform can independently confirm or
   contradict. `runtime/observed.py`'s `RUNTIME_CHECKS` registry is the extension point ("apply the same logic
   wherever observability data can confirm or contradict a claim" is this dict, not a fixed pair of special cases);
   it ships with two, matching the brief's own examples, both newly marked with `runtime_telemetry` as a verification
   source in the Master NFR List: **ENC-002/ENC-004** (a service-to-service or database/cache call claimed to use
   TLS is checked against the live topology's own `remoteEndpoint` for each dependency-like edge — a bare
   `http://`/`ws://`/`ftp://` scheme, or a `jdbc:` URL with `sslmode=disable`/`ssl=false`, is a plaintext observation;
   `grpc://` and a bare `jdbc:` URL with no ssl parameter are left **inconclusive** rather than guessed, since neither
   scheme says anything about TLS on its own — no evidence, no re-check, Pass 1's verdict stands), and **CAP-002**
   (an autoscaler's declared policy is checked against a replica-count metric series, when the provider returned one
   as real timestamped samples rather than a single aggregate — `MetricSeries.samples`, new in the common runtime
   schema — a constant value across the window is evidence the policy was never observed triggering). When evidence
   exists, it is appended to Pass 1's own prompt (the *same* `gap_assessor` agent, not a second judge) and the model
   re-assesses with both the dataset and the live observation in view; a verdict that does not change stays tagged
   `code_and_infra` (the live data corroborated what code already showed, it did not newly reveal anything).
2. **Undocumented dependency, no resilience pattern.** The brief's own worked example: for every dependency in Stage
   5's `runtime_only` list (something the platform saw live that no repository's code ever declared), a
   deterministic check (no LLM: a name-token match, the same comparison `cross_validate` itself uses) asks whether
   any reliability pattern's `protects` field names it. If none does, that is a new `DC-001` gap Pass 1 could never
   have produced, since it never knew the dependency existed.

### FMEA (`fmea/`)

One LLM call per major component — a Stage 1 `DependencyClassification` (falls back to raw traced dependencies when
that step never ran) plus, when given, every Stage 5 `runtime_only` dependency, deduplicated by name, each carrying
its own `origin: code_and_infra | runtime_only` through to the final report. The agent (`fmea_analyst`) is reasoned
**from architecture, not incident history** — it never sees or is asked to fabricate a past incident, only what the
dependency is, its Stage 1 hard-failure/degradable classification and blast radius, its existing protecting
patterns, which flows use it, and the service's business purpose. For each component it identifies 1–4 distinct
plausible failure modes, their likely cause, effect on the transaction flow, and a severity, each optionally
cross-referenced (by the same name-token match) to a related gap from the Stage 6 report.

### Operations runbook (`runbook/`)

One entry per FMEA failure mode, **never re-deriving or contradicting** the failure mode, its effect or its
severity — the runbook agent (`runbook_writer`) is asked only for what FMEA does not already determine: detection
signals, an ordered list of immediate actions, and an escalation target and trigger condition. Detection signals
prefer real, already-designed telemetry over an invented one: any Stage 4 SLI suggestion whose subject overlaps the
component's name is handed to the model as a known signal to name (and kept in the output even if the model's own
answer omits it), with the model adding further, more failure-mode-specific signals on top. Output is both JSON
(`<service>.runbook.json`, for other tooling) and Markdown (`<service>.runbook.md`, grouped by severity — the
brief's own words: "a runbook the operations team can use during a live failure").

### End to end against the pilot service

Stage 1 through Stage 4's existing Pet Clinic artifacts were reused unchanged as input (`output/spring-petclinic.*`,
generated in earlier stages with real Ollama/`gemma4` reasoning: 17 traced flows, 2 dependency classifications, 4
reliability patterns). Pet Clinic itself is not deployed anywhere Dynatrace can see it, so its Stage 5 runtime layer
for this run is a small, honestly-labelled **synthetic** topology/metrics pair fed through the already-existing
`StaticProvider` (not the live Dynatrace path — that MCP mechanism was already proven live against a real tenant in
Stage 5; see above), declaring three things on purpose: the real MySQL/Postgres connection observed *without* TLS
(`jdbc:mysql://...?useSSL=false`, matching the real Stage 1 finding that the datasource URL has no TLS parameter),
a fictional `notification-email-service` the code never declared (to exercise the undocumented-dependency path), and
nothing at all for the in-process Spring Cache (it correctly has no live network entity to observe).

`sreadvisor runtime` on this synthetic pair produced exactly the three outcomes: **1 matched** (the database, high
confidence), **1 runtime-only** (`notification-email-service`), **1 code-only** (`cache (Spring Cache)` — correctly
never observed live, since an in-process cache has no network presence to see). Running Pass 2 on top of the real
122-requirement Pass 1 assessment then:

* re-examined **ENC-002** and **ENC-004** with the live evidence appended, and the model's own rationale explicitly
  cited it — *"the dataset provides evidence of ... one observed service-to-service call"* (ENC-002); *"the runtime
  observability evidence confirms that the live connection to the MySQL database is insecure"* (ENC-004) — both
  verdicts stayed `missing` (Pet Clinic's code already showed no TLS anywhere; the live data corroborated rather than
  contradicted it), so both stayed tagged `code_and_infra`, exactly as designed;
* correctly **abstained** on `CAP-002` (no autoscaler is declared for Pet Clinic at all, so there is nothing for a
  replica-count series to confirm or contradict — this is the negative path working correctly, not a gap in the
  mechanism);
* added exactly **one new `runtime`-tagged gap**, `DC-001` for `notification-email-service`, with the warning "found
  only through Stage 5 runtime observability; Gap Analysis Pass 1 could not see this dependency" — precisely the
  brief's own worked example.

FMEA then produced **10 failure modes across the 3 components** (2 critical, 6 high, 2 medium), including both
failure modes for the runtime-only dependency; the runbook turned every one into a full entry with detection
signals (several reused verbatim from Stage 4's own SLI suggestions — connection-pool saturation, query latency,
cache hit ratio), a distinct ordered action list per failure mode (for example: restart the database service for a
connection-refused outage, but for silent data corruption, do *not* restart it — fail over to a read replica and
halt writes instead), and a named escalation team and trigger condition. The full six-stage output for the pilot
service is committed under `output/spring-petclinic.*`.

**Known limitation, left as-is rather than over-fitted to one run:** `related_gap_ids` (on both FMEA and runbook
entries) is the same coarse name-token overlap used elsewhere in this project; for a widely-referenced dependency
like a relational database it can list several dozen tangentially related gaps rather than a tight, curated few. It
is offered as a starting cross-reference for a human to narrow, not a precise mapping.

## Web UI

```
uv run sreadvisor ui                 # http://127.0.0.1:8765, opens a browser; --port, --workspace DIR, --no-browser
```

A local page over the same pipeline (no build step, no external assets, works offline). The workspace is the current directory: it reads
and writes `config/` and `output/` there. The server has no authentication and can start analyses and edit the knowledge base, so it
binds to `127.0.0.1` by default.

| Page | What it does |
|---|---|
| **Analyze** | A form for the per-service config (repositories or git URLs, IaC paths, observability provider and service id, run options). Validate names every bad field; Save writes `config/<service>.yaml` (usable with `sreadvisor analyze --config`); Save & run starts a background job. An API token typed here is used for that run only and is never written to disk |
| **Jobs** | Live log of a running analysis or gap analysis, cancel, and a link to the resulting reports. One job runs at a time |
| **Reports** | Every service in `output/`. The gap report: summary, gaps ordered by priority with the reasoning and `file:line` evidence for each, all requirements (including met and not assessable), per-module results, coverage and telemetry tiers, and the dataset facts. **Unrecognized tech stacks are highlighted** and each has an "Add an NFR module for this" button that opens the catalogue with the module form prefilled |
| **NFR catalogue** | Browse and edit the Master NFR List: module settings and detect rules, and every requirement (best practice, audit requirement, monitoring signals, verification with autocompleted Stage 1 dataset paths, module-specific fields). The two telemetry catalogues are shown read-only |

Editing the catalogue changes the YAML sources (the source of truth) and rebuilds the JSON that Stage 3 loads. A save is applied only if the whole
knowledge base validates (schema, references between modules, every dataset path); the previous version is backed up under
`.sreadvisor/nfr_backups/` and can be restored from the History menu; an etag stops a stale page overwriting a hand edit. A new tech-stack module also
gets a placeholder in both telemetry catalogues, marked "Not yet catalogued".

## Adding things

* **A provider (New Relic, Datadog...)**: subclass `ObservabilityProvider`, normalise into `schema/runtime.py`, add a `providers:` entry to the registry.
* **A tech stack**: add a parser to `MANIFEST_PARSERS`, signatures to `signatures.py`, entry-point rules to `graph/entrypoints.py`.
* **An output format**: subclass `OutputSink`, add it under `output_sinks:` in the registry.
* **An MCP integration**: register an `MCPToolset` (see `DynatraceProvider.mcp_toolset`); if no usable MCP server exists for it, build a thin one under `mcp_servers/` (see `mcp_servers/dynatrace_server.py`) rather than a hand-rolled REST client.
* **A runtime-observable NFR check** (Stage 6): add one entry to `runtime.observed.RUNTIME_CHECKS` (an NFR id -> a function building live evidence text, or `None` when nothing usable was observed) and mark the entry's `sources` in the Master NFR List YAML with `runtime_telemetry`; Gap Analysis Pass 2 picks it up automatically.
* **A business-aware SLI suggestion**: add a category to `report/sli.py`'s `BUSINESS_SLI_TABLE` (or rely on the generic key-operations fallback for a category not yet in the table).

## Tests

`uv run pytest` (no LLM or network needed).
