"""Report output: NFR coverage JSON (for Stage 3/4) plus a readable Markdown report.

The report is where the feedback loop surfaces: technologies found in the service that have no module in the
Master NFR List are listed explicitly under "Unrecognized tech stacks", and the three telemetry tiers are shown side by side.
"""

from __future__ import annotations

import re
from pathlib import Path

from sreadvisor.nfr.coverage import NfrCoverage, compute_coverage
from sreadvisor.nfr.loader import load_app_catalogue, load_master, load_oneagent
from sreadvisor.schema.dataset import ServiceDataset
from sreadvisor.sinks.base import OutputSink


def _cell(text: object) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def render_markdown(ds: ServiceDataset, cov: NfrCoverage) -> str:
    out: list[str] = [f"# NFR coverage report: {ds.service_name}", ""]
    out.append(f"Generated {cov.generated_at:%Y-%m-%d %H:%M UTC}. Dataset schema {cov.dataset_schema_version}, "
               f"Master NFR List schema {cov.kb_schema_version}.")
    if ds.business_context:
        b = ds.business_context
        out += ["", f"**Business context:** {b.capability} ({b.category}, {b.confidence} confidence)."]
    c = ds.completeness
    out += ["", f"**Stage 1 completeness:** {c.get('summary', 'n/a')}."]

    # -- unrecognized (feedback loop)
    out += ["", "## Unrecognized tech stacks requiring NFR coverage", ""]
    if not cov.unrecognized_tech_stacks:
        out.append("None. Every technology found in the fingerprint has a module in the Master NFR List.")
    else:
        out.append(f"{len(cov.unrecognized_tech_stacks)} technology item(s) were found that no module in the Master NFR List covers. "
                   "They are not skipped silently: review each and add an NFR module (or a `recognizes` rule if an existing module already covers it).")
        out += ["", "| Kind | Technology | Found as | Evidence |", "|---|---|---|---|"]
        for u in cov.unrecognized_tech_stacks:
            ev = ", ".join(f"{e.file}{':' + str(e.line) if e.line else ''}" for e in u.evidence[:2]) or "-"
            out.append(f"| {_cell(u.kind)} | {_cell(u.name)} | {_cell(u.detail)} | {_cell(ev)} |")

    # -- applicable modules
    out += ["", "## Applicable NFR modules", "",
            f"{len(cov.applicable_modules)} of {len(cov.applicable_modules) + len(cov.modules_not_applicable)} modules apply "
            f"({cov.applicable_entry_count} requirements). Evaluation against the Stage 1 dataset happens in Stage 3.", "",
            "| Module | Layer | Why it applies | Requirements |", "|---|---|---|---|"]
    for m in cov.applicable_modules:
        pr = ", ".join(f"{n} {p}" for p, n in sorted(m.entries_by_priority.items(), key=lambda kv: ["critical", "high", "medium", "low"].index(kv[0])))
        out.append(f"| {_cell(m.title)} (`{m.id}`) | {m.layer} | {_cell('; '.join(m.matched_by[:3]))} | {m.entry_count} ({pr}) |")
    if cov.modules_not_applicable:
        out += ["", "Not applicable to this service: " + ", ".join(f"`{m}`" for m in cov.modules_not_applicable) + "."]

    # -- telemetry tiers
    t = cov.telemetry_tiers
    out += ["", "## Telemetry tiers", "", f"> {t.overlap_policy.strip()}", ""]
    t1 = t.tier1_oneagent_default
    out += ["### Tier 1: Dynatrace OneAgent default (out of the box)", "",
            "Captured with zero configuration. Tagged `oneagent_default`.", "",
            "| Module | OneAgent support |", "|---|---|"]
    out += [f"| `{m.module}` | {m.support_level}: {_cell(m.summary)} |" for m in t1.modules]
    out += ["", "| Signal | Category | Type | Metric key | Via |", "|---|---|---|---|---|"]
    for s in t1.signals:
        sg = s.signal
        via = "every monitored service" if "oneagent_platform" in s.applies_via else ", ".join(s.applies_via[:4]) + (
            f" +{len(s.applies_via) - 4}" if len(s.applies_via) > 4 else "")
        out.append(f"| {_cell(sg.name)} | {sg.category} | {sg.signal_type} | {_cell(sg.metric_key or '-')} | {_cell(via)} |")
    if t1.not_covered_by_default:
        out += ["", "Not covered by default (candidates for tier 2 or 3), by likely source:"]
        for source in ("library_emitted", "custom_instrumentation", "extension", "other_integration"):
            items = [g for g in t1.not_covered_by_default if g.item.likely_source == source]
            if items:
                out += ["", f"*{source}*", ""]
                out += [f"- **{_cell(g.item.signal)}**: {_cell(g.item.why)}" for g in items]

    t2 = t.tier2_application_library
    out += ["", "### Tier 2: application level, library emitted", "",
            "Emitted by the application itself. Tagged `application_level_library_emitted`. Distinct from tier 1; never assumed to overlap.", ""]
    if not t2.detected_in_service:
        out.append("No metric-emitting instrumentation library was detected in this service.")
    for d in t2.detected_in_service:
        out += [f"**{d.library}** (`{d.library_id}`, module `{d.module}`), detected because {d.detected_because}.", "",
                f"- Configuration: {d.configuration}", f"- Export: {d.export}"]
        if d.configuration_found:
            out.append("- Found in the service: " + "; ".join(f"`{x.get('key')}={x.get('value')}`" for x in d.configuration_found[:6]))
        if d.metrics:
            out.append("- Metrics: " + ", ".join(f"`{m.name}`" for m in d.metrics))
        if d.custom_metrics_found:
            out.append("- Custom metrics defined in code: " + ", ".join(f"`{m['name']}`" for m in d.custom_metrics_found))
        out.append("")
    if t2.available_not_detected:
        out += ["Available if added (not detected here): " + "; ".join(
            f"{a.library} ({len(a.metric_names)} metrics)" for a in t2.available_not_detected) + "."]

    t3 = t.tier3_custom_instrumentation
    out += ["", "### Tier 3: business-aware custom instrumentation", "",
            f"Status: {t3.status}. {t3.note}", ""]
    if t3.business_capability:
        out.append(f"- Capability: {t3.business_capability} ({t3.business_category})")
        out.append("- Key operations: " + (", ".join(t3.key_operations) or "-"))
        out.append("- Domain entities: " + (", ".join(t3.domain_entities) or "-"))
    return "\n".join(out) + "\n"


class NfrReportSink(OutputSink):
    """Writes ``<service>.nfr-coverage.json`` and ``<service>.report.md`` next to the dataset."""

    name = "nfr_report"

    def __init__(self, master_list: str | None = None, oneagent_catalogue: str | None = None,
                 app_catalogue: str | None = None) -> None:
        self.paths = (master_list, oneagent_catalogue, app_catalogue)

    def emit(self, dataset: ServiceDataset, out_dir: Path) -> str:
        master, oneagent, app = self.paths
        cov = compute_coverage(dataset, load_master(master), load_oneagent(oneagent), load_app_catalogue(app))
        out_dir.mkdir(parents=True, exist_ok=True)
        safe = re.sub(r"[^A-Za-z0-9_.-]+", "-", dataset.service_name).strip("-") or "service"
        cov_path, md_path = out_dir / f"{safe}.nfr-coverage.json", out_dir / f"{safe}.report.md"
        cov_path.write_text(cov.model_dump_json(indent=2, exclude_none=True), encoding="utf-8")
        md_path.write_text(render_markdown(dataset, cov), encoding="utf-8")
        if cov.unrecognized_tech_stacks:
            print(f"\nUnrecognized tech stacks requiring NFR coverage ({len(cov.unrecognized_tech_stacks)}):")
            for u in cov.unrecognized_tech_stacks:
                print(f"  ! {u.kind}: {u.name} ({u.detail})")
        return f"{md_path}\nWrote {cov_path}"
