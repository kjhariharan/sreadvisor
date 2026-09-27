"""Renders a :class:`~sreadvisor.report.schema.UnifiedReport` as one self-contained HTML file: inline CSS only, no
external stylesheets, fonts or scripts, so it opens directly from disk in any browser. Every dynamic value is HTML
escaped before insertion; nothing here trusts dataset text, LLM output or repository names not to contain markup.
"""

from __future__ import annotations

import html as _html

from sreadvisor.gap.schema import FindingEvidence
from sreadvisor.report.schema import ActionItem, RepoSummary, SliSuggestion, UnifiedReport
from sreadvisor.schema.dataset import EntryPoint, TransactionFlow

_PRIORITY_ORDER = ("critical", "high", "medium", "low")
_TIER_LABELS = {1: "Tier 1 — OneAgent default", 2: "Tier 2 — application level, library emitted", 3: "Tier 3 — business-aware custom"}


def esc(value: object) -> str:
    return _html.escape("" if value is None else str(value), quote=True)


def _join(items: list[str], sep: str = "") -> str:
    return sep.join(items)


def _badge(text: object, css_class: str) -> str:
    return f'<span class="badge {esc(css_class)}">{esc(text)}</span>'


def _priority_badge(p: str) -> str:
    return _badge(p, f"prio-{p}")


def _status_badge(s: str) -> str:
    return _badge(s.replace("_", " "), f"status-{s}")


def _tier_badge(tier: int) -> str:
    return _badge(f"tier {tier}", f"tier-{tier}")


# ------------------------------------------------------------------------------------------------ header


def _header(report: UnifiedReport) -> str:
    b = report.business_context
    business = (
        f'<p class="business">{esc(b.capability)} '
        f'<span class="muted">({esc(b.category)}, {esc(b.confidence)} confidence)</span></p>'
        if b else '<p class="muted">Business purpose was not inferred for this service.</p>'
    )
    completeness = esc(report.completeness.get("summary", "not available"))
    return f"""
<header>
  <h1>{esc(report.service_name)}</h1>
  <p class="subtitle">SRE readiness report &middot; generated {esc(report.generated_at.strftime('%Y-%m-%d %H:%M UTC'))}</p>
  {business}
  <p class="muted">Stage 1 completeness: {completeness}</p>
  <nav class="toc">
    <a href="#unrecognized">Unrecognized tech stacks</a>
    <a href="#action-items">Action items</a>
    <a href="#tech-stack">Tech stack &amp; transaction flow</a>
    <a href="#telemetry">Telemetry tiers</a>
    <a href="#slis">SLI suggestions</a>
  </nav>
</header>
"""


# ------------------------------------------------------------------------------------ unrecognized tech (highlight)


def _unrecognized_section(report: UnifiedReport) -> str:
    items = report.unrecognized_tech_gaps
    if not items:
        return (
            '<section id="unrecognized"><h2>Unrecognized tech stacks</h2>'
            '<p class="ok">None. Every technology found in the fingerprint has a module in the Master NFR List.</p></section>'
        )
    rows = []
    for u in items:
        ev = ", ".join(f"{esc(e.file)}{f':{e.line}' if e.line else ''}" for e in u.evidence[:4]) or "-"
        rows.append(f"""
      <div class="unrec-card">
        <div class="unrec-head">{_badge(u.kind, 'kind')} <b>{esc(u.name)}</b></div>
        <p><b>Found as:</b> {esc(u.found_as)}</p>
        <p><b>Evidence:</b> {ev}</p>
        <p><b>Impact:</b> {esc(u.impact)}</p>
        <p><b>Recommended action:</b> {esc(u.recommended_action)}</p>
      </div>""")
    return f"""
<section id="unrecognized" class="highlight">
  <h2>&#9888; {len(items)} unrecognized tech stack{'s' if len(items) != 1 else ''} — needs Master NFR List coverage</h2>
  <p>No module in the Master NFR List covers these technologies, so their own requirements were not assessed; the
     service was only checked against the baseline and cross-cutting modules for them. This is a gap in the
     knowledge base, not necessarily in the service.</p>
  {_join(rows)}
</section>
"""


# --------------------------------------------------------------------------------------------- action items


def _evidence_html(ev: FindingEvidence) -> str:
    parts = []
    if ev.found:
        items = []
        for f in ev.found:
            loc = f"{esc(f.file)}{f':{f.line}' if f.line else ''}" if f.file else (esc(f.path) if f.path else "")
            shows = _badge(f.shows, f"shows-{f.shows}") if f.shows else ""
            items.append(f"<li>{shows} <code>{loc}</code> {esc(f.note)}</li>")
        parts.append(f"<p><b>Evidence found:</b></p><ul class=\"evidence\">{_join(items)}</ul>")
    if ev.not_found:
        parts.append("<p><b>Expected but not found:</b></p><ul>" + _join(f"<li>{esc(n)}</li>" for n in ev.not_found) + "</ul>")
    if ev.stage1_steps:
        chips = _join(f'<span class="chip">{esc(k)}: {esc(v)}</span>' for k, v in ev.stage1_steps.items())
        parts.append(f'<p class="muted small">Stage 1 steps checked: {chips}</p>')
    return _join(parts)


def _action_item_html(a: ActionItem) -> str:
    audit = f'<p><b>Audit requirement:</b> {esc(a.nfr.audit_requirement)}</p>' if a.nfr.audit_requirement else ""
    warn = (
        '<p class="warn">' + _join(f'&#9888; {esc(w)}<br>' for w in a.warnings) + '</p>' if a.warnings else ""
    )
    return f"""
    <details class="action-item" open>
      <summary>
        {_priority_badge(a.priority)} {_status_badge(a.status)}
        <span class="action-text">{esc(a.action)}</span>
        <span class="muted small nfr-id">{esc(a.nfr.id)} &middot; {esc(a.nfr.module_title)}</span>
      </summary>
      <div class="action-body">
        <p><b>Why this is a gap:</b> {esc(a.why)}</p>
        <p><b>Requirement:</b> {esc(a.nfr.requirement)}</p>
        <p><b>Best practice:</b> {esc(a.nfr.best_practice)}</p>
        {audit}
        {_evidence_html(a.evidence)}
        {warn}
      </div>
    </details>"""


def _action_items_section(report: UnifiedReport) -> str:
    s = report.action_item_summary
    counts = f"""
    <div class="stat-row">
      <div class="stat"><span class="n">{s.applicable_requirements}</span><span class="l">applicable requirements</span></div>
      <div class="stat"><span class="n">{s.gap_count}</span><span class="l">action items</span></div>
      <div class="stat"><span class="n">{s.by_status.get('met', 0)}</span><span class="l">met</span></div>
      <div class="stat"><span class="n">{s.by_status.get('not_assessable', 0)}</span><span class="l">not assessable</span></div>
    </div>
    <p class="muted">Gaps by priority: {
        ', '.join(f'{_priority_badge(p)} {s.gaps_by_priority.get(p, 0)}' for p in _PRIORITY_ORDER)
    }</p>"""
    if not report.action_items:
        body = '<p class="ok">No gaps: every applicable requirement is met or not assessable from the dataset alone.</p>'
    else:
        body = _join(_action_item_html(a) for a in report.action_items)
    return f"""
<section id="action-items">
  <h2>Action items ({len(report.action_items)})</h2>
  {counts}
  {body}
</section>
"""


# ------------------------------------------------------------------------------------- tech stack & flows


def _entry_point_line(ep: EntryPoint) -> str:
    route = f"{esc(ep.http_method)} {esc(ep.route)}" if ep.http_method or ep.route else esc(ep.symbol)
    return f'<li>{_badge(ep.kind, "kind")} <code>{route}</code> <span class="muted small">{esc(ep.symbol)}</span></li>'


def _flow_html(flow: TransactionFlow) -> str:
    steps = _join(
        f'<li>{_badge(s.layer, "layer")} <b>{esc(s.symbol)}</b> — {esc(s.action)}'
        f'{f" &rarr; <i>{esc(s.target_name)}</i>" if s.target_name else ""}</li>'
        for s in flow.steps
    )
    deps = (
        "<p><b>Dependencies:</b> " + _join(f'<span class="chip">{esc(d.kind)}: {esc(d.name)}</span>' for d in flow.dependencies) + "</p>"
        if flow.dependencies else ""
    )
    ep = flow.entry_point
    subject = f"{esc(ep.http_method)} {esc(ep.route)}" if ep.http_method or ep.route else esc(ep.symbol)
    return f"""
    <details class="flow">
      <summary>{_badge(ep.kind, "kind")} <code>{subject}</code></summary>
      <div class="flow-body">
        <p class="muted">{esc(flow.summary)}</p>
        <ol class="steps">{steps}</ol>
        {deps}
      </div>
    </details>"""


def _repo_html(r: RepoSummary) -> str:
    fp = r.fingerprint
    frameworks = ", ".join(f"{f.name} {f.version or ''}".strip() for f in fp.frameworks) or "-"
    runtimes = ", ".join(f"{k} {v}" for k, v in fp.runtime_versions.items()) or "-"
    highlights = (
        _join(
            f'<span class="chip">{esc(cat)}: {esc(", ".join(coords[:4]))}{" ..." if len(coords) > 4 else ""}</span>'
            for cat, coords in r.dependency_highlights.items()
        )
        or "-"
    )
    eps = _join(_entry_point_line(e) for e in r.entry_points) or "<li class=\"muted\">none detected</li>"
    flows = _join(_flow_html(f) for f in r.transaction_flows) or '<p class="muted">No transaction flows traced.</p>'
    return f"""
  <div class="repo-card">
    <h3>{esc(r.repo)}</h3>
    <dl class="kv">
      <dt>Languages</dt><dd>{esc(', '.join(fp.languages) or '-')}</dd>
      <dt>Frameworks</dt><dd>{esc(frameworks)}</dd>
      <dt>Build tools</dt><dd>{esc(', '.join(fp.build_tools) or '-')}</dd>
      <dt>Runtime</dt><dd>{esc(runtimes)}</dd>
      <dt>Dependencies</dt><dd>{len(fp.dependencies)} ({highlights})</dd>
    </dl>
    <h4>Entry points ({len(r.entry_points)})</h4>
    <ul class="entry-points">{eps}</ul>
    <h4>Transaction flows ({len(r.transaction_flows)})</h4>
    {flows}
  </div>"""


def _tech_stack_section(report: UnifiedReport) -> str:
    i = report.infrastructure
    infra_chips = _join(
        f'<span class="chip">{esc(k.replace("_", " "))}: {esc(v)}</span>'
        for k, v in i.model_dump().items() if v not in (0, False)
    ) or '<span class="muted">no infrastructure-as-code analysed</span>'
    return f"""
<section id="tech-stack">
  <h2>Tech stack &amp; transaction flow</h2>
  <p><b>Infrastructure:</b> {infra_chips}</p>
  {_join(_repo_html(r) for r in report.tech_stack)}
</section>
"""


# ------------------------------------------------------------------------------------------- telemetry tiers


def _telemetry_section(report: UnifiedReport) -> str:
    t = report.telemetry_tiers
    t1, t2, t3 = t.tier1_oneagent_default, t.tier2_application_library, t.tier3_custom_instrumentation
    tier1_rows = _join(
        f"<tr><td>{esc(s.signal.name)}</td><td>{esc(s.signal.category)}</td><td>{esc(s.signal.signal_type)}</td>"
        f"<td><code>{esc(s.signal.metric_key or '-')}</code></td></tr>"
        for s in t1.signals if s.signal.signal_type == "metric"
    )
    tier2_cards = _join(f"""
      <div class="lib-card">
        <b>{esc(d.library)}</b> <span class="muted small">({esc(d.module)})</span>
        <p class="muted small">{esc(d.detected_because)}</p>
        <p class="small">Metrics: {esc(', '.join(m.name for m in d.metrics)) or '-'}</p>
      </div>""" for d in t2.detected_in_service) or '<p class="muted">No metric-emitting instrumentation library was detected.</p>'
    tier3_items = (
        "<ul>" + _join(f"<li>{esc(op)}</li>" for op in t3.key_operations) + "</ul>" if t3.key_operations else '<p class="muted">No key operations inferred.</p>'
    )
    return f"""
<section id="telemetry">
  <h2>Telemetry tiers</h2>
  <p class="muted small">{esc(t.overlap_policy)}</p>

  <h3>{esc(_TIER_LABELS[1])}</h3>
  <p class="small">Captured with zero configuration once the service is monitored.</p>
  <div class="table-scroll"><table class="data"><thead><tr><th>Signal</th><th>Category</th><th>Type</th><th>Metric key</th></tr></thead>
  <tbody>{tier1_rows}</tbody></table></div>

  <h3>{esc(_TIER_LABELS[2])}</h3>
  <p class="small">Emitted by the application's own instrumentation libraries; never assumed to overlap tier 1.</p>
  {tier2_cards}

  <h3>{esc(_TIER_LABELS[3])}</h3>
  <p class="small">Business-aware metrics proposed from the inferred purpose below; see the SLI suggestions for concrete names.</p>
  {tier3_items}
</section>
"""


# ------------------------------------------------------------------------------------------------------- SLIs


def _sli_row(s: SliSuggestion) -> str:
    key = f"<code>{esc(s.metric_key)}</code>" if s.metric_key else '<span class="muted">-</span>'
    return f"""<tr>
      <td>{_tier_badge(s.tier)}</td><td>{esc(s.name)}</td><td>{_badge(s.kind.replace('_', ' '), f'kind-{s.kind}')}</td>
      <td>{esc(s.subject)}</td><td>{esc(s.measurement_source)}</td><td>{key}</td>
    </tr>"""


def _slis_section(report: UnifiedReport) -> str:
    if not report.sli_suggestions:
        body = '<p class="muted">No SLIs could be suggested (no entry points, dependencies or business context found).</p>'
    else:
        rows = _join(_sli_row(s) for s in report.sli_suggestions)
        body = f"""<div class="table-scroll"><table class="data">
      <thead><tr><th>Tier</th><th>SLI</th><th>Kind</th><th>Subject</th><th>Measurement source</th><th>Metric key</th></tr></thead>
      <tbody>{rows}</tbody>
    </table></div>"""
    return f"""
<section id="slis">
  <h2>SLI suggestions ({len(report.sli_suggestions)})</h2>
  <p class="muted small">Tier 1 signals need no configuration; tier 2 requires the library's metrics to be exported to the
     observability platform; tier 3 needs new custom instrumentation. See the generated Dynatrace dashboard for an
     importable starting point.</p>
  {body}
</section>
"""


# ------------------------------------------------------------------------------------------------------- footer


def _footer(report: UnifiedReport) -> str:
    warnings = ("<ul>" + _join(f"<li>{esc(w)}</li>" for w in report.warnings) + "</ul>") if report.warnings else '<p class="ok">none</p>'
    return f"""
<footer>
  <h2>Provenance</h2>
  <dl class="kv">
    <dt>Dataset</dt><dd>{esc(report.inputs['dataset']['service_name'])}, schema {esc(report.inputs['dataset']['schema_version'])},
      generated {esc(report.inputs['dataset']['generated_at'])}, model {esc(report.inputs['dataset']['model_backend'])}</dd>
    <dt>Gap analysis</dt><dd>generated {esc(report.inputs['gap_report']['generated_at'])},
      assessor {esc(report.inputs['gap_report']['assessor_model'])}</dd>
  </dl>
  <h3>Warnings</h3>
  {warnings}
  <p class="muted small">Generated by sreadvisor. This page makes no network requests and loads no external resources.</p>
</footer>
"""


_STYLE = """
:root { --bg:#f6f7f9; --panel:#fff; --panel-2:#f1f3f6; --text:#1a2233; --muted:#5b667a; --border:#dde2ea;
  --accent:#4f46e5; --ok:#15803d; --ok-bg:#e8f6ed; --warn:#a15c07; --warn-bg:#fdf3e0; --bad:#b42318; --bad-bg:#fdecea;
  --na:#566175; --na-bg:#eceff3; --crit:#a31d1d; --high:#b4470c; --med:#8a6a06; --low:#566175; --radius:10px; }
@media (prefers-color-scheme: dark) {
  :root { --bg:#0f131a; --panel:#171c26; --panel-2:#1d2430; --text:#e6eaf2; --muted:#93a0b5; --border:#2b3445;
    --accent:#8b93ff; --ok:#4ade80; --ok-bg:#12301f; --warn:#fbbf24; --warn-bg:#33270d; --bad:#f87171; --bad-bg:#3a1717;
    --na:#a3aec2; --na-bg:#222a38; --crit:#ff8a8a; --high:#ffab7a; --med:#f0d060; --low:#a3aec2; }
}
* { box-sizing:border-box; }
body { margin:0; background:var(--bg); color:var(--text); font:14px/1.55 -apple-system,"Segoe UI",Roboto,Arial,sans-serif; }
h1,h2,h3,h4 { letter-spacing:-.01em; } h1 { font-size:26px;margin:0 0 4px; } h2 { font-size:19px;border-bottom:1px solid var(--border);padding-bottom:6px; }
h3 { font-size:15px;margin-top:20px; } h4 { font-size:13px;color:var(--muted);text-transform:uppercase;letter-spacing:.04em;margin:16px 0 6px; }
code { font-family:ui-monospace,Consolas,monospace; font-size:12.5px; background:var(--panel-2); padding:1px 5px; border-radius:5px; overflow-wrap:anywhere; }
.evidence li,.action-body p,summary { overflow-wrap:anywhere; }
header,section,footer { max-width:1100px; margin:0 auto; padding:24px 20px; }
header { padding-bottom:12px; }
.subtitle,.muted { color:var(--muted); } .small { font-size:12.5px; } .ok { color:var(--ok); } .warn { color:var(--warn); }
.business { font-size:16px; margin:8px 0 4px; }
nav.toc { display:flex; gap:14px; flex-wrap:wrap; margin-top:14px; font-size:13px; }
nav.toc a { color:var(--accent); text-decoration:none; } nav.toc a:hover { text-decoration:underline; }
.badge { display:inline-block; padding:1px 9px; border-radius:999px; font-size:11px; font-weight:700; white-space:nowrap; background:var(--na-bg); color:var(--na); }
.prio-critical,.status-missing,.shows-shortfall { background:var(--bad-bg); color:var(--bad); }
.prio-high { background:#fdeee3; color:var(--high); } .prio-medium,.status-partially_met { background:var(--warn-bg); color:var(--warn); }
.prio-low { background:var(--na-bg); color:var(--low); } .status-met,.shows-satisfied { background:var(--ok-bg); color:var(--ok); }
.status-not_assessable,.kind { background:var(--na-bg); color:var(--na); }
.tier-1 { background:var(--ok-bg); color:var(--ok); } .tier-2 { background:#e7f0fd; color:#1d5fbf; } .tier-3 { background:#f3e8fd; color:#7e22ce; }
.chip { display:inline-block; padding:1px 8px; border-radius:6px; background:var(--panel-2); border:1px solid var(--border); font-size:12px; margin:0 4px 4px 0; }
.highlight { border:2px solid var(--warn); background:var(--warn-bg); border-radius:var(--radius); }
.highlight h2 { border-bottom:none; color:var(--warn); }
.unrec-card { background:var(--panel); border:1px solid var(--border); border-radius:8px; padding:12px 14px; margin:10px 0; }
.unrec-head { margin-bottom:6px; }
.stat-row { display:flex; gap:16px; flex-wrap:wrap; margin:14px 0; }
.stat { background:var(--panel); border:1px solid var(--border); border-radius:8px; padding:10px 16px; min-width:120px; }
.stat .n { display:block; font-size:24px; font-weight:700; } .stat .l { color:var(--muted); font-size:12px; }
details.action-item { background:var(--panel); border:1px solid var(--border); border-radius:9px; margin-bottom:10px; }
details.action-item > summary { padding:10px 14px; cursor:pointer; list-style:none; display:flex; gap:10px; align-items:baseline; flex-wrap:wrap; }
details.action-item > summary::-webkit-details-marker { display:none; }
.action-text { font-weight:600; } .nfr-id { margin-left:auto; }
.action-body { padding:2px 16px 14px; border-top:1px solid var(--border); }
.evidence { list-style:none; margin:0; padding:0; } .evidence li { padding:4px 0; border-bottom:1px dashed var(--border); }
.repo-card { background:var(--panel); border:1px solid var(--border); border-radius:9px; padding:14px 18px; margin-bottom:16px; }
.kv { display:grid; grid-template-columns:150px 1fr; gap:4px 14px; margin:0; } .kv dt { color:var(--muted); font-weight:600; font-size:12.5px; } .kv dd { margin:0; }
ul.entry-points { list-style:none; padding:0; margin:0; } ul.entry-points li { padding:3px 0; }
details.flow { background:var(--panel-2); border:1px solid var(--border); border-radius:8px; margin-bottom:8px; }
details.flow > summary { padding:8px 12px; cursor:pointer; } .flow-body { padding:4px 14px 12px; }
ol.steps { margin:6px 0; padding-left:20px; } ol.steps li { padding:2px 0; }
table.data { width:100%; border-collapse:collapse; margin:10px 0; } table.data th,table.data td { text-align:left; padding:7px 10px; border-bottom:1px solid var(--border); font-size:13px; }
table.data th { color:var(--muted); font-size:11px; text-transform:uppercase; letter-spacing:.04em; background:var(--panel-2); }
.lib-card { background:var(--panel); border:1px solid var(--border); border-radius:8px; padding:10px 14px; margin:8px 0; }
footer { border-top:1px solid var(--border); margin-top:20px; }
.table-scroll { overflow-x:auto; }
@media (max-width:700px) {
  header,section,footer { padding:16px 14px; }
  .kv { grid-template-columns:1fr; }
  nav.toc { gap:8px 12px; }
  .stat-row { gap:10px; } .stat { min-width:100px; padding:8px 12px; }
}
"""


def render_html(report: UnifiedReport) -> str:
    body = "".join([
        _header(report),
        _unrecognized_section(report),
        _action_items_section(report),
        _tech_stack_section(report),
        _telemetry_section(report),
        _slis_section(report),
        _footer(report),
    ])
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(report.service_name)} — SRE readiness report</title>
<style>{_STYLE}</style>
</head>
<body>
{body}
</body>
</html>
"""
