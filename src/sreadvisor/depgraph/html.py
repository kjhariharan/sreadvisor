"""Renders a :class:`~sreadvisor.depgraph.schema.DependencyGraph` as one self-contained HTML file: inline CSS and
one small inline script only, no external stylesheets, fonts or scripts, so it opens directly from disk in any
browser — the same rule ``report/html.py`` follows, and the same ``esc()`` discipline: every dynamic value is HTML
escaped before insertion, nothing here trusts dataset text not to contain markup.

The graph itself is plain SVG in a deterministic radial layout (the service node centered, dependencies arranged
in a circle around it) computed server-side in Python — not a hand-rolled force-directed physics simulation, and
not a JS charting library (none is available without breaking the no-external-resources rule; see the feature's
plan for that trade-off). The one script block does exactly one thing: show the pre-rendered, pre-escaped detail
card for whichever node or edge was clicked. No dynamic HTML is ever built in JS.
"""

from __future__ import annotations

import html as _html
import math

from sreadvisor.depgraph.platform import platform_label
from sreadvisor.depgraph.schema import DependencyGraph, DependencyGraphEdge, DependencyGraphNode

_CENTER = (420, 320)
_SERVICE_R = 40
_NODE_R = 26
_RING_R = 230


def esc(value: object) -> str:
    return _html.escape("" if value is None else str(value), quote=True)


def _badge(text: object, css_class: str) -> str:
    return f'<span class="badge {esc(css_class)}">{esc(text)}</span>'


def _evidence_html(evidence: list) -> str:
    items = [f"<li><code>{esc(e.file)}{f':{e.line}' if e.line else ''}</code></li>" for e in evidence[:6]]
    return f'<ul class="evidence">{"".join(items)}</ul>' if items else '<p class="muted small">no evidence citation</p>'


# --------------------------------------------------------------------------------------------------------- layout


def _positions(n: int) -> list[tuple[float, float]]:
    """One (x, y) per dependency node, evenly spaced on a circle around the service node. n == 0 is handled by the
    caller (nothing to lay out)."""
    cx, cy = _CENTER
    return [(cx + _RING_R * math.cos(2 * math.pi * i / n - math.pi / 2),
            cy + _RING_R * math.sin(2 * math.pi * i / n - math.pi / 2)) for i in range(n)]


# ------------------------------------------------------------------------------------------------------ detail cards


def _node_detail(node: DependencyGraphNode) -> str:
    parts = [f'<h3>{esc(node.name)}</h3>', f'<p>{_badge(node.kind, f"kind-{node.kind}")} '
            f'{_badge("runtime-only", "origin-runtime_only") if node.origin == "runtime_only" else ""}</p>']
    if node.tech_stack:
        t = node.tech_stack
        parts.append(f"""<dl class="kv">
      <dt>Languages</dt><dd>{esc(', '.join(t.languages) or '-')}</dd>
      <dt>Frameworks</dt><dd>{esc(', '.join(t.frameworks) or '-')}</dd>
      <dt>Build tools</dt><dd>{esc(', '.join(t.build_tools) or '-')}</dd>
      <dt>Runtime versions</dt><dd>{esc(', '.join(f'{k} {v}' for k, v in t.runtime_versions.items()) or '-')}</dd>
    </dl>""")
    if node.hosting_platform:
        hp = node.hosting_platform
        parts.append(f'<p><b>Hosting platform:</b> {esc(platform_label(hp.kind))}'
                     f'{f" — {esc(hp.detail)}" if hp.detail else ""}</p>')
    if node.key_management:
        km = node.key_management
        parts.append(f'<p><b>Key management:</b> {esc(", ".join(km.mechanisms) or "none detected")}</p>')
    if node.mesh:
        m = node.mesh
        parts.append(f'<p><b>Mesh:</b> {esc(m.mesh or "-")}'
                     f'{f", mTLS {esc(m.mtls_mode)}" if m.mtls_mode else ""}</p>')
    if node.database:
        d = node.database
        parts.append(f'<p><b>Database:</b> {esc(d.engine) if d.engine else "not determined"}'
                     f'{f" {esc(d.version)}" if d.version else ""}</p>')
    parts.append(_evidence_html(node.evidence))
    return "".join(parts)


_RUNTIME_LABEL = {"matched_high": "confirmed live (high confidence)", "matched_medium": "confirmed live (medium confidence)",
                  "runtime_only": "found only at runtime — not declared in code", "code_only": "declared in code — not observed live",
                  "not_checked": "not cross-checked against runtime data"}


def _resilience_row(r) -> str:
    params = ", ".join(f"{k}={v}" for k, v in r.parameters.items())
    detail = f" ({esc(params)})" if params else ""
    return f'<li>{_badge(r.layer, f"layer-{r.layer}")} <b>{esc(r.pattern)}</b> via {esc(r.mechanism)}{detail}</li>'


def _edge_detail(edge: DependencyGraphEdge, name: str) -> str:
    parts = [f"<h3>{esc(name)}</h3>", f'<p>{_badge(edge.kind, f"kind-{edge.kind}")} '
            f'{_badge(edge.classification.replace("_", " "), f"cls-{edge.classification}")}</p>',
            f'<p><b>Runtime status:</b> {esc(_RUNTIME_LABEL.get(edge.runtime_status, edge.runtime_status))}</p>']
    if edge.blast_radius:
        parts.append(f'<p><b>Blast radius:</b> {esc(", ".join(edge.blast_radius))}</p>')
    if edge.resilience:
        rows = "".join(_resilience_row(r) for r in edge.resilience)
        parts.append(f'<p><b>Resilience:</b></p><ul class="resilience">{rows}</ul>')
    else:
        parts.append('<p class="warn"><b>Resilience:</b> no retry, circuit breaker or similar pattern found for this dependency.</p>')
    parts.append(_evidence_html(edge.evidence))
    return "".join(parts)


# ------------------------------------------------------------------------------------------------------------- svg


def _node_svg(node: DependencyGraphNode, x: float, y: float, r: int, detail_id: str) -> str:
    dash = ' stroke-dasharray="4 3"' if node.origin == "runtime_only" else ""
    return f"""<g class="graph-node node-{esc(node.kind)}" tabindex="0" data-detail="{esc(detail_id)}">
    <circle cx="{x:.1f}" cy="{y:.1f}" r="{r}"{dash}><title>{esc(node.name)}</title></circle>
    <text x="{x:.1f}" y="{y + r + 14:.1f}" text-anchor="middle">{esc(node.name[:22])}</text>
  </g>"""


def _edge_svg(edge: DependencyGraphEdge, x1: float, y1: float, x2: float, y2: float, detail_id: str) -> str:
    dash = {"runtime_only": '4 3', "code_only": '2 3'}.get(edge.runtime_status, "")
    dash_attr = f' stroke-dasharray="{dash}"' if dash else ""
    return (f'<line class="graph-edge cls-{esc(edge.classification)}" tabindex="0" data-detail="{esc(detail_id)}" '
           f'x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}"{dash_attr}><title>{esc(edge.kind)}</title></line>')


def _graph_section(graph: DependencyGraph) -> tuple[str, str]:
    """Returns (svg_and_details_html, script). Split out only so render_html can place the script at the end of body."""
    by_id = {n.id: n for n in graph.nodes}
    service = by_id.get("service")
    deps = [n for n in graph.nodes if n.id != "service"]
    positions = dict(zip((n.id for n in deps), _positions(len(deps)))) if deps else {}
    cx, cy = _CENTER

    edge_svgs, node_svgs, details = [], [], []
    if service is not None:
        node_svgs.append(_node_svg(service, cx, cy, _SERVICE_R, "detail-service"))
        details.append(f'<div class="detail-card" id="detail-service">{_node_detail(service)}</div>')

    for e in graph.edges:
        target = by_id.get(e.target)
        pos = positions.get(e.target)
        if target is None or pos is None:
            continue
        x, y = pos
        edge_svgs.append(_edge_svg(e, cx, cy, x, y, f"detail-{e.id}"))
        details.append(f'<div class="detail-card" id="detail-{e.id}">{_edge_detail(e, target.name)}</div>')
        node_svgs.append(_node_svg(target, x, y, _NODE_R, f"detail-{target.id}"))
        details.append(f'<div class="detail-card" id="detail-{target.id}">{_node_detail(target)}</div>')

    viewbox_w, viewbox_h = _CENTER[0] * 2, _CENTER[1] * 2
    svg = f"""<svg viewBox="0 0 {viewbox_w} {viewbox_h}" role="img" aria-label="Dependency graph">
    {''.join(edge_svgs)}
    {''.join(node_svgs)}
  </svg>"""
    default_detail = '<div class="detail-card" id="detail-default">' + (
        _node_detail(service) if service is not None else '<p class="muted">No nodes.</p>') + '</div>'
    body = f"""
<section id="graph">
  <h2>Dependency graph</h2>
  <p class="muted small">Click a node or a connection to see its properties. Dashed = runtime-only (not declared in
     code); dotted = declared in code but not observed live.</p>
  <div class="graph-layout">
    <div class="graph-canvas">{svg}</div>
    <aside id="detail-panel">{default_detail}{''.join(details)}</aside>
  </div>
</section>
"""
    script = """
<script>
(function () {
  var cards = document.querySelectorAll('.detail-card');
  function show(id) {
    cards.forEach(function (c) { c.hidden = c.id !== id; });
  }
  show('detail-default');
  document.querySelectorAll('.graph-node, .graph-edge').forEach(function (el) {
    var id = el.getAttribute('data-detail');
    el.addEventListener('click', function () { show(id); });
    el.addEventListener('keydown', function (ev) { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); show(id); } });
  });
})();
</script>
"""
    return body, script


# ------------------------------------------------------------------------------------------------------- footer


def _footer(graph: DependencyGraph) -> str:
    warnings = ("<ul>" + "".join(f"<li>{esc(w)}</li>" for w in graph.warnings) + "</ul>") if graph.warnings else '<p class="ok">none</p>'
    return f"""
<footer>
  <h2>Provenance</h2>
  <dl class="kv">
    <dt>Dataset</dt><dd>{esc(graph.inputs.get('dataset', {}).get('service_name'))},
      schema {esc(graph.inputs.get('dataset', {}).get('schema_version'))},
      generated {esc(graph.inputs.get('dataset', {}).get('generated_at'))}</dd>
  </dl>
  <h3>Warnings</h3>
  {warnings}
  <p class="muted small">Generated by sreadvisor. This page makes no network requests and loads no external resources.</p>
</footer>
"""


_STYLE = """
:root { --bg:#f6f7f9; --panel:#fff; --panel-2:#f1f3f6; --text:#1a2233; --muted:#5b667a; --border:#dde2ea;
  --accent:#4f46e5; --ok:#15803d; --ok-bg:#e8f6ed; --warn:#a15c07; --warn-bg:#fdf3e0; --bad:#b42318; --bad-bg:#fdecea;
  --na:#566175; --na-bg:#eceff3; --radius:10px; }
@media (prefers-color-scheme: dark) {
  :root { --bg:#0f131a; --panel:#171c26; --panel-2:#1d2430; --text:#e6eaf2; --muted:#93a0b5; --border:#2b3445;
    --accent:#8b93ff; --ok:#4ade80; --ok-bg:#12301f; --warn:#fbbf24; --warn-bg:#33270d; --bad:#f87171; --bad-bg:#3a1717;
    --na:#a3aec2; --na-bg:#222a38; }
}
* { box-sizing:border-box; }
body { margin:0; background:var(--bg); color:var(--text); font:14px/1.55 -apple-system,"Segoe UI",Roboto,Arial,sans-serif; }
h1,h2,h3 { letter-spacing:-.01em; } h1 { font-size:26px;margin:0 0 4px; } h2 { font-size:19px;border-bottom:1px solid var(--border);padding-bottom:6px; }
h3 { font-size:15px;margin-top:0; }
code { font-family:ui-monospace,Consolas,monospace; font-size:12.5px; background:var(--panel-2); padding:1px 5px; border-radius:5px; overflow-wrap:anywhere; }
header,section,footer { max-width:1100px; margin:0 auto; padding:24px 20px; }
.muted { color:var(--muted); } .small { font-size:12.5px; } .ok { color:var(--ok); } .warn { color:var(--warn); }
.badge { display:inline-block; padding:1px 9px; border-radius:999px; font-size:11px; font-weight:700; white-space:nowrap; background:var(--na-bg); color:var(--na); }
.cls-hard_failure { background:var(--bad-bg); color:var(--bad); } .cls-gracefully_degradable { background:var(--ok-bg); color:var(--ok); }
.origin-runtime_only { background:var(--warn-bg); color:var(--warn); }
.layer-application { background:#e7f0fd; color:#1d5fbf; } .layer-mesh { background:#f3e8fd; color:#7e22ce; }
.kv { display:grid; grid-template-columns:140px 1fr; gap:4px 14px; margin:8px 0; } .kv dt { color:var(--muted); font-weight:600; font-size:12.5px; } .kv dd { margin:0; }
.evidence, .resilience { list-style:none; margin:6px 0; padding:0; } .evidence li, .resilience li { padding:3px 0; border-bottom:1px dashed var(--border); }
.graph-layout { display:flex; gap:20px; flex-wrap:wrap; align-items:flex-start; }
.graph-canvas { flex:2 1 480px; background:var(--panel); border:1px solid var(--border); border-radius:var(--radius); }
.graph-canvas svg { width:100%; height:auto; display:block; }
#detail-panel { flex:1 1 280px; min-width:260px; background:var(--panel); border:1px solid var(--border); border-radius:var(--radius); padding:14px 16px; }
.graph-node circle { fill:var(--panel-2); stroke:var(--accent); stroke-width:2; cursor:pointer; }
.graph-node.node-service circle { fill:var(--accent); stroke:var(--accent); opacity:0.15; stroke-width:3; }
.graph-node.node-datastore circle { stroke:#1d5fbf; } .graph-node.node-cache circle { stroke:#7e22ce; }
.graph-node.node-messaging circle { stroke:var(--warn); } .graph-node.node-external_api circle,.graph-node.node-http_service circle { stroke:var(--ok); }
.graph-node text { fill:var(--text); font-size:11px; text-anchor:middle; }
.graph-node:focus circle, .graph-edge:focus { outline:none; filter:drop-shadow(0 0 3px var(--accent)); }
.graph-edge { stroke:var(--muted); stroke-width:2; cursor:pointer; }
.graph-edge.cls-hard_failure { stroke:var(--bad); } .graph-edge.cls-gracefully_degradable { stroke:var(--ok); }
.detail-card[hidden] { display:none; }
footer { border-top:1px solid var(--border); margin-top:20px; }
@media (max-width:700px) {
  header,section,footer { padding:16px 14px; }
  .graph-layout { flex-direction:column; }
}
"""


def render_html(graph: DependencyGraph) -> str:
    body, script = _graph_section(graph)
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(graph.service_name)} — dependency graph</title>
<style>{_STYLE}</style>
</head>
<body>
<header>
  <h1>{esc(graph.service_name)}</h1>
  <p class="muted">Dependency graph &middot; generated {esc(graph.generated_at.strftime('%Y-%m-%d %H:%M UTC'))}</p>
</header>
{body}
{_footer(graph)}
{script}
</body>
</html>
"""
