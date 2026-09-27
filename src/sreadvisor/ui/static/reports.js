/* Reports: list of analysed services, and the gap report viewer (gaps, all requirements, unrecognized tech stacks, modules, coverage, dataset). */
"use strict";

const Reports = (() => {
  const STATUSES = ["missing", "partially_met", "met", "not_assessable"];
  const PRIOS = ["critical", "high", "medium", "low"];

  // ------------------------------------------------------------------------------ list
  async function list(root) {
    clear(root).append(spinner());
    let rows;
    try { rows = await api("/reports"); } catch (e) { clear(root).append(banner("bad", e.message)); return; }
    clear(root).append(h("div", { class: "page-head" }, h("div", null, h("h1", null, "Reports"), h("p", null, "Everything the pipeline has written to the output folder, per service.")),
      h("div", { class: "actions" }, h("a", { class: "btn btn-primary", href: "#/analyze" }, "Analyze a service"))),
      rows.length ? h("div", { class: "grid cols-2" }, rows.map(card)) : emptyState("No reports yet", "Analyze a service to create the dataset, the coverage report and the gap report.", h("a", { class: "btn btn-primary", href: "#/analyze" }, "Analyze a service")));
  }
  function card(r) {
    const s = r.gap_summary, f = r.files;
    return h("div", { class: "card" },
      h("h2", null, h("a", { href: "#/reports/" + encodeURIComponent(r.service) }, r.service)),
      h("div", { style: { marginBottom: "10px" } }, [["dataset", "dataset"], ["coverage", "NFR coverage"], ["gaps", "gap report"]].map(([k, l]) =>
        f[k] ? h("span", { class: "badge b-met", style: { marginRight: "6px" }, title: fmt.time(f[k].modified) }, "✓ " + l) : h("span", { class: "badge", style: { marginRight: "6px" } }, "– " + l))),
      s ? h("div", null, h("div", { class: "small muted", style: { marginBottom: "6px" } }, `${s.applicable_requirements} requirements · ${s.gap_count} gaps · ${s.unrecognized_tech_gap_count} unrecognized tech stack${s.unrecognized_tech_gap_count === 1 ? "" : "s"}`),
        statusBar(s.by_status), h("div", { class: "small muted", style: { marginTop: "6px" } }, "assessed by ", r.assessor_model || "?", " · ", fmt.ago(new Date(r.generated_at).getTime() / 1000)))
        : h("p", { class: "muted" }, f.dataset ? "No gap report yet." : "No dataset."),
      h("div", { class: "actions", style: { marginTop: "12px" } },
        h("a", { class: "btn btn-primary btn-sm", href: "#/reports/" + encodeURIComponent(r.service) }, s ? "Open report" : "Open"),
        f.dataset ? h("button", { class: "btn btn-sm", onclick: () => runGapsDialog(r.service) }, s ? "Re-run gap analysis" : "Run gap analysis") : null));
  }

  function statusBar(by) {
    const total = STATUSES.reduce((n, k) => n + (by[k] || 0), 0) || 1;
    return h("div", { class: "bar", role: "img", "aria-label": STATUSES.map((k) => `${by[k] || 0} ${fmt.label(k)}`).join(", ") },
      STATUSES.map((k) => h("i", { class: "s-" + k, style: { width: ((by[k] || 0) / total) * 100 + "%" }, title: `${by[k] || 0} ${fmt.label(k)}` })));
  }

  function runGapsDialog(service, applicable) {
    const opt = { limit: "", modules: "", no_llm: false, model_backend: "", ollama_model: "" };
    const body = h("div", null,
      h("p", null, "Assess every requirement that applies to ", h("b", null, service), " against its dataset. Each requirement is one model call."),
      h("label", { class: "field" }, h("span", null, "Only the first N requirements (quick trial)"), h("input", { type: "number", min: "1", placeholder: "all", oninput: (e) => { opt.limit = e.target.value; } })),
      h("label", { class: "field" }, h("span", null, "Only these modules (comma separated ids, optional)"), h("input", { type: "text", placeholder: "capacity_scaling, kubernetes", oninput: (e) => { opt.modules = e.target.value; } })),
      h("label", { class: "check" }, h("input", { type: "checkbox", onchange: (e) => { opt.no_llm = e.target.checked; } }), "Skip the model (deterministic parts and unrecognized tech only)"));
    modal({ title: "Run gap analysis", body, actions: [{ label: "Cancel" }, { label: "Start", class: "btn-primary", onclick: async () => {
      try {
        const job = await api("/jobs/gaps", { method: "POST", body: { service, no_llm: opt.no_llm, limit: opt.limit ? +opt.limit : undefined,
          modules: opt.modules.split(",").map((s) => s.trim()).filter(Boolean) } });
        location.hash = "#/jobs/" + job.id;
      } catch (e) { toast(e.message, "bad"); return true; }
    } }] });
  }

  // ---------------------------------------------------------------------------- detail
  async function detail(root, service, tab) {
    clear(root).append(spinner());
    const [gapsR, covR, factsR] = await Promise.allSettled([api(`/reports/${service}/gaps`), api(`/reports/${service}/coverage`), api(`/reports/${service}/dataset-facts`)]);
    const gaps = gapsR.status === "fulfilled" ? gapsR.value : null, cov = covR.status === "fulfilled" ? covR.value : null, facts = factsR.status === "fulfilled" ? factsR.value : null;
    if (!gaps && !cov && !facts) { clear(root).append(emptyState("Nothing found for " + service, "No dataset, coverage or gap report exists for this service.", h("a", { class: "btn", href: "#/reports" }, "Back to reports"))); return; }

    const utg = gaps ? gaps.unrecognized_tech_gaps : (cov ? cov.unrecognized_tech_stacks.map((u, i) => ({ id: "UTG-" + String(i + 1).padStart(3, "0"), kind: u.kind, name: u.name, found_as: u.detail, evidence: u.evidence, finding: "No module in the Master NFR List covers this technology.", impact: "Technology-specific requirements for it were not assessed.", recommended_action: u.action })) : []);
    const tabs = [];
    if (gaps) tabs.push(["gaps", "Gaps", gaps.summary.gap_count], ["all", "All requirements", gaps.summary.applicable_requirements]);
    tabs.push(["tech", "Unrecognized tech", utg.length]);
    if (gaps) tabs.push(["modules", "Modules", gaps.modules.length]);
    if (cov) tabs.push(["coverage", "Coverage & telemetry", null]);
    if (facts) tabs.push(["dataset", "Dataset", null]);
    const active = tabs.some((t) => t[0] === tab) ? tab : tabs[0][0];

    const content = h("div", null);
    const view = () => {
      clear(content);
      if (active === "gaps") content.append(gapsTab(gaps, gaps.gaps, true));
      else if (active === "all") content.append(gapsTab(gaps, gaps.assessments.map(fromAssessment), false));
      else if (active === "tech") content.append(techTab(utg));
      else if (active === "modules") content.append(modulesTab(gaps));
      else if (active === "coverage") content.append(coverageTab(cov));
      else content.append(datasetTab(facts));
    };

    clear(root).append(
      h("div", { class: "page-head" }, h("div", null, h("a", { href: "#/reports", class: "small" }, "← Reports"), h("h1", null, service),
        h("p", null, gaps ? h("span", null, `Gap analysis pass 1 · assessed by ${gaps.inputs.assessor_model} · ${fmt.time(gaps.generated_at)}`, gaps.business_context ? " · " + gaps.business_context : "") : "No gap report yet.")),
        h("div", { class: "actions" },
          facts ? h("button", { class: "btn", onclick: () => runGapsDialog(service) }, gaps ? "Re-run gap analysis" : "Run gap analysis") : null,
          gaps ? h("a", { class: "btn", href: `/api/reports/${encodeURIComponent(service)}/download/gaps` }, "Download JSON") : null,
          cov ? h("a", { class: "btn", href: `/api/reports/${encodeURIComponent(service)}/download/report` }, "Download report.md") : null)),
      !gaps ? banner("info", "No gap report for this service yet.", ["Run the gap analysis to assess it against the Master NFR List."]) : null,
      gaps ? summary(gaps) : null,
      utg.length ? spotlight(utg, () => { location.hash = `#/reports/${encodeURIComponent(service)}/tech`; }) : null,
      h("div", { class: "tabs", role: "tablist" }, tabs.map(([id, label, n]) => h("button", { class: "tab" + (id === active ? " active" : ""), role: "tab", "aria-selected": id === active ? "true" : "false",
        onclick: () => { location.hash = `#/reports/${encodeURIComponent(service)}/${id}`; } }, label, n != null ? h("span", { class: "badge count" }, n) : null))),
      content);
    view();
  }

  function summary(g) {
    const s = g.summary;
    return h("div", null,
      h("div", { class: "stats" },
        h("div", { class: "stat" }, h("div", { class: "n" }, s.applicable_requirements), h("div", { class: "l" }, "applicable requirements")),
        STATUSES.map((k) => h("div", { class: "stat s-" + k }, h("div", { class: "n" }, s.by_status[k] || 0), h("div", { class: "l" }, fmt.label(k))))),
      h("div", { class: "card", style: { padding: "12px 18px" } }, statusBar(s.by_status),
        h("div", { class: "small muted", style: { marginTop: "8px" } }, "Gaps by priority: ", PRIOS.map((p) => h("span", { style: { marginRight: "10px" } }, prioBadge(p), " ", s.gaps_by_priority[p] || 0)),
          " · ", s.assessed_by_llm, " assessed by the model", s.failed_assessments ? ` · ${s.failed_assessments} failed` : "")));
  }

  function spotlight(utg, onTab) {
    return h("div", { class: "spotlight", role: "region", "aria-label": "Unrecognized tech stacks" },
      h("h2", null, "⚠ ", utg.length, " unrecognized tech stack", utg.length === 1 ? "" : "s", " need NFR coverage"),
      h("p", { class: "small" }, "No module in the Master NFR List covers these technologies, so their specific requirements were not assessed. Review each and add it to the catalogue."),
      h("div", null, utg.slice(0, 8).map((u) => h("span", { class: "chip" }, u.kind + ": " + u.name))),
      h("div", { class: "actions", style: { marginTop: "8px" } }, h("button", { class: "btn btn-sm", onclick: onTab }, "Review and add to the catalogue")));
  }

  // ---------------------------------------------------------------------- gap tables
  function fromAssessment(a) { return { id: "", status: a.status, priority: a.nfr.priority, confidence: a.confidence, nfr: a.nfr, why: a.rationale, evidence: a.evidence, warnings: a.warnings, method: a.method }; }

  function gapsTab(g, rows, isGaps) {
    const f = { q: "", prios: new Set(), status: "", module: "", method: "" };
    const modules = [...new Map(rows.map((r) => [r.nfr.module_id, r.nfr.module_title])).entries()];
    const body = h("tbody", null), count = h("span", { class: "muted small" });
    const match = (r) => {
      if (f.prios.size && !f.prios.has(r.priority)) return false;
      if (f.status && r.status !== f.status) return false;
      if (f.module && r.nfr.module_id !== f.module) return false;
      if (f.q) { const t = (r.id + " " + r.nfr.id + " " + r.nfr.title + " " + r.why + " " + r.nfr.module_title).toLowerCase(); if (!t.includes(f.q.toLowerCase())) return false; }
      return true;
    };
    const draw = () => {
      clear(body); const shown = rows.filter(match);
      shown.forEach((r) => {
        const det = h("tr", { class: "detail", hidden: true }, h("td", { colspan: "7" }, h("div", { class: "detail-body" }, detailBody(r))));
        const tr = h("tr", { class: "clickable", tabindex: "0", "aria-expanded": "false" },
          h("td", { class: "nowrap mono" }, r.id || "·"), h("td", null, prioBadge(r.priority)), h("td", null, statusBadge(r.status)),
          h("td", null, h("b", { class: "mono" }, r.nfr.id), " ", r.nfr.title), h("td", { class: "small" }, r.nfr.module_title), h("td", { class: "small" }, r.confidence), h("td", { class: "right muted" }, "▾"));
        const toggle = () => { det.hidden = !det.hidden; tr.classList.toggle("open", !det.hidden); tr.setAttribute("aria-expanded", String(!det.hidden)); };
        tr.addEventListener("click", toggle); tr.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); toggle(); } });
        body.append(tr, det);
      });
      count.textContent = `${shown.length} of ${rows.length}`;
      if (!shown.length) body.append(h("tr", null, h("td", { colspan: "7" }, emptyState("Nothing matches", "Adjust the filters."))));
    };
    const chips = PRIOS.map((p) => { const c = h("span", { class: "toggle-chip", role: "button", tabindex: "0", onclick: () => { f.prios.has(p) ? f.prios.delete(p) : f.prios.add(p); c.classList.toggle("on"); draw(); } }, p); return c; });
    const statusOpts = (isGaps ? ["missing", "partially_met"] : STATUSES);
    const table = h("div", { class: "table-wrap" }, h("table", null, h("thead", null, h("tr", null, ["ID", "Priority", "Status", "Requirement", "Module", "Conf.", ""].map((c) => h("th", null, c)))), body));
    draw();
    return h("div", null,
      h("div", { class: "filters" }, h("input", { type: "search", placeholder: "Search requirements and reasons...", "aria-label": "Search", oninput: (e) => { f.q = e.target.value; draw(); } }), chips,
        h("select", { "aria-label": "Status", onchange: (e) => { f.status = e.target.value; draw(); } }, h("option", { value: "" }, "any status"), statusOpts.map((s) => h("option", { value: s }, fmt.label(s)))),
        h("select", { "aria-label": "Module", onchange: (e) => { f.module = e.target.value; draw(); } }, h("option", { value: "" }, "all modules"), modules.map(([id, t]) => h("option", { value: id }, t))), count),
      table,
      isGaps && g.warnings.length ? h("details", { class: "card", style: { marginTop: "16px" } }, h("summary", null, h("b", null, `Warnings (${g.warnings.length})`)), h("ul", null, g.warnings.map((w) => h("li", { class: "small" }, w)))) : null);
  }

  function detailBody(r) {
    const n = r.nfr, ev = r.evidence || {};
    return [
      h("div", null, h("div", { class: "lbl" }, r.id ? "Why this is a gap" : "Assessment"), h("div", { class: "quote" }, r.why),
        r.warnings && r.warnings.length ? h("div", { class: "small", style: { marginTop: "6px", color: "var(--warn)" } }, r.warnings.map((w) => h("div", null, "⚠ " + w))) : null),
      (ev.found || []).length ? h("div", null, h("div", { class: "lbl" }, "What the dataset shows"), h("ul", { class: "evidence" }, ev.found.map((f) =>
        h("li", null, f.shows ? badge(f.shows, "b-" + f.shows) : null, f.file ? loc(f.file, f.line) : null, f.path ? h("code", { class: "muted" }, f.path) : null, f.note ? h("span", null, f.note) : null)))) : null,
      (ev.not_found || []).length ? h("div", null, h("div", { class: "lbl" }, "Not found"), h("ul", { style: { margin: 0, paddingLeft: "20px" } }, ev.not_found.map((x) => h("li", null, x)))) : null,
      h("div", null, h("div", { class: "lbl" }, "Checked in"),
        (ev.examined_locations || []).length ? h("div", null, ev.examined_locations.map((l) => h("span", { class: "chip" }, l))) : null,
        h("div", null, (ev.examined_paths || []).map((p) => h("span", { class: "chip" }, p))),
        h("div", { class: "small muted" }, "Stage 1 steps: ", Object.entries(ev.stage1_steps || {}).map(([k, v]) => h("span", { class: "chip" }, k + " " + v)))),
      h("details", null, h("summary", { class: "small" }, "Requirement, best practice and pass criteria"),
        h("dl", { class: "kv", style: { marginTop: "8px" } }, h("dt", null, "Requirement"), h("dd", null, n.requirement), h("dt", null, "Best practice"), h("dd", null, n.best_practice),
          h("dt", null, "Audit requirement"), h("dd", null, n.audit_requirement || "none"), h("dt", null, "Pass criteria"), h("dd", null, n.criteria),
          h("dt", null, "Assessed by"), h("dd", null, r.method === "llm" ? "the model" : "deterministic rule"))),
      h("div", { class: "actions" }, h("a", { class: "btn btn-sm", href: `#/catalogue/${n.module_id}?entry=${n.id}` }, "Open ", n.id, " in the catalogue")),
    ];
  }

  // ----------------------------------------------------------------- other tabs
  function techTab(utg) {
    if (!utg.length) return h("div", { class: "card" }, emptyState("Nothing unrecognized", "Every technology found in the fingerprint has a module in the Master NFR List."));
    return h("div", null, h("div", { class: "banner info" }, "These are gaps in the ", h("b", null, "knowledge base"), ", not in the service. Adding a module makes the next run assess this technology's requirements."),
      utg.map((u) => h("div", { class: "card" }, h("div", { class: "row" }, h("span", { class: "mono muted" }, u.id), badge(fmt.label(u.kind), "b-accent"), h("h2", { style: { margin: 0 } }, u.name)),
        h("dl", { class: "kv" }, h("dt", null, "Found as"), h("dd", null, u.found_as), h("dt", null, "Where"), h("dd", null, (u.evidence || []).length ? u.evidence.map((e) => h("span", { class: "chip" }, e.line ? `${e.file}:${e.line}` : e.file)) : "-"),
          h("dt", null, "Finding"), h("dd", null, u.finding), h("dt", null, "Impact"), h("dd", null, u.impact), h("dt", null, "Recommended"), h("dd", null, u.recommended_action)),
        h("div", { class: "actions", style: { marginTop: "10px" } }, h("button", { class: "btn btn-primary btn-sm", onclick: () => { Catalogue.prefill(u); } }, "Add an NFR module for this…")))));
  }

  function modulesTab(g) {
    return h("div", { class: "table-wrap" }, h("table", null, h("thead", null, h("tr", null, ["Module", "Layer", "Why it applies", "Requirements", "Result"].map((c) => h("th", null, c)))),
      h("tbody", null, g.modules.map((m) => h("tr", null, h("td", null, h("a", { href: "#/catalogue/" + m.module_id }, m.title)), h("td", null, badge(fmt.label(m.layer), "b-info")),
        h("td", { class: "small" }, (m.matched_by || []).slice(0, 2).join("; ")), h("td", null, m.assessed),
        h("td", { style: { minWidth: "220px" } }, statusBar({ met: m.met, partially_met: m.partially_met, missing: m.missing, not_assessable: m.not_assessable }),
          h("div", { class: "small muted" }, `${m.met} met · ${m.partially_met} partial · ${m.missing} missing · ${m.not_assessable} n/a`)))))));
  }

  function coverageTab(c) {
    const t = c.telemetry_tiers, t1 = t.tier1_oneagent_default, t2 = t.tier2_application_library, t3 = t.tier3_custom_instrumentation;
    const idx = (n) => t.metric_index.filter((m) => m.tier === n).length;
    return h("div", null,
      h("div", { class: "card" }, h("h2", null, "Applicable modules"), h("p", { class: "small muted" }, `${c.applicable_modules.length} of ${c.applicable_modules.length + c.modules_not_applicable.length} modules apply (${c.applicable_entry_count} requirements).`),
        h("div", { class: "table-wrap" }, h("table", null, h("thead", null, h("tr", null, ["Module", "Layer", "Why", "Requirements"].map((x) => h("th", null, x)))),
          h("tbody", null, c.applicable_modules.map((m) => h("tr", null, h("td", null, h("a", { href: "#/catalogue/" + m.id }, m.title)), h("td", null, badge(fmt.label(m.layer), "b-info")), h("td", { class: "small" }, m.matched_by.slice(0, 2).join("; ")), h("td", null, m.entry_count))))))),
      h("div", { class: "card" }, h("h2", null, "Telemetry tiers"), h("p", { class: "small muted" }, t.overlap_policy),
        h("div", { class: "grid cols-3" },
          h("div", { class: "sub" }, h("div", { class: "lbl" }, "Tier 1: OneAgent default"), h("div", { class: "stat" }, h("div", { class: "n" }, t1.signals.length), h("div", { class: "l" }, "signals out of the box (" + idx(1) + " metrics)")),
            h("div", { class: "small muted" }, t1.not_covered_by_default.length, " signals not covered by default")),
          h("div", { class: "sub" }, h("div", { class: "lbl" }, "Tier 2: emitted by the application"), h("div", { class: "stat" }, h("div", { class: "n" }, t2.detected_in_service.length), h("div", { class: "l" }, "instrumentation libraries detected")),
            t2.detected_in_service.map((d) => h("div", { class: "small" }, h("b", null, d.library), " · ", d.metrics.length, " metrics"))),
          h("div", { class: "sub" }, h("div", { class: "lbl" }, "Tier 3: custom (see the Stage 4 unified report for concrete suggestions)"), h("div", { class: "small" }, t3.business_capability || "No business context."),
            h("div", { class: "small muted" }, (t3.key_operations || []).join(", "))))));
  }

  function datasetTab(f) {
    const b = f.business_context;
    return h("div", null,
      h("div", { class: "card" }, h("h2", null, "Stage 1 dataset"), h("dl", { class: "kv" },
        h("dt", null, "Generated"), h("dd", null, fmt.time(f.generated_at)), h("dt", null, "Schema"), h("dd", null, f.schema_version), h("dt", null, "Model"), h("dd", null, f.model_backend || "-"),
        h("dt", null, "Observability"), h("dd", null, f.observability ? `${f.observability.provider} · ${f.observability.service_id}` : "-"),
        h("dt", null, "Business context"), h("dd", null, b ? `${b.capability} (${b.category}, ${b.confidence} confidence)` : "not inferred"),
        h("dt", null, "Completeness"), h("dd", null, (f.completeness || {}).summary || "-"))),
      f.repositories.map((r) => h("div", { class: "card" }, h("h2", null, r.repo), h("dl", { class: "kv" },
        h("dt", null, "Languages"), h("dd", null, (r.languages || []).join(", ") || "-"), h("dt", null, "Frameworks"), h("dd", null, (r.frameworks || []).join(", ") || "-"),
        h("dt", null, "Build tools"), h("dd", null, (r.build_tools || []).join(", ") || "-"), h("dt", null, "Dependencies"), h("dd", null, r.dependencies),
        h("dt", null, "Entry points / flows"), h("dd", null, `${r.entry_points} / ${r.flows}`), h("dt", null, "Reliability patterns"), h("dd", null, r.reliability_patterns),
        h("dt", null, "Dependency classifications"), h("dd", null, r.dependency_classifications)))),
      h("div", { class: "card" }, h("h2", null, "Infrastructure"), h("div", null, Object.entries(f.infrastructure).map(([k, v]) => h("span", { class: "chip" }, `${fmt.label(k)}: ${v === true ? "yes" : v === false ? "no" : v}`)))),
      (f.completeness && f.completeness.warnings && f.completeness.warnings.length) ? h("details", { class: "card" }, h("summary", null, h("b", null, `Stage 1 warnings (${f.completeness.warnings.length})`)), h("ul", null, f.completeness.warnings.map((w) => h("li", { class: "small" }, w)))) : null);
  }

  return { render(view, service, tab) { return service ? detail(view, decodeURIComponent(service), tab) : list(view); } };
})();
