/* NFR catalogue: browse and edit the Master NFR List (the YAML sources; the JSON Stage 3 reads is rebuilt on save),
   and browse the two telemetry catalogues read-only. */
"use strict";

const Catalogue = (() => {
  const KNOWN = ["id", "title", "requirement", "best_practice", "audit_requirement", "monitoring", "priority", "verification", "extends", "tags"];
  const LAYER_LABEL = { baseline: "Baseline", tech_stack: "Tech stack", cross_cutting: "Cross-cutting" };
  const CAT_LABEL = { language: "Languages", framework: "Frameworks", architecture: "Architecture", source_control: "Source control", cicd: "CI/CD", iac_container: "IaC and containers",
    integration: "Integration layer", data: "Data", security: "Security", observability: "Observability", cross_cutting: "Cross-cutting", baseline: "Baseline" };
  let mods = [], cur = null, problems = [], pendingNew = null, vTimer = null, openSet = new Set(), root = null, main = null, side = null, filterQ = "", saving = false, wantEntry = null;

  /* Canonical form: keys holding empty lists or objects are dropped (the editor creates them while rendering), so only real edits count as changes
     and the YAML stays free of empty noise. Array elements are never removed, so error paths keep pointing at the right entry. */
  const canon = (v) => Array.isArray(v) ? v.map(canon) : (v && typeof v === "object" ? Object.fromEntries(Object.entries(v).map(([k, x]) => [k, canon(x)]).filter(([, x]) => !((Array.isArray(x) && !x.length) || (x && typeof x === "object" && !Array.isArray(x) && !Object.keys(x).length)))) : v);
  const snap = (doc) => JSON.stringify(canon(doc));
  const dirty = () => !!cur && snap(cur.doc) !== cur.orig;

  // ---------------------------------------------------------------- new-module prefill
  function prefill(u) {
    const art = u.name.includes(":") ? u.name.split(":").pop() : u.name;
    const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const infra = { "GitLab CI": "gitlab_ci", Jenkins: "jenkins", "Azure Pipelines": "azure_pipelines" };
    let rule = {}, category = "integration";
    if (u.kind === "language" || u.kind === "manifest") { rule = { language: u.name }; category = "language"; }
    else if (u.kind === "framework") { rule = { framework: u.name }; category = "framework"; }
    else if (u.kind === "dependency") { rule = { dependency: esc(art) }; category = /sql|mongo|redis|cassandra|elastic|dynamo|neo4j|jdbc|db/i.test(u.name) ? "data" : "integration"; }
    else if (u.kind === "infrastructure") { if (infra[u.name]) rule = { infra: infra[u.name] }; category = "cicd"; }
    else if (u.kind === "cloud_provider") { rule = { terraform: "^" + esc(u.name) + "_" }; category = "iac_container"; }
    else if (u.kind === "api_style") { rule = { entry_point: u.name.toLowerCase() }; category = "integration"; }
    const id = slugify(art).slice(0, 40) || "new_module";
    pendingNew = blankModule({ id, title: art, category, detect: Object.keys(rule).length ? [rule] : [{}], note: `Prefilled from the unrecognized tech stack "${u.name}" (${u.kind}); found as: ${u.found_as}.` });
    location.hash = "#/catalogue/new";
  }
  function blankModule(o) {
    const pfx = (o.id || "NEW").replace(/[^a-z]/gi, "").toUpperCase().slice(0, 4) || "NEW";
    return { _note: o.note || null, doc: { id: o.id || "", title: o.title || "", layer: "tech_stack", category: o.category || "framework", description: "Requirements specific to " + (o.title || "this technology") + ". Extends the baseline.",
      extends: ["baseline"], detect: o.detect || [{}], recognizes: [], catalogue_refs: ["oneagent_default", "application_level"], entry_extensions: {},
      entries: [{ id: pfx + "-001", title: "TODO: first requirement for " + (o.title || "this technology"), requirement: "Describe the requirement.", best_practice: "Describe the best practice this requirement reflects.",
        audit_requirement: null, priority: "medium", monitoring: [{ source: "platform", signal: "Describe the signal that verifies this requirement" }],
        verification: { sources: ["manual_review"], criteria: "Describe how a reviewer decides this requirement is met." } }] } };
  }

  // -------------------------------------------------------------------------- shell
  async function render(view, arg, query) {
    root = view; wantEntry = (query || {}).entry || null;
    clear(root).append(spinner());
    try {
      [mods, App.hints, App.paths] = await Promise.all([api("/nfr/modules"), App.hints || api("/nfr/hints"), App.paths || api("/nfr/dataset-paths")]);
    } catch (e) { clear(root).append(banner("bad", e.message)); return; }
    clear($("#dl-paths")).append(App.paths.map((p) => h("option", { value: p })));
    clear($("#dl-entries")).append(App.hints.entry_ids.map((p) => h("option", { value: p })));
    side = h("aside", { class: "card side" }); main = h("section", null);
    clear(root).append(h("div", { class: "two-pane" }, side, main));
    drawSide(arg);
    if (arg === "_oneagent" || arg === "_instrumentation") return catalogueView(arg);
    if (arg === "new") return newModule();
    if (arg) return openModule(decodeURIComponent(arg));
    cur = null; overview();
  }

  function drawSide(active) {
    clear(side);
    const q = h("input", { type: "search", placeholder: "Filter modules...", value: filterQ, "aria-label": "Filter modules", oninput: (e) => { filterQ = e.target.value; drawList(); } });
    const listEl = h("div", null);
    side.append(h("div", { class: "row" }, q), h("a", { class: "btn btn-primary btn-sm", style: { width: "100%", marginBottom: "6px" }, href: "#/catalogue/new" }, "+ New module"), listEl);
    function drawList() {
      clear(listEl);
      const match = (m) => !filterQ || (m.id + " " + m.title + " " + (m.description || "")).toLowerCase().includes(filterQ.toLowerCase());
      const groups = [["Baseline", mods.filter((m) => m.layer === "baseline")]];
      const tech = mods.filter((m) => m.layer === "tech_stack");
      for (const cat of Object.keys(CAT_LABEL)) { const g = tech.filter((m) => m.category === cat); if (g.length) groups.push([CAT_LABEL[cat], g]); }
      groups.push(["Cross-cutting", mods.filter((m) => m.layer === "cross_cutting")]);
      for (const [name, g] of groups) {
        const items = g.filter(match); if (!items.length) continue;
        listEl.append(h("h4", null, name), items.map((m) => h("a", { class: "item" + (m.id === active ? " active" : ""), href: "#/catalogue/" + m.id, title: m.description || "" }, h("span", null, m.title), h("span", { class: "n" }, m.entry_count))));
      }
      listEl.append(h("h4", null, "Telemetry catalogues (read-only)"),
        h("a", { class: "item" + (active === "_oneagent" ? " active" : ""), href: "#/catalogue/_oneagent" }, "OneAgent defaults"),
        h("a", { class: "item" + (active === "_instrumentation" ? " active" : ""), href: "#/catalogue/_instrumentation" }, "Application instrumentation"));
    }
    drawList();
  }

  function overview() {
    const total = mods.reduce((n, m) => n + m.entry_count, 0);
    clear(main).append(h("div", { class: "page-head" }, h("div", null, h("h1", null, "Master NFR List"),
      h("p", null, "The requirements every service is assessed against: a generic baseline, tech-stack modules that extend it, and cross-cutting modules. Edits are validated as a whole, backed up, and rebuild the JSON that gap analysis reads."))),
      h("div", { class: "stats" }, h("div", { class: "stat" }, h("div", { class: "n" }, mods.length), h("div", { class: "l" }, "modules")), h("div", { class: "stat" }, h("div", { class: "n" }, total), h("div", { class: "l" }, "requirements")),
        ["critical", "high", "medium", "low"].map((p) => h("div", { class: "stat" }, h("div", { class: "n" }, mods.reduce((n, m) => n + ((m.priorities || {})[p] || 0), 0)), h("div", { class: "l" }, p + " priority")))),
      h("div", { class: "card" }, h("h2", null, "How editing works"), h("ul", null,
        h("li", null, "Pick a module on the left, change a requirement, and press Save. Nothing is written unless the whole knowledge base still validates (schema, references between modules, and every dataset path)."),
        h("li", null, "The previous version of the module is kept and can be restored from the History menu."),
        h("li", null, "A new tech-stack module also gets a placeholder in both telemetry catalogues, marked \"Not yet catalogued\", because the build requires an entry for every module."),
        h("li", null, "Unrecognized tech stacks found by an analysis link here with the module form prefilled."))));
  }

  // ------------------------------------------------------------------ module loading
  async function openModule(id) {
    clear(main).append(spinner());
    try {
      const r = await api("/nfr/modules/" + id);
      cur = { id, isNew: false, etag: r.etag, file: r.file, backups: r.backups, doc: deepCopy(r.module), orig: snap(r.module), note: null };
    } catch (e) { clear(main).append(banner("bad", e.message)); return; }
    problems = []; openSet = new Set();
    if (wantEntry) { const i = cur.doc.entries.findIndex((e) => e.id === wantEntry); if (i >= 0) openSet.add(i); }
    drawEditor();
    if (wantEntry) setTimeout(() => { const el = main.querySelector(`[data-entry="${wantEntry}"]`); if (el) el.scrollIntoView({ block: "center" }); }, 50);
  }
  function newModule() {
    const b = pendingNew || blankModule({}); pendingNew = null;
    cur = { id: null, isNew: true, etag: null, file: null, backups: [], doc: b.doc, orig: "", note: b._note };
    problems = []; openSet = new Set([0]); drawEditor();
  }

  // ------------------------------------------------------------------------ editor
  const field = (label, control, hint) => h("label", { class: "field" }, h("span", null, label), control, hint ? h("div", { class: "hint" }, hint) : null);
  const errFor = (pfx) => problems.filter((p) => (p.path || "").startsWith(pfx));
  const errForEntry = (i) => problems.filter((p) => (p.path || "").startsWith(`entries[${i}]`) || (p.entry && cur.doc.entries[i] && p.entry === cur.doc.entries[i].id));
  const touch = () => { scheduleValidate(); updateBar(); };

  function drawEditor() {
    const d = cur.doc, hints = App.hints;
    const scroll = window.scrollY;
    clear(main);
    main.append(
      h("div", { class: "page-head" }, h("div", null, h("h1", null, cur.isNew ? "New module" : d.title), h("p", null, cur.isNew ? "Define the module and its first requirement." : [h("code", null, d.id), " · ", LAYER_LABEL[d.layer], " · ", h("code", null, cur.file)]))),
      cur.note ? banner("info", cur.note) : null,
      h("div", { id: "problems" }),
      moduleSettings(d, hints),
      h("div", { class: "page-head", style: { marginTop: "6px" } }, h("h2", { style: { margin: 0 } }, `Requirements (${d.entries.length})`),
        h("div", { class: "actions" }, h("input", { type: "search", placeholder: "Filter...", "aria-label": "Filter requirements", style: { width: "180px" }, oninput: (e) => filterEntries(e.target.value) }),
          h("button", { class: "btn btn-sm", onclick: () => { document.querySelectorAll("#entries details").forEach((x) => (x.open = true)); } }, "Expand all"),
          h("button", { class: "btn btn-sm", onclick: () => { document.querySelectorAll("#entries details").forEach((x) => (x.open = false)); } }, "Collapse all"),
          h("button", { class: "btn btn-sm btn-primary", onclick: addEntry }, "+ Add requirement"))),
      h("div", { id: "entries" }, d.entries.map((e, i) => entryEditor(e, i))),
      actionBar());
    window.scrollTo(0, scroll); showProblems(); updateBar();
  }

  function moduleSettings(d, hints) {
    return h("details", { class: "card", open: cur.isNew }, h("summary", null, h("b", null, "Module settings"), h("span", { class: "muted small" }, "  identity, when it applies, extends")),
      h("div", { style: { marginTop: "12px" } },
        h("div", { class: "grid cols-2" },
          field("Module id", h("input", { type: "text", value: d.id, readOnly: !cur.isNew, disabled: !cur.isNew, placeholder: "mongodb", oninput: (e) => { d.id = e.target.value; touch(); } }), cur.isNew ? "Lower-case letters, digits and underscores. Cannot be changed later." : "Ids are permanent: other modules refer to them."),
          field("Title", h("input", { type: "text", value: d.title, oninput: (e) => { d.title = e.target.value; if (cur.isNew && !d.id) { d.id = slugify(d.title); } touch(); } }))),
        h("div", { class: "grid cols-2" },
          field("Layer", h("select", { disabled: !cur.isNew, onchange: (e) => { d.layer = e.target.value; touch(); } }, hints.layers.filter((l) => cur.isNew ? l !== "baseline" : true).map((l) => h("option", { value: l, selected: d.layer === l }, LAYER_LABEL[l])))),
          field("Category", h("select", { onchange: (e) => { d.category = e.target.value; touch(); } }, hints.categories.map((c) => h("option", { value: c, selected: d.category === c }, CAT_LABEL[c] || c))))),
        field("Description", h("textarea", { oninput: (e) => { d.description = e.target.value; touch(); } }, d.description)),
        field("Extends (module ids, comma separated)", h("input", { type: "text", value: (d.extends || []).join(", "), oninput: (e) => { d.extends = e.target.value.split(",").map((s) => s.trim()).filter(Boolean); touch(); } }), "Tech-stack modules must extend baseline."),
        h("div", { class: "sub" }, h("div", { class: "lbl" }, "Applies when any of these rules matches (all conditions inside one rule must hold)"), ruleEditor(d, "detect"), h("div", { class: "hint" }, "Cross-cutting modules use \"always\". Regex keys (dependency, image, terraform) are case-insensitive regular expressions.")),
        h("div", { class: "sub" }, h("div", { class: "lbl" }, "Recognizes (technologies this module covers without applying because of them)"), ruleEditor(d, "recognizes")),
        h("div", { class: "grid cols-2" },
          h("div", null, h("div", { class: "lbl" }, "Telemetry catalogue references"), ["oneagent_default", "application_level"].map((c) => h("label", { class: "check" }, h("input", { type: "checkbox", checked: (d.catalogue_refs || []).includes(c), onchange: (e) => {
            d.catalogue_refs = (d.catalogue_refs || []).filter((x) => x !== c); if (e.target.checked) d.catalogue_refs.push(c); touch(); } }), fmt.label(c)))),
          h("div", null, h("div", { class: "lbl" }, "Documented extra entry fields"), kvEditor(d, "entry_extensions", "field name", "what it means")))));
  }

  function ruleEditor(d, key) {
    const hints = App.hints, rules = d[key] = d[key] || [];
    return h("div", null, rules.map((rule, ri) => h("div", { class: "sub", style: { background: "var(--panel)" } },
      h("div", { class: "row" }, h("span", { class: "muted small" }, "Rule " + (ri + 1)), h("span", { class: "grow" }), h("button", { class: "btn btn-ghost btn-sm", onclick: () => { rules.splice(ri, 1); touch(); drawEditor(); } }, "Remove rule")),
      h("label", { class: "check" }, h("input", { type: "checkbox", checked: !!rule.always, onchange: (e) => { if (e.target.checked) rule.always = true; else delete rule.always; touch(); } }), "always (applies to every service)"),
      Object.keys(rule).filter((k) => k !== "always").map((k) => h("div", { class: "row" },
        h("select", { style: { width: "190px" }, onchange: (e) => { const v = rule[k]; delete rule[k]; rule[e.target.value] = v; touch(); drawEditor(); } }, hints.rule_keys.map((rk) => h("option", { value: rk, selected: rk === k }, rk))),
        h("input", { type: "text", class: "grow", value: Array.isArray(rule[k]) ? rule[k].join(", ") : rule[k] || "", placeholder: k === "infra" ? hints.infra_signals.join(" | ") : hints.regex_keys.includes(k) ? "regular expression" : "value",
          list: k === "infra" ? undefined : undefined, oninput: (e) => { rule[k] = Array.isArray(rule[k]) ? e.target.value.split(",").map((s) => s.trim()).filter(Boolean) : e.target.value; touch(); } }),
        h("button", { class: "btn btn-ghost btn-sm", title: "Remove condition", onclick: () => { delete rule[k]; touch(); drawEditor(); } }, "✕"))),
      h("button", { class: "btn btn-sm", onclick: () => { const free = hints.rule_keys.find((k) => !(k in rule)); if (free) { rule[free] = ""; touch(); drawEditor(); } } }, "+ condition"))),
      h("button", { class: "btn btn-sm", onclick: () => { rules.push({}); touch(); drawEditor(); } }, "+ rule"));
  }

  function kvEditor(obj, key, kPh, vPh) {
    const map = obj[key] = obj[key] || {};
    const wrap = h("div", null);
    const draw = () => { clear(wrap).append(Object.entries(map).map(([k, v]) => h("div", { class: "row" },
      h("input", { type: "text", style: { width: "35%" }, value: k, placeholder: kPh, onchange: (e) => { const nk = e.target.value.trim(); if (nk && nk !== k) { const val = map[k]; delete map[k]; map[nk] = val; touch(); draw(); } } }),
      h("input", { type: "text", class: "grow", value: typeof v === "string" ? v : JSON.stringify(v), placeholder: vPh, oninput: (e) => { map[k] = coerce(e.target.value); touch(); } }),
      h("button", { class: "btn btn-ghost btn-sm", onclick: () => { delete map[k]; touch(); draw(); } }, "✕"))),
      h("button", { class: "btn btn-sm", onclick: () => { let n = "field"; let i = 1; while (n in map) n = "field" + ++i; map[n] = ""; touch(); draw(); } }, "+ add"));
    };
    draw(); return wrap;
  }
  const coerce = (s) => (s === "true" ? true : s === "false" ? false : /^-?\d+(\.\d+)?$/.test(s) ? Number(s) : s);

  // -------------------------------------------------------------------------- entries
  function entryEditor(e, i) {
    const hints = App.hints, bad = errForEntry(i).length > 0;
    const extras = () => Object.keys(e).filter((k) => !KNOWN.includes(k));
    const v = (e.verification = e.verification || { sources: ["manual_review"], stage1_paths: [], criteria: "" });
    e.monitoring = e.monitoring || [];
    const wrap = h("div", { class: "row" });
    const exKv = (() => { const tmp = {}; extras().forEach((k) => (tmp[k] = e[k])); return tmp; })();
    return h("details", { class: "entry" + (bad ? " invalid" : ""), "data-entry": e.id, open: openSet.has(i) || bad, ontoggle: (ev) => { ev.target.open ? openSet.add(i) : openSet.delete(i); } },
      h("summary", null, h("span", { class: "mono", style: { minWidth: "84px" } }, e.id), h("span", { class: "title grow" }, e.title || "(untitled)"), prioBadge(e.priority || "medium"), (v.sources || []).map((s) => badge(fmt.label(s), s === "stage1_dataset" ? "b-info" : ""))),
      h("div", { class: "body" },
        errForEntry(i).length ? banner("bad", "Fix in this requirement:", errForEntry(i).map((p) => ({ path: (p.path || "").replace(`entries[${i}].`, "").replace(`entries[${i}]`, ""), message: p.message }))) : null,
        h("div", { class: "grid cols-2" },
          field("Id", h("input", { type: "text", value: e.id, onchange: (ev) => { e.id = ev.target.value.trim(); touch(); drawEditor(); } }), "Unique across the whole list, e.g. ABC-001."),
          field("Priority", h("select", { onchange: (ev) => { e.priority = ev.target.value; touch(); drawEditor(); } }, hints.priorities.map((p) => h("option", { value: p, selected: e.priority === p }, p))))),
        field("Title", h("input", { type: "text", value: e.title, oninput: (ev) => { e.title = ev.target.value; const t = ev.target.closest("details").querySelector("summary .title"); if (t) t.textContent = e.title || "(untitled)"; touch(); } })),
        field("Requirement", h("textarea", { oninput: (ev) => { e.requirement = ev.target.value; touch(); } }, e.requirement), "What must be true."),
        field("Best practice", h("textarea", { oninput: (ev) => { e.best_practice = ev.target.value; touch(); } }, e.best_practice)),
        field("Audit requirement", h("textarea", { style: { minHeight: "50px" }, oninput: (ev) => { e.audit_requirement = ev.target.value.trim() ? ev.target.value : null; touch(); } }, e.audit_requirement || ""), "Leave empty if none is tied to this requirement."),
        field("Extends (an earlier requirement this specialises)", h("input", { type: "text", list: "dl-entries", value: e.extends || "", oninput: (ev) => { if (ev.target.value.trim()) e.extends = ev.target.value.trim(); else delete e.extends; touch(); } })),
        h("div", { class: "sub" }, h("div", { class: "lbl" }, "Monitoring or telemetry that verifies it"),
          e.monitoring.map((m, mi) => h("div", { class: "row" },
            h("select", { style: { width: "170px" }, "aria-label": "Signal source", onchange: (ev) => { m.source = ev.target.value; touch(); } }, hints.signal_sources.map((s) => h("option", { value: s, selected: m.source === s }, fmt.label(s)))),
            h("input", { type: "text", class: "grow", value: m.signal, placeholder: "signal", "aria-label": "Signal", oninput: (ev) => { m.signal = ev.target.value; touch(); } }),
            h("input", { type: "text", style: { width: "28%" }, value: m.detail || "", placeholder: "detail (optional)", "aria-label": "Detail", oninput: (ev) => { if (ev.target.value) m.detail = ev.target.value; else delete m.detail; touch(); } }),
            h("button", { class: "btn btn-ghost btn-sm", title: "Remove", onclick: () => { e.monitoring.splice(mi, 1); touch(); drawEditor(); } }, "✕"))),
          h("button", { class: "btn btn-sm", onclick: () => { e.monitoring.push({ source: "platform", signal: "" }); touch(); drawEditor(); } }, "+ signal")),
        h("div", { class: "sub" }, h("div", { class: "lbl" }, "Verification (how gap analysis checks it)"),
          h("div", null, hints.evidence_sources.map((s) => h("label", { class: "check" }, h("input", { type: "checkbox", checked: (v.sources || []).includes(s), onchange: (ev) => {
            v.sources = (v.sources || []).filter((x) => x !== s); if (ev.target.checked) v.sources.push(s); touch(); drawEditor(); } }), fmt.label(s)))),
          h("div", { class: "lbl", style: { marginTop: "8px" } }, "Stage 1 dataset paths (required when stage1_dataset is a source)"),
          (v.stage1_paths = v.stage1_paths || []).map((p, pi) => h("div", { class: "row" },
            h("input", { type: "text", class: "grow mono", list: "dl-paths", value: p, "aria-label": "Dataset path", oninput: (ev) => { v.stage1_paths[pi] = ev.target.value.trim(); touch(); }, placeholder: "infrastructure.workloads[].containers[].readiness" }),
            h("button", { class: "btn btn-ghost btn-sm", onclick: () => { v.stage1_paths.splice(pi, 1); touch(); drawEditor(); } }, "✕"))),
          h("button", { class: "btn btn-sm", onclick: () => { v.stage1_paths.push(""); touch(); drawEditor(); } }, "+ dataset path"),
          field("Pass criteria", h("textarea", { style: { marginTop: "8px" }, oninput: (ev) => { v.criteria = ev.target.value; touch(); } }, v.criteria), "The test the assessor applies to the dataset evidence.")),
        h("div", { class: "sub" }, h("div", { class: "lbl" }, "Module-specific fields"), extraFields(e, extras)),
        h("div", { class: "actions" },
          h("button", { class: "btn btn-sm", disabled: i === 0, onclick: () => { moveEntry(i, -1); } }, "↑ Move up"), h("button", { class: "btn btn-sm", disabled: i === cur.doc.entries.length - 1, onclick: () => moveEntry(i, 1) }, "↓ Move down"),
          h("button", { class: "btn btn-sm", onclick: () => dupEntry(i) }, "Duplicate"), h("button", { class: "btn btn-sm btn-danger", onclick: async () => { if (await confirmBox("Delete requirement", `Delete ${e.id}? Save to apply it.`, "Delete", true)) { cur.doc.entries.splice(i, 1); touch(); drawEditor(); } } }, "Delete"))));
  }

  function extraFields(e, extras) {
    const wrap = h("div", null);
    const draw = () => { clear(wrap).append(extras().map((k) => h("div", { class: "row" },
      h("input", { type: "text", style: { width: "32%" }, value: k, "aria-label": "Field name", onchange: (ev) => { const nk = ev.target.value.trim(); if (nk && nk !== k && !KNOWN.includes(nk)) { e[nk] = e[k]; delete e[k]; touch(); draw(); } } }),
      h("input", { type: "text", class: "grow", value: typeof e[k] === "string" ? e[k] : JSON.stringify(e[k]), "aria-label": "Field value", oninput: (ev) => { e[k] = coerce(ev.target.value); touch(); } }),
      h("button", { class: "btn btn-ghost btn-sm", onclick: () => { delete e[k]; touch(); draw(); } }, "✕"))),
      h("button", { class: "btn btn-sm", onclick: () => { let n = "field"; let i = 1; while (n in e) n = "field" + ++i; e[n] = ""; touch(); draw(); } }, "+ field"));
    };
    draw(); return wrap;
  }

  function nextId() {
    const es = cur.doc.entries, pfx = es.length ? es[0].id.split("-")[0] : (cur.doc.id || "NEW").toUpperCase().slice(0, 4);
    const nums = es.map((e) => parseInt((e.id.split("-").pop() || "0"), 10) || 0);
    return `${pfx}-${String(Math.max(0, ...nums) + 1).padStart(3, "0")}`;
  }
  function addEntry() {
    const id = nextId();
    cur.doc.entries.push({ id, title: "New requirement", requirement: "Describe the requirement.", best_practice: "Describe the best practice.", audit_requirement: null, priority: "medium",
      monitoring: [{ source: "platform", signal: "" }], verification: { sources: ["manual_review"], stage1_paths: [], criteria: "Describe how this is judged." } });
    openSet.add(cur.doc.entries.length - 1); touch(); drawEditor();
    setTimeout(() => { const el = main.querySelector(`[data-entry="${id}"]`); if (el) el.scrollIntoView({ block: "center" }); }, 30);
  }
  function dupEntry(i) { const c = deepCopy(cur.doc.entries[i]); c.id = nextId(); c.title += " (copy)"; cur.doc.entries.splice(i + 1, 0, c); openSet = new Set([i + 1]); touch(); drawEditor(); }
  function moveEntry(i, d) { const es = cur.doc.entries; [es[i], es[i + d]] = [es[i + d], es[i]]; openSet = new Set([i + d]); touch(); drawEditor(); }
  function filterEntries(q) { q = q.toLowerCase(); document.querySelectorAll("#entries details.entry").forEach((el) => { el.hidden = !!q && !el.textContent.toLowerCase().includes(q) && !el.dataset.entry.toLowerCase().includes(q); }); }

  // -------------------------------------------------------------- validation and saving
  function pathToEntry(path) { const m = /^entries\[(\d+)\]/.exec(path || ""); return m ? cur.doc.entries[+m[1]] : null; }
  function showProblems() {
    const el = $("#problems"); if (!el) return; clear(el);
    if (!problems.length) return;
    el.append(banner("bad", `${problems.length} problem${problems.length === 1 ? "" : "s"}: fix before saving`, problems.map((p) => { const en = pathToEntry(p.path); return (en ? en.id + " " : p.entry ? p.entry + " " : "") + (p.path ? "(" + p.path + ") " : "") + p.message; })));
  }
  function scheduleValidate() { clearTimeout(vTimer); vTimer = setTimeout(() => validateNow(true), 900); }
  async function validateNow(quiet) {
    if (!cur) return;
    try { const r = await api("/nfr/validate", { method: "POST", body: { module: canon(cur.doc), module_id: cur.id } }); problems = r.problems; }
    catch (e) { problems = [{ path: "", message: e.message }]; }
    const open = new Set([...document.querySelectorAll("#entries details")].map((d, i) => (d.open ? i : -1)).filter((i) => i >= 0)); open.forEach((i) => openSet.add(i));
    document.querySelectorAll("#entries details.entry").forEach((el, i) => { const bad = errForEntry(i).length > 0; el.classList.toggle("invalid", bad); if (bad) el.open = true; });
    showProblems(); updateBar();
    if (!quiet) toast(problems.length ? `${problems.length} problem(s) found` : "Valid: this module can be saved", problems.length ? "bad" : "ok");
  }
  function actionBar() {
    return h("div", { class: "sticky-save", id: "bar" }, h("span", { id: "bar-state", class: "grow small muted" }),
      !cur.isNew && cur.backups.length ? h("button", { class: "btn btn-sm", onclick: historyDialog }, `History (${cur.backups.length})`) : null,
      !cur.isNew && cur.doc.layer !== "baseline" ? h("button", { class: "btn btn-sm btn-danger", onclick: deleteModule }, "Delete module") : null,
      h("button", { class: "btn btn-sm", onclick: () => validateNow(false) }, "Validate"),
      h("button", { class: "btn btn-sm", id: "btn-discard", onclick: async () => { if (!dirty() || await confirmBox("Discard changes", "Throw away your unsaved edits?", "Discard", true)) { if (cur.isNew) location.hash = "#/catalogue"; else openModule(cur.id); } } }, "Discard"),
      h("button", { class: "btn btn-primary", id: "btn-save", onclick: save }, cur.isNew ? "Create module" : "Save"));
  }
  function updateBar() {
    const st = $("#bar-state"), sv = $("#btn-save"), dc = $("#btn-discard"); if (!st) return;
    const isDirty = cur.isNew || dirty();
    st.textContent = saving ? "Saving..." : problems.length ? `${problems.length} problem(s)` : isDirty ? (cur.isNew ? "Not created yet" : "Unsaved changes") : "No changes";
    st.style.color = problems.length ? "var(--bad)" : isDirty ? "var(--warn)" : "";
    sv.disabled = saving || !isDirty; dc.disabled = !isDirty;
  }
  async function save() {
    const txt = snap(cur.doc);
    if (/TODO|Describe the (requirement|best practice)/.test(txt) && !(await confirmBox("Placeholder text remains", "Some fields still contain placeholder text (\"TODO\" or \"Describe ...\"). Save anyway?", "Save anyway"))) return;
    saving = true; updateBar();
    try {
      const r = cur.isNew ? await api("/nfr/modules", { method: "POST", body: { module: canon(cur.doc) } }) : await api("/nfr/modules/" + cur.id, { method: "PUT", body: { module: canon(cur.doc), etag: cur.etag } });
      toast(cur.isNew ? "Module created; JSON rebuilt" : "Saved; JSON rebuilt", "ok");
      App.hints = await api("/nfr/hints"); saving = false;
      if (cur.isNew) { location.hash = "#/catalogue/" + r.module.id; return; }
      cur = { id: cur.id, isNew: false, etag: r.etag, file: r.file, backups: r.backups, doc: deepCopy(r.module), orig: snap(r.module), note: null }; problems = [];
      mods = await api("/nfr/modules"); drawSide(cur.id); drawEditor();
    } catch (e) {
      saving = false; problems = e.problems || [{ path: "", message: e.message }];
      if (e.status === 409) toast(e.message, "bad"); else toast(e.message, "bad");
      drawEditor();
    }
  }
  async function deleteModule() {
    if (!(await confirmBox("Delete module", `Delete "${cur.doc.title}" and its telemetry catalogue placeholders? The previous file is kept as a backup. This is refused if other modules extend it.`, "Delete module", true))) return;
    try { await api("/nfr/modules/" + cur.id, { method: "DELETE" }); toast("Module deleted", "ok"); cur = null; App.hints = null; location.hash = "#/catalogue"; }
    catch (e) { problems = e.problems; toast(e.message, "bad"); drawEditor(); }
  }
  function historyDialog() {
    modal({ title: "Previous versions", body: h("div", null, h("p", { class: "small muted" }, "Restoring validates the old version and saves it as a new version; nothing is lost."),
      h("div", { class: "table-wrap" }, h("table", null, h("tbody", null, cur.backups.map((b) => h("tr", null, h("td", null, fmt.time(b.saved_at)), h("td", { class: "right" }, h("button", { class: "btn btn-sm", onclick: async () => {
        try { await api(`/nfr/modules/${cur.id}/restore`, { method: "POST", body: { backup: b.name, etag: cur.etag } }); toast("Restored", "ok"); $("#modal-root").replaceChildren(); openModule(cur.id); }
        catch (e) { toast(e.message, "bad"); } } }, "Restore")))))))), actions: [{ label: "Close" }] });
  }

  // ------------------------------------------------------------ read-only catalogues
  async function catalogueView(which) {
    clear(main).append(spinner());
    let c; try { c = await api("/nfr/catalogues/" + (which === "_oneagent" ? "oneagent" : "instrumentation")); } catch (e) { clear(main).append(banner("bad", e.message)); return; }
    const isOA = which === "_oneagent", q = { v: "" }, listEl = h("div", null);
    const draw = () => {
      clear(listEl);
      Object.entries(c.modules).filter(([id, m]) => !q.v || (id + " " + (m.summary || "")).toLowerCase().includes(q.v.toLowerCase())).forEach(([id, m]) => {
        listEl.append(isOA ? oaModule(id, m) : instModule(id, m));
      });
    };
    clear(main).append(h("div", { class: "page-head" }, h("div", null, h("h1", null, isOA ? "OneAgent default telemetry" : "Application-level instrumentation"),
      h("p", null, isOA ? "Tier 1: what Dynatrace OneAgent captures with zero configuration, per module." : "Tier 2: metrics the application emits through library instrumentation, per module."))),
      h("div", { class: "banner info" }, "Read-only view. ", c.provenance), h("div", { class: "filters" }, h("input", { type: "search", placeholder: "Filter modules...", "aria-label": "Filter", oninput: (e) => { q.v = e.target.value; draw(); } })), listEl);
    draw();
  }
  function oaModule(id, m) {
    return h("details", { class: "card" }, h("summary", null, h("b", null, id), " ", badge(m.support_level, m.support_level === "full" ? "b-met" : m.support_level === "none" ? "b-not_assessable" : "b-partially_met"), h("span", { class: "muted small" }, "  " + (m.signals || []).length + " signals")),
      h("p", { class: "small", style: { marginTop: "8px" } }, m.summary), (m.inherits || []).length ? h("p", { class: "small muted" }, "Also inherits: ", m.inherits.join(", ")) : null,
      (m.signals || []).length ? h("div", { class: "table-wrap" }, h("table", null, h("thead", null, h("tr", null, ["Signal", "Category", "Type", "Metric key", "Confidence"].map((x) => h("th", null, x)))),
        h("tbody", null, m.signals.map((s) => h("tr", null, h("td", null, s.name, h("div", { class: "small muted" }, s.description)), h("td", null, s.category), h("td", null, s.signal_type), h("td", { class: "mono small" }, s.metric_key || "-"), h("td", null, s.confidence)))))) : null,
      (m.not_covered_by_default || []).length ? h("div", { style: { marginTop: "10px" } }, h("div", { class: "lbl" }, "Not covered by default"), h("ul", { class: "small" }, m.not_covered_by_default.map((g) => h("li", null, h("b", null, g.signal), " (", g.likely_source, "): ", g.why)))) : null);
  }
  function instModule(id, m) {
    return h("details", { class: "card" }, h("summary", null, h("b", null, id), h("span", { class: "muted small" }, "  " + (m.libraries || []).length + " libraries")), h("p", { class: "small", style: { marginTop: "8px" } }, m.summary),
      m.reason_none ? h("p", { class: "small muted" }, "No library metrics: ", m.reason_none) : null,
      (m.libraries || []).map((l) => h("div", { class: "sub" }, h("b", null, l.library), " ", l.confidence === "medium" ? badge("medium confidence", "b-partially_met") : null,
        h("div", { class: "small" }, h("b", null, "Enabled by: "), l.configuration), h("div", { class: "small" }, h("b", null, "Export: "), l.export),
        h("div", { style: { marginTop: "6px" } }, (l.metrics || []).map((x) => h("span", { class: "chip", title: x.description + (x.enabled_by_default === false ? " (opt-in)" : "") }, x.name + (x.enabled_by_default === false ? " *" : "")))))));
  }

  return { render, prefill, isDirty: dirty };
})();
