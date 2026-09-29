/* Analyze: fill in (or load) a per-service config, validate it, and run the pipeline as a background job. */
"use strict";

const Analyze = (() => {
  const blank = () => ({ saved: null, service_name: "", repos: [{ kind: "path", value: "", ref: "" }], iac: [""], provider: "", service_id: "", options: {},
    output_dir: "", token: "", run: { no_llm: false, refresh_graph: false, gaps: false, model_backend: "", ollama_model: "" } });
  let S = blank(), result = null, root = null;

  function fromConfig(name, cfg) {
    const s = blank();
    s.saved = name; s.service_name = cfg.service_name || "";
    s.repos = (cfg.code_repos || []).map((r) => (typeof r === "string" ? { kind: /^(https?:|git@|ssh:)/.test(r) ? "url" : "path", value: r, ref: "" }
      : { kind: r.url ? "url" : "path", value: r.url || r.path || "", ref: r.ref || "" }));
    if (!s.repos.length) s.repos = blank().repos;
    s.iac = (cfg.iac_paths || []).length ? [...cfg.iac_paths] : [""];
    const o = cfg.observability || {};
    s.provider = o.provider || ""; s.service_id = o.service_id || ""; s.options = { ...(o.options || {}) };
    s.output_dir = cfg.output_dir || "";
    return s;
  }
  function toConfig() {
    const options = {};
    for (const [k, v] of Object.entries(S.options)) if (v !== "" && v != null && k !== "api_token") options[k] = v;
    const cfg = {
      service_name: S.service_name.trim(),
      code_repos: S.repos.filter((r) => r.value.trim()).map((r) => (r.kind === "url" ? { url: r.value.trim(), ...(r.ref.trim() ? { ref: r.ref.trim() } : {}) } : { path: r.value.trim() })),
      iac_paths: S.iac.map((p) => p.trim()).filter(Boolean),
      observability: { provider: S.provider, service_id: S.service_id.trim(), options },
    };
    if (S.output_dir.trim()) cfg.output_dir = S.output_dir.trim();
    return cfg;
  }
  const cfgName = () => S.saved || slugify(S.service_name).replace(/_/g, "-");

  function rowsEditor(list, makeRow, addLabel, onAdd) {
    return h("div", null, list.map((item, i) => makeRow(item, i)), h("button", { class: "btn btn-sm", type: "button", onclick: () => { onAdd(); draw(); } }, "+ " + addLabel));
  }

  function providerFields() {
    const p = (App.meta.providers || []).find((x) => x.name === S.provider);
    if (!p) return h("p", { class: "hint" }, "Choose the active observability provider.");
    const ph = { environment_url: "https://abc12345.live.dynatrace.com", api_token_env: "DT_API_TOKEN", topology_file: "path/to/topology.json", metrics_file: "path/to/metrics.json" };
    const help = { api_token_env: "Name of the environment variable that holds the API token. The token itself is never written to the config." };
    const fields = p.options.filter((o) => o !== "api_token");
    const out = fields.map((o) => h("label", { class: "field" }, h("span", null, fmt.label(o)),
      h("input", { type: "text", value: S.options[o] || "", placeholder: ph[o] || "", oninput: (e) => { S.options[o] = e.target.value; } }), help[o] ? h("div", { class: "hint" }, help[o]) : null));
    if (p.options.includes("api_token")) {
      const env = S.options.api_token_env || "DT_API_TOKEN", present = App.meta.env[env];
      out.push(h("label", { class: "field" }, h("span", null, "API token (this run only)"),
        h("input", { type: "password", autocomplete: "off", value: S.token, placeholder: present ? `using $${env} from the server's environment` : "paste a token, or set $" + env + " before starting the UI",
          oninput: (e) => { S.token = e.target.value; } }),
        h("div", { class: "hint" }, present ? h("span", null, "$", env, " is set on the server. Leave this empty to use it.") : h("span", null, "$", env, " is not set. A token entered here is passed to the run only and is never saved to disk."))));
    }
    return out;
  }

  function resultBox() {
    if (!result) return null;
    if (result.error) return banner("bad", result.error, result.problems);
    if (result.valid) return banner("ok", "Configuration is valid.");
    const tokenOnly = result.problems.length && result.problems.every((p) => /api_token/.test(typeof p === "string" ? p : p.message || ""));
    return h("div", null, banner("bad", "Fix these before running:", result.problems),
      tokenOnly ? h("button", { class: "btn btn-sm", onclick: () => save(true) }, "Save anyway (token supplied at run time)") : null);
  }

  async function validate() {
    try { const r = await api("/configs/validate", { method: "POST", body: { config: toConfig(), token: S.token } }); result = r; }
    catch (e) { result = { error: e.message, problems: e.problems }; }
    draw();
  }
  async function save(force) {
    try {
      const r = await api("/configs/" + encodeURIComponent(cfgName() || "service"), { method: "PUT", body: { config: toConfig(), token: S.token, force: !!force } });
      S.saved = r.name; result = { valid: true, problems: [] }; await refreshMeta(); toast("Saved config/" + r.file, "ok"); draw(); return true;
    } catch (e) { result = { error: e.message, problems: e.problems.map((p) => (p.message || p)) }; result.valid = false; draw(); return false; }
  }
  async function run() {
    if (!(await save(true))) return;
    try {
      const job = await api("/jobs/analyze", { method: "POST", body: { config: S.saved, token: S.token || undefined, ...S.run } });
      toast("Started: " + job.label, "ok"); await refreshMeta(); location.hash = "#/jobs/" + job.id;
    } catch (e) { result = { error: e.message, problems: e.problems }; draw(); }
  }

  function draw() {
    const m = App.meta;
    const running = !!m.running_job;
    const saved = h("select", { onchange: async (e) => { if (!e.target.value) { S = blank(); result = null; draw(); return; }
      try { const c = await api("/configs/" + e.target.value); S = fromConfig(c.name, c.config); result = null; draw(); } catch (err) { toast(err.message, "bad"); } } },
      h("option", { value: "" }, "New service..."), m.configs.map((c) => h("option", { value: c.name, selected: c.name === S.saved }, `${c.service_name || c.name} (${c.file})`)));
    clear(root).append(
      h("div", { class: "page-head" }, h("div", null, h("h1", null, "Analyze a service"),
        h("p", null, "Point sreadvisor at a code repository and its infrastructure-as-code. It fingerprints the stack, traces transaction flows, and writes a consolidated dataset, an NFR coverage report, and (optionally) the gap analysis.")),
        h("div", { class: "actions" }, h("label", { class: "field", style: { margin: 0 } }, h("span", null, "Saved services"), saved))),
      m.model.problem ? banner("warn", "The model is not available: " + m.model.problem, ["Tick \"Skip LLM steps\" to run only the deterministic analysis."]) : null,
      h("div", { class: "grid cols-2" },
        h("div", null,
          h("div", { class: "card" }, h("h2", null, "Service"),
            h("label", { class: "field" }, h("span", null, "Service name"), h("input", { type: "text", value: S.service_name, placeholder: "spring-petclinic", oninput: (e) => { S.service_name = e.target.value; } })),
            h("div", { class: "lbl" }, "Code repositories (a local path or a git URL)"),
            rowsEditor(S.repos, (r, i) => h("div", { class: "row" },
              h("select", { style: { width: "92px" }, onchange: (e) => { r.kind = e.target.value; draw(); } }, h("option", { value: "path", selected: r.kind === "path" }, "path"), h("option", { value: "url", selected: r.kind === "url" }, "git URL")),
              h("input", { type: "text", class: "grow", value: r.value, placeholder: r.kind === "url" ? "https://github.com/org/repo.git" : "C:\\work\\my-service", oninput: (e) => { r.value = e.target.value; } }),
              r.kind === "url" ? h("input", { type: "text", style: { width: "110px" }, value: r.ref, placeholder: "branch/tag", oninput: (e) => { r.ref = e.target.value; } }) : null,
              S.repos.length > 1 ? h("button", { class: "btn btn-ghost btn-sm", title: "Remove", onclick: () => { S.repos.splice(i, 1); draw(); } }, "✕") : null), "repository", () => S.repos.push({ kind: "path", value: "", ref: "" })),
            h("div", { class: "lbl", style: { marginTop: "14px" } }, "Infrastructure-as-code paths (Helm, Kubernetes, Terraform, CI/CD; may be the same folder)"),
            rowsEditor(S.iac, (p, i) => h("div", { class: "row" },
              h("input", { type: "text", class: "grow", value: p, placeholder: "C:\\work\\my-service\\deploy", oninput: (e) => { S.iac[i] = e.target.value; } }),
              S.iac.length > 1 ? h("button", { class: "btn btn-ghost btn-sm", title: "Remove", onclick: () => { S.iac.splice(i, 1); draw(); } }, "✕") : null), "IaC path", () => S.iac.push("")),
            h("p", { class: "hint" }, "Relative paths are resolved against ", h("code", null, m.workspace), ".")),
          h("div", { class: "card" }, h("h2", null, "Observability provider"),
            h("label", { class: "field" }, h("span", null, "Active provider"), h("select", { onchange: (e) => { S.provider = e.target.value; S.options = {}; draw(); } },
              h("option", { value: "" }, "Select..."), m.providers.map((p) => h("option", { value: p.name, selected: p.name === S.provider }, p.name)))),
            h("label", { class: "field" }, h("span", null, "Service ID in the provider"), h("input", { type: "text", value: S.service_id, placeholder: (App.meta.providers.find((p) => p.name === S.provider) || {}).name === "dynatrace" ? "SERVICE-0123456789ABCDEF" : "", oninput: (e) => { S.service_id = e.target.value; } })),
            providerFields())),
        h("div", null,
          h("div", { class: "card" }, h("h2", null, "Run options"),
            h("label", { class: "field" }, h("span", null, "Output directory (optional)"), h("input", { type: "text", value: S.output_dir, placeholder: "output", oninput: (e) => { S.output_dir = e.target.value; } })),
            h("div", null,
              h("label", { class: "check" }, h("input", { type: "checkbox", checked: S.run.no_llm, onchange: (e) => { S.run.no_llm = e.target.checked; } }), "Skip LLM steps (fast, deterministic only)"),
              h("label", { class: "check" }, h("input", { type: "checkbox", checked: S.run.refresh_graph, onchange: (e) => { S.run.refresh_graph = e.target.checked; } }), "Rebuild the code graph"),
              h("label", { class: "check" }, h("input", { type: "checkbox", checked: S.run.gaps, onchange: (e) => { S.run.gaps = e.target.checked; } }), "Also run gap analysis")),
            h("div", { class: "row", style: { marginTop: "12px" } },
              h("label", { class: "field grow", style: { margin: 0 } }, h("span", null, "Model backend"), h("select", { onchange: (e) => { S.run.model_backend = e.target.value; } },
                h("option", { value: "" }, `registry default (${m.model.backend})`), ["ollama", "gemini", "vertex"].map((b) => h("option", { value: b, selected: S.run.model_backend === b }, b)))),
              h("label", { class: "field grow", style: { margin: 0 } }, h("span", null, "Ollama model"), h("input", { type: "text", value: S.run.ollama_model, placeholder: "gemma4:latest", oninput: (e) => { S.run.ollama_model = e.target.value; } }))),
            h("p", { class: "hint" }, "Model in use: ", h("code", null, m.model.label), m.model.problem ? " (unavailable)" : " (reachable)"),
            S.run.gaps && !S.run.no_llm ? h("p", { class: "hint" }, "The gap analysis assesses about a hundred requirements with the model; with a local model this can take 20 to 30 minutes.") : null),
          resultBox(),
          h("div", { class: "card" }, h("div", { class: "actions" },
            h("button", { class: "btn", onclick: validate }, "Validate"),
            h("button", { class: "btn", onclick: () => save(false) }, "Save config"),
            h("button", { class: "btn btn-primary", disabled: running, title: running ? "Another job is running" : "", onclick: run }, running ? "A job is running..." : "Save & run analysis")),
            S.saved ? h("p", { class: "hint", style: { marginTop: "10px" } }, "Saved as ", h("code", null, "config/" + S.saved + ".yaml"), " (the same file works with ", h("code", null, "sreadvisor analyze --config"), ").") : null))));
  }

  return {
    async render(view) {
      root = view; clear(root).append(spinner());
      await refreshMeta();
      if (!S.provider && App.meta.providers.length) S.provider = (App.meta.providers.find((p) => p.name === "dynatrace") || App.meta.providers[0]).name;
      draw();
    },
    loadFor(name) { return api("/configs/" + name).then((c) => { S = fromConfig(c.name, c.config); location.hash = "#/analyze"; }); },
  };
})();
