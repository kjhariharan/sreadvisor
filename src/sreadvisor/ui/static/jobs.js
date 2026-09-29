/* Jobs: background runs of the CLI (analyze, gap analysis) with a live log. */
"use strict";

const Jobs = (() => {
  let timer = null;
  const stop = () => { if (timer) { clearInterval(timer); timer = null; } };
  const jobBadge = (s) => badge(s, s === "succeeded" ? "b-met" : s === "failed" ? "b-missing" : s === "running" ? "b-info" : "b-not_assessable");

  async function list(root) {
    stop(); clear(root).append(spinner());
    const draw = async () => {
      const jobs = await api("/jobs"); await refreshMeta();
      clear(root).append(h("div", { class: "page-head" }, h("div", null, h("h1", null, "Jobs"), h("p", null, "Analyses and gap assessments started from this page. One job runs at a time.")),
        h("div", { class: "actions" }, h("a", { class: "btn btn-primary", href: "#/analyze" }, "New analysis"))),
        jobs.length ? h("div", { class: "table-wrap" }, h("table", null, h("thead", null, h("tr", null, ["Job", "Status", "Started", "Duration", "Command"].map((c) => h("th", null, c)))),
          h("tbody", null, jobs.map((j) => h("tr", { class: "clickable", onclick: () => { location.hash = "#/jobs/" + j.id; } },
            h("td", null, j.label), h("td", null, jobBadge(j.status)), h("td", { class: "nowrap" }, fmt.time(j.started)), h("td", { class: "nowrap" }, fmt.dur(j.started, j.finished)), h("td", null, h("code", null, j.command)))))))
          : emptyState("No jobs yet", "Run an analysis to see it here.", h("a", { class: "btn btn-primary", href: "#/analyze" }, "Analyze a service")));
    };
    await draw();
    timer = setInterval(() => { if (location.hash.startsWith("#/jobs") && !location.hash.includes("/", 7)) draw().catch(() => {}); else stop(); }, 3000);
  }

  async function detail(root, id) {
    stop(); clear(root).append(spinner());
    let since = 0, lines = [];
    const logEl = h("pre", { class: "log", "aria-label": "Job log", tabindex: "0" }), head = h("div", null), foot = h("div", null);
    clear(root).append(head, logEl, foot);
    const tick = async () => {
      let j;
      try { j = await api(`/jobs/${id}?since=${since}`); } catch (e) { stop(); clear(root).append(banner("bad", e.message)); return; }
      if (j.log.length) {
        const atBottom = logEl.scrollTop + logEl.clientHeight >= logEl.scrollHeight - 30;
        since = j.log_size; lines = lines.concat(j.log); logEl.textContent = lines.join("\n"); if (atBottom) logEl.scrollTop = logEl.scrollHeight;
      } else if (!lines.length) logEl.textContent = j.status === "running" ? "Waiting for output..." : "(no output)";
      clear(head).append(h("div", { class: "page-head" }, h("div", null, h("h1", null, j.label, " ", jobBadge(j.status)),
        h("p", null, h("code", null, j.command), " · started ", fmt.time(j.started), " · ", fmt.dur(j.started, j.finished))),
        h("div", { class: "actions" }, h("a", { class: "btn", href: "#/jobs" }, "All jobs"),
          j.status === "running" ? h("button", { class: "btn btn-danger", onclick: async () => { await api(`/jobs/${id}/cancel`, { method: "POST" }); tick(); } }, "Cancel") : null)));
      clear(foot);
      if (j.status !== "running") {
        stop(); refreshMeta();
        const named = (j.label.match(/^(?:analyze|gap analysis) (.+)$/) || [])[1];
        const svc = named ? named.replace(/[^A-Za-z0-9_.-]+/g, "-").replace(/^-+|-+$/g, "") : null; // same naming the report files use
        foot.append(h("div", { class: "actions", style: { marginTop: "14px" } },
          j.status === "succeeded" ? h("a", { class: "btn btn-primary", href: svc ? "#/reports/" + encodeURIComponent(svc) : "#/reports" }, "View reports") : banner("bad", "The job did not finish successfully (exit code " + j.returncode + "). See the log above.")));
      }
    };
    await tick();
    timer = setInterval(() => { if (!location.hash.startsWith("#/jobs/")) { stop(); return; } tick().catch(() => {}); }, 1000);
  }
  return { render(view, id) { return id ? detail(view, id) : list(view); }, stop };
})();
