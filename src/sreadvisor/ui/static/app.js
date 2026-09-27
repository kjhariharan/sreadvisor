/* Router and boot. Hash routes: #/analyze  #/reports[/service[/tab]]  #/catalogue[/module|new|_oneagent|_instrumentation][?entry=ID]  #/jobs[/id] */
"use strict";

(() => {
  const view = $("#view");
  let lastHash = location.hash || "#/analyze", ignoreNext = false;

  function parse() {
    const raw = (location.hash || "#/analyze").slice(1), [pathPart, qs] = raw.split("?");
    const parts = pathPart.split("/").filter(Boolean), query = Object.fromEntries(new URLSearchParams(qs || ""));
    return { parts, query };
  }

  async function route() {
    const { parts, query } = parse(), section = parts[0] || "analyze";
    Jobs.stop(); setActiveNav(section);
    document.title = "sreadvisor · " + ({ analyze: "Analyze", reports: "Reports", catalogue: "NFR catalogue", jobs: "Jobs" }[section] || "");
    try {
      if (!App.meta) await refreshMeta();
      if (section === "analyze") await Analyze.render(view);
      else if (section === "reports") await Reports.render(view, parts[1], parts[2]);
      else if (section === "catalogue") await Catalogue.render(view, parts[1], query);
      else if (section === "jobs") await Jobs.render(view, parts[1]);
      else { location.hash = "#/analyze"; return; }
    } catch (e) { clear(view).append(banner("bad", "Something went wrong: " + e.message)); console.error(e); }
    view.focus({ preventScroll: true });
    if (section !== "catalogue" && section !== "reports") window.scrollTo(0, 0);
  }

  window.addEventListener("hashchange", async () => {
    if (ignoreNext) { ignoreNext = false; return; }
    if (Catalogue.isDirty() && !location.hash.startsWith("#/catalogue/" + (parse().parts[1] || "\u0000")) ) {
      const ok = await confirmBox("Unsaved changes", "You have unsaved edits in the catalogue. Leave without saving?", "Leave", true);
      if (!ok) { ignoreNext = true; location.hash = lastHash; return; }
    }
    lastHash = location.hash; route();
  });
  window.addEventListener("beforeunload", (e) => { if (Catalogue.isDirty()) { e.preventDefault(); e.returnValue = ""; } });

  // Keep the header's model and job indicators fresh.
  setInterval(() => { if (!document.hidden) refreshMeta(); }, 15000);
  refreshMeta().then(route);
})();
