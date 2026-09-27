/* Shared helpers. Everything is built with DOM nodes (textContent), never innerHTML, so report and config text can not inject markup. */
"use strict";

/* Native Element.append() renders null as the text "null" and arrays as "[object ...]". Views pass conditional children and arrays freely,
   so append() is made to skip null/false and flatten arrays. */
Element.prototype.append = function (...kids) {
  for (const c of kids.flat(Infinity)) {
    if (c == null || c === false) continue;
    this.appendChild(c.nodeType ? c : document.createTextNode(String(c)));
  }
};

function h(tag, attrs, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === false || v == null) continue;
    if (k === "class") e.className = v;
    else if (k === "style" && typeof v === "object") Object.assign(e.style, v);
    else if (k.startsWith("on") && typeof v === "function") e.addEventListener(k.slice(2), v);
    else if (["checked", "disabled", "selected", "open", "hidden", "readOnly", "multiple"].includes(k)) e[k] = !!v;
    else if (k === "value") e._pendingValue = v;
    else e.setAttribute(k, v === true ? "" : v);
  }
  for (const c of kids.flat(Infinity)) {
    if (c == null || c === false) continue;
    e.append(c.nodeType ? c : document.createTextNode(String(c)));
  }
  if ("_pendingValue" in e) e.value = e._pendingValue; // after children, so <select> options exist
  return e;
}
const $ = (sel, root = document) => root.querySelector(sel);
const clear = (node) => { while (node.firstChild) node.removeChild(node.firstChild); return node; };

async function api(path, opts = {}) {
  const init = { method: opts.method || "GET", headers: {} };
  if (opts.body !== undefined) { init.headers["Content-Type"] = "application/json"; init.body = JSON.stringify(opts.body); }
  let res;
  try { res = await fetch("/api" + path, init); } catch (e) { throw Object.assign(new Error("Cannot reach the sreadvisor server. Is it still running?"), { problems: [] }); }
  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch (e) { data = text; }
  if (!res.ok) {
    const err = new Error((data && data.error) || (typeof data === "string" && data) || `Request failed (${res.status})`);
    err.status = res.status; err.problems = (data && data.problems) || [];
    throw err;
  }
  return data;
}

function toast(msg, kind) {
  const t = h("div", { class: "toast " + (kind || "") }, msg);
  $("#toasts").append(t);
  setTimeout(() => t.remove(), kind === "bad" ? 7000 : 3500);
}

function modal({ title, body, actions }) {
  const root = $("#modal-root");
  const close = () => clear(root);
  const back = h("div", { class: "modal-back", onclick: (e) => { if (e.target === back) close(); } },
    h("div", { class: "modal", role: "dialog", "aria-modal": "true", "aria-label": title }, h("h2", null, title), body,
      h("div", { class: "actions" }, (actions || []).map((a) => h("button", { class: "btn " + (a.class || ""), onclick: async () => { if (a.onclick) { const keep = await a.onclick(close); if (keep === true) return; } close(); } }, a.label)))));
  clear(root).append(back);
  const first = back.querySelector("input,select,textarea,button.btn-primary");
  if (first) first.focus();
  return close;
}
function confirmBox(title, message, okLabel, danger) {
  return new Promise((resolve) => modal({ title, body: h("p", null, message),
    actions: [{ label: "Cancel", onclick: () => resolve(false) }, { label: okLabel || "OK", class: danger ? "btn-danger" : "btn-primary", onclick: () => resolve(true) }] }));
}

const fmt = {
  time(ts) { if (!ts) return "-"; const d = new Date(typeof ts === "number" ? ts * 1000 : ts); return isNaN(d) ? "-" : d.toLocaleString(); },
  ago(ts) { if (!ts) return ""; const s = Math.max(0, Date.now() / 1000 - (typeof ts === "number" ? ts : new Date(ts).getTime() / 1000)); if (s < 90) return "just now"; if (s < 5400) return Math.round(s / 60) + " min ago"; if (s < 129600) return Math.round(s / 3600) + " h ago"; return Math.round(s / 86400) + " d ago"; },
  dur(a, b) { const s = Math.round(((b || Date.now() / 1000) - a)); return s < 60 ? s + " s" : Math.floor(s / 60) + " min " + (s % 60) + " s"; },
  kb(n) { return n > 1048576 ? (n / 1048576).toFixed(1) + " MB" : Math.round(n / 1024) + " KB"; },
  label(s) { return String(s || "").replace(/_/g, " "); },
};

const badge = (text, cls) => h("span", { class: "badge " + (cls || "") }, text);
const statusBadge = (s) => badge(fmt.label(s), "b-" + s);
const prioBadge = (p) => badge(p, "b-" + p);
const loc = (file, line) => h("span", { class: "loc" }, line ? `${file}:${line}` : file);
const spinner = (msg) => h("div", { class: "empty" }, h("span", { class: "spinner" }), " ", msg || "Loading...");
const emptyState = (title, text, action) => h("div", { class: "empty" }, h("h3", null, title), h("p", null, text), action || null);

function banner(kind, title, problems) {
  const list = (problems || []).map((p) => (typeof p === "string" ? p : (p.path ? p.path + ": " : "") + p.message));
  return h("div", { class: "banner " + kind, role: kind === "bad" ? "alert" : "status" }, h("b", null, title),
    list.length ? h("ul", null, list.slice(0, 30).map((p) => h("li", null, p))) : null);
}

/* Small state shared across views. */
const App = { meta: null, hints: null, paths: null, currentJob: null };

async function refreshMeta() {
  try { App.meta = await api("/meta"); } catch (e) { return; }
  const m = App.meta.model, pill = $("#model-pill");
  pill.textContent = m.label; pill.className = "pill " + (m.problem ? "bad" : "ok");
  pill.title = m.problem ? "Model problem: " + m.problem : "Model backend reachable";
  $("#job-pill").hidden = !App.meta.running_job;
  if (App.meta.running_job) $("#job-pill").href = "#/jobs/" + App.meta.running_job;
}

function setActiveNav(name) { document.querySelectorAll("#nav a").forEach((a) => a.classList.toggle("active", a.dataset.nav === name)); }
function download(text, filename, type) { const a = h("a", { href: URL.createObjectURL(new Blob([text], { type: type || "application/json" })), download: filename }); document.body.append(a); a.click(); a.remove(); }
const deepCopy = (o) => JSON.parse(JSON.stringify(o));
const slugify = (s) => String(s || "").toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "");
