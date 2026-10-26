// Client script (DOM wiring only; view logic is in logic.ts and is concatenated in front of it).
export const APP_SRC = `
const $ = (id) => document.getElementById(id);
async function api(method, path, body) {
  const r = await fetch(path, { method, credentials: "same-origin",
    headers: body ? { "content-type": "application/json" } : {}, body: body ? JSON.stringify(body) : undefined });
  if (r.status === 401) { show(false); throw new Error("Signed out"); }
  if (!r.ok) { const t = await r.text(); let m = t; try { m = JSON.parse(t).error; } catch (_) {} throw new Error(String(m || "HTTP " + r.status).slice(0, 200)); }
  return r.headers.get("content-type") && r.headers.get("content-type").includes("json") ? r.json() : null;
}
const show = (inn) => { $("login").hidden = inn; $("dash").hidden = !inn; };
const fail = (id, e) => { $(id).textContent = e.message; };
async function loadConsoles() {
  try { $("consoles").innerHTML = renderConsoles(await api("GET", "/api/consoles"), Date.now()); } catch (e) { fail("cerr", e); }
}
async function loadRelease() {
  try {
    const s = releaseState(await api("GET", "/api/release"));
    $("rel-text").textContent = s.text; $("rel-err").textContent = s.error ? "Install check failed: " + s.error : "";
    $("btn-update").hidden = !s.canUpdate; $("btn-update").textContent = "Update to " + s.latest;
    $("btn-rollback").hidden = !s.canRollback; $("cmd-box").hidden = !s.showCommand;
    $("cmd").textContent = s.command || ""; return s;
  } catch (e) { fail("rel-err", e); }
}
async function start() { show(true); loadConsoles(); return loadRelease(); }
$("login-form").onsubmit = async (e) => {
  e.preventDefault(); $("lerr").textContent = "";
  try { await api("POST", "/admin/login", { secret: $("secret").value }); $("secret").value = ""; start(); }
  catch (er) { fail("lerr", er.message === "Signed out" ? new Error("Wrong secret") : er); }
};
const copy = (t, b) => navigator.clipboard.writeText(t).then(() => { b.textContent = "Copied"; });
$("copy-cmd").onclick = (e) => copy($("cmd").textContent, e.target);
$("copy-link").onclick = (e) => copy($("link").textContent, e.target);
$("btn-invite").onclick = async () => {
  try {
    const name = $("inv-name").value.trim();
    const r = await api("POST", "/api/invites", name ? { name } : {});
    $("link").textContent = r.url; $("inv-hint").textContent = inviteHint(r); $("inv-out").hidden = false; $("copy-link").textContent = "Copy";
  } catch (e) { fail("ierr", e); }
};
$("btn-update").onclick = async (e) => {
  const before = $("rel-text").textContent; e.target.disabled = true; $("rel-err").textContent = "";
  try {
    await api("POST", "/api/update"); $("rel-text").textContent = "Updating, this takes a minute...";
    for (let i = 0; i < 40; i++) {
      await new Promise((r) => setTimeout(r, 3000));
      try { const s = await loadRelease(); if (s && !s.newer) break; } catch (_) {}
    }
  } catch (er) { fail("rel-err", er); $("rel-text").textContent = before; }
  e.target.disabled = false; loadRelease();
};
$("btn-rollback").onclick = async () => {
  if (!confirm("Roll the relay back to the previous version?")) return;
  try { await api("POST", "/api/rollback"); setTimeout(loadRelease, 3000); } catch (e) { fail("rel-err", e); }
};
$("consoles").onclick = async (e) => {
  const act = e.target.dataset && e.target.dataset.act, row = e.target.closest(".row");
  if (!act || !row) return;
  const id = row.dataset.id, name = row.querySelector(".name").value;
  try {
    if (act === "revoke") { if (confirm("Revoke " + name + "? It is disconnected and cannot reconnect.")) { await api("POST", "/api/consoles/" + id + "/revoke"); loadConsoles(); } }
    if (act === "logs") {
      const pre = row.querySelector(".logs");
      if (!pre.hidden) { pre.hidden = true; return; }
      pre.textContent = "Loading..."; pre.hidden = false;
      pre.textContent = renderLogs(await api("GET", "/api/consoles/" + id + "/logs?limit=200"));
    }
  } catch (er) { fail("cerr", er); }
};
$("consoles").onchange = async (e) => {
  if (e.target.dataset.act !== "rename") return;
  try { await api("PATCH", "/api/consoles/" + e.target.closest(".row").dataset.id, { name: e.target.value.trim() }); $("cerr").textContent = ""; }
  catch (er) { fail("cerr", er); loadConsoles(); }
};
api("GET", "/api/consoles").then(() => start(), () => show(false));
`;
