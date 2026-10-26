// Pure view logic of the admin page, kept as plain-JS source so index.ts can inline it into the page
// (no bundler, no runtime fs, no eval at runtime) and tests can load the very same text.
// ponytail: source-as-string, not real TS functions: wrangler's keep_names would inject __name() into toString().
export const LOGIC_SRC = `
const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => "&#" + c.charCodeAt(0) + ";");
function ago(t, now) {
  if (!t) return "never";
  const s = Math.max(0, Math.round((now - t) / 1000));
  if (s < 60) return "just now";
  if (s < 3600) return Math.floor(s / 60) + " min ago";
  if (s < 86400) return Math.floor(s / 3600) + " h ago";
  return Math.floor(s / 86400) + " d ago";
}
function renderConsoles(list, now) {
  if (!list || !list.length) return '<p class="muted">No consoles yet. Invite one below.</p>';
  return list.map((c) => {
    const fixed = String(c.id).startsWith("env:");
    const rej = c.rejectedBuild ? '<span class="warn"> (rejected build ' + esc(c.rejectedBuild) + ')</span>' : "";
    return '<div class="row" data-id="' + esc(c.id) + '">' +
      '<div class="head"><span class="dot ' + (c.online ? "on" : "off") + '" title="' + (c.online ? "online" : "offline") + '"></span>' +
      '<input class="name" value="' + esc(c.name) + '" maxlength="32"' + (fixed ? " readonly" : "") + ' aria-label="Console name" data-act="rename">' +
      '</div><div class="meta">' + (c.online ? "online" : "last seen " + esc(ago(c.lastSeen, now))) +
      " &middot; " + (c.version ? "v" + esc(c.version) : "version unknown") +
      (c.runningBuild ? " (build " + esc(c.runningBuild) + ")" : "") + rej + '</div>' +
      '<div class="acts"><button data-act="logs">Logs</button> <button class="danger" data-act="revoke"' + (fixed ? ' disabled title="Deploy-time secret: delete the secret to revoke"' : "") + '>Revoke</button></div>' +
      '<pre class="logs" hidden></pre></div>';
  }).join("");
}
function renderLogs(lines) {
  if (!lines || !lines.length) return "No log lines.";
  return lines.slice().sort((a, b) => b.at - a.at)
    .map((l) => new Date(l.at).toISOString().slice(0, 19).replace("T", " ") + "  " + l.line).join("\\n");
}
function isNewer(latest, deployed) {
  if (!latest) return false;
  if (typeof latest.build === "number" && typeof deployed.build === "number") return latest.build > deployed.build;
  const a = String(latest.version).split(".").map(Number), b = String(deployed.version).split(".").map(Number);
  for (let i = 0; i < 3; i++) { if ((a[i] || 0) !== (b[i] || 0)) return (a[i] || 0) > (b[i] || 0); }
  return false;
}
function releaseState(d) {
  const dep = d.deployed || {};
  const s = { deployed: dep.version ? "v" + dep.version : "unknown", latest: d.latest ? "v" + d.latest.version : null,
    newer: isNewer(d.latest, dep), platform: d.platform, command: d.updateCommand || null };
  const self = d.canSelfUpdate !== undefined ? !!d.canSelfUpdate : d.platform === "cloudflare";
  s.canUpdate = s.newer && self;
  s.canRollback = self;
  s.error = d.installError || null;
  s.showCommand = s.newer && d.platform === "docker" && !!s.command;
  s.text = s.newer ? "Deployed " + s.deployed + ". " + s.latest + " is available." : "Deployed " + s.deployed + ". Up to date.";
  return s;
}
function inviteHint(r) {
  return "Send this link to the console's owner. It works once. Unzip the download onto the SD card root and restart the Switch. Expires " +
    new Date(r.expiresAt).toISOString().slice(0, 16).replace("T", " ") + " UTC.";
}
`;
