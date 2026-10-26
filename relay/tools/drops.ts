// Relay drop rows (GET /api/drops) next to each console's link lines (GET /api/consoles/<id>/logs), by time:
// who ended a relay link. Read-only.
//   RELAY_URL=https://relay.example ADMIN_FILE=~/relay-admin.txt npm run drops [-- --minutes 120]
// The admin password comes from ADMIN_FILE (a file holding it) or ADMIN, never from argv.
// A console line is stamped when the relay received it: a "link ended" line arrives on the next link.
import { readFileSync } from "node:fs";
import { parseArgs } from "node:util";

const { values } = parseArgs({ options: { minutes: { type: "string", default: "180" } } });
const base = (process.env.RELAY_URL ?? "").replace(/\/+$/, "");
if (!base) throw new Error("set RELAY_URL to the relay, e.g. https://relay.example");
const secret = (process.env.ADMIN_FILE ? readFileSync(process.env.ADMIN_FILE, "utf8") : (process.env.ADMIN ?? "")).trim();
if (!secret) throw new Error("set ADMIN_FILE to a file holding the admin password (or ADMIN)");
const get = async (path: string) => {
  const res = await fetch(base + path, { headers: { Authorization: `Bearer ${secret}` } });
  if (!res.ok) throw new Error(`GET ${path} -> ${res.status}`);
  return res.json() as Promise<any[]>;
};

const since = Date.now() - Number(values.minutes) * 60_000;
const out: [number, string][] = [];
for (const d of await get("/api/drops")) {
  const { at, ev, who, ...rest } = d;
  out.push([Date.parse(at), `relay   ${ev} ${who ?? ""} ${JSON.stringify(rest)}`]);
}
for (const c of await get("/api/consoles")) {
  for (const l of await get(`/api/consoles/${encodeURIComponent(c.id)}/logs?limit=2000`)) {
    if (/link ended|upgrade 101|resume|TLS session closed|TLS read failed|send failed|relay: link down/.test(l.line)) {
      out.push([l.at, `console ${c.name}: ${l.line}`]);
    }
  }
}
for (const [t, line] of out.filter(([t]) => t >= since).sort((a, b) => a[0] - b[0])) {
  console.log(new Date(t).toISOString(), line);
}
