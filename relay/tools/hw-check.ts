// Checks a manual two-console session from the consoles' remote logs (config.ini [debug] remote_log = 1),
// read through the relay's admin API. See docs/testing.md for the procedure.
//   RELAY_URL=https://relay.example ADMIN_FILE=~/relay-admin.txt \
//     node --experimental-transform-types tools/hw-check.ts --since 2026-10-26T14:00 [--version 0.2.0]
//     [--console <id or name>]... [--allow <regex>]... [--heap-max <bytes>] [--nodes 2] [--limit 2000]
// --since: an ISO time or "<n>m" (minutes ago). Consoles: by default every console the relay saw since then.
// The admin password comes from ADMIN_FILE (a file holding it) or ADMIN, never from argv.
// The patterns are the module's own log lines (crates/sys/src, crates/core/src/ldn); keep them in step.
import { readFileSync } from "node:fs";
import { parseArgs } from "node:util";

type Line = { at: number; line: string };
type Row = { check: string; ok: boolean; detail: string };
export type Opts = { since: number; version?: string; allow: RegExp[]; heapMax: number; nodes: number };

const ERRORS = /\[ERROR\]|server error|recv buffer empty|panic|link down|relay link lost/;

/** The checks for one console's lines (already cut to the window), in log order. */
function checkConsole(lines: Line[], o: Opts): Row[] {
  const text = lines.map((l) => l.line);
  const find = (re: RegExp, from = 0) => {
    for (let i = from; i < text.length; i++) {
      const m = re.exec(text[i]);
      if (m) return { i, m };
    }
    return null;
  };
  const rows: Row[] = [];
  // each step must come after the one it names (by position in the log, not wall time)
  const at: Record<string, number> = {};
  const step = (check: string, re: RegExp, after: string | null, judge: (m: RegExpExecArray) => string | null = () => null) => {
    const from = after === null ? 0 : at[after];
    const f = from === undefined ? null : find(re, from);
    if (!f) {
      rows.push({ check, ok: false, detail: from === undefined ? `needs "${after}" first` : `no line matching ${re.source}` });
      return;
    }
    const bad = judge(f.m);
    at[check] = f.i;
    rows.push({ check, ok: !bad, detail: bad ?? text[f.i].replace(/^\[\s*[\d.]+\] /, "") });
  };

  step("started", /ldn-tunnel (\S+) \(build (\d+)\) starting/, null, (m) =>
    o.version && m[1].replace(/^v/, "") !== o.version.replace(/^v/, "") ? `version ${m[1]}, expected ${o.version}` : null);
  step("relay handshake", /ldn: relay handshake done/, "started");
  step("ldn connected", /ldn: connected: (\d+)\/(\d+) nodes/, "relay handshake", () => {
    const max = Math.max(...text.map((t) => Number(/ldn: connected: (\d+)\//.exec(t)?.[1] ?? 0)));
    // The host only logs its own 1/N when it creates the room; the joiners' lines show the full count.
    const need = text.some((t) => /ldn: connected: \d+\/\d+ nodes, local node 0\b/.test(t)) ? 1 : o.nodes;
    return max < need ? `at most ${max} nodes, expected ${need}` : null;
  });
  step("socket tracked", /bsd: client \d+ fd \d+ tracked/, "started");
  step("bound to proxy", /bsd: client \d+ fd \d+ bound to the LDN proxy/, "socket tracked");
  step("ProxyData out", /bsd: first ProxyData out:/, "ldn connected");
  step("ProxyData in", /bsd: first ProxyData in:/, "ldn connected");
  step("datagram from relay", /first datagram from the relay \((\d+) bytes\)/, "ProxyData in", (m) =>
    Number(m[1]) > 0 ? null : "0 bytes");

  const errors = text.filter((t) => ERRORS.test(t) && !o.allow.some((a) => a.test(t)));
  rows.push({ check: "no errors", ok: errors.length === 0, detail: errors.length ? `${errors.length}: ${errors.slice(0, 3).join(" | ")}` : "none" });

  const heap = text.map((t) => /mem: heap high=(\d+) of (\d+)/.exec(t)).filter((m) => m !== null);
  const high = Math.max(0, ...heap.map((m) => Number(m[1])));
  rows.push({
    check: "heap high-water",
    ok: heap.length > 0 && high <= o.heapMax,
    detail: heap.length ? `${high} of ${heap[0][2]} (limit ${o.heapMax})` : "no mem: line",
  });
  return rows;
}

type Console = { id: string; name: string; version: string | null; lastSeen: number | null };

/** Logs in, picks the consoles, checks each. `pick`: ids or names; empty = every console seen since `o.since`. */
export async function run(base: string, secret: string, o: Opts, pick: string[], limit: number): Promise<{ ok: boolean; out: string[] }> {
  const login = await fetch(base + "/admin/login", {
    method: "POST",
    headers: { "content-type": "application/json", Origin: new URL(base).origin },
    body: JSON.stringify({ secret }),
  });
  const cookie = login.headers.getSetCookie().map((c) => c.split(";")[0]).find((c) => c.startsWith("ldnt_admin="));
  if (!login.ok || !cookie) throw new Error(`POST /admin/login -> ${login.status}`);
  const get = async <T>(path: string): Promise<T> => {
    const res = await fetch(base + path, { headers: { Cookie: cookie } });
    if (!res.ok) throw new Error(`GET ${path} -> ${res.status}`);
    return (await res.json()) as T;
  };

  const all = await get<Console[]>("/api/consoles");
  const chosen = pick.length ? all.filter((c) => pick.includes(c.id) || pick.includes(c.name)) : all.filter((c) => (c.lastSeen ?? 0) >= o.since);
  const out: string[] = [];
  let ok = true;
  if (chosen.length < 2) {
    out.push(`FAIL: ${chosen.length} console(s) ${pick.length ? "matched --console" : "seen since --since"}, a session needs 2`);
    ok = false;
  }
  for (const c of chosen) {
    const lines = await get<Line[]>(`/api/consoles/${encodeURIComponent(c.id)}/logs?limit=${limit}`);
    const win = lines.filter((l) => l.at >= o.since);
    const rows = checkConsole(win, o);
    const pass = rows.every((r) => r.ok);
    ok &&= pass;
    out.push(`${pass ? "PASS" : "FAIL"}  ${c.name} (${c.id}), ${win.length} lines, relay reports version ${c.version ?? "?"}`);
    if (lines.length >= limit && win.length === lines.length) out.push(`  note: all ${limit} lines fetched are in the window, older ones were cut (raise --limit, max 2000)`);
    for (const r of rows) out.push(`  ${r.ok ? "PASS" : "FAIL"}  ${r.check.padEnd(20)} ${r.detail}`);
  }
  out.push(`hw-check: ${ok ? "PASS" : "FAIL"}`);
  return { ok, out };
}

if (import.meta.main) {
  const { values } = parseArgs({
    options: {
      since: { type: "string" },
      version: { type: "string" },
      console: { type: "string", multiple: true, default: [] },
      allow: { type: "string", multiple: true, default: [] },
      "heap-max": { type: "string", default: String(896 * 1024) }, // of the 1 MiB heap (HEAP_SIZE in crates/sys/src/rt.rs)
      nodes: { type: "string", default: "2" },
      limit: { type: "string", default: "2000" },
    },
  });
  const base = (process.env.RELAY_URL ?? "").replace(/\/+$/, "");
  if (!base) throw new Error("set RELAY_URL to the relay, e.g. https://relay.example");
  const secret = (process.env.ADMIN_FILE ? readFileSync(process.env.ADMIN_FILE, "utf8") : (process.env.ADMIN ?? "")).trim();
  if (!secret) throw new Error("set ADMIN_FILE to a file holding the admin password (or ADMIN)");
  const s = values.since ?? "";
  const since = /^\d+m$/.test(s) ? Date.now() - parseInt(s) * 60_000 : Date.parse(s);
  if (!Number.isFinite(since)) throw new Error('pass --since <ISO time> or --since <n>m (the session start)');
  const o: Opts = { since, version: values.version, allow: values.allow.map((a) => new RegExp(a)), heapMax: Number(values["heap-max"]), nodes: Number(values.nodes) };
  const r = await run(base, secret, o, values.console, Number(values.limit));
  console.log(r.out.join("\n"));
  process.exit(r.ok ? 0 : 1);
}
