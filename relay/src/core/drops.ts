// Who ended each console WebSocket: one row per drop (and per relay start) in the `drops` table, the last
// 500 kept, read through GET /api/drops and logged for `wrangler tail`. Lay them next to the consoles'
// "relay: link ended" lines (tools/drops.ts) to tell an edge cut from our own close.
//
// A drop row: { ev: "drop", who, by, code, reason, clean, colo, country, age_s, frames_in, frames_out,
//   idle_in_ms, idle_out_ms, do_start, same_sec }
//  - by: "relay" (we closed it: reason says why), "peer" (webSocketClose: the console, or the edge for it),
//    "error" (webSocketError)
//  - frames/idle: counted in memory since accept or since this instance started (do_start), whichever is later
//  - same_sec: other drops this instance saw in the second before (both consoles cut at once)
// Resume outcomes (relay.ts, Cloudflare and Node): { ev: "resume", awayMs, .. } after a drop within the grace
// window, { ev: "leave", why: "not resumed", .. } when it ran out, { ev: "resume-refused", .. }.
// A start row: { ev: "relay-start", sockets: 0 }: a fresh instance, or one reset under its consoles. A start
// that finds sockets (a wake from hibernation, which keeps them) is not stored: it can come every few seconds
// (relay.ts logs every start).
import type { Sql } from "./ports.ts";

const KEEP = 500;

/** Stored in the socket attachment at the upgrade (`request.cf`), so it survives hibernation. */
export interface Edge {
  at: number;
  colo?: string;
  country?: string;
}

interface Live {
  fin: number;
  fout: number;
  lastIn: number;
  lastOut: number;
  done: boolean;
}

/** Stores and logs one row (rare events only: drops, starts, resume outcomes). */
export function record(sql: Sql, row: Record<string, unknown>) {
  console.log(row);
  ensure(sql);
  sql.exec("INSERT INTO drops (at, row) VALUES (?, ?)", Date.now(), JSON.stringify(row));
  sql.exec("DELETE FROM drops WHERE id <= (SELECT MAX(id) FROM drops) - ?", KEEP);
}

const ensure = (sql: Sql) => sql.exec("CREATE TABLE IF NOT EXISTS drops (id INTEGER PRIMARY KEY AUTOINCREMENT, at INTEGER NOT NULL, row TEXT NOT NULL)");

export function listDrops(sql: Sql, limit = KEEP) {
  ensure(sql);
  return sql.exec<{ at: number; row: string }>("SELECT at, row FROM drops ORDER BY id DESC LIMIT ?", limit)
    .map((r) => ({ at: new Date(r.at).toISOString(), ...JSON.parse(r.row) }));
}

export class Drops {
  readonly start = Date.now();
  private live = new WeakMap<object, Live>();
  private recent: number[] = [];

  constructor(private sql: Sql, sockets: number) {
    if (!sockets) record(sql, { ev: "relay-start", sockets });
  }

  private get(ws: object): Live {
    let c = this.live.get(ws);
    if (!c) this.live.set(ws, (c = { fin: 0, fout: 0, lastIn: 0, lastOut: 0, done: false }));
    return c;
  }

  in(ws: object) {
    const c = this.get(ws);
    c.fin++;
    c.lastIn = Date.now();
  }

  out(ws: object) {
    const c = this.get(ws);
    c.fout++;
    c.lastOut = Date.now();
  }

  /** The first end of a socket is recorded; later ones (our close, then its close event) are not. */
  ended(ws: object, by: "relay" | "peer" | "error", code: number, reason: string, clean: boolean, who?: string, edge?: Edge) {
    const c = this.get(ws);
    if (c.done) return;
    c.done = true;
    const now = Date.now();
    this.recent = this.recent.filter((t) => now - t < 1000);
    record(this.sql, {
      ev: "drop", who, by, code, reason, clean, colo: edge?.colo, country: edge?.country,
      age_s: edge ? Math.round((now - edge.at) / 1000) : null,
      frames_in: c.fin, frames_out: c.fout,
      idle_in_ms: c.lastIn ? now - c.lastIn : null, idle_out_ms: c.lastOut ? now - c.lastOut : null,
      do_start: new Date(this.start).toISOString(), same_sec: this.recent.length,
    });
    this.recent.push(now);
  }
}
