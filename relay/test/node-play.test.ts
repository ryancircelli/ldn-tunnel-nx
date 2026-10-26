// play.ts against the Node server (real HTTP + `ws` + node:sqlite), plus a restart on the same database and
// the core's CPU time per message under Node.
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync, type SQLInputValue } from "node:sqlite";
import WebSocket from "ws";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { startServer } from "../src/node/server.ts";
import { Relay } from "../src/core/relay.ts";
import type { Conn, Host } from "../src/core/ports.ts";
import { Ldn, ip } from "../tools/ldn-client.ts";
import { PacketId, ProxyConfig } from "../src/core/codec/types.ts";
import { type Client, type Target, freshLcid, perfBroadcast, perfScan, playSuite, ready, resume, resumeSuite, room, roster } from "./play.ts";

const TOKEN = "a".repeat(64);
const ENV = { TOKEN_SWITCH_A: "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb", RESUME_GRACE_MS: "0" };
const dir = mkdtempSync(join(tmpdir(), "relay-play-"));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

/** A Target on a Node server over `dbPath`. */
function nodeTarget(port: () => number, dbPath: string): Target {
  return {
    async open() {
      const ws = new WebSocket(`ws://127.0.0.1:${port()}/ldn`, { headers: { Authorization: `Bearer ${TOKEN}` } });
      const c = new Ldn((b) => ws.send(b)) as Client;
      c.raw = (b) => ws.send(b);
      c.close = () => ws.close(1000);
      ws.on("message", (d, bin) => bin && c.push(new Uint8Array(d as Buffer)));
      ws.on("close", (code) => ((c.closeCode = code), c.end()));
      await new Promise((r, j) => (ws.on("open", r), ws.on("error", j)));
      return c;
    },
    async gamesOf(sids) {
      const db = new DatabaseSync(dbPath, { readOnly: true });
      try {
        return db.prepare("SELECT meta FROM games").all().filter((g) => sids.includes(JSON.parse(g.meta as string).owner)).length;
      } finally {
        db.close();
      }
    },
  };
}

describe("play (Node)", () => {
  const dbPath = join(dir, "play.sqlite");
  let srv: Awaited<ReturnType<typeof startServer>>;
  beforeAll(async () => void (srv = await startServer({ port: 0, dbPath, env: ENV })));
  afterAll(() => srv.close());
  playSuite(nodeTarget(() => srv.port, dbPath));
});

describe("resume (Node)", () => {
  const dbPath = join(dir, "resume.sqlite");
  let srv: Awaited<ReturnType<typeof startServer>>;
  beforeAll(async () => void (srv = await startServer({ port: 0, dbPath, env: { ...ENV, RESUME_GRACE_MS: "15000" } })));
  afterAll(() => srv.close());
  resumeSuite(nodeTarget(() => srv.port, dbPath));
});

describe("Node restart with the resume grace on", () => {
  it("every console resumes its node in the stored game; the room carries on", async () => {
    const dbPath = join(dir, "restart-resume.sqlite");
    const env = { ...ENV, RESUME_GRACE_MS: "15000" };
    let srv = await startServer({ port: 0, dbPath, env });
    const t = nodeTarget(() => srv.port, dbPath);
    const { players, net, lcid } = await room(t, 3);
    await srv.close(); // every socket goes, as when the Durable Object restarts
    srv = await startServer({ port: 0, dbPath, env });
    try {
      for (const p of players) roster(await resume(t, p, net), players);
      const [seen] = await (await ready(t)).c.scanAll(lcid);
      roster(seen, players);
      players[1].c.proxyData(0, players[0].ip, Uint8Array.of(7));
      expect((await players[0].c.expect(PacketId.ProxyData)).at(-1)).toBe(7);
    } finally {
      await srv.close();
    }
  });
});

describe("Node restart on the same database", () => {
  it("drops every game of the old process; consoles reconnect to a clean relay", async () => {
    const dbPath = join(dir, "restart.sqlite");
    let srv = await startServer({ port: 0, dbPath, env: ENV });
    const t = nodeTarget(() => srv.port, dbPath);
    const lcid = freshLcid();
    const { players } = await room(t, 3, { lcid });
    const id = crypto.getRandomValues(new Uint8Array(16));
    const priv = await ready(t);
    priv.c.createApPrivate(id);
    await priv.c.expect(PacketId.ProxyConfig);
    await priv.c.expect(PacketId.Connected);
    const sids = [...players.map((p) => p.sid), priv.sid];
    expect(await t.gamesOf(sids)).toBe(2); // mid-game state is on disk
    await srv.close();

    srv = await startServer({ port: 0, dbPath, env: ENV });
    try {
      expect(await t.gamesOf(sids)).toBe(0);
      const watcher = await ready(t);
      expect(await watcher.c.scanAll(lcid)).toEqual([]);
      const again = await ready(t);
      again.c.createApPrivate(id); // the private room's id is free again
      expect(ProxyConfig.decode(await again.c.expect(PacketId.ProxyConfig)).proxy_ip).toBe(ip("10.114.0.1"));
      const fresh = await room(t, 3, { lcid });
      expect(fresh.players.map((p) => [p.node, p.ip])).toEqual([[0, ip("10.114.0.1")], [1, ip("10.114.0.2")], [2, ip("10.114.0.3")]]);
      expect(await watcher.c.scanAll(lcid)).toHaveLength(1);
    } finally {
      await srv.close();
    }
  });
});

describe("CPU time per message (Node)", () => {
  // the core over node:sqlite, sockets replaced by recorders: what server.ts runs, minus the network
  const db = new DatabaseSync(":memory:");
  const conns = new Map<string, Conn>();
  const host: Host = {
    sql: {
      exec: <T,>(q: string, ...b: unknown[]) => db.prepare(q).all(...b.map((v) => (v instanceof ArrayBuffer ? new Uint8Array(v) : v) as SQLInputValue)) as T[],
      tx: (fn) => fn(),
    },
    conns: () => [...conns.values()],
    conn: (sid) => conns.get(sid),
    getAlarm: async () => null,
    setAlarm: async () => {},
    env: {},
    fetch,
    assets: { ca: "", gamelist: "" },
    platform: "docker",
  };
  const relay = new Relay(host);

  it("Scan with 200 hosted games", () => {
    const { median, p95, replies } = perfScan(relay, (sid, c) => conns.set(sid, c));
    expect(replies).toBe(201); // 200 ScanReply + ScanReplyEnd
    // ~4.4 ms here; Node has no CPU cap, so looser than the workerd bound (relay-play.test.ts)
    expect(median).toBeLessThan(8);
    expect(p95).toBeLessThan(15);
  });

  it("ProxyData broadcast in an 8-player game", () => {
    const { median, p95, delivered } = perfBroadcast(relay, (sid, c) => conns.set(sid, c));
    expect(delivered).toBe(8);
    expect(median).toBeLessThan(1);
    expect(p95).toBeLessThan(2);
  });
});
