// play.ts against the Durable Object (workerd), plus what only the object has: restarts, the ping alarm,
// revocation and CPU time per message. Tests that restart or alarm an object get one of their own.
import { env, exports } from "cloudflare:workers";
import { runDurableObjectAlarm, runInDurableObject } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";
import { DisconnectMessage, NetworkInfo, PacketId, PingMessage, ProxyConfig } from "../src/core/codec/types.ts";
import { Ldn, ip } from "../tools/ldn-client.ts";
import type { Lobby } from "../src/cloudflare/lobby.ts";
import type { Relay, Session } from "../src/core/relay.ts";
import { type Client, type Player, type Target, freshLcid, hex, join, perfScan, playSuite, ready, resumeSuite, room, roster, sample } from "./play.ts";

const TOKEN = "a".repeat(64); // TOKEN_SWITCH_A in vitest.config.ts
/** The relay core plus the private state these tests inspect. */
type Core = Pick<Relay, "message" | "closed" | "newSession"> & { games: Map<string, { owner: string }>; lastMsg: Map<string, number> };

/** A Lobby object: "main" is reached through the Worker as consoles reach it, any other name directly. */
function object(name = "main", token = TOKEN) {
  const stub = () => env.LOBBY.get(env.LOBBY.idFromName(name));
  const core = <T,>(fn: (r: Core, state: DurableObjectState) => T) =>
    runInDurableObject(stub(), (o: Lobby, state) => fn((o as unknown as { relay: Core }).relay, state));
  const target: Target = {
    async open(): Promise<Client> {
      const req = new Request("https://relay.test/ldn", { headers: { Upgrade: "websocket", Authorization: `Bearer ${token}` } });
      const res = await (name === "main" ? exports.default.fetch(req) : stub().fetch(req));
      expect(res.status).toBe(101);
      const ws = res.webSocket!;
      ws.accept();
      ws.binaryType = "arraybuffer";
      const c = new Ldn((b) => ws.send(b)) as Client;
      c.raw = (b) => ws.send(b);
      c.close = () => ws.close(1000);
      ws.addEventListener("message", (e) => c.push(new Uint8Array(e.data as ArrayBuffer)));
      ws.addEventListener("close", (e) => ((c.closeCode = e.code), c.end()));
      return c;
    },
    gamesOf: (sids) =>
      core((r, state) => {
        const live = [...r.games.values()].filter((g) => sids.includes(g.owner)).length;
        const rows = state.storage.sql.exec("SELECT meta FROM games").toArray().filter((g) => sids.includes(JSON.parse(g.meta as string).owner));
        return live + rows.length;
      }),
  };
  return { stub, core, target };
}

describe("play (Durable Object)", () => playSuite(object().target));

describe("resume (Durable Object)", () => {
  const { core, target } = object("resume");
  // the grace is on for this object only (vitest.config.ts turns it off for the rest)
  const grace = () => core((r) => void ((r as unknown as { grace: number }).grace = 15_000));
  const expire = async () => {
    await core((r) => {
      for (const g of (r as unknown as { games: Map<string, { players: { gone?: number }[] }> }).games.values()) {
        for (const p of g.players) if (p.gone !== undefined) p.gone -= 15_000;
      }
    });
    await runDurableObjectAlarm(env.LOBBY.get(env.LOBBY.idFromName("resume")));
  };
  beforeAll(grace);
  resumeSuite(target, expire);
  it("the drops table has each socket end and each resume outcome", async () => {
    const evs = await core((_r, state) => state.storage.sql.exec("SELECT row FROM drops").toArray().map((x) => JSON.parse(x.row as string)));
    const kinds = new Set(evs.map((e) => e.ev));
    for (const k of ["drop", "resume", "leave", "resume-refused"]) expect(kinds).toContain(k);
    expect(evs.find((e) => e.ev === "leave")).toMatchObject({ why: "not resumed" });
    expect(evs.some((e) => e.ev === "drop" && e.by === "relay" && e.reason === "resumed on a new socket")).toBe(true);
  });
});

const closed = async (c: Client, code: number) => {
  await expect(c.next()).rejects.toThrow("closed");
  expect(c.closeCode).toBe(code);
};
const lost = async (p: Player, rest: Player[]) => {
  roster(NetworkInfo.decode(await p.c.expect(PacketId.SyncNetwork)), rest);
  expect(await p.c.expect(PacketId.Disconnect)).toEqual(DisconnectMessage.encode({ disconnect_ip: 0 }));
};

describe("object restart mid-game", () => {
  it("drops every socket; reconnecting consoles find no phantom game, the old ids are free, addresses start over", async () => {
    const { core, target: t } = object("restart");
    const lcid = freshLcid();
    const { players } = await room(t, 3, { lcid });
    const id = crypto.getRandomValues(new Uint8Array(16));
    const priv = await ready(t);
    priv.c.createApPrivate(id);
    await priv.c.expect(PacketId.ProxyConfig);
    await priv.c.expect(PacketId.Connected);
    expect(await core((_r, state) => state.storage.sql.exec("SELECT COUNT(*) AS n FROM games").one().n)).toBe(2); // on disk

    await core((_r, state) => state.abort("deploy")).catch(() => {}); // as a deploy or crash: the sockets go with it
    for (const c of [...players.map((p) => p.c), priv.c]) await closed(c, 1006);

    const watcher = await ready(t); // wakes a fresh object
    expect(await watcher.c.scanAll(lcid)).toEqual([]);
    expect(await t.gamesOf([...players.map((p) => p.sid), priv.sid])).toBe(0);
    const again = await ready(t);
    again.c.createApPrivate(id);
    expect(ProxyConfig.decode(await again.c.expect(PacketId.ProxyConfig)).proxy_ip).toBe(ip("10.114.0.1"));
    const fresh = await room(t, 3, { lcid });
    expect(fresh.players.map((p) => [p.node, p.ip])).toEqual([1, 2, 3].map((n) => [n - 1, ip(`10.114.0.${n}`)]));
    expect(await watcher.c.scanAll(lcid)).toHaveLength(1);
  });
});

describe("ping timeout in a running game", () => {
  const silence = (core: ReturnType<typeof object>["core"], sid: string) => core((r) => void r.lastMsg.set(sid, 0));

  it("only the silent station is pinged and cut; the others keep routing", async () => {
    const { stub, core, target: t } = object("ping-station");
    const { players } = await room(t, 3);
    const [a, b, c] = players;
    await silence(core, c.sid);
    expect(await runDurableObjectAlarm(stub())).toBe(true);
    PingMessage.decode(await c.c.expect(PacketId.Ping)); // never answered
    await runDurableObjectAlarm(stub());
    await closed(c.c, 1000);
    for (const p of [a, b]) roster(NetworkInfo.decode(await p.c.expect(PacketId.SyncNetwork)), [a, b]);
    b.c.proxyData(0, a.ip, Uint8Array.of(1));
    b.c.proxyData(0, ip("10.114.255.255"), Uint8Array.of(2));
    expect((await a.c.expect(PacketId.ProxyData)).at(-1)).toBe(1);
    for (const p of [a, b]) expect((await p.c.expect(PacketId.ProxyData)).at(-1)).toBe(2);
    for (const p of [a, b]) await p.c.none(0); // neither was pinged
  });

  it("a silent host is cut and its game closes for the stations", async () => {
    const { stub, core, target: t } = object("ping-host");
    const { players, lcid } = await room(t, 3);
    const [a, b, c] = players;
    await silence(core, a.sid);
    await runDurableObjectAlarm(stub());
    await a.c.expect(PacketId.Ping);
    await runDurableObjectAlarm(stub());
    await closed(a.c, 1000);
    for (const p of [b, c]) await lost(p, [b, c]);
    expect(await (await ready(t)).c.scanAll(lcid)).toEqual([]);
  });
});

describe("revoking a console mid-game", () => {
  const ADMIN = "correct horse"; // vitest.config.ts
  /** A per-console token, as an invite mints it. */
  async function mint() {
    const token = hex(crypto.getRandomValues(new Uint8Array(32)));
    const id = hex(crypto.getRandomValues(new Uint8Array(4)));
    const hash = hex(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token))));
    await object().core((_r, state) => void state.storage.sql.exec("INSERT INTO tokens (id, hash, name, created) VALUES (?, ?, ?, ?)", id, hash, "kicked", Date.now()));
    return { id, token, t: object("main", token).target };
  }
  const revoke = async (id: string) => {
    const res = await exports.default.fetch(new Request(`https://relay.test/api/consoles/${id}/revoke`, { method: "POST", headers: { Authorization: `Bearer ${ADMIN}` } }));
    expect(res.status).toBe(200);
  };
  const t = object().target;

  it("a revoked station's socket is cut and the room resyncs without it", async () => {
    const { players, net } = await room(t, 3);
    const k = await mint();
    await join(k.t, net, players);
    const kicked = players.pop()!;
    await revoke(k.id);
    await closed(kicked.c, 1000);
    for (const p of players) roster(NetworkInfo.decode(await p.c.expect(PacketId.SyncNetwork)), players);
    const again = await exports.default.fetch(new Request("https://relay.test/ldn", { headers: { Upgrade: "websocket", Authorization: `Bearer ${k.token}` } }));
    expect(again.status).toBe(404);
  });

  it("a revoked host's game closes for its stations", async () => {
    const k = await mint();
    const { players, lcid } = await room(k.t, 1);
    const [h] = players;
    const [net] = await (await ready(t)).c.scanAll(lcid);
    await join(t, net, players);
    await join(t, net, players);
    await revoke(k.id);
    await closed(h.c, 1000);
    for (const p of players.slice(1)) await lost(p, players.slice(1));
    expect(await (await ready(t)).c.scanAll(lcid)).toEqual([]);
  });
});

describe("CPU time per message (workerd)", () => {
  // Workers bill (and the free plan caps) 10 ms of CPU per event: one message is one event.
  it("Scan with 200 hosted games", async () => {
    const { median, p95, replies } = await object("perf").core((r) => perfScan(r as unknown as Relay));
    expect(replies).toBe(201); // 200 ScanReply + ScanReplyEnd
    expect(median).toBeLessThan(5); // ~3.3 ms here: about 17 µs per matching game, mostly NetworkInfo.encode
    expect(p95).toBeLessThan(10);
  });

  it("ProxyData broadcast to 8 real sockets", async () => {
    const { core, target: t } = object("perf");
    const { players } = await room(t, 8);
    const sender = players[3].sid;
    const { median, p95 } = await core((r, state) => {
      const ws = state.getWebSockets(sender)[0];
      const conn = { send: (b: Uint8Array) => ws.send(b), close() {}, load: <T,>() => ws.deserializeAttachment() as T, save: (s: Session) => ws.serializeAttachment(s) };
      let pkt!: Uint8Array;
      new Ldn((b) => (pkt = b)).proxyData(0, ip("10.114.255.255"), new Uint8Array(512));
      return sample(60, 10, () => r.message(conn as never, pkt));
    });
    for (const p of players) expect((await p.c.expect(PacketId.ProxyData)).length).toBeGreaterThan(512);
    expect(median).toBeLessThan(1);
    expect(p95).toBeLessThan(2);
  });
});
