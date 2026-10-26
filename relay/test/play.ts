// Real-play scenarios (MK8D-style rooms of 2..8 consoles), written once and run against both adapters:
// relay-play.test.ts (Durable Object in workerd) and node-play.test.ts (Node server). A target only supplies
// a socket opener and a way to count the games a set of sessions still owns.
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import {
  ConnectPrivateRequest, ConnectRequest, CreateAccessPointPrivateRequest, CreateAccessPointRequest, DisconnectMessage,
  InitializeMessage, MAGIC, MAX_PACKET_SIZE, NetworkError, NetworkErrorMessage, NetworkInfo, PacketId,
  PassphraseMessage, PingMessage, ProxyConfig, ProxyConnectRequest, ProxyDataHeader, ProxyDisconnectMessage, RejectRequest,
  ScanFilterFull, UpdateCheckRequest, UpdateChunkHeader, UpdateChunkRequest, VERSION, packet,
} from "../src/core/codec/types.ts";
import { Ldn, ip } from "../tools/ldn-client.ts";
import type { Relay } from "../src/core/relay.ts";
import type { Conn } from "../src/core/ports.ts";
import consoleWire from "./wire/console.json";
import relayWire from "./wire/relay.json";

export type Client = Ldn & { raw(b: Uint8Array): void; close(): void; closeCode?: number };
export interface Target {
  open(): Promise<Client>;
  /** Games (live or stored) owned by these session ids. */
  gamesOf(sids: string[]): Promise<number>;
}
export interface Player { c: Client; sid: string; ip: number; node: number }

export const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const BCAST = ip("10.114.255.255");
const at = (n: number) => ip(`10.114.0.${n}`);
const err = (b: Uint8Array) => NetworkErrorMessage.decode(b).error_code;
let lcidSeq = 0x0100000000003000n;
export const freshLcid = () => ++lcidSeq;

/** Deterministic PRNG (mulberry32), so a fuzz failure replays. */
function rng(seed: number) {
  return () => {
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export async function ready(t: Target, pass = ""): Promise<{ c: Client; sid: string }> {
  const c = await t.open();
  return { c, sid: hex((await c.initialize(pass)).id) };
}

async function host(t: Target, o: Parameters<Ldn["createAp"]>[0] = {}) {
  const { c, sid } = await ready(t);
  const lcid = o.lcid ?? freshLcid();
  c.createAp({ ...o, lcid });
  const p: Player = { c, sid, ip: ProxyConfig.decode(await c.expect(PacketId.ProxyConfig)).proxy_ip, node: 0 };
  return { p, net: NetworkInfo.decode(await c.expect(PacketId.Connected)), lcid };
}

/** Joins `net`; every player already in `players` must get the same SyncNetwork. Pushes the newcomer. */
export async function join(t: Target, net: NetworkInfo, players: Player[], o: Parameters<Ldn["connect"]>[1] = {}) {
  const { c, sid } = await ready(t);
  c.connect(net, o);
  const ipv = ProxyConfig.decode(await c.expect(PacketId.ProxyConfig)).proxy_ip;
  const info = NetworkInfo.decode(await c.expect(PacketId.Connected));
  for (const p of players) expect(NetworkInfo.decode(await p.c.expect(PacketId.SyncNetwork))).toEqual(info);
  const me = { c, sid, ip: ipv, node: info.ldn.nodes.findIndex((n) => n.is_connected && n.ipv4_address === ipv) };
  players.push(me);
  return { me, info };
}

/** A host plus n-1 stations, all synced. */
export async function room(t: Target, n: number, o: Parameters<Ldn["createAp"]>[0] = {}) {
  const { p, net, lcid } = await host(t, o);
  const players = [p];
  for (let i = 1; i < n; i++) await join(t, net, players, { version: o.version });
  return { players, net, lcid };
}

/** node_count matches the connected slots, and the connected slots are exactly these players. */
export function roster(info: NetworkInfo, players: Player[]) {
  const live = info.ldn.nodes.filter((n) => n.is_connected).map((n) => [n.node_id, n.ipv4_address]);
  expect(info.ldn.node_count, "node_count").toBe(live.length);
  expect(live).toEqual(players.map((p) => [p.node, p.ip]).sort((a, b) => a[0] - b[0]));
}

/** A player leaves (Disconnect packet or socket close); the rest get one SyncNetwork, checked with roster(). */
async function leave(players: Player[], who: Player, how: "disconnect" | "close") {
  if (how === "disconnect") who.c.send(PacketId.Disconnect, DisconnectMessage.encode({ disconnect_ip: 0 }));
  else who.c.close();
  players.splice(players.indexOf(who), 1);
  let info: NetworkInfo | undefined;
  for (const p of players) {
    const got = NetworkInfo.decode(await p.c.expect(PacketId.SyncNetwork));
    if (info) expect(got).toEqual(info);
    info = got;
  }
  roster(info!, players);
  return info!;
}

/** Last payload bytes of the ProxyData a player gets, up to and including `end`: nothing else may arrive before. */
async function got(p: Player, end: number): Promise<number[]> {
  const out: number[] = [];
  for (;;) {
    const v = (await p.c.expect(PacketId.ProxyData)).at(-1)!;
    out.push(v);
    if (v === end) return out;
  }
}
const send = (p: Player, dst: number, v: number, src = 0) => p.c.proxyData(src, dst, Uint8Array.of(v));

/** A raw packet with a ProxyInfo-led payload (ProxyConnect / ProxyConnectReply / ProxyDisconnect). */
function proxyMsg(type: PacketId, src: number, dst: number) {
  const s = type === PacketId.ProxyDisconnect ? ProxyDisconnectMessage : ProxyConnectRequest;
  const v = s.zero() as { info: { source_ipv4: number; dest_ipv4: number; protocol: number } };
  Object.assign(v.info, { source_ipv4: src, dest_ipv4: dst, protocol: 17 });
  return packet(type, s.encode(v as never));
}

/** Server frame (unmasked) -> the packet inside it. */
function unframe(frame: Uint8Array): Uint8Array {
  const n = frame[1] & 0x7f;
  return frame.subarray(n === 126 ? 4 : n === 127 ? 10 : 2);
}
/** Client frame (masked) -> the packet inside it. */
function unmask(frame: Uint8Array): Uint8Array {
  const n = frame[1] & 0x7f;
  const h = n === 126 ? 4 : n === 127 ? 10 : 2;
  const key = frame.subarray(h, h + 4);
  return frame.slice(h + 4).map((x, i) => x ^ key[i & 3]);
}
const fromHex = (s: string) => Uint8Array.from(s.match(/../g)!, (h) => parseInt(h, 16));
const consoleFrame = (name: string) => unmask(fromHex(consoleWire.frames.find((f) => f.name === name)!.hex));
const relayPacket = (name: string) => unframe(fromHex(relayWire.frames.find((f) => f.name === name)!.hex));

// ---- CPU time, on the core directly (fake sockets record what they are sent) ----------------------------

function fakeConn() {
  let state: unknown = null;
  const sent: Uint8Array[] = [];
  return { sent, send: (b: Uint8Array) => void sent.push(b), close() {}, load: <T,>() => state as T, save: (x: unknown) => void (state = x) };
}
/** One packet from the test client's request builders. */
const build = (f: (l: Ldn) => void) => {
  let out!: Uint8Array;
  f(new Ldn((b) => (out = b)));
  return out;
};
/** An initialized session on the core; `register` makes it reachable by session id where the host allows it. */
function session(r: Relay, register: (sid: string, c: Conn) => void) {
  const s = r.newSession("env:TOKEN_SWITCH_A");
  const c = fakeConn();
  c.save(s);
  register(s.sid, c);
  r.message(c, packet(PacketId.Initialize, new Uint8Array(InitializeMessage.size)));
  c.sent.length = 0;
  return c;
}
/** Per-call milliseconds over n batches (batches beat a coarse clock). */
export function sample(n: number, batch: number, fn: () => void) {
  const per: number[] = [];
  for (let i = 0; i < n; i++) {
    const t0 = performance.now();
    for (let k = 0; k < batch; k++) fn();
    per.push((performance.now() - t0) / batch);
  }
  per.sort((a, b) => a - b);
  return { median: per[n >> 1], p95: per[Math.floor(n * 0.95)] };
}

/** Scan against 200 games of the same title (every one matches, as in a busy MK8D evening). */
export function perfScan(r: Relay, register: (sid: string, c: Conn) => void = () => {}) {
  const lcid = freshLcid();
  const hosts = Array.from({ length: 200 }, () => {
    const c = session(r, register);
    r.message(c, build((l) => l.createAp({ lcid })));
    return c;
  });
  const scanner = session(r, register);
  const scan = build((l) => l.scan(lcid));
  r.message(scanner, scan);
  const replies = scanner.sent.length;
  const t = sample(60, 10, () => {
    scanner.sent.length = 0;
    r.message(scanner, scan);
  });
  for (const c of [...hosts, scanner]) r.closed(c);
  return { ...t, replies };
}

/** A 512-byte ProxyData broadcast in a full room; `register` must make the players reachable. */
export function perfBroadcast(r: Relay, register: (sid: string, c: Conn) => void) {
  const ps = Array.from({ length: 8 }, () => session(r, register));
  r.message(ps[0], build((l) => l.createAp({ lcid: freshLcid() })));
  const net = NetworkInfo.decode(ps[0].sent.find((b) => b[4] === PacketId.Connected)!.subarray(12));
  for (const p of ps.slice(1)) r.message(p, build((l) => l.connect(net)));
  const data = build((l) => l.proxyData(0, BCAST, new Uint8Array(512)));
  for (const p of ps) p.sent.length = 0;
  r.message(ps[3], data);
  const delivered = ps.filter((p) => p.sent.length === 1).length;
  const t = sample(60, 10, () => r.message(ps[3], data));
  for (const p of ps) r.closed(p);
  return { ...t, delivered };
}

export function playSuite(t: Target) {
  // A console UpdateCheck (fixtures, fuzz) makes the relay fetch its pinned release: never reach the network.
  beforeAll(() => void vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("offline in tests")));
  afterAll(() => vi.restoreAllMocks());

  describe("allocation: node ids, IPs, room size, version", () => {
    it("8 consoles get node ids 0..7 and 10.114.0.1..8; a 9th is TooManyPlayers until a slot frees", async () => {
      const { players, net, lcid } = await room(t, 8, { max: 8, version: 5 });
      expect(players.map((p) => [p.node, p.ip])).toEqual([1, 2, 3, 4, 5, 6, 7, 8].map((n) => [n - 1, at(n)]));
      const ninth = await ready(t);
      const [seen] = await ninth.c.scanAll(lcid);
      roster(seen, players);
      for (const [version, code] of [[4, NetworkError.VersionTooLow], [6, NetworkError.VersionTooHigh], [5, NetworkError.TooManyPlayers]]) {
        ninth.c.connect(net, { version });
        expect(err(await ninth.c.expect(PacketId.NetworkError))).toBe(code);
      }
      await leave(players, players[3], "close"); // node 3, 10.114.0.4
      ninth.c.connect(net, { version: 5 });
      const ipv = ProxyConfig.decode(await ninth.c.expect(PacketId.ProxyConfig)).proxy_ip;
      const info = NetworkInfo.decode(await ninth.c.expect(PacketId.Connected));
      // the lowest free slot, but the next IP in the DHCP cycle (VirtualDhcp.cs), not the leaver's
      expect(ipv).toBe(at(9));
      expect(info.ldn.nodes[3]).toMatchObject({ node_id: 3, ipv4_address: at(9), is_connected: 1 });
      expect(info.ldn.node_count).toBe(8);
      for (const p of players) await p.c.expect(PacketId.SyncNetwork);
    });

    it("rejoin after a leave: lowest free node id, next IP in the cycle", async () => {
      const { players, net } = await room(t, 3);
      await leave(players, players[1], "disconnect"); // node 1, .2
      const { me: d } = await join(t, net, players);
      expect([d.node, d.ip]).toEqual([1, at(4)]);
      const { me: e, info } = await join(t, net, players);
      expect([e.node, e.ip]).toEqual([3, at(5)]);
      roster(info, players);
    });
  });

  describe("leaving in any order leaves no ghost node", () => {
    const perms = [[1, 2, 3], [1, 3, 2], [2, 1, 3], [2, 3, 1], [3, 1, 2], [3, 2, 1]];
    for (const perm of perms) {
      it(`4 consoles, stations leave as nodes ${perm.join(",")}`, async () => {
        const { players, net } = await room(t, 4);
        const byNode = (n: number) => players.find((p) => p.node === n)!;
        for (const [i, n] of perm.entries()) await leave(players, byNode(n), i % 2 ? "close" : "disconnect");
        expect(players).toHaveLength(1);
        // and the room still takes 7 stations
        for (let i = 0; i < 7; i++) await join(t, net, players);
        expect(players.map((p) => p.node).sort()).toEqual([0, 1, 2, 3, 4, 5, 6, 7]);
      });
    }
  });

  describe("routing", () => {
    it("broadcast reaches every player incl. the sender; unicast only its target; nothing crosses games", async () => {
      const lcid = freshLcid(); // two rooms of the same game, as two MK8D lobbies would be
      const x = (await room(t, 4, { lcid })).players;
      const y = (await room(t, 3, { lcid })).players;
      const outsider = await ready(t);
      expect(await outsider.c.scanAll(lcid)).toHaveLength(2);

      send(x[2], BCAST, 1); // 10.114.255.255 from node 2, source left 0
      for (const p of x) {
        const h = ProxyDataHeader.decode(await p.c.expect(PacketId.ProxyData)).info;
        expect([h.source_ipv4, h.dest_ipv4]).toEqual([at(3), BCAST]);
      }
      // one sender per room, so each room's order is fixed; the closing broadcast fences what came before
      send(x[0], at(2), 2); // unicast in room X
      send(x[0], BCAST, 99);
      send(y[0], at(2), 3); // the same IP in room Y
      send(y[0], at(3), 4, at(1)); // explicit, correct source
      send(y[0], BCAST, 98);
      expect(await Promise.all(x.map((p) => got(p, 99)))).toEqual([[99], [2, 99], [99], [99]]);
      expect(await Promise.all(y.map((p) => got(p, 98)))).toEqual([[98], [3, 98], [4, 98]]);
      await sleep(100);
      for (const p of [...x, ...y]) await p.c.none(0);
    });

    it("8 players: a broadcast storm reaches all 8, in the same order everywhere; unicast stays private", async () => {
      const { players } = await room(t, 8);
      for (let r = 0; r < 5; r++) for (const p of players) send(p, BCAST, r * 8 + p.node);
      const all = await Promise.all(players.map(async (p) => {
        const seq: number[] = [];
        while (seq.length < 40) seq.push((await p.c.expect(PacketId.ProxyData)).at(-1)!);
        return seq;
      }));
      for (const seq of all) {
        expect([...seq].sort((a, b) => a - b)).toEqual([...Array(40).keys()]);
        expect(seq).toEqual(all[0]); // the relay fans each packet out before handling the next
      }
      send(players[7], at(1), 200);
      send(players[7], BCAST, 201);
      expect(await Promise.all(players.map((p) => got(p, 201)))).toEqual(players.map((_, i) => (i === 0 ? [200, 201] : [201])));
    });

    it("spoofed, foreign or out-of-subnet ProxyData is dropped; source 0 is stamped", async () => {
      const { players: [a, b, c] } = await room(t, 3);
      const stranger = await ready(t); // initialized, in no game
      send(b, at(3), 1, at(1)); // pretends to be A
      send(b, at(3), 2, ip("192.168.0.2")); // source outside the subnet
      send(b, at(3), 3, ip("10.114.0.9")); // an unassigned address
      send(b, ip("10.115.0.3"), 4); // dest outside the subnet
      send(b, ip("8.8.8.8"), 5);
      send(b, at(9), 6); // in the subnet, not in the game
      send(b, ip("10.114.0.0"), 7); // network address
      stranger.c.proxyData(0, at(1), Uint8Array.of(8));
      stranger.c.proxyData(0, BCAST, Uint8Array.of(9));
      b.c.send(PacketId.ProxyData, new Uint8Array(ProxyDataHeader.size - 1)); // truncated header
      for (const type of [PacketId.ProxyConnect, PacketId.ProxyConnectReply, PacketId.ProxyDisconnect]) {
        b.c.raw(proxyMsg(type, at(1), at(3))); // spoofed: dropped
        b.c.raw(proxyMsg(type, 0, at(3))); // stamped with B's IP, to C only
      }
      send(b, at(3), 10); // stamped
      send(b, BCAST, 99); // fences B's packets
      expect(await got(a, 99)).toEqual([99]);
      for (const type of [PacketId.ProxyConnect, PacketId.ProxyConnectReply, PacketId.ProxyDisconnect]) {
        const p = await c.c.expect(type);
        expect(new DataView(p.buffer, p.byteOffset).getUint32(0, true)).toBe(at(2));
      }
      const last = await c.c.expect(PacketId.ProxyData);
      expect([ProxyDataHeader.decode(last).info.source_ipv4, last.at(-1)]).toEqual([at(2), 10]);
      expect(await got(c, 99)).toEqual([99]);
      expect(await got(b, 99)).toEqual([99]);
      await sleep(100); // the stranger's packets come over another socket: no order to fence them with
      for (const p of [a, b, c, stranger]) await p.c.none(0);
      expect(b.c.closeCode).toBeUndefined();
    });
  });

  describe("kick and room loss", () => {
    const reject = (node: number) => RejectRequest.encode({ node_id: node, disconnect_reason: 5 });

    it("host rejects a station mid-game: RejectReply, the rest resync, the kicked one is out and can rejoin", async () => {
      const { players, net } = await room(t, 4);
      const [a, , c] = players;
      a.c.send(PacketId.Reject, reject(2));
      await a.c.expect(PacketId.RejectReply);
      players.splice(2, 1);
      for (const p of players) roster(NetworkInfo.decode(await p.c.expect(PacketId.SyncNetwork)), players);
      send(c, BCAST, 1); // no longer routed
      send(a, BCAST, 99);
      for (const p of players) expect(await got(p, 99)).toEqual([99]);
      await sleep(100);
      for (const p of [...players, c]) await p.c.none(0); // C# parity: the rejected station is not told
      c.c.connect(net);
      expect(ProxyConfig.decode(await c.c.expect(PacketId.ProxyConfig)).proxy_ip).toBe(at(5));
      expect(NetworkInfo.decode(await c.c.expect(PacketId.Connected)).ldn.nodes[2]).toMatchObject({ is_connected: 1, ipv4_address: at(5) });
    });

    it("host can reject any station after an earlier leave (node ids are sparse), but not itself", async () => {
      const { players } = await room(t, 4);
      await leave(players, players[1], "disconnect"); // players: nodes 0, 2, 3
      players[0].c.send(PacketId.Reject, reject(0)); // not itself: its game would lose its owner and never close
      expect(err(await players[0].c.expect(PacketId.NetworkError))).toBe(NetworkError.RejectFailed);
      await players[0].c.expect(PacketId.RejectReply);
      players[0].c.send(PacketId.Reject, reject(3));
      await players[0].c.expect(PacketId.RejectReply);
      players.splice(2, 1);
      for (const p of players) roster(NetworkInfo.decode(await p.c.expect(PacketId.SyncNetwork)), players);
    });

    it("host leaves: stations get SyncNetwork then Disconnect; a station must Disconnect before it can host", async () => {
      const { players, lcid } = await room(t, 3);
      const [a, b, c] = players;
      a.c.close();
      for (const p of [b, c]) {
        roster(NetworkInfo.decode(await p.c.expect(PacketId.SyncNetwork)), [b, c]);
        expect(await p.c.expect(PacketId.Disconnect)).toEqual(DisconnectMessage.encode({ disconnect_ip: 0 }));
      }
      expect(await (await ready(t)).c.scanAll(lcid)).toEqual([]);
      // C# parity: the closed game keeps its stations until they Disconnect (the console module answers the room loss)
      b.c.createAp({ lcid: freshLcid() });
      expect(err(await b.c.expect(PacketId.NetworkError))).toBe(NetworkError.Unknown);
      b.c.send(PacketId.Disconnect, DisconnectMessage.encode({ disconnect_ip: 0 }));
      expect(NetworkInfo.decode(await c.c.expect(PacketId.SyncNetwork)).ldn.node_count).toBe(1);
      b.c.createAp({ lcid: freshLcid() });
      expect(ProxyConfig.decode(await b.c.expect(PacketId.ProxyConfig)).proxy_ip).toBe(at(1));
      await b.c.expect(PacketId.Connected);
      c.c.close();
      await expect.poll(() => t.gamesOf([a.sid]), { timeout: 2000 }).toBe(0); // the last station gone: the game is dropped
    });

    it("an AP too small for its own host leaves nothing behind (its private id stays usable)", async () => {
      const id = crypto.getRandomValues(new Uint8Array(16));
      const bad = await ready(t);
      const r = CreateAccessPointPrivateRequest.zero();
      r.security_parameter.session_id = id;
      r.network_config.local_communication_version = 1; // node_count_max stays 0
      bad.c.send(PacketId.CreateAccessPointPrivate, CreateAccessPointPrivateRequest.encode(r));
      await bad.c.none(100);
      const good = await ready(t);
      good.c.createApPrivate(id);
      expect(ProxyConfig.decode(await good.c.expect(PacketId.ProxyConfig)).proxy_ip).toBe(at(1));
      await good.c.expect(PacketId.Connected);
      expect(await t.gamesOf([bad.sid])).toBe(0);
    });
  });

  describe("wire compat with the console fixtures (test/wire)", () => {
    it("the console's host packets are accepted and answered", async () => {
      const h = await t.open();
      for (const n of ["Initialize", "CreateAccessPoint"]) h.raw(consoleFrame(n));
      await h.expect(PacketId.Initialize);
      expect(ProxyConfig.decode(await h.expect(PacketId.ProxyConfig)).proxy_ip).toBe(at(1));
      const net = NetworkInfo.decode(await h.expect(PacketId.Connected));
      expect(net.ldn).toMatchObject({ node_count_max: 8, advertise_data_size: 4, security_mode: 1 });
      expect(net.ldn.nodes[0].user_name.subarray(0, 6)).toEqual(new TextEncoder().encode("alice\0"));
      h.raw(consoleFrame("SetAcceptPolicy"));
      expect(NetworkInfo.decode(await h.expect(PacketId.SyncNetwork)).ldn.station_accept_policy).toBe(1);
      h.raw(consoleFrame("SetAdvertiseData"));
      expect(NetworkInfo.decode(await h.expect(PacketId.SyncNetwork)).ldn.advertise_data.subarray(0, 4)).toEqual(Uint8Array.of(5, 6, 7, 0));
      h.raw(consoleFrame("Reject")); // node 1: nobody there
      expect(err(await h.expect(PacketId.NetworkError))).toBe(NetworkError.RejectFailed);
      expect(packet(PacketId.RejectReply, await h.expect(PacketId.RejectReply))).toEqual(relayPacket("RejectReply"));
      h.raw(consoleFrame("Disconnect"));
      await h.none(100);
      expect(h.closeCode).toBeUndefined();
      h.close();
    });

    it("the console's station packets are accepted; the relay's replies match relay.json byte for byte", async () => {
      // the fixture Connect targets session a0..af (wire_compat.rs network_info), hosted here as a private AP
      const p = await ready(t);
      p.c.createApPrivate(Uint8Array.from({ length: 16 }, (_, i) => 0xa0 + i), { lcid: 0x0100000000001234n });
      await p.c.expect(PacketId.ProxyConfig);
      await p.c.expect(PacketId.Connected);

      const s = await t.open();
      for (const n of ["Initialize", "Scan", "Connect"]) s.raw(consoleFrame(n));
      await s.expect(PacketId.Initialize);
      for (let q = await s.next(); q.type !== PacketId.ScanReplyEnd; q = await s.next()) expect(q.type).toBe(PacketId.ScanReply);
      expect(packet(PacketId.ProxyConfig, await s.expect(PacketId.ProxyConfig))).toEqual(relayPacket("ProxyConfig"));
      await s.expect(PacketId.Connected);
      await p.c.expect(PacketId.SyncNetwork);
      s.raw(consoleFrame("ProxyData")); // 10.114.0.2:1234 -> 10.114.0.1:5678 "hello", forwarded untouched
      expect(packet(PacketId.ProxyData, await p.c.expect(PacketId.ProxyData))).toEqual(consoleFrame("ProxyData"));
      // relay.json ProxyData: .1:5678 -> .2:1234 "howdy"
      const back = ProxyDataHeader.encode({ info: { source_ipv4: at(1), source_port: 5678, dest_ipv4: at(2), dest_port: 1234, protocol: 17 }, data_length: 5 });
      p.c.send(PacketId.ProxyData, Uint8Array.from([...back, ...new TextEncoder().encode("howdy")]));
      expect(packet(PacketId.ProxyData, await s.expect(PacketId.ProxyData))).toEqual(relayPacket("ProxyData"));
      s.raw(consoleFrame("UpdateCheck"));
      await s.expect(PacketId.UpdateManifest);
      for (const n of ["DebugLog", "PingEcho"]) s.raw(consoleFrame(n));
      await s.none(100);
      p.c.close(); // host gone: SyncNetwork, then relay.json's Disconnect
      await s.expect(PacketId.SyncNetwork);
      expect(packet(PacketId.Disconnect, await s.expect(PacketId.Disconnect))).toEqual(relayPacket("Disconnect"));
      s.raw(consoleFrame("CloseDisconnect"));
      s.scan(1n);
      expect(packet(PacketId.ScanReplyEnd, await s.expect(PacketId.ScanReplyEnd))).toEqual(relayPacket("ScanReplyEnd"));
      expect(s.closeCode).toBeUndefined();
      s.close();
      expect(await t.gamesOf([p.sid])).toBe(0);
    });

    it("a full room answers relay.json's NetworkError", async () => {
      const { net } = await room(t, 2, { max: 2 });
      const c = await ready(t);
      c.c.connect(net);
      expect(packet(PacketId.NetworkError, await c.c.expect(PacketId.NetworkError))).toEqual(relayPacket("NetworkError"));
    });
  });

  describe("fuzz: malformed packets never throw or close the relay", () => {
    const SIZES: Record<number, number> = {
      [PacketId.Initialize]: InitializeMessage.size, [PacketId.Passphrase]: PassphraseMessage.size,
      [PacketId.CreateAccessPoint]: CreateAccessPointRequest.size, [PacketId.CreateAccessPointPrivate]: CreateAccessPointPrivateRequest.size,
      [PacketId.Reject]: RejectRequest.size, [PacketId.Scan]: ScanFilterFull.size, [PacketId.Connect]: ConnectRequest.size,
      [PacketId.ConnectPrivate]: ConnectPrivateRequest.size, [PacketId.Disconnect]: DisconnectMessage.size,
      [PacketId.ProxyConnect]: ProxyConnectRequest.size, [PacketId.ProxyConnectReply]: ProxyConnectRequest.size,
      [PacketId.ProxyData]: ProxyDataHeader.size, [PacketId.ProxyDisconnect]: ProxyDisconnectMessage.size,
      [PacketId.SetAcceptPolicy]: 1, [PacketId.Ping]: PingMessage.size, [PacketId.DebugLog]: 8,
      [PacketId.UpdateCheck]: UpdateCheckRequest.size, [PacketId.UpdateChunk]: UpdateChunkRequest.size,
    };
    // every id the relay knows, plus unknown ones
    const TYPES = [...Array(24).keys(), 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xfe, 0xff, 24, 0x7f, 0xbf, 0xc5];

    /** Round trip: an UpdateChunk for an unknown blob always gets its header back. Everything before it was handled. */
    async function barrier(c: Client, r: () => number) {
      const sha = Uint8Array.from({ length: 32 }, () => (r() * 256) | 0);
      c.send(PacketId.UpdateChunk, UpdateChunkRequest.encode({ sha256: sha, offset: 0, length: 1 }));
      for (;;) {
        const q = await c.next(5000);
        if (q.type === PacketId.UpdateChunkData && hex(UpdateChunkHeader.decode(q.payload).sha256) === hex(sha)) return;
      }
    }

    it("every packet type with empty, truncated, exact, oversized and mutated payloads, as lone console, host and station", async () => {
      const errors = vi.spyOn(console, "error");
      const r = rng(0x1d2b);
      const rand = (n: number) => Uint8Array.from({ length: n }, () => (r() * 256) | 0);
      const lone = await ready(t);
      const { players: [h, s] } = await room(t, 2);
      const sids = [lone.sid, h.sid, s.sid];
      for (const c of [lone.c, h.c, s.c]) {
        for (const type of TYPES) {
          const size = SIZES[type] ?? 16;
          const payloads = [new Uint8Array(0), rand(Math.max(0, size - 1)), rand(size), rand(size + 1 + ((r() * 512) | 0)), rand((r() * 4096) | 0)];
          for (let i = 0; i < 6; i++) {
            const m = new Uint8Array(size); // mostly zero, a few bytes poked: hits the boundary values
            for (let k = 0; k < 4; k++) m[(r() * size) | 0] = [0, 0xff, 1, (r() * 256) | 0][(r() * 4) | 0];
            payloads.push(m);
          }
          if (type === PacketId.ProxyData || type === PacketId.SetAdvertiseData || type === PacketId.DebugLog) {
            payloads.push(rand(MAX_PACKET_SIZE - 13)); // the largest packet the relay takes
          }
          for (const p of payloads) c.send(type, p);
        }
        await barrier(c, r);
        expect(c.closeCode).toBeUndefined();
      }
      expect(errors.mock.calls.filter((a) => JSON.stringify(a).includes("handler-error"))).toEqual([]);
      errors.mockRestore();

      // the relay still serves a normal room
      const { players, net, lcid } = await room(t, 3);
      expect((await (await ready(t)).c.scanAll(lcid)).map((i) => i.network_id.session_id)).toEqual([net.network_id.session_id]);
      send(players[2], BCAST, 7);
      for (const p of players) expect(await got(p, 7)).toEqual([7]);

      // and the fuzzers' games are gone once their sockets are
      for (const c of [lone.c, h.c, s.c]) c.close();
      await expect.poll(() => t.gamesOf(sids), { timeout: 2000 }).toBe(0);
    }, 30_000); // workerd's test harness takes ~3 ms per WebSocket message

    it("bad headers close only that socket with 1002; good headers with random ids are ignored", async () => {
      const r = rng(0xbeef);
      const witness = (await room(t, 2)).players;
      let c = await t.open();
      for (let i = 0; i < 60; i++) {
        const len = (r() * 64) | 0;
        const p = packet(0, Uint8Array.from({ length: len }, () => (r() * 256) | 0));
        const dv = new DataView(p.buffer);
        p[4] = (r() * 256) | 0; // type
        const kind = i % 5;
        if (kind === 0) dv.setUint32(0, MAGIC ^ (1 + ((r() * 0x7ffffffe) | 0)), true);
        if (kind === 1) p[5] = VERSION + 1 + ((r() * 254) | 0);
        if (kind === 2) dv.setInt32(8, len + 1 + ((r() * 1000) | 0) * (r() < 0.5 ? -1 : 1), true);
        const bad = kind < 4; // 3: cut inside the header
        c.raw(kind === 3 ? p.subarray(0, (r() * 12) | 0) : p);
        if (bad) {
          await expect(c.next(), `case ${i}`).rejects.toThrow("closed");
          expect(c.closeCode).toBe(1002);
          c = await t.open();
        }
      }
      await barrier(c, r);
      send(witness[1], BCAST, 5);
      for (const p of witness) expect(await got(p, 5)).toEqual([5]);
    });
  });
}
