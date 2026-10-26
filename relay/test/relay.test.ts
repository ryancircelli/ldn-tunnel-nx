// Worker auth + Lobby behaviour, run inside workerd against the real Worker.
import { env, exports } from "cloudflare:workers";
import { evictDurableObject, runDurableObjectAlarm, runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import {
  DisconnectMessage, InitializeMessage, NetworkError, NetworkErrorMessage, NetworkInfo, PacketId, PingMessage,
  ProxyConfig, ProxyDataHeader, UpdateCheckRequest, packet,
} from "../src/core/codec/types.ts";
import { Ldn, ip } from "../tools/ldn-client.ts";
import type { Lobby } from "../src/cloudflare/lobby.ts";
import worker from "../src/cloudflare/worker.ts";

const TOKEN = "a".repeat(64); // sha256 is bound as TOKEN_SWITCH_A in vitest.config.ts

function upgrade(headers: Record<string, string>, path = "/ldn") {
  return exports.default.fetch(new Request("https://relay.test" + path, { headers: { Upgrade: "websocket", ...headers } }));
}

type Conn = Ldn & { ws: WebSocket; closeCode?: number };

async function open(): Promise<Conn> {
  const res = await upgrade({ Authorization: `Bearer ${TOKEN}` });
  expect(res.status).toBe(101);
  const ws = res.webSocket!;
  ws.accept();
  ws.binaryType = "arraybuffer";
  const c = new Ldn((b) => ws.send(b)) as Conn;
  c.ws = ws;
  ws.addEventListener("message", (e) => c.push(new Uint8Array(e.data as ArrayBuffer)));
  ws.addEventListener("close", (e) => {
    c.closeCode = e.code;
    c.end();
  });
  return c;
}

async function ready(pass = ""): Promise<Conn> {
  const c = await open();
  await c.initialize(pass);
  return c;
}

const stub = () => env.LOBBY.get(env.LOBBY.idFromName("main"));
const info = (b: Uint8Array) => NetworkInfo.decode(b);
const err = (b: Uint8Array) => NetworkErrorMessage.decode(b).error_code;
let lcidSeq = 0x0100000000001000n;
const freshLcid = () => ++lcidSeq; // keeps tests from seeing each other's games

/** Host creates an AP; returns the host plus its Connected info. */
async function host(o: Parameters<Ldn["createAp"]>[0] = {}) {
  const h = await ready();
  const lcid = o.lcid ?? freshLcid();
  h.createAp({ ...o, lcid });
  const cfg = ProxyConfig.decode(await h.expect(PacketId.ProxyConfig));
  const net = info(await h.expect(PacketId.Connected));
  return { h, cfg, net, lcid };
}

describe("worker auth", () => {
  const good = { Authorization: `Bearer ${TOKEN}` };
  const cases: [string, Promise<Response>][] = [
    ["missing token", upgrade({})],
    ["wrong token", upgrade({ ...good, Authorization: `Bearer ${"b".repeat(64)}` })],
    ["uppercase token", upgrade({ ...good, Authorization: `Bearer ${"A".repeat(64)}` })],
    ["no Bearer prefix", upgrade({ ...good, Authorization: TOKEN })],
    ["wrong path", upgrade(good, "/")],
    // direct call: the test harness's exports.default.fetch turns upgrade requests into GETs
    ["POST", worker.fetch(new Request("https://relay.test/ldn", { method: "POST", headers: { Upgrade: "websocket", ...good } }), env)],
    ["no upgrade", exports.default.fetch(new Request("https://relay.test/ldn", { headers: good }))],
  ];
  for (const [name, p] of cases) {
    it(`${name} -> 404, empty body`, async () => {
      const res = await p;
      expect(res.status).toBe(404);
      expect(await res.text()).toBe("");
    });
  }
  const accepted: [string, Record<string, string>][] = [
    ["valid token", good],
    ["token of another TOKEN_* secret", { Authorization: `Bearer ${"b".repeat(63)}c` }],
    ["legacy X-Console-Id header is ignored", { ...good, "X-Console-Id": "whatever" }],
  ];
  for (const [name, headers] of accepted) {
    it(`${name} -> 101`, async () => {
      const res = await upgrade(headers);
      expect(res.status).toBe(101);
      res.webSocket!.accept();
      res.webSocket!.close();
    });
  }
});

describe("framing", () => {
  it("bad magic closes with 1002", async () => {
    const c = await open();
    const p = packet(PacketId.Ping, new Uint8Array(2));
    p[0] = 0;
    c.ws.send(p);
    await expect(c.next()).rejects.toThrow("closed");
    expect(c.closeCode).toBe(1002);
  });
  it("size mismatch closes with 1002", async () => {
    const c = await open();
    c.ws.send(packet(PacketId.Ping, new Uint8Array(2)).subarray(0, 13));
    await expect(c.next()).rejects.toThrow("closed");
    expect(c.closeCode).toBe(1002);
  });
  it("text message closes with 1002", async () => {
    const c = await open();
    c.ws.send("hello");
    await expect(c.next()).rejects.toThrow("closed");
    expect(c.closeCode).toBe(1002);
  });
  it("short payloads are ignored, like C# MemoryMarshal.Read throwing", async () => {
    const c = await open();
    c.send(PacketId.Initialize, new Uint8Array(10));
    await c.none();
    expect((await c.initialize()).mac_address.length).toBe(6);
  });
});

describe("initialize", () => {
  it("assigns a session id and MAC, and ignores a second Initialize", async () => {
    const c = await open();
    const a = await c.initialize();
    expect(a.id.some((x) => x !== 0)).toBe(true);
    expect(a.mac_address.some((x) => x !== 0)).toBe(true);
    c.send(PacketId.Initialize, InitializeMessage.encode(InitializeMessage.zero()));
    await c.none();
  });
  it("gives back the same MAC to a client presenting its old id and MAC", async () => {
    const a = await ready();
    const first = await (async () => {
      const c = await open();
      return c.initialize();
    })();
    const c = await open();
    c.send(PacketId.Initialize, InitializeMessage.encode(first));
    expect(InitializeMessage.decode(await c.expect(PacketId.Initialize)).mac_address).toEqual(first.mac_address);
    a.ws.close();
  });
  it("create/connect before Initialize -> NetworkError", async () => {
    const c = await open();
    c.createAp();
    expect(err(await c.expect(PacketId.NetworkError))).toBe(NetworkError.Unknown);
    c.connect(NetworkInfo.zero());
    expect(err(await c.expect(PacketId.NetworkError))).toBe(NetworkError.ConnectFailure);
  });
});

describe("lobby", () => {
  it("host, scan, connect, ProxyData, spoof drop, broadcast", async () => {
    const adv = new Uint8Array([1, 2, 3, 4]);
    const { h, cfg, net, lcid } = await host({ name: "Host", advertise: adv });
    expect(cfg).toEqual({ proxy_ip: ip("10.114.0.1"), proxy_subnet_mask: 0xffff0000 });
    expect(net.ldn.node_count).toBe(1);
    expect(net.ldn.nodes[0]).toMatchObject({ ipv4_address: ip("10.114.0.1"), node_id: 0, is_connected: 1 });
    expect(net.common).toMatchObject({ link_level: 3, network_type: 2, channel: 0 });
    expect(net.common.ssid.length).toBe(32);
    expect(net.ldn.advertise_data_size).toBe(4);
    expect(net.ldn.advertise_data.subarray(0, 4)).toEqual(adv);

    const s = await ready();
    const found = await s.scanAll(lcid);
    expect(found).toHaveLength(1);
    expect(found[0]).toEqual(net);

    s.connect(found[0], { name: "Friend" });
    expect(ProxyConfig.decode(await s.expect(PacketId.ProxyConfig)).proxy_ip).toBe(ip("10.114.0.2"));
    const joined = info(await s.expect(PacketId.Connected));
    expect(joined.ldn.node_count).toBe(2);
    expect(joined.ldn.nodes[1]).toMatchObject({ ipv4_address: ip("10.114.0.2"), node_id: 1, is_connected: 1 });
    expect(info(await h.expect(PacketId.SyncNetwork))).toEqual(joined);

    // source 0 is stamped with the sender's IP
    s.proxyData(0, ip("10.114.0.1"), new Uint8Array([9, 9, 9]));
    const got = await h.expect(PacketId.ProxyData);
    expect(ProxyDataHeader.decode(got).info.source_ipv4).toBe(ip("10.114.0.2"));
    expect(got.subarray(ProxyDataHeader.size)).toEqual(new Uint8Array([9, 9, 9]));

    // the right source passes through unchanged
    h.proxyData(ip("10.114.0.1"), ip("10.114.0.2"), new Uint8Array([7]));
    expect((await s.expect(PacketId.ProxyData)).at(-1)).toBe(7);

    // spoofed source: dropped
    s.proxyData(ip("10.114.0.1"), ip("10.114.0.1"), new Uint8Array([6]));
    await h.none();

    // 192.168.0.255 reaches every player, sender included, and keeps its dest IP
    s.proxyData(0, ip("192.168.0.255"), new Uint8Array([5]));
    for (const c of [h, s]) {
      const p = ProxyDataHeader.decode(await c.expect(PacketId.ProxyData));
      expect(p.info.dest_ipv4).toBe(ip("192.168.0.255"));
      expect(p.info.source_ipv4).toBe(ip("10.114.0.2"));
    }
    // ProxyConnect is routed the same way
    const pc = new Uint8Array(16);
    new DataView(pc.buffer).setUint32(6, ip("10.114.0.1"), true);
    s.send(PacketId.ProxyConnect, pc);
    expect(new DataView((await h.expect(PacketId.ProxyConnect)).buffer).getUint32(0, true)).toBe(ip("10.114.0.2"));

    // host leaves: station gets SyncNetwork then Disconnect; game gone from scans
    h.send(PacketId.Disconnect, DisconnectMessage.encode({ disconnect_ip: 0 }));
    expect(info(await s.expect(PacketId.SyncNetwork)).ldn.node_count).toBe(1);
    expect(DisconnectMessage.decode(await s.expect(PacketId.Disconnect)).disconnect_ip).toBe(0);
    await h.none();
    const other = await ready();
    expect(await other.scanAll(lcid)).toHaveLength(0);
  });

  it("station socket close: host gets SyncNetwork without the station", async () => {
    const { h, lcid } = await host();
    const s = await ready();
    s.connect((await s.scanAll(lcid))[0]);
    await s.expect(PacketId.ProxyConfig);
    await s.expect(PacketId.Connected);
    await h.expect(PacketId.SyncNetwork);
    s.ws.close();
    const after = info(await h.expect(PacketId.SyncNetwork));
    expect(after.ldn.node_count).toBe(1);
    expect(after.ldn.nodes[1].is_connected).toBe(0);
  });

  it("connect errors: not found, version, full", async () => {
    const { h, net } = await host({ max: 2, version: 3 });
    const s = await ready();
    s.connect(NetworkInfo.zero());
    expect(err(await s.expect(PacketId.NetworkError))).toBe(NetworkError.ConnectNotFound);
    s.connect(net, { version: 4 });
    expect(err(await s.expect(PacketId.NetworkError))).toBe(NetworkError.VersionTooHigh);
    s.connect(net, { version: 2 });
    expect(err(await s.expect(PacketId.NetworkError))).toBe(NetworkError.VersionTooLow);
    s.connect(net, { version: 3 });
    await s.expect(PacketId.ProxyConfig);
    await s.expect(PacketId.Connected);
    await h.expect(PacketId.SyncNetwork);
    const t = await ready();
    t.connect(net, { version: 3 });
    expect(err(await t.expect(PacketId.NetworkError))).toBe(NetworkError.TooManyPlayers);
  });

  it("creating an AP while in a game -> NetworkError Unknown", async () => {
    const { h } = await host();
    h.createAp();
    expect(err(await h.expect(PacketId.NetworkError))).toBe(NetworkError.Unknown);
  });

  it("P2P port requested: PortUnreachable, then the AP is created relayed", async () => {
    const h = await ready();
    h.createAp({ p2pPort: 39990, lcid: freshLcid() });
    expect(err(await h.expect(PacketId.NetworkError))).toBe(NetworkError.PortUnreachable);
    await h.expect(PacketId.ProxyConfig);
    await h.expect(PacketId.Connected);
  });

  it("scan hides games by passphrase and RejectAll; SetAcceptPolicy syncs", async () => {
    const { h, lcid } = await host();
    const s = await ready("Ryujinx-0123abcd");
    expect(await s.scanAll(lcid)).toHaveLength(0);
    const t = await ready("not-a-valid-pass"); // invalid passphrases become ""
    expect(await t.scanAll(lcid)).toHaveLength(1);
    h.send(PacketId.SetAcceptPolicy, new Uint8Array([1]));
    expect(info(await h.expect(PacketId.SyncNetwork)).ldn.station_accept_policy).toBe(1);
    expect(await t.scanAll(lcid)).toHaveLength(0);
    // the host never sees its own game
    h.send(PacketId.SetAcceptPolicy, new Uint8Array([0]));
    await h.expect(PacketId.SyncNetwork);
    expect(await h.scanAll(lcid)).toHaveLength(0);
  });

  it("SetAdvertiseData: owner only, size kept, data capped at 0x180", async () => {
    const { h, net } = await host();
    const s = await ready();
    s.connect(net);
    await s.expect(PacketId.ProxyConfig);
    await s.expect(PacketId.Connected);
    await h.expect(PacketId.SyncNetwork);
    s.send(PacketId.SetAdvertiseData, new Uint8Array([1]));
    await h.none(100);
    h.send(PacketId.SetAdvertiseData, new Uint8Array(0x190).fill(0xab));
    for (const c of [h, s]) {
      const i = info(await c.expect(PacketId.SyncNetwork));
      expect(i.ldn.advertise_data_size).toBe(0x190);
      expect(i.ldn.advertise_data.every((x) => x === 0xab)).toBe(true);
    }
  });

  it("Reject: RejectReply first, then SyncNetwork; the rejected player is not told", async () => {
    const { h, net } = await host();
    const s = await ready();
    s.connect(net);
    await s.expect(PacketId.ProxyConfig);
    await s.expect(PacketId.Connected);
    await h.expect(PacketId.SyncNetwork);

    const rej = (node: number) => {
      const b = new Uint8Array(8);
      new DataView(b.buffer).setUint32(0, node, true);
      return b;
    };
    s.send(PacketId.Reject, rej(0)); // not the owner
    expect(err(await s.expect(PacketId.NetworkError))).toBe(NetworkError.RejectFailed);
    await s.expect(PacketId.RejectReply);
    h.send(PacketId.Reject, rej(5)); // no such node
    expect(err(await h.expect(PacketId.NetworkError))).toBe(NetworkError.RejectFailed);
    await h.expect(PacketId.RejectReply);

    h.send(PacketId.Reject, rej(1));
    await h.expect(PacketId.RejectReply);
    expect(info(await h.expect(PacketId.SyncNetwork)).ldn.node_count).toBe(1);
    await s.none();
    s.proxyData(0, ip("10.114.0.1"), new Uint8Array([1])); // no longer in the game
    await h.none();
  });

  it("private AP: id is the security parameter's session id", async () => {
    const sid = crypto.getRandomValues(new Uint8Array(16));
    const h = await ready();
    h.createApPrivate(sid);
    await h.expect(PacketId.ProxyConfig);
    expect(info(await h.expect(PacketId.Connected)).network_id.session_id).toEqual(sid);
    const s = await ready();
    s.connectPrivate(sid);
    await s.expect(PacketId.ProxyConfig);
    expect(info(await s.expect(PacketId.Connected)).ldn.node_count).toBe(2);
    // another session cannot take the same id
    const t = await ready();
    t.createApPrivate(sid);
    expect(err(await t.expect(PacketId.NetworkError))).toBe(NetworkError.Unknown);
  });
});

describe("liveness and hibernation", () => {
  it("idle ping: answered keeps the socket, unanswered closes it", async () => {
    const c = await ready();
    const age = () =>
      runInDurableObject(stub(), (o: Lobby) => {
        (o as unknown as { relay: { lastMsg: Map<string, number> } }).relay.lastMsg.forEach((_, k, m) => m.set(k, 0));
      });
    await age();
    expect(await runDurableObjectAlarm(stub())).toBe(true);
    const ping = PingMessage.decode(await c.expect(PacketId.Ping));
    expect(ping.requester).toBe(0);
    c.pong(ping.id);
    await c.none(100);
    await age();
    await runDurableObjectAlarm(stub());
    const ping2 = PingMessage.decode(await c.expect(PacketId.Ping));
    expect(ping2.id).toBe((ping.id + 1) & 0xff);
    await runDurableObjectAlarm(stub()); // not answered
    await expect(c.next()).rejects.toThrow("closed");
  });

  it("games and sessions survive eviction (SQLite + attachments)", async () => {
    const { h, lcid } = await host();
    const s = await ready();
    await evictDurableObject(stub());
    const found = await s.scanAll(lcid);
    expect(found).toHaveLength(1);
    s.connect(found[0]);
    await s.expect(PacketId.ProxyConfig);
    await s.expect(PacketId.Connected);
    await h.expect(PacketId.SyncNetwork);
    await evictDurableObject(stub());
    s.proxyData(0, ip("10.114.0.1"), new Uint8Array([42]));
    expect((await h.expect(PacketId.ProxyData)).at(-1)).toBe(42);
  });
});

describe("debug log", () => {
  const dbg = (label: string, text: string) => {
    const l = new TextEncoder().encode(label);
    return new Uint8Array([l.length, ...l, ...new TextEncoder().encode(text)]);
  };
  const readLogs = async (qs = "", token = TOKEN) => {
    const res = await exports.default.fetch(new Request("https://relay.test/logs" + qs, { headers: { Authorization: `Bearer ${token}` } }));
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toBe("text/plain; charset=utf-8");
    return (await res.text()).split("\n").filter(Boolean).map((l) => l.split("\t"));
  };
  /** Sends DebugLog packets, then a round trip so they are known to be processed. */
  const sendLogs = async (c: Conn, ...payloads: Uint8Array[]) => {
    for (const p of payloads) c.send(PacketId.DebugLog, p);
    await c.initialize();
  };

  it("is stored from an un-initialized session, unanswered, and served in the documented format", async () => {
    const c = await open();
    const lbl = "fmt-" + freshLcid();
    c.send(PacketId.DebugLog, dbg(lbl, "one\ntwo\n"));
    c.send(PacketId.Initialize, new Uint8Array(InitializeMessage.size));
    await c.expect(PacketId.Initialize); // first reply is Initialize: DebugLog got none
    await c.none(100);
    const rows = await readLogs(`?label=${lbl}`);
    expect(rows).toHaveLength(2);
    expect(rows[0][0]).toBe(rows[1][0]); // same row id for the batch
    expect(new Date(rows[0][1]).toISOString()).toBe(rows[0][1]);
    expect(Math.abs(Date.now() - Date.parse(rows[0][1]))).toBeLessThan(10_000);
    expect(rows.map((r) => [r[2], r[3]])).toEqual([[lbl, "one"], [lbl, "two"]]);
  });

  it("drops malformed payloads", async () => {
    const c = await open();
    const lbl = "bad-" + freshLcid();
    const ok = dbg(lbl, "good");
    await sendLogs(
      c,
      new Uint8Array(0),
      new Uint8Array([0, 65, 66]), // label_len 0
      new Uint8Array([33, ...new Uint8Array(33).fill(65), 66]), // label_len 33
      new Uint8Array([5, 65, 66]), // shorter than 1+label_len
      dbg(lbl, ""), // empty text
      dbg(lbl, "\n"), // blank text
      dbg(lbl, "x".repeat(2048)), // over 2048 bytes
      ok,
    );
    expect(await readLogs(`?label=${lbl}`)).toHaveLength(1);
    expect((await readLogs("?after=0&limit=2000")).filter((r) => r[3] === "x".repeat(2048) || r[2] === "AB")).toHaveLength(0);
  });

  it("sanitizes the label and text control characters", async () => {
    const c = await open();
    await sendLogs(c, dbg("a\tb\x01c", "x\ty\r\n"));
    const rows = await readLogs("?label=a b c");
    expect(rows.at(-1)?.slice(2)).toEqual(["a b c", "x y"]);
  });

  it("serves after= and label= filters, and limit", async () => {
    const c = await open();
    const [a, b] = ["fa-" + freshLcid(), "fb-" + freshLcid()];
    await sendLogs(c, dbg(a, "1"), dbg(b, "2"), dbg(a, "3"));
    const all = (await readLogs(`?label=${a}`)).map((r) => [Number(r[0]), r[3]]);
    expect(all.map((r) => r[1])).toEqual(["1", "3"]);
    expect(await readLogs(`?label=${a}&after=${all[0][0]}`)).toEqual([expect.arrayContaining(["3"])]);
    expect((await readLogs(`?label=${b}`)).map((r) => r[3])).toEqual(["2"]);
    expect(await readLogs(`?label=${a}&limit=1`)).toHaveLength(1);
  });

  it("/logs without a valid token is an empty 404; /logs upgrades are refused", async () => {
    for (const h of [{}, { Authorization: `Bearer ${"b".repeat(64)}` }, { Authorization: TOKEN }] as Record<string, string>[]) {
      const res = await exports.default.fetch(new Request("https://relay.test/logs", { headers: h }));
      expect(res.status).toBe(404);
      expect(await res.text()).toBe("");
    }
    expect((await upgrade({ Authorization: `Bearer ${TOKEN}` }, "/logs")).status).toBe(404);
  });

  it("alarm prunes old rows and rows beyond the cap", async () => {
    await runInDurableObject(stub(), (_o: Lobby, state) => {
      state.storage.sql.exec("DELETE FROM logs");
      state.storage.sql.exec("INSERT INTO logs (at, label, text) VALUES (?, 'old', 'x')", Date.now() - 4 * 86400_000);
      state.storage.sql.exec("INSERT INTO logs (at, label, text) VALUES (?, 'new', 'x')", Date.now());
    });
    await runDurableObjectAlarm(stub());
    expect((await readLogs()).map((r) => r[2])).toEqual(["new"]);
  });
});

describe("hostile console", () => {
  type Core = { relay: { message(c: unknown, m: Uint8Array): void } };
  const fakeConn = (session: unknown, sent: Uint8Array[] = []) =>
    ({ send: (b: Uint8Array) => void sent.push(b), close() {}, load: () => session, save() {} });

  it("cannot grow the update-check table without bound", async () => {
    const rows = await runInDurableObject(stub(), (o: Lobby, state) => {
      for (let i = 0; i < 2500; i++) {
        const conn = fakeConn({ sid: "f".repeat(32), who: "c:spam" + i, init: false, game: null });
        const label = new TextEncoder().encode("spam-" + i);
        (o as unknown as Core).relay.message(conn, packet(PacketId.UpdateCheck, UpdateCheckRequest.encode({
          running_build: 1, rejected_build: 0, channel: 1, label_len: label.length, reserved: new Uint8Array([0, 0]),
          label, version: new Uint8Array(0),
        })));
      }
      return state.storage.sql.exec<{ n: number }>("SELECT COUNT(*) AS n FROM console_status WHERE label LIKE 'spam-%'").one().n;
    });
    expect(rows).toBeLessThan(2000); // 1000 kept at each trim, plus at most 999 since the last one
  });

  it("trims the MAC table to its cap, newest kept", async () => {
    const n = await runInDurableObject(stub(), (o: Lobby, state) => {
      state.storage.sql.exec("DELETE FROM macs");
      for (let i = 0; i < 10_500; i++) state.storage.sql.exec("INSERT INTO macs (id, mac, at) VALUES (?, ?, ?)", "m" + i, "00", i);
      const conn = fakeConn({ sid: "e".repeat(32), who: "c:macs", init: false, game: null });
      const check = packet(PacketId.UpdateCheck, UpdateCheckRequest.encode({
        running_build: 1, rejected_build: 0, channel: 1, label_len: 0, reserved: new Uint8Array([0, 0]),
        label: new Uint8Array(32), version: new Uint8Array(0),
      }));
      for (let i = 0; i < 1000; i++) (o as unknown as Core).relay.message(conn, check); // 1000 writes = one trim
      return state.storage.sql.exec<{ n: number; lo: number }>("SELECT COUNT(*) AS n, MIN(at) AS lo FROM macs").one();
    });
    expect(n).toEqual({ n: 10_000, lo: 500 });
  });

  it("a handler that throws drops the packet, not the object", async () => {
    await runInDurableObject(stub(), (o: Lobby) => {
      const conn = { ...fakeConn({ sid: "d".repeat(32), who: "c:boom", init: false, game: null }), save() { throw new Error("boom"); } };
      expect(() => (o as unknown as Core).relay.message(conn, packet(PacketId.Initialize, new Uint8Array(22)))).not.toThrow();
    });
  });

  it("update-check rows are per token and module: a shared label does not overwrite", async () => {
    const rows = await runInDurableObject(stub(), (o: Lobby, state) => {
      const check = (who: string, module: number, build: number) =>
        (o as unknown as Core).relay.message(fakeConn({ sid: "f".repeat(32), who, init: false, game: null }), packet(PacketId.UpdateCheck, UpdateCheckRequest.encode({
          running_build: build, rejected_build: 0, channel: 1, label_len: 6, reserved: new Uint8Array([module, 0]),
          label: new TextEncoder().encode("shared"), version: new Uint8Array(0),
        })));
      check("c:one", 0, 1); check("c:two", 0, 2); check("c:two", 1, 3); check("c:two", 1, 4); // last one replaces its own row only
      return state.storage.sql.exec<{ who: string; module: number; running_build: number }>(
        "SELECT who, module, running_build FROM console_status WHERE label = 'shared' ORDER BY who, module").toArray();
    });
    expect(rows).toEqual([{ who: "c:one", module: 0, running_build: 1 }, { who: "c:two", module: 0, running_build: 2 }, { who: "c:two", module: 1, running_build: 4 }]);
  });

  it("a socket whose session was dropped (revoked) ignores further frames", async () => {
    await runInDurableObject(stub(), (o: Lobby) => {
      const sent: Uint8Array[] = [];
      (o as unknown as Core).relay.message(fakeConn(null, sent), packet(PacketId.Initialize, new Uint8Array(InitializeMessage.size)));
      expect(sent).toHaveLength(0);
    });
  });
});
