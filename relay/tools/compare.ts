// Differential check: runs one scripted session against the relay (ws) and a
// C# LdnServer (tcp), records every packet each client receives after each
// step, blanks the random fields, and prints any difference. C# runs player
// removal and game close on separate Task.Run calls, so some runs differ at
// the Reject step (SyncNetwork/RejectReply swap) or when a host leaves (the
// host also gets Disconnect, or Disconnect comes before SyncNetwork). Those
// are C# races; the relay always takes one fixed order. Rerun before chasing.
//   LDN_TOKEN_A=.. LDN_TOKEN_B=.. node --experimental-transform-types tools/compare.ts \
//       --url ws://127.0.0.1:8787/ldn --tcp 127.0.0.1:30456
import { randomBytes } from "node:crypto";
import { parseArgs } from "node:util";
import {
  InitializeMessage, NetworkErrorMessage, NetworkInfo, PacketId, PingMessage, ProxyConfig,
  ProxyDataHeader, DisconnectMessage,
} from "../src/core/codec/types.ts";
import { ip, LCID, type Pkt } from "./ldn-client.ts";
import { authHeaders, connectTcp, connectWs, type Conn } from "./client.ts";

const { values } = parseArgs({ options: { url: { type: "string" }, tcp: { type: "string" } } });
const names = ["A", "B", "C", "D"] as const;
type Name = (typeof names)[number];
type Clients = Record<Name, Conn>;

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");

/** Human-readable packet with per-run random values blanked. */
function show(p: Pkt): string {
  const t = PacketId[p.type] ?? `type${p.type}`;
  switch (p.type) {
    case PacketId.Initialize: {
      const m = InitializeMessage.decode(p.payload);
      return `${t} id=${m.id.some((x) => x) ? "*" : 0} mac=${m.mac_address.some((x) => x) ? "*" : 0}`;
    }
    case PacketId.Connected:
    case PacketId.SyncNetwork:
    case PacketId.ScanReply: {
      const i = NetworkInfo.decode(p.payload);
      i.network_id.session_id = new Uint8Array(0);
      i.network_id.intent_id.local_communication_id = 0n;
      i.common.mac_address = new Uint8Array(0);
      for (const n of i.ldn.nodes) n.mac_address = new Uint8Array(0);
      return `${t} ${JSON.stringify(i, (_k, v) => (typeof v === "bigint" ? String(v) : v instanceof Uint8Array ? hex(v) : v))}`;
    }
    case PacketId.NetworkError: return `${t} ${NetworkErrorMessage.decode(p.payload).error_code}`;
    case PacketId.ProxyConfig: return `${t} ${JSON.stringify(ProxyConfig.decode(p.payload))}`;
    case PacketId.Ping: return `${t} ${JSON.stringify(PingMessage.decode(p.payload))}`;
    case PacketId.Disconnect: return `${t} ${DisconnectMessage.decode(p.payload).disconnect_ip}`;
    default: return `${t} ${hex(p.payload)}`;
  }
}

async function drain(c: Conn, ms: number): Promise<string[]> {
  const out: string[] = [];
  const until = Date.now() + ms;
  for (;;) {
    const left = until - Date.now();
    if (left <= 0) return out;
    try {
      out.push(show(await c.next(left)));
    } catch (e) {
      if (String(e).includes("closed")) return [...out, "<closed>"];
      return out;
    }
  }
}

const rej = (node: number) => {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setUint32(0, node, true);
  return b;
};
const proxy4 = (src: number, dst: number) => {
  const b = new Uint8Array(20);
  const dv = new DataView(b.buffer);
  dv.setUint32(0, src, true);
  dv.setUint32(6, dst, true);
  dv.setInt32(12, 6, true);
  return b;
};

async function run(open: (n: Name) => Promise<Conn>): Promise<string[]> {
  const lcid = LCID + BigInt(randomBytes(2).readUInt16LE()) * 0x10000n;
  const priv = randomBytes(16);
  const c = {} as Clients;
  const trace: string[] = [];
  let net: NetworkInfo | null = null;
  const gone = new Set<Name>(); // closed by us: not drained again
  const steps: [string, (c: Clients) => void | Promise<void>, number?][] = [
    ["init A B C", async (c) => { for (const n of ["A", "B", "C"] as const) await c[n].initialize(); }],
    ["init D with passphrase", async (c) => void (await c.D.initialize("Ryujinx-0123abcd"))],
    ["A creates AP (advertise 4 bytes)", (c) => c.A.createAp({ lcid, advertise: new Uint8Array([1, 2, 3, 4]), version: 2 })],
    ["A creates AP again while hosting", (c) => c.A.createAp({ lcid })],
    ["B scans", (c) => c.B.scan(lcid)],
    ["D scans (other passphrase)", (c) => c.D.scan(lcid)],
    ["B connects to an unknown game", (c) => c.B.connect(NetworkInfo.zero())],
    ["B connects, version too high", (c) => c.B.connect(net!, { version: 3 })],
    ["B connects, version too low", (c) => c.B.connect(net!, { version: 1 })],
    ["B connects", (c) => c.B.connect(net!, { name: "Bee", version: 2 })],
    ["B ProxyData src 0 -> A", (c) => c.B.proxyData(0, ip("10.114.0.1"), new Uint8Array([1, 2, 3]))],
    ["B ProxyData spoofed src", (c) => c.B.proxyData(ip("10.114.0.1"), ip("10.114.0.1"), new Uint8Array([4]))],
    ["B ProxyData to 192.168.0.255", (c) => c.B.proxyData(0, ip("192.168.0.255"), new Uint8Array([5]))],
    ["A ProxyData to 10.114.255.255", (c) => c.A.proxyData(ip("10.114.0.1"), ip("10.114.255.255"), new Uint8Array([6]))],
    ["A ProxyData to nobody", (c) => c.A.proxyData(0, ip("10.114.0.9"), new Uint8Array([7]))],
    ["A ProxyConnect -> B", (c) => c.A.send(PacketId.ProxyConnect, proxy4(0, ip("10.114.0.2")).subarray(0, 16))],
    ["B ProxyConnectReply -> A", (c) => c.B.send(PacketId.ProxyConnectReply, proxy4(0, ip("10.114.0.1")).subarray(0, 16))],
    ["A ProxyDisconnect -> B", (c) => c.A.send(PacketId.ProxyDisconnect, proxy4(0, ip("10.114.0.2")))],
    ["C ProxyData while in no game", (c) => c.C.proxyData(0, ip("10.114.0.1"), new Uint8Array([8]))],
    ["A SetAdvertiseData 3 bytes", (c) => c.A.send(PacketId.SetAdvertiseData, new Uint8Array([9, 9, 9]))],
    ["B SetAdvertiseData (not owner)", (c) => c.B.send(PacketId.SetAdvertiseData, new Uint8Array([1]))],
    ["A SetAcceptPolicy RejectAll", (c) => c.A.send(PacketId.SetAcceptPolicy, new Uint8Array([1]))],
    ["C scans", (c) => c.C.scan(lcid)],
    ["A SetAcceptPolicy AcceptAll", (c) => c.A.send(PacketId.SetAcceptPolicy, new Uint8Array([0]))],
    ["C scans again", (c) => c.C.scan(lcid)],
    ["B rejects node 0 (not owner)", (c) => c.B.send(PacketId.Reject, rej(0))],
    ["A rejects node 5", (c) => c.A.send(PacketId.Reject, rej(5))],
    ["A rejects node 1", (c) => c.A.send(PacketId.Reject, rej(1))],
    ["B ProxyData after reject", (c) => c.B.proxyData(0, ip("10.114.0.1"), new Uint8Array([1]))],
    ["B sends Disconnect (in no game)", (c) => c.B.send(PacketId.Disconnect, new Uint8Array(4))],
    ["C connects (gets .3)", (c) => c.C.connect(net!, { name: "Cee", version: 2 })],
    ["C socket closes", (c) => (c.C.close(), gone.add("C"))],
    ["A pings as requester 1", (c) => c.A.send(PacketId.Ping, PingMessage.encode({ requester: 1, id: 3 }))],
    ["A sends Initialize again", (c) => c.A.send(PacketId.Initialize, new Uint8Array(22))],
    ["A leaves its game", (c) => c.A.send(PacketId.Disconnect, new Uint8Array(4))],
    ["B creates private AP", (c) => c.B.createApPrivate(priv)],
    // Padded to 0xC0: C# silently drops the 0xBC wire size (see README).
    ["D connects private (passphrase does not matter)", (c) => c.D.connectPrivate(priv, { padTo: 0xc0 })],
    ["A creates private AP with the same id", (c) => c.A.createApPrivate(priv)],
    ["A short Scan payload", (c) => c.A.send(PacketId.Scan, new Uint8Array(0x24))],
    ["B (host) socket closes", (c) => (c.B.close(), gone.add("B"))],
  ];
  for (const n of names) c[n] = await open(n);
  for (const [name, f, settle] of steps) {
    await f(c);
    trace.push(`== ${name}`);
    const got = await Promise.all(names.map((n) => (gone.has(n) ? [] : drain(c[n], settle ?? 400))));
    // Idle pings depend on wall-clock timing, not on the step: leave them out.
    names.forEach((n, i) => got[i].filter((l) => !l.startsWith("Ping")).forEach((line) => trace.push(`${n} <- ${line}`)));
    if (!net) {
      // Remember A's game for the Connect steps (session id is random per run).
      const raw = got[0].find((l) => l.startsWith("Connected"));
      if (raw) net = await scanFor(c.D, lcid, c);
    }
  }
  for (const n of names) c[n].close();
  return trace;
}

/** Fetch the real NetworkInfo (with its session id) through a passphrase-less scanner. */
async function scanFor(_d: Conn, lcid: bigint, c: Clients): Promise<NetworkInfo> {
  const found = await c.C.scanAll(lcid);
  return found[0];
}

const tokens: Record<Name, string> = { A: process.env.LDN_TOKEN_A ?? "", B: process.env.LDN_TOKEN_B ?? "", C: process.env.LDN_TOKEN_A ?? "", D: process.env.LDN_TOKEN_B ?? "" };
const [host, port] = values.tcp!.split(":");
const csharp = await run(() => connectTcp(host, Number(port)));
const relay = await run((n) => connectWs(values.url!, authHeaders(tokens[n])));

let diffs = 0;
for (let i = 0; i < Math.max(csharp.length, relay.length); i++) {
  if (csharp[i] !== relay[i]) {
    diffs++;
    console.log(`line ${i}:\n  C#:    ${csharp[i]}\n  relay: ${relay[i]}`);
    if (diffs > 20) break;
  }
}
if (process.env.TRACE) console.log(relay.join("\n"));
console.log(diffs ? `${diffs} difference(s)` : `identical: ${relay.length} lines, ${relay.filter((l) => !l.startsWith("==")).length} packets`);
process.exit(diffs ? 1 : 0);
