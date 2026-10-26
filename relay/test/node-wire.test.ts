// Cross-language wire check against the Rust console (crates/core/tests/wire_compat.rs is the other half).
// - relay.json: the relay→console frames, encoded here with the relay's codec; the Rust test feeds them to Conn.
//   `WIRE_FIXTURES=write npm test` rewrites it.
// - console.json: the bytes the Rust console puts on the wire; decoded here field by field, then replayed over
//   raw TCP into the Node server, which must answer 101 with the right accept and never close with 1002.
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { connect } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  ConnectRequest, CreateAccessPointRequest, DisconnectMessage, InitializeMessage, NetworkError, NetworkErrorMessage,
  NetworkInfo, NodeInfo, PacketId, PingMessage, ProxyConfig, ProxyDataHeader, RejectRequest, ScanFilterFull, SignedManifest,
  UpdateChannel, UpdateCheckRequest, UpdateChunkHeader, packet, parsePacket,
} from "../src/core/codec/types.ts";
import { startServer } from "../src/node/server.ts";

const fixture = (name: string) => new URL(`./wire/${name}`, import.meta.url);
const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const utf8 = (s: string) => new TextEncoder().encode(s);
const cstr = (b: Uint8Array) => new TextDecoder().decode(b.subarray(0, b.indexOf(0) < 0 ? b.length : b.indexOf(0)));
const pad = (s: string, n: number) => { const o = new Uint8Array(n); o.set(utf8(s)); return o; };
const seq = (n: number, from: number) => Uint8Array.from({ length: n }, (_, i) => from + i);
const cat = (...a: Uint8Array[]) => Uint8Array.from(Buffer.concat(a));

const PROGRAM_ID = 0x0100000000001234n;
const IP_A = 0x0a720001, IP_B = 0x0a720002, MASK = 0xffff0000;

/** Every WebSocket frame in a byte stream: [opcode, unmasked payload, masked]. */
function frames(buf: Uint8Array): [number, Uint8Array, boolean][] {
  const b = Uint8Array.from(buf);
  const out: [number, Uint8Array, boolean][] = [];
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  for (let at = 0; at < b.length;) {
    expect(b[at] & 0xf0, "FIN, no RSV").toBe(0x80);
    const masked = (b[at + 1] & 0x80) !== 0;
    let len = b[at + 1] & 0x7f, h = at + 2;
    if (len === 126) (len = dv.getUint16(h)), (h += 2);
    else if (len === 127) (len = Number(dv.getBigUint64(h))), (h += 8);
    const key = masked ? b.subarray(h, h + 4) : null;
    if (key) h += 4;
    const p = b.slice(h, h + len).map((x, i) => (key ? x ^ key[i & 3] : x));
    out.push([b[at] & 0x0f, p, masked]);
    at = h + len;
  }
  return out;
}

/** An unmasked FIN binary frame, as the relay sends one packet. */
function serverFrame(p: Uint8Array): Uint8Array {
  const n = p.length;
  const h = n < 126 ? [0x82, n] : n < 65536 ? [0x82, 126, n >> 8, n & 0xff] : [0x82, 127, 0, 0, 0, 0, n >>> 24, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff];
  return cat(Uint8Array.from(h), p);
}

const node = (ip: number, last: number, id: number, name: string) => ({
  ipv4_address: ip, mac_address: Uint8Array.of(2, 0, 0x5e, 0, 0, last), node_id: id, is_connected: 1,
  user_name: pad(name, 33), reserved1: 0x66, local_communication_version: 1, reserved2: new Uint8Array(16).fill(0x77),
});

/** wire_compat.rs network_info(): every field set. */
function ni(): NetworkInfo {
  const n = NetworkInfo.zero();
  n.network_id.intent_id = { local_communication_id: PROGRAM_ID, reserved1: 0x1111, scene_id: 3, reserved2: 0x22222222 };
  n.network_id.session_id = seq(16, 0xa0);
  n.common = {
    mac_address: Uint8Array.of(2, 0, 0x5e, 0, 0, 1), ssid: { length: 32, name: pad("12345678".repeat(4), 33) },
    channel: 6, link_level: 3, network_type: 2, reserved: 0x33333333,
  };
  Object.assign(n.ldn, {
    security_parameter: seq(16, 0x10), security_mode: 1, station_accept_policy: 0, unknown1: 0x44, reserved1: 0x5555,
    node_count_max: 8, node_count: 2, reserved2: 0x8888, advertise_data_size: 4, advertise_data: pad("\x01\x02\x03\x04", 384),
    unknown2: new Uint8Array(140).fill(0x99), authentication_id: 0x0123456789abcdefn,
  });
  n.ldn.nodes[0] = node(IP_A, 1, 0, "alice");
  n.ldn.nodes[1] = node(IP_B, 2, 1, "bob");
  return n;
}

function relayFrames(): [string, Uint8Array][] {
  const manifest = new Uint8Array(readFileSync(new URL("../../tools/release/test/fixture-manifest.bin", import.meta.url)));
  const m = SignedManifest.decode(manifest).manifest;
  const info = { source_ipv4: IP_A, source_port: 5678, dest_ipv4: IP_B, dest_port: 1234, protocol: 17 };
  const net = NetworkInfo.encode(ni());
  return [
    ["Initialize", packet(PacketId.Initialize, InitializeMessage.encode({ id: seq(16, 0x40), mac_address: Uint8Array.of(2, 0, 0x5e, 0, 0, 7) }))],
    ["Ping", packet(PacketId.Ping, PingMessage.encode({ requester: 0, id: 7 }))],
    ["ProxyConfig", packet(PacketId.ProxyConfig, ProxyConfig.encode({ proxy_ip: IP_B, proxy_subnet_mask: MASK }))],
    ["Connected", packet(PacketId.Connected, net)],
    ["SyncNetwork", packet(PacketId.SyncNetwork, net)],
    ["ScanReply", packet(PacketId.ScanReply, net)],
    ["ScanReplyEnd", packet(PacketId.ScanReplyEnd)],
    ["ProxyData", packet(PacketId.ProxyData, cat(ProxyDataHeader.encode({ info, data_length: 5 }), utf8("howdy")))],
    ["NetworkError", packet(PacketId.NetworkError, NetworkErrorMessage.encode({ error_code: NetworkError.TooManyPlayers }))],
    ["RejectReply", packet(PacketId.RejectReply)],
    ["Disconnect", packet(PacketId.Disconnect, DisconnectMessage.encode({ disconnect_ip: 0 }))],
    ["UpdateManifest", packet(PacketId.UpdateManifest, manifest)],
    ["UpdateManifestEmpty", packet(PacketId.UpdateManifest)],
    ["UpdateChunkData", packet(PacketId.UpdateChunkData, cat(
      UpdateChunkHeader.encode({ sha256: m.exefs_sha256, offset: 0, total_size: m.exefs_size }), seq(m.exefs_size, 0)))],
  ];
}

const console_ = JSON.parse(readFileSync(fixture("console.json"), "utf8")) as { key: string; accept: string; frames: { name: string; hex: string }[] };
const wire = (name: string) => Buffer.from(console_.frames.find((f) => f.name === name)!.hex, "hex");
/** The single packet in a console frame, checked by the relay's own parser (null = it would close 1002). */
function pkt(name: string, type: PacketId) {
  const [[op, p, masked]] = frames(wire(name));
  expect([op, masked], name).toEqual([2, true]);
  const r = parsePacket(p);
  expect(r?.type, name).toBe(type);
  return r!.payload;
}

describe("wire: relay → console (relay.json)", () => {
  it("matches the committed fixture", () => {
    const json = `{\n  "frames": [\n${relayFrames().map(([n, p]) => `    {"name": "${n}", "hex": "${hex(serverFrame(p))}"}`).join(",\n")}\n  ]\n}\n`;
    if (process.env.WIRE_FIXTURES === "write") writeFileSync(fixture("relay.json"), json);
    expect(readFileSync(fixture("relay.json"), "utf8"), "relay.json is stale: WIRE_FIXTURES=write npm test").toBe(json);
  });
});

describe("wire: console → relay (console.json)", () => {
  it("Initialize, no Passphrase", () => {
    expect(InitializeMessage.decode(pkt("Initialize", PacketId.Initialize))).toEqual({ id: seq(16, 0xc0), mac_address: Uint8Array.of(2, 0, 0x5e, 0, 0x53, 0x42) });
  });

  it("host: CreateAccessPoint, SetAcceptPolicy, SetAdvertiseData, Reject, Disconnect", () => {
    const p = pkt("CreateAccessPoint", PacketId.CreateAccessPoint);
    const r = CreateAccessPointRequest.decode(p);
    expect(r.security_config.security_mode).toBe(1);
    expect(cstr(r.user_config.user_name)).toBe("alice");
    expect(r.network_config).toMatchObject({ channel: 6, node_count_max: 8, local_communication_version: 1 });
    expect(r.network_config.intent_id).toMatchObject({ local_communication_id: PROGRAM_ID, scene_id: 3 });
    expect(p.subarray(CreateAccessPointRequest.size)).toEqual(Uint8Array.of(1, 2, 3, 4));
    expect(pkt("SetAcceptPolicy", PacketId.SetAcceptPolicy)).toEqual(Uint8Array.of(1)); // RejectAll
    expect(pkt("SetAdvertiseData", PacketId.SetAdvertiseData)).toEqual(Uint8Array.of(5, 6, 7));
    expect(RejectRequest.decode(pkt("Reject", PacketId.Reject))).toEqual({ node_id: 1, disconnect_reason: 5 }); // Rejected
    expect(pkt("Disconnect", PacketId.Disconnect).length).toBe(DisconnectMessage.size);
  });

  it("station: Scan, Connect, ProxyData", () => {
    const f = ScanFilterFull.decode(pkt("Scan", PacketId.Scan));
    expect([f.network_id.intent_id.scene_id, f.network_type]).toEqual([3, 2]);
    const c = ConnectRequest.decode(pkt("Connect", PacketId.Connect));
    expect([c.security_config.security_mode, cstr(c.user_config.user_name), c.local_communication_version]).toEqual([1, "bob", 1]);
    const want = ni();
    want.ldn.node_count = 1;
    want.ldn.nodes[1] = NodeInfo.zero();
    expect(c.network_info).toEqual(want);
    const p = pkt("ProxyData", PacketId.ProxyData);
    expect(ProxyDataHeader.decode(p)).toEqual({ info: { source_ipv4: IP_B, source_port: 1234, dest_ipv4: IP_A, dest_port: 5678, protocol: 17 }, data_length: 5 });
    expect(new TextDecoder().decode(p.subarray(ProxyDataHeader.size))).toBe("hello");
  });

  it("UpdateCheck, DebugLog, PingEcho, Disconnect + Close(1000)", () => {
    const u = UpdateCheckRequest.decode(pkt("UpdateCheck", PacketId.UpdateCheck));
    expect([u.running_build, u.rejected_build, u.channel, Array.from(u.reserved)]).toEqual([1, 7, UpdateChannel.Test, [1, 0]]);
    expect([new TextDecoder().decode(u.label.subarray(0, u.label_len)), cstr(u.version)]).toEqual(["Switch 1234", "v0.1.0-3-gabcdef0"]);
    const d = pkt("DebugLog", PacketId.DebugLog);
    expect(new TextDecoder().decode(d.subarray(1, 1 + d[0]))).toBe("Switch 1234");
    expect(new TextDecoder().decode(d.subarray(1 + d[0]))).toMatch(/hello[^]*world/);
    expect(PingMessage.decode(pkt("PingEcho", PacketId.Ping))).toEqual({ requester: 0, id: 7 });
    expect(pkt("CloseDisconnect", PacketId.Disconnect).length).toBe(DisconnectMessage.size);
    expect(frames(wire("Close"))).toEqual([[8, Uint8Array.of(0x03, 0xe8), true]]);
  });

  it("the Node server accepts the whole stream: 101 with the expected accept, closed with 1000", async () => {
    const dir = mkdtempSync(join(tmpdir(), "relay-wire-"));
    const srv = await startServer({ port: 0, dbPath: join(dir, "relay.sqlite"), env: { TOKEN_SWITCH_A: "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb" } });
    try {
      const sock = connect(srv.port, "127.0.0.1");
      const got: Buffer[] = [];
      sock.on("data", (b) => got.push(b));
      const ended = new Promise((r) => sock.on("close", r));
      sock.write(wire("Upgrade"));
      await new Promise((r) => sock.once("data", r)); // the 101
      for (const f of console_.frames.slice(1)) sock.write(Buffer.from(f.hex, "hex"));
      await ended;
      const all = Buffer.concat(got);
      const end = all.indexOf("\r\n\r\n") + 4;
      const head = all.subarray(0, end).toString();
      expect(head).toMatch(/^HTTP\/1\.1 101 /);
      expect(head).toContain(`Sec-WebSocket-Accept: ${console_.accept}`);
      const out = frames(all.subarray(end));
      expect(out.filter(([op]) => op === 8), "one close, 1000").toEqual([[8, Uint8Array.of(0x03, 0xe8), false]]);
      expect(out.map(([, p]) => p[4]).slice(0, 3)).toEqual([PacketId.Initialize, PacketId.ProxyConfig, PacketId.Connected]);
    } finally {
      await srv.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
