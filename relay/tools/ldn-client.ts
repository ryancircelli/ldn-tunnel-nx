// Transport-agnostic RyuLDN test client: feed it received packets with push(),
// give it a function that sends one packet. Used by the Worker tests (inside
// workerd) and by tools/client.ts (Node, over ws:// or raw TCP).
import {
  ConnectRequest, CreateAccessPointPrivateRequest, CreateAccessPointRequest, ConnectPrivateRequest,
  InitializeMessage, LdnHeader, NetworkInfo, PacketId, PassphraseMessage, PingMessage, ProxyDataHeader,
  ScanFilterFull, HEADER_SIZE, packet,
} from "../src/core/codec/types.ts";

export interface Pkt {
  type: PacketId;
  payload: Uint8Array;
}

export const LCID = 0x01000bb9000e0000n;
export const ip = (s: string) => s.split(".").reduce((a, b) => ((a << 8) | Number(b)) >>> 0, 0);
export const ipStr = (n: number) => [24, 16, 8, 0].map((s) => (n >>> s) & 0xff).join(".");
const utf8 = (s: string) => new TextEncoder().encode(s);

export class Ldn {
  private queue: Pkt[] = [];
  private waiter: (() => void) | null = null;
  closed = false;
  /** Answer server pings automatically (off in tests that check exact sequences). */
  autoPong = false;

  constructor(private sendBytes: (b: Uint8Array) => void) {}

  /** One complete packet (header + payload) from the transport. */
  push(bytes: Uint8Array) {
    const h = LdnHeader.decode(bytes);
    const p = { type: h.type as PacketId, payload: bytes.slice(HEADER_SIZE, HEADER_SIZE + h.data_size) };
    if (this.autoPong && p.type === PacketId.Ping && p.payload[0] === 0) {
      this.send(PacketId.Ping, p.payload);
      return;
    }
    this.queue.push(p);
    this.waiter?.();
  }

  end() {
    this.closed = true;
    this.waiter?.();
  }

  send(type: PacketId, payload?: Uint8Array) {
    this.sendBytes(packet(type, payload));
  }

  async next(timeoutMs = 3000): Promise<Pkt> {
    const deadline = Date.now() + timeoutMs;
    while (!this.queue.length) {
      if (this.closed) throw new Error("connection closed");
      const left = deadline - Date.now();
      if (left <= 0) throw new Error("timed out waiting for a packet");
      await new Promise<void>((res) => {
        const t = setTimeout(res, left);
        this.waiter = () => (clearTimeout(t), res());
      });
      this.waiter = null;
    }
    return this.queue.shift()!;
  }

  /** Next packet must be `type`; returns its payload. */
  async expect(type: PacketId, timeoutMs?: number): Promise<Uint8Array> {
    const p = await this.next(timeoutMs);
    if (p.type !== type) throw new Error(`expected ${PacketId[type]}, got ${PacketId[p.type]}`);
    return p.payload;
  }

  /** Asserts nothing arrives for `ms`. */
  async none(ms = 300) {
    await new Promise((r) => setTimeout(r, ms));
    if (this.queue.length) throw new Error(`unexpected ${PacketId[this.queue[0].type]}`);
  }

  // ---- request builders -----------------------------------------------------

  async initialize(passphrase = "") {
    const pm = PassphraseMessage.zero();
    pm.passphrase.set(utf8(passphrase));
    this.send(PacketId.Passphrase, PassphraseMessage.encode(pm));
    this.send(PacketId.Initialize, InitializeMessage.encode(InitializeMessage.zero()));
    return InitializeMessage.decode(await this.expect(PacketId.Initialize));
  }

  createAp(o: { name?: string; lcid?: bigint; max?: number; version?: number; advertise?: Uint8Array; p2pPort?: number } = {}) {
    const r = CreateAccessPointRequest.zero();
    r.security_config.security_mode = 1;
    r.user_config.user_name.set(utf8(o.name ?? "Host"));
    r.network_config.intent_id.local_communication_id = o.lcid ?? LCID;
    r.network_config.node_count_max = o.max ?? 8;
    r.network_config.local_communication_version = o.version ?? 1;
    r.ryu_network_config.game_version.set(utf8("1.0"));
    r.ryu_network_config.external_proxy_port = o.p2pPort ?? 0;
    const adv = o.advertise ?? new Uint8Array(0);
    const body = new Uint8Array(CreateAccessPointRequest.size + adv.length);
    CreateAccessPointRequest.encode(r, body);
    body.set(adv, CreateAccessPointRequest.size);
    this.send(PacketId.CreateAccessPoint, body);
  }

  createApPrivate(sessionId: Uint8Array, o: { name?: string; lcid?: bigint } = {}) {
    const r = CreateAccessPointPrivateRequest.zero();
    r.security_config.security_mode = 1;
    r.security_parameter.session_id = sessionId;
    r.user_config.user_name.set(utf8(o.name ?? "PrivHost"));
    r.network_config.intent_id.local_communication_id = o.lcid ?? LCID;
    r.network_config.node_count_max = 8;
    r.network_config.local_communication_version = 1;
    this.send(PacketId.CreateAccessPointPrivate, CreateAccessPointPrivateRequest.encode(r));
  }

  scan(lcid?: bigint) {
    const f = ScanFilterFull.zero();
    f.network_type = 3;
    if (lcid !== undefined) {
      f.flag = 1; // LocalCommunicationId
      f.network_id.intent_id.local_communication_id = lcid;
    }
    this.send(PacketId.Scan, ScanFilterFull.encode(f));
  }

  /** Scans and collects ScanReply infos until ScanReplyEnd. */
  async scanAll(lcid?: bigint): Promise<NetworkInfo[]> {
    this.scan(lcid);
    const out: NetworkInfo[] = [];
    for (;;) {
      const p = await this.next();
      if (p.type === PacketId.ScanReplyEnd) return out;
      if (p.type !== PacketId.ScanReply) throw new Error(`unexpected ${PacketId[p.type]} during scan`);
      out.push(NetworkInfo.decode(p.payload));
    }
  }

  connect(info: NetworkInfo, o: { name?: string; version?: number } = {}) {
    const r = ConnectRequest.zero();
    r.security_config.security_mode = 1;
    r.user_config.user_name.set(utf8(o.name ?? "Station"));
    r.local_communication_version = o.version ?? 1;
    r.network_info = info;
    this.send(PacketId.Connect, ConnectRequest.encode(r));
  }

  /** padTo: C# LdnServer only accepts 0xC0 bytes (its managed struct is 8-aligned); the wire struct is 0xBC. */
  connectPrivate(sessionId: Uint8Array, o: { name?: string; padTo?: number } = {}) {
    const r = ConnectPrivateRequest.zero();
    r.security_parameter.session_id = sessionId;
    r.user_config.user_name.set(utf8(o.name ?? "PrivStation"));
    r.local_communication_version = 1;
    const out = new Uint8Array(Math.max(o.padTo ?? 0, ConnectPrivateRequest.size));
    this.send(PacketId.ConnectPrivate, ConnectPrivateRequest.encode(r, out));
  }

  proxyData(src: number, dst: number, data: Uint8Array, ports = { src: 1000, dst: 2000 }) {
    const h = ProxyDataHeader.zero();
    h.info = { source_ipv4: src, source_port: ports.src, dest_ipv4: dst, dest_port: ports.dst, protocol: 17 };
    h.data_length = data.length;
    const body = new Uint8Array(ProxyDataHeader.size + data.length);
    ProxyDataHeader.encode(h, body);
    body.set(data, ProxyDataHeader.size);
    this.send(PacketId.ProxyData, body);
  }

  pong(id: number) {
    this.send(PacketId.Ping, PingMessage.encode({ requester: 0, id }));
  }
}
