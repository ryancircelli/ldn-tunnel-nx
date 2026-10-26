// Desktop RyuLDN client over wss:// (the relay) or raw TCP (a C# LdnServer).
//
// Library: connectWs / connectTcp / upgradeStatus, used by tools/e2e.ts.
// CLI (token from LDN_TOKEN, never from argv, so it stays out of shell history):
//   LDN_TOKEN=<hex> node --experimental-transform-types tools/client.ts host [--url ws://127.0.0.1:8787/ldn]
//   LDN_TOKEN=<hex> node --experimental-transform-types tools/client.ts join [--url ...]
// The host echoes every ProxyData back; the joiner sends one and prints the echo.
import net from "node:net";
import { parseArgs } from "node:util";
import WebSocket from "ws";
import { HEADER_SIZE, MAX_PACKET_SIZE, PacketId, ProxyConfig, ProxyDataHeader } from "../src/core/codec/types.ts";
import { Ldn, ipStr } from "./ldn-client.ts";

export type Conn = Ldn & { close(): void };

export const authHeaders = (token: string) => ({ Authorization: `Bearer ${token}` });

export function connectWs(url: string, headers: Record<string, string>): Promise<Conn> {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(url, { headers });
    const c = new Ldn((b) => ws.send(b)) as Conn;
    c.close = () => ws.close();
    ws.on("message", (d: Buffer) => c.push(new Uint8Array(d)));
    ws.on("close", () => c.end());
    ws.on("open", () => resolve(c));
    ws.on("unexpected-response", (_req, res) => reject(new Error(`upgrade failed: HTTP ${res.statusCode}`)));
    ws.on("error", reject);
  });
}

/** HTTP status of an upgrade attempt (101 on success). */
export function upgradeStatus(url: string, headers: Record<string, string>): Promise<number> {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(url, { headers });
    ws.on("open", () => (ws.close(), resolve(101)));
    ws.on("unexpected-response", (_req, res) => (res.resume(), resolve(res.statusCode ?? 0)));
    ws.on("error", reject);
  });
}

/** Splits a TCP byte stream into packets by the header's data_size. */
export function packetSplitter(onPacket: (p: Buffer) => void) {
  let buf: Buffer = Buffer.alloc(0);
  return (d: Buffer) => {
    buf = buf.length ? Buffer.concat([buf, d]) : d;
    while (buf.length >= HEADER_SIZE) {
      const size = buf.readInt32LE(8);
      if (size < 0 || HEADER_SIZE + size >= MAX_PACKET_SIZE) {
        // Unframeable: pass it on as-is and let the server reject it.
        onPacket(buf);
        buf = Buffer.alloc(0);
        return;
      }
      if (buf.length < HEADER_SIZE + size) return;
      onPacket(buf.subarray(0, HEADER_SIZE + size));
      buf = buf.subarray(HEADER_SIZE + size);
    }
  };
}

export function connectTcp(host: string, port: number): Promise<Conn> {
  return new Promise((resolve, reject) => {
    const sock = net.connect({ host, port, noDelay: true });
    const c = new Ldn((b) => sock.write(b)) as Conn;
    c.close = () => sock.end();
    sock.on("data", packetSplitter((p) => c.push(new Uint8Array(p))));
    sock.on("close", () => c.end());
    sock.on("connect", () => resolve(c));
    sock.on("error", reject);
  });
}

async function cli() {
  const { positionals, values } = parseArgs({
    allowPositionals: true,
    options: { url: { type: "string", default: "ws://127.0.0.1:8787/ldn" } },
  });
  const role = positionals[0];
  if (role !== "host" && role !== "join") throw new Error("usage: client.ts host|join [--url URL]");
  const token = process.env.LDN_TOKEN ?? "";
  const c = await connectWs(values.url!, authHeaders(token));
  c.autoPong = true;
  const init = await c.initialize();
  console.log(`initialized, MAC ${Buffer.from(init.mac_address).toString("hex")}`);

  if (role === "host") {
    c.createAp({ name: "DesktopHost" });
    console.log(`access point up, my IP ${ipStr(ProxyConfig.decode(await c.expect(PacketId.ProxyConfig)).proxy_ip)}`);
    await c.expect(PacketId.Connected);
    for (;;) {
      const p = await c.next(24 * 3600_000);
      if (p.type === PacketId.ProxyData) {
        const h = ProxyDataHeader.decode(p.payload);
        const data = p.payload.subarray(ProxyDataHeader.size);
        console.log(`ProxyData from ${ipStr(h.info.source_ipv4)}: ${new TextDecoder().decode(data)}`);
        c.proxyData(0, h.info.source_ipv4, data, { src: h.info.dest_port, dst: h.info.source_port });
      } else {
        console.log(PacketId[p.type]);
      }
    }
  } else {
    const games = await c.scanAll();
    console.log(`scan: ${games.length} game(s)`);
    if (!games.length) return c.close();
    c.connect(games[0], { name: "DesktopJoin" });
    console.log(`joined, my IP ${ipStr(ProxyConfig.decode(await c.expect(PacketId.ProxyConfig)).proxy_ip)}`);
    await c.expect(PacketId.Connected);
    c.proxyData(0, games[0].ldn.nodes[0].ipv4_address, new TextEncoder().encode("hello from the desktop client"));
    const echo = await c.expect(PacketId.ProxyData);
    console.log(`echo: ${new TextDecoder().decode(echo.subarray(ProxyDataHeader.size))}`);
    c.close();
  }
}

if (import.meta.main) await cli();
