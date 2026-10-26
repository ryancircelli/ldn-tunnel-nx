// TCP -> WebSocket bridge: lets plain-TCP RyuLDN clients (the sysmodule's
// integration tests, Ryujinx) talk to the relay. Each TCP connection gets its
// own authenticated WebSocket; each LDN packet becomes one binary message.
//   LDN_TOKEN=<hex> node --experimental-transform-types tools/tcp-bridge.ts [--listen 30456] [--url ws://127.0.0.1:8787/ldn]
import net from "node:net";
import { parseArgs } from "node:util";
import WebSocket from "ws";
import { authHeaders, packetSplitter } from "./client.ts";

const { values } = parseArgs({
  options: {
    listen: { type: "string", default: "30456" },
    url: { type: "string", default: "ws://127.0.0.1:8787/ldn" },
  },
});
const headers = authHeaders(process.env.LDN_TOKEN ?? "");

net
  .createServer((sock) => {
    sock.setNoDelay(true);
    const ws = new WebSocket(values.url!, { headers });
    const pending: Buffer[] = [];
    sock.on(
      "data",
      packetSplitter((p) => (ws.readyState === WebSocket.OPEN ? ws.send(p) : pending.push(Buffer.from(p)))),
    );
    ws.on("open", () => pending.splice(0).forEach((p) => ws.send(p)));
    ws.on("message", (d: Buffer) => sock.write(d));
    ws.on("close", () => sock.end());
    ws.on("error", () => sock.destroy());
    ws.on("unexpected-response", (_req, res) => {
      console.error(`bridge: upgrade refused, HTTP ${res.statusCode}`);
      sock.destroy();
    });
    const done = () => (ws.readyState === WebSocket.OPEN ? ws.close() : ws.terminate());
    sock.on("close", done);
    sock.on("error", done);
  })
  .listen(Number(values.listen), "127.0.0.1", () => console.log(`bridge: 127.0.0.1:${values.listen} -> ${values.url}`));
