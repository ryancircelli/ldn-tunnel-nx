// The same relay scenarios as relay.test.ts, through the Node adapter: real HTTP server, `ws` clients,
// node:sqlite. Runs in plain Node (the "node" vitest project).
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { request } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import WebSocket from "ws";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  InitializeMessage, NetworkError, NetworkErrorMessage, NetworkInfo, PacketId, ProxyConfig, ProxyDataHeader, packet,
} from "../src/core/codec/types.ts";
import { Ldn, ip } from "../tools/ldn-client.ts";
import { startServer } from "../src/node/server.ts";
import { PIN } from "../src/core/release.ts";

const TOKEN = "a".repeat(64);
const ENV = {
  ADMIN: "pw",
  TOKEN_SWITCH_A: "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb",
  TOKEN_SWITCH_B: "", // an empty secret must never match
  TOKEN_FRIEND: "4ac281b4c9cf420d4641ab1644ce13cfde53b857ff57ac7a7ce8b09d9b52d7b9", // "b" * 63 + "c"
  RESUME_GRACE_MS: "0", // the C# behaviour; play.ts resumeSuite covers the grace
};

let dir: string;
let srv: Awaited<ReturnType<typeof startServer>>;
const url = (path = "/ldn") => `ws://127.0.0.1:${srv.port}${path}`;
beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), "relay-node-"));
  srv = await startServer({ port: 0, dbPath: join(dir, "relay.sqlite"), env: { ...ENV, TRUST_PROXY: "1" } }); // as behind Caddy
});
afterAll(async () => {
  await srv.close();
  rmSync(dir, { recursive: true, force: true });
});

/** Resolves with the HTTP status of an upgrade attempt (101 if it opened; the socket is closed again). */
function tryUpgrade(headers: Record<string, string>, path = "/ldn"): Promise<number> {
  return new Promise((resolve) => {
    const ws = new WebSocket(url(path), { headers });
    ws.on("unexpected-response", (_q, res) => (resolve(res.statusCode!), res.resume()));
    ws.on("open", () => (resolve(101), ws.close()));
    ws.on("error", () => {});
  });
}

type Conn = Ldn & { ws: WebSocket; closeCode?: number };

async function open(): Promise<Conn> {
  const ws = new WebSocket(url(), { headers: { Authorization: `Bearer ${TOKEN}` } });
  const c = new Ldn((b) => ws.send(b)) as Conn;
  c.ws = ws;
  ws.on("message", (d, bin) => bin && c.push(new Uint8Array(d as Buffer)));
  ws.on("close", (code) => ((c.closeCode = code), c.end()));
  await new Promise((r, j) => (ws.on("open", r), ws.on("error", j)));
  return c;
}
async function ready(): Promise<Conn> {
  const c = await open();
  await c.initialize("");
  return c;
}
const info = (b: Uint8Array) => NetworkInfo.decode(b);
let lcidSeq = 0x0100000000002000n;

describe("node auth", () => {
  const good = { Authorization: `Bearer ${TOKEN}` };
  const cases: [string, Record<string, string>, string][] = [
    ["missing token", {}, "/ldn"],
    ["wrong token", { Authorization: `Bearer ${"b".repeat(64)}` }, "/ldn"],
    ["uppercase token", { Authorization: `Bearer ${"A".repeat(64)}` }, "/ldn"],
    ["no Bearer prefix", { Authorization: TOKEN }, "/ldn"],
    ["wrong path", good, "/"],
  ];
  for (const [name, h, path] of cases) it(`${name} -> 404`, async () => expect(await tryUpgrade(h, path)).toBe(404));
  it("valid token -> 101", async () => expect(await tryUpgrade(good)).toBe(101));
  it("another TOKEN_* secret -> 101", async () => expect(await tryUpgrade({ Authorization: `Bearer ${"b".repeat(63)}c` })).toBe(101));
  it("POST upgrade and plain GET /ldn -> 404", async () => {
    expect((await fetch(`http://127.0.0.1:${srv.port}/ldn`, { headers: good })).status).toBe(404);
    expect((await fetch(`http://127.0.0.1:${srv.port}/ldn`, { method: "POST", headers: good })).status).toBe(404);
  });
  it("admin page: login form is public, the API needs the cookie", async () => {
    const base = `http://127.0.0.1:${srv.port}`;
    const page = await fetch(`${base}/admin`);
    expect(page.status).toBe(200);
    expect(await page.text()).toContain("<");
    expect((await fetch(`${base}/api/consoles`)).status).toBe(401);
    const bad = await fetch(`${base}/admin/login`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ secret: "nope" }) });
    expect(bad.status).toBe(401);
    const ok = await fetch(`${base}/admin/login`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ secret: "pw" }) });
    expect(ok.status).toBe(204);
    const cookie = (ok.headers.get("set-cookie") ?? "").split(";")[0];
    expect(cookie).toMatch(/^ldnt_admin=/);
    expect((await fetch(`${base}/api/consoles`, { headers: { cookie } })).status).toBe(200);
  });
  it("release API needs UPDATE_ADMIN; unset means closed", async () => {
    expect((await fetch(`http://127.0.0.1:${srv.port}/update/status`, { headers: { Authorization: "Bearer x" } })).status).toBe(404);
  });
});

describe("node framing", () => {
  it("bad magic closes with 1002", async () => {
    const c = await open();
    const p = packet(PacketId.Ping, new Uint8Array(2));
    p[0] = 0;
    c.ws.send(p);
    await expect(c.next()).rejects.toThrow("closed");
    expect(c.closeCode).toBe(1002);
  });
  it("text message closes with 1002", async () => {
    const c = await open();
    c.ws.send("hello");
    await expect(c.next()).rejects.toThrow("closed");
    expect(c.closeCode).toBe(1002);
  });
  it("create before Initialize -> NetworkError", async () => {
    const c = await open();
    c.createAp();
    expect(NetworkErrorMessage.decode(await c.expect(PacketId.NetworkError)).error_code).toBe(NetworkError.Unknown);
  });
  it("same MAC back for a client presenting its old id and MAC", async () => {
    const first = await (await open()).initialize("");
    const c = await open();
    c.send(PacketId.Initialize, InitializeMessage.encode(first));
    expect(InitializeMessage.decode(await c.expect(PacketId.Initialize)).mac_address).toEqual(first.mac_address);
  });
});

describe("node lobby", () => {
  it("host, scan, connect, ProxyData, broadcast, station leaves", async () => {
    const h = await ready();
    const lcid = ++lcidSeq;
    h.createAp({ name: "Host", lcid });
    expect(ProxyConfig.decode(await h.expect(PacketId.ProxyConfig)).proxy_ip).toBe(ip("10.114.0.1"));
    const net = info(await h.expect(PacketId.Connected));

    const s = await ready();
    const found = await s.scanAll(lcid);
    expect(found).toEqual([net]);
    s.connect(found[0], { name: "Friend" });
    expect(ProxyConfig.decode(await s.expect(PacketId.ProxyConfig)).proxy_ip).toBe(ip("10.114.0.2"));
    const joined = info(await s.expect(PacketId.Connected));
    expect(info(await h.expect(PacketId.SyncNetwork))).toEqual(joined);

    s.proxyData(0, ip("10.114.0.1"), new Uint8Array([9]));
    const got = await h.expect(PacketId.ProxyData);
    expect(ProxyDataHeader.decode(got).info.source_ipv4).toBe(ip("10.114.0.2"));
    s.proxyData(ip("10.114.0.1"), ip("10.114.0.1"), new Uint8Array([6])); // spoofed source
    await h.none();

    s.ws.close();
    expect(info(await h.expect(PacketId.SyncNetwork)).ldn.node_count).toBe(1);
    h.ws.close();
  });
});

describe("node persistence", () => {
  it("a restart on the same database reconciles: the game whose owner socket is gone is dropped", async () => {
    const dbPath = join(dir, "restart.sqlite");
    let a = await startServer({ port: 0, dbPath, env: ENV });
    const ws = new WebSocket(`ws://127.0.0.1:${a.port}/ldn`, { headers: { Authorization: `Bearer ${TOKEN}` } });
    const c = new Ldn((b) => ws.send(b));
    ws.on("message", (d) => c.push(new Uint8Array(d as Buffer)));
    await new Promise((r) => ws.on("open", r));
    await c.initialize("");
    const lcid = ++lcidSeq;
    c.createAp({ lcid });
    await c.expect(PacketId.ProxyConfig);
    await c.expect(PacketId.Connected);
    await a.close();
    a = await startServer({ port: 0, dbPath, env: ENV });
    const ws2 = new WebSocket(`ws://127.0.0.1:${a.port}/ldn`, { headers: { Authorization: `Bearer ${TOKEN}` } });
    const d = new Ldn((b) => ws2.send(b));
    ws2.on("message", (m) => d.push(new Uint8Array(m as Buffer)));
    await new Promise((r) => ws2.on("open", r));
    await d.initialize("");
    expect(await d.scanAll(lcid)).toEqual([]);
    ws2.close();
    await a.close();
  });
});

describe("node behind a TLS proxy", () => {
  it("admin POST with the public https Origin passes the same-origin check", async () => {
    const host = `127.0.0.1:${srv.port}`;
    const res = await fetch(`http://${host}/admin`, {
      method: "POST",
      headers: { Authorization: "Basic " + btoa("x:pw"), Origin: `https://${host}`, "X-Forwarded-Proto": "https", "content-type": "application/x-www-form-urlencoded" },
      body: "action=none",
    });
    expect(res.status).not.toBe(403);
  });
});

describe("node release source", () => {
  it("RELEASE_BASE_URL replaces the GitHub releases URL", async () => {
    const seen: string[] = [];
    const { createServer } = await import("node:http");
    const mirror = createServer((q, s) => (seen.push(q.url!), s.writeHead(404).end()));
    await new Promise<void>((r) => mirror.listen(0, "127.0.0.1", r));
    const m = await startServer({ port: 0, dbPath: ":memory:", env: { ADMIN: "pw", RELEASE_BASE_URL: `http://127.0.0.1:${(mirror.address() as { port: number }).port}/` } });
    try {
      const r = await fetch(`http://127.0.0.1:${m.port}/api/release`, { headers: { Authorization: "Bearer pw" } });
      expect(r.status).toBe(200);
      expect(seen).toContain(`/download/${PIN.tag}/release.json`);
      expect(seen).toContain("/latest/download/release.json");
    } finally {
      await m.close();
      mirror.close();
    }
  });
});

describe("release built by tools/release (Rust)", () => {
  // tools/release/test/bundle-rs holds manifest.bin, release.json and release.sig as `ldn-tunnel-release` wrote them
  // (fixture key, v0.1.2 = the tag in relay/release.json, build 1700000000; the tool's tests regenerate and compare them). The three payload files are
  // the inputs it was run on.
  const bundle = new URL("../../tools/release/test/bundle-rs/", import.meta.url);
  const FIXTURE_PUB = "040c81e42dc599eb75436bbe8281aff4c39ac762010a33fbc49c745842d4f811e4b6e9604a819499e3a51887ac1bbe7482b15e5ff9f48f6b941523af586998eff6";
  const files: Record<string, Buffer> = {
    "exefs.nsp": Buffer.from("exefs bytes"), "ldn-tunnel.ovl": Buffer.from("overlay bytes"), "relay-cloudflare.zip": Buffer.from("zip bytes"),
    ...Object.fromEntries(["manifest.bin", "release.json", "release.sig"].map((n) => [n, readFileSync(new URL(n, bundle))])),
  };
  async function install(tamper?: (f: Record<string, Buffer>) => void) {
    const served = { ...files };
    tamper?.(served);
    const { createServer } = await import("node:http");
    const mirror = createServer((q, s) => {
      const f = served[q.url!.split("/").pop()!];
      f ? s.end(f) : s.writeHead(404).end();
    });
    await new Promise<void>((r) => mirror.listen(0, "127.0.0.1", r));
    const m = await startServer({
      port: 0, dbPath: ":memory:",
      env: { ADMIN: "pw", PUBLISHER_KEY: FIXTURE_PUB, RELEASE_BASE_URL: `http://127.0.0.1:${(mirror.address() as { port: number }).port}/` },
    });
    try {
      return await (await fetch(`http://127.0.0.1:${m.port}/api/release`, { headers: { Authorization: "Bearer pw" } })).json() as any;
    } finally {
      await m.close();
      mirror.close();
    }
  }
  it("is verified and installed", async () => {
    const body = await install();
    expect(body.installError).toBeUndefined();
    expect(body.deployed).toEqual({ version: "0.1.2", build: 1700000000 });
  });
  it("a flipped release.sig bit is refused", async () => {
    const body = await install((f) => (f["release.sig"] = Buffer.from(f["release.sig"]), f["release.sig"][63] ^= 1));
    expect(body.installError).toContain("bad publisher signature");
    expect(body.deployed.build).toBeNull();
  });
});

describe("node hardening", () => {
  const login = (port: number, secret: string, xff?: string) =>
    fetch(`http://127.0.0.1:${port}/admin/login`, {
      method: "POST", headers: { "content-type": "application/json", ...(xff ? { "x-forwarded-for": xff } : {}) }, body: JSON.stringify({ secret }),
    });
  it("a message bigger than any packet closes the socket (1009)", async () => {
    const c = await open();
    c.ws.send(new Uint8Array(200_000));
    await expect(c.next()).rejects.toThrow("closed");
    expect(c.closeCode).toBe(1009);
  });
  it("wrong secrets lock out the X-Forwarded-For client only", async () => {
    for (let i = 0; i < 11; i++) expect((await login(srv.port, "nope", "10.0.0.9, 198.51.100.1")).status).toBe(401);
    expect((await login(srv.port, "pw", "198.51.100.1")).status).toBe(429);
    expect((await login(srv.port, "pw", "198.51.100.2")).status).toBe(204);
  });
  it("without TRUST_PROXY, X-Forwarded-For and -Proto are ignored: the socket peer is the client", async () => {
    const a = await startServer({ port: 0, dbPath: ":memory:", env: ENV });
    // from 127.0.0.2, so the lockout below cannot reach the other tests' 127.0.0.1
    const post = (path: string, headers: Record<string, string>, body: string) =>
      new Promise<number>((resolve, reject) => {
        const q = request({ host: "127.0.0.1", port: a.port, path, method: "POST", localAddress: "127.0.0.2", headers }, (res) => (resolve(res.statusCode!), res.resume()));
        q.on("error", reject).end(body);
      });
    const spoofed = (i: number, secret: string) =>
      post("/admin/login", { "content-type": "application/json", "x-forwarded-for": `198.51.100.${100 + i}` }, JSON.stringify({ secret }));
    try {
      for (let i = 0; i < 11; i++) expect(await spoofed(i, "nope")).toBe(401);
      expect(await spoofed(11, "pw")).toBe(429);
      const host = `127.0.0.1:${a.port}`;
      expect(await post("/admin", { host, Origin: `https://${host}`, "X-Forwarded-Proto": "https", Authorization: "Basic " + btoa("x:pw"),
        "content-type": "application/x-www-form-urlencoded" }, "action=none")).toBe(403);
    } finally {
      await a.close();
    }
  });
  it("changing ADMIN signs every session out; the example value keeps /admin closed", async () => {
    const dbPath = join(dir, "admin.sqlite");
    let a = await startServer({ port: 0, dbPath, env: { ...ENV, ADMIN: "first secret" } });
    const cookie = ((await login(a.port, "first secret", "198.51.100.3")).headers.get("set-cookie") ?? "").split(";")[0];
    expect((await fetch(`http://127.0.0.1:${a.port}/api/consoles`, { headers: { cookie } })).status).toBe(200);
    await a.close();
    a = await startServer({ port: 0, dbPath, env: { ...ENV, ADMIN: "second secret" } });
    expect((await fetch(`http://127.0.0.1:${a.port}/api/consoles`, { headers: { cookie } })).status).toBe(401);
    await a.close();
    a = await startServer({ port: 0, dbPath, env: { ...ENV, ADMIN: "change-me" } });
    expect((await fetch(`http://127.0.0.1:${a.port}/admin`)).status).toBe(503);
    expect((await login(a.port, "change-me", "198.51.100.4")).status).toBe(503);
    await a.close();
  });
});
