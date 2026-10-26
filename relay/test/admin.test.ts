/// <reference types="node" />
// Admin JSON API, invite links, per-console tokens, pinned-release install and the Cloudflare self-update.
// GitHub and the Cloudflare API are mocked by replacing fetch in the test isolate (the Durable Object runs here too).
import { env, exports } from "cloudflare:workers";
import { runInDurableObject } from "cloudflare:test";
import { createHash, sign } from "node:crypto";
import { unzipSync, zipSync } from "fflate";
import { afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { PacketId, UpdateCheckRequest } from "../src/core/codec/types.ts";
import { Ldn } from "../tools/ldn-client.ts";
import { encodeManifest, signManifest } from "../tools/update-manifest.ts";
import { PIN, RATE_LIMITED } from "../src/core/release.ts";
import { cloudflareDeployer } from "../src/cloudflare/lobby.ts";

const e = env as unknown as Record<string, string>;
const ORIGIN = "https://relay.test";
const ADMIN = "correct horse"; // vitest.config.ts
const enc = new TextEncoder();
const dec = new TextDecoder();
const sha = (b: Uint8Array) => createHash("sha256").update(b).digest();
const bytes = (n: number, seed: number) => Uint8Array.from({ length: n }, (_, i) => (i * 31 + seed) & 0xff);
const p1363 = (b: Uint8Array) => new Uint8Array(sign("sha256", b, { key: e.TEST_PUBLISHER_PRIVATE_PEM, dsaEncoding: "ieee-p1363" }));

/** A signed release as CI publishes it (tools/release: version = the tag): asset name -> bytes. */
function makeRelease(semver: string, seed: number) {
  const version = "v" + semver;
  const exefs = bytes(70_000 + seed, seed), overlay = bytes(3000 + seed, seed + 1);
  const worker = zipSync({
    "index.js": enc.encode(`export default {}; // ${version}`),
    "metadata.json": enc.encode(JSON.stringify({ main_module: "index.js", compatibility_date: "2026-10-01" })),
  });
  const manifest = signManifest(encodeManifest({
    build: 1000 + seed, version, exefs: { size: exefs.length, sha256: sha(exefs) }, overlay: { size: overlay.length, sha256: sha(overlay) },
  }, 2), e.TEST_PUBLISHER_PRIVATE_PEM);
  const files: Record<string, Uint8Array> = { "manifest.bin": manifest, "exefs.nsp": exefs, "ldn-tunnel.ovl": overlay, "relay-cloudflare.zip": worker };
  const doc = enc.encode(JSON.stringify({
    version, build: 1000 + seed,
    assets: Object.fromEntries(Object.entries(files).map(([n, b]) => [n, { sha256: sha(b).toString("hex"), size: b.length }])),
  }));
  return { tag: version, exefs, overlay, manifest, worker, assets: { ...files, "release.json": doc, "release.sig": p1363(doc) } };
}

const pinned = makeRelease(PIN.tag.slice(1), 1);
const next = makeRelease("9.9.9", 2);
type Call = { url: string; init?: RequestInit };
let calls: Call[] = [];
let github: Record<string, Uint8Array> = {};
let cloudflare: (url: string, init?: RequestInit) => Response = () => new Response("{}", { status: 500 });
let rateLimit: (url: string) => Response | undefined = () => undefined;
const tooMany = (retryAfter = "0") => new Response("rate limited", { status: 429, headers: { "retry-after": retryAfter } });
const realFetch = globalThis.fetch;
const gh = (tag: string, name: string) => `https://github.com/${PIN.repo}/releases/download/${tag}/${name}`;

function serve(rel: ReturnType<typeof makeRelease>, latest = false) {
  for (const [name, b] of Object.entries(rel.assets)) {
    github[gh(rel.tag, name)] = b;
    if (latest) github[`https://github.com/${PIN.repo}/releases/latest/download/${name}`] = b;
  }
}

const stub = () => env.LOBBY.get(env.LOBBY.idFromName("main"));
const sqlRun = (q: string, ...b: SqlStorageValue[]) => runInDurableObject(stub(), (_o, state) => state.storage.sql.exec(q, ...b).toArray());

beforeAll(async () => {
  // the Durable Object's storage may carry rows from the other test files
  for (const t of ["kv", "tokens", "invites", "seen", "admin_sessions"]) await sqlRun(`DELETE FROM ${t}`);
  await sqlRun("DELETE FROM channels WHERE name LIKE 'ldn-tunnel/%'");
});
beforeEach(() => {
  calls = [];
  github = {};
  rateLimit = () => undefined;
  serve(pinned, true);
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = input instanceof Request ? input.url : String(input);
    if (url.startsWith("https://github.com/") || url.startsWith("https://api.github.com/")) {
      calls.push({ url, init });
      const limited = rateLimit(url);
      if (limited) return limited;
      const b = github[url];
      return b ? new Response(b) : new Response("not found", { status: 404 });
    }
    if (url.startsWith("https://api.cloudflare.com/")) {
      calls.push({ url, init });
      return cloudflare(url, init);
    }
    return realFetch(input, init);
  }) as typeof fetch;
});
afterEach(() => {
  globalThis.fetch = realFetch;
});

const req = (path: string, init: RequestInit = {}) => exports.default.fetch(new Request(ORIGIN + path, init));
const api = (path: string, method = "GET", body?: unknown, auth = `Bearer ${ADMIN}`) =>
  req(path, { method, headers: { Authorization: auth, "content-type": "application/json" }, body: body === undefined ? undefined : JSON.stringify(body) });
const apiJson = async (path: string, method = "GET", body?: unknown) => {
  const res = await api(path, method, body);
  expect(res.headers.get("content-type")).toContain("application/json");
  return { status: res.status, body: (await res.json()) as any };
};

async function invite(name?: string): Promise<string> {
  const { status, body } = await apiJson("/api/invites", "POST", name === undefined ? {} : { name });
  expect(status).toBe(200);
  expect(body.expiresAt - Date.now()).toBeGreaterThan(23 * 3600_000);
  const m = (body.url as string).match(/^https:\/\/relay\.test\/invite\/([0-9a-f]{64})$/);
  expect(m).not.toBeNull();
  return m![1];
}
async function redeem(token: string) {
  const res = await req(`/invite/${token}`, { method: "POST" });
  expect(res.status).toBe(200);
  expect(res.headers.get("content-type")).toBe("application/zip");
  const files = unzipSync(new Uint8Array(await res.arrayBuffer()));
  const ini = dec.decode(files["config/ldn-tunnel/config.ini"]);
  return { files, ini, token: ini.match(/^token = ([0-9a-f]{64})$/m)![1] };
}
async function connect(token: string): Promise<{ status: number; c?: Ldn; ws?: WebSocket }> {
  const res = await req("/ldn", { headers: { Upgrade: "websocket", Authorization: `Bearer ${token}` } });
  if (res.status !== 101) return { status: res.status };
  const ws = res.webSocket!;
  ws.accept();
  ws.binaryType = "arraybuffer";
  const c = new Ldn((b) => ws.send(b));
  ws.addEventListener("message", (ev) => c.push(new Uint8Array(ev.data as ArrayBuffer)));
  ws.addEventListener("close", () => c.end());
  return { status: 101, c, ws };
}
const updateCheck = (module: number, version = "v-running", build = 5) => UpdateCheckRequest.encode({
  running_build: build, rejected_build: 0, channel: 1, label_len: 4, reserved: new Uint8Array([module, 0]),
  label: enc.encode("test"), version: enc.encode(version),
});
const consoleOf = async (name: string) => (await apiJson("/api/consoles")).body.find((c: any) => c.name === name);

describe("admin auth", () => {
  it("/api needs the cookie or the ADMIN secret as a bearer token", async () => {
    for (const auth of ["", "Bearer wrong", `Bearer ${"a".repeat(64)}`, `Basic ${btoa("x:" + ADMIN)}`]) {
      const res = await api("/api/consoles", "GET", undefined, auth);
      expect(res.status).toBe(401);
    }
    expect((await api("/api/consoles")).status).toBe(200);
  });
  it("login sets an HttpOnly, Secure, SameSite=Strict session cookie that opens /api", async () => {
    expect((await req("/admin/login", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ secret: "nope" }) })).status).toBe(401);
    const res = await req("/admin/login", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ secret: ADMIN }) });
    expect(res.status).toBe(204);
    const cookie = res.headers.get("Set-Cookie")!;
    expect(cookie).toMatch(/^ldnt_admin=[0-9a-f]{64}; Path=\/; HttpOnly; Secure; SameSite=Strict; Max-Age=\d+$/);
    const jar = cookie.split(";")[0];
    expect((await req("/api/consoles", { headers: { Cookie: jar } })).status).toBe(200);
    expect((await req("/api/consoles", { headers: { Cookie: "ldnt_admin=" + "0".repeat(64) } })).status).toBe(401);
    // a form post works too (the page may use either)
    const form = await req("/admin/login", { method: "POST", body: new URLSearchParams({ secret: ADMIN }) });
    expect(form.status).toBe(204);
  });
  it("the page itself is static and public; it holds no data", async () => {
    const res = await req("/admin");
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("text/html");
  });
  it("refuses cross-site writes", async () => {
    const res = await req("/api/invites", { method: "POST", headers: { Authorization: `Bearer ${ADMIN}`, Origin: "https://evil.example" } });
    expect(res.status).toBe(403);
  });
  it("wrong secrets lock the client (IPv6 by /64) out with backoff, login and bearer alike", async () => {
    const login = (ip: string, secret: string) =>
      req("/admin/login", { method: "POST", headers: { "content-type": "application/json", "cf-connecting-ip": ip }, body: JSON.stringify({ secret }) });
    for (let i = 0; i < 6; i++) expect((await login("2001:db8:1:2::5", "nope")).status).toBe(401);
    for (let i = 0; i < 5; i++) {
      expect((await req("/api/consoles", { headers: { Authorization: "Bearer nope", "cf-connecting-ip": "2001:db8:1:2:aa::1" } })).status).toBe(401);
    }
    // 11 failures from that /64: locked, even with the right secret, and before the body is read
    const locked = await login("2001:db8:1:2:ffff::9", ADMIN);
    expect(locked.status).toBe(429);
    expect(Number(locked.headers.get("retry-after"))).toBeGreaterThan(0);
    expect((await req("/api/consoles", { headers: { Authorization: `Bearer ${ADMIN}`, "cf-connecting-ip": "2001:db8:1:2::5" } })).status).toBe(429);
    // other clients are not affected
    expect((await login("2001:db8:1:3::5", ADMIN)).status).toBe(204);
    expect((await login("203.0.113.7", ADMIN)).status).toBe(204);
  });
  it("refuses request bodies over 16 KiB", async () => {
    const big = JSON.stringify({ secret: ADMIN, pad: "x".repeat(20_000) });
    const headers = { "content-type": "application/json", "cf-connecting-ip": "203.0.113.8" };
    expect((await req("/admin/login", { method: "POST", headers, body: big })).status).toBe(413);
    expect((await api("/api/invites", "POST", { name: "x".repeat(20_000) })).status).toBe(413);
  });
  it("the page's CSP allows its own script and style by hash, nothing inline", async () => {
    const res = await req("/admin");
    const csp = res.headers.get("content-security-policy")!;
    expect(csp).not.toContain("unsafe-inline");
    const html = await res.text();
    const b64 = (s: string) => createHash("sha256").update(s).digest("base64");
    expect(csp).toContain(`script-src 'sha256-${b64(html.match(/<script>([\s\S]*)<\/script>/)![1])}'`);
    expect(csp).toContain(`style-src 'sha256-${b64(html.match(/<style>([\s\S]*)<\/style>/)![1])}'`);
    expect(res.headers.get("x-content-type-options")).toBe("nosniff");
  });
  it("the admin secret opens neither consoles' routes nor the release API", async () => {
    expect((await req("/update/status", { headers: { Authorization: `Bearer ${ADMIN}` } })).status).toBe(404);
    expect((await connect(ADMIN)).status).toBe(404);
  });
  it("unknown routes -> 404", async () => {
    expect((await api("/api/nope")).status).toBe(404);
    expect((await api("/api/consoles", "DELETE")).status).toBe(404);
    expect((await req("/admin/other")).status).toBe(404);
  });
});

describe("pinned release", () => {
  it("a bad signature is refused and nothing is installed", async () => {
    github[gh(PIN.tag, "release.sig")] = new Uint8Array(64);
    const { body } = await apiJson("/api/release");
    expect(body.installError).toContain("bad publisher signature");
    expect(body.deployed).toEqual({ version: PIN.tag.slice(1), build: null });
    expect(await sqlRun("SELECT v FROM kv WHERE k = 'installed'")).toEqual([]);
  });
  it("a file that does not match release.json is refused", async () => {
    github[gh(PIN.tag, "exefs.nsp")] = bytes(10, 9);
    expect((await apiJson("/api/release")).body.installError).toContain("does not match release.json");
  });
  it("a manifest signed by someone else is refused", async () => {
    const forged = pinned.manifest.slice();
    forged[200 - 9] ^= 1; // signature byte
    const d = JSON.parse(dec.decode(pinned.assets["release.json"]));
    d.assets["manifest.bin"].sha256 = sha(forged).toString("hex");
    const doc = enc.encode(JSON.stringify(d));
    Object.assign(github, { [gh(PIN.tag, "manifest.bin")]: forged, [gh(PIN.tag, "release.json")]: doc, [gh(PIN.tag, "release.sig")]: p1363(doc) });
    expect((await apiJson("/api/release")).body.installError).toContain("manifest.bin: bad publisher signature");
  });
  it("installs the console files of the relay's own tag; only ldn-tunnel consoles get them", async () => {
    const { body } = await apiJson("/api/release");
    expect(body).toMatchObject({ deployed: { version: PIN.tag.slice(1), build: 1001 }, platform: "cloudflare", canSelfUpdate: true });
    expect(body.installError).toBeUndefined();
    expect(calls.some((c) => c.url === gh(PIN.tag, "exefs.nsp"))).toBe(true);
    expect(calls.some((c) => c.url.endsWith("relay-cloudflare.zip"))).toBe(false); // only the self-update needs the Worker
    const { c } = await connect("a".repeat(64));
    c!.send(PacketId.UpdateCheck, updateCheck(1));
    expect(await c!.expect(PacketId.UpdateManifest)).toEqual(pinned.manifest);
    c!.send(PacketId.UpdateCheck, updateCheck(0));
    expect(await c!.expect(PacketId.UpdateManifest)).toHaveLength(0);
    calls = [];
    await apiJson("/api/release");
    expect(calls.filter((x) => !x.url.includes("/latest/"))).toEqual([]); // installed once
  });
  it("the first ldn-tunnel update check installs a missing release by itself", async () => {
    await sqlRun("DELETE FROM kv WHERE k = 'installed'");
    await sqlRun("DELETE FROM channels WHERE name = 'ldn-tunnel/release'");
    const { c } = await connect("a".repeat(64));
    c!.send(PacketId.UpdateCheck, updateCheck(1));
    expect(await c!.expect(PacketId.UpdateManifest)).toHaveLength(0); // nothing yet
    await new Promise((r) => setTimeout(r, 200));
    c!.send(PacketId.UpdateCheck, updateCheck(1));
    expect(await c!.expect(PacketId.UpdateManifest)).toEqual(pinned.manifest);
  });
});

describe("invites and console tokens", () => {
  it("one-time link -> zip with the SD card layout, this relay's host and a fresh token", async () => {
    const t = await invite("Alice's Switch");
    const page = await req(`/invite/${t}`); // a chat app's link preview only GETs
    expect(page.status).toBe(200);
    expect(await page.text()).toContain("Download for my Switch");
    const { files, ini, token } = await redeem(t);
    expect(Object.keys(files).sort()).toEqual([
      "atmosphere/contents/420000004C444E54/exefs.nsp",
      "atmosphere/contents/420000004C444E54/flags/boot2.flag",
      "atmosphere/contents/420000004C444E54/toolbox.json",
      "config/ldn-tunnel/ca.pem",
      "config/ldn-tunnel/config.ini",
      "config/ldn-tunnel/gamelist.txt",
      "switch/.overlays/ldn-tunnel.ovl",
    ]);
    expect(files["atmosphere/contents/420000004C444E54/exefs.nsp"]).toEqual(pinned.exefs);
    expect(files["switch/.overlays/ldn-tunnel.ovl"]).toEqual(pinned.overlay);
    expect(files["atmosphere/contents/420000004C444E54/flags/boot2.flag"]).toHaveLength(0);
    expect(JSON.parse(dec.decode(files["atmosphere/contents/420000004C444E54/toolbox.json"]))).toEqual({
      name: "ldn-tunnel", tid: "0x420000004C444E54", requires_reboot: true,
    });
    expect(dec.decode(files["config/ldn-tunnel/ca.pem"]).match(/BEGIN CERTIFICATE/g)).toHaveLength(9);
    expect(dec.decode(files["config/ldn-tunnel/gamelist.txt"])).toMatch(/^0x0100[0-9a-f]{12}$/m);
    expect(ini).toMatch(/^host = relay\.test$/m);
    expect(ini).toMatch(/^ca_file = sdmc:\/config\/ldn-tunnel\/ca\.pem$/m);
    expect((await connect(token)).status).toBe(101);
    expect(await sqlRun("SELECT hash, name FROM tokens WHERE name = ?", "Alice's Switch")).toEqual([{ hash: sha(enc.encode(token)).toString("hex"), name: "Alice's Switch" }]);
  });

  it("works once; unknown, malformed and expired links are refused", async () => {
    const t = await invite();
    await redeem(t);
    for (const method of ["GET", "POST"]) expect((await req(`/invite/${t}`, { method })).status).toBe(404);
    expect((await req(`/invite/${"0".repeat(64)}`, { method: "POST" })).status).toBe(404);
    expect((await req("/invite/xyz")).status).toBe(404);
    const old = await invite();
    await sqlRun("UPDATE invites SET expires = ?", Date.now() - 1);
    expect((await req(`/invite/${old}`, { method: "POST" })).status).toBe(404);
  });

  it("redeemed by several requests at once: exactly one gets the zip and a token", async () => {
    const t = await invite("Race");
    const res = await Promise.all([0, 1, 2, 3].map(() => req(`/invite/${t}`, { method: "POST" })));
    await Promise.all(res.map((r) => r.arrayBuffer()));
    expect(res.map((r) => r.status).sort()).toEqual([200, 404, 404, 404]);
    expect(await sqlRun("SELECT id FROM tokens WHERE name = 'Race'")).toHaveLength(1);
  });

  it("an invite survives while the console files cannot be fetched", async () => {
    await sqlRun("DELETE FROM kv WHERE k = 'installed'");
    const t = await invite();
    github = {};
    expect((await req(`/invite/${t}`, { method: "POST" })).status).toBe(503);
    serve(pinned, true);
    await redeem(t);
  });

  it("/update/status names a console that sent no label by its token", async () => {
    const noLabel = (build: number) => UpdateCheckRequest.encode({
      running_build: build, rejected_build: 0, channel: 1, label_len: 0, reserved: new Uint8Array([1, 0]),
      label: new Uint8Array(32), version: enc.encode("v-x"),
    });
    const { c } = await connect((await redeem(await invite("Carol's Switch"))).token);
    c!.send(PacketId.UpdateCheck, noLabel(9101));
    await c!.expect(PacketId.UpdateManifest);
    const { c: d } = await connect("a".repeat(64)); // TOKEN_SWITCH_A
    d!.send(PacketId.UpdateCheck, noLabel(9102));
    await d!.expect(PacketId.UpdateManifest);
    const consoles = ((await (await req("/update/status", { headers: { Authorization: `Bearer ${"c".repeat(64)}` } })).json()) as any).consoles;
    expect(consoles.find((x: any) => x.running_build === 9101)?.label).toBe("Carol's Switch");
    expect(consoles.find((x: any) => x.running_build === 9102)?.label).toBe("TOKEN_SWITCH_A");
  });

  it("lists consoles with version, builds and online state; logs; rename; revoke cuts one off", async () => {
    const { token } = await redeem(await invite("Lite-2"));
    const { c } = await connect(token);
    c!.send(PacketId.UpdateCheck, updateCheck(1, "v0.1.2-test", 77));
    await c!.expect(PacketId.UpdateManifest);
    const label = enc.encode("lite");
    c!.send(PacketId.DebugLog, new Uint8Array([label.length, ...label, ...enc.encode("hello\nworld")]));
    await c!.none(100);
    const row = await consoleOf("Lite-2");
    expect(row).toMatchObject({ version: "v0.1.2-test", runningBuild: 77, online: true, rejectedBuild: null });
    expect(Math.abs(Date.now() - row.lastSeen)).toBeLessThan(10_000);
    expect(await consoleOf("TOKEN_SWITCH_A")).toMatchObject({ id: "env:TOKEN_SWITCH_A" });
    expect((await apiJson("/api/consoles")).body.some((x: any) => x.name === "TOKEN_SWITCH_B")).toBe(false); // empty secret
    const logs = (await apiJson(`/api/consoles/${row.id}/logs?limit=10`)).body;
    expect(logs.map((l: any) => l.line)).toEqual(["hello", "world"]);
    expect((await apiJson(`/api/consoles/${row.id}`, "PATCH", { name: "Lite 3" })).status).toBe(200);
    expect((await consoleOf("Lite 3")).id).toBe(row.id);
    expect((await apiJson(`/api/consoles/${row.id}`, "PATCH", { name: " " })).status).toBe(400);
    expect((await apiJson(`/api/consoles/env:TOKEN_SWITCH_A/revoke`, "POST")).status).toBe(400);
    expect(await sqlRun("SELECT 1 FROM console_status WHERE who = ?", "c:" + row.id)).toHaveLength(1);
    expect((await apiJson(`/api/consoles/${row.id}/revoke`, "POST")).status).toBe(200);
    expect(await sqlRun("SELECT 1 FROM console_status WHERE who = ?", "c:" + row.id)).toHaveLength(0);
    await expect(c!.next()).rejects.toThrow("closed");
    expect((await connect(token)).status).toBe(404);
    expect((await apiJson(`/api/consoles/${row.id}/revoke`, "POST")).status).toBe(404);
  });
});

describe("drops", () => {
  const drops = async (who: string) => (await apiJson("/api/drops")).body.filter((d: any) => d.who === who);
  const waitDrops = async (who: string, n: number) => {
    for (let i = 0; i < 50; i++) {
      const rows = await drops(who);
      if (rows.length >= n) return rows;
      await new Promise((r) => setTimeout(r, 20));
    }
    throw new Error("no drop row");
  };

  it("records who ended each socket, with its traffic, in /api/drops", async () => {
    const { token } = await redeem(await invite("Drop-1"));
    const who = "c:" + (await consoleOf("Drop-1")).id;
    const a = await connect(token);
    a.c!.send(PacketId.UpdateCheck, updateCheck(1));
    await a.c!.expect(PacketId.UpdateManifest);
    a.c!.send(PacketId.DebugLog, new Uint8Array([1, 120, ...enc.encode("hi")]));
    await a.c!.none(50);
    a.ws!.close(4001, "bye");
    const [peer] = await waitDrops(who, 1);
    expect(peer).toMatchObject({ ev: "drop", by: "peer", code: 4001, reason: "bye", frames_in: 2 });
    expect(peer.frames_out).toBeGreaterThanOrEqual(1);
    expect(peer.idle_in_ms).toBeGreaterThanOrEqual(0);
    expect(peer.age_s).toBe(0);
    expect(Date.parse(peer.do_start)).toBeLessThanOrEqual(Date.parse(peer.at));

    const b = await connect(token);
    expect((await apiJson(`/api/consoles/${who.slice(2)}/revoke`, "POST")).status).toBe(200);
    await expect(b.c!.next()).rejects.toThrow("closed");
    const [relay] = await waitDrops(who, 2); // newest first
    expect(relay).toMatchObject({ by: "relay", code: 1000, reason: "revoked", frames_in: 0, frames_out: 0, idle_in_ms: null });
    expect((await apiJson("/api/drops")).body.some((d: any) => d.ev === "relay-start")).toBe(true);
  });
});

describe("Cloudflare self-update", () => {
  let versions = 0;
  beforeEach(() => {
    cloudflare = (url, init) => {
      if (url.endsWith("/versions") && init?.method === "POST") return Response.json({ success: true, result: { id: "ver-" + ++versions } });
      if (url.endsWith("/deployments") && init?.method === "POST") return Response.json({ success: true, result: {} });
      if (url.endsWith("/deployments")) {
        return Response.json({ success: true, result: { deployments: [{ versions: [{ version_id: "ver-new" }] }, { versions: [{ version_id: "ver-old" }] }] } });
      }
      return Response.json({ success: false, errors: [{ message: "unexpected" }] }, { status: 400 });
    };
  });

  it("reports the latest release and deploys it: version upload (bindings restated, secrets kept), then 100%", async () => {
    serve(next, true);
    await sqlRun("DELETE FROM kv WHERE k = 'latest'");
    const { body } = await apiJson("/api/release");
    expect(body.latest).toEqual({ version: "9.9.9", build: 1002, url: `https://github.com/${PIN.repo}/releases/tag/v9.9.9` });
    expect(body.updateCommand).toBeUndefined();
    expect((await apiJson("/api/update", "POST", {})).body).toEqual({ ok: true, version: "9.9.9" });
    const cf = calls.filter((c) => c.url.startsWith("https://api.cloudflare.com/"));
    expect(cf.map((c) => [c.init?.method, c.url])).toEqual([
      ["POST", "https://api.cloudflare.com/client/v4/accounts/acct123/workers/scripts/ldn-tunnel/versions"],
      ["POST", "https://api.cloudflare.com/client/v4/accounts/acct123/workers/scripts/ldn-tunnel/deployments"],
    ]);
    expect(new Headers(cf[0].init!.headers).get("Authorization")).toBe("Bearer cf-test-token");
    const form = cf[0].init!.body as FormData;
    const meta = JSON.parse(await (form.get("metadata") as Blob).text());
    expect(meta).toEqual({
      main_module: "index.js", compatibility_date: "2026-10-01", compatibility_flags: [],
      bindings: [{ type: "durable_object_namespace", name: "LOBBY", class_name: "Lobby" }],
      keep_bindings: ["secret_text", "secret_key", "plain_text", "json"],
    });
    const part = form.get("index.js") as File;
    expect(part.type).toBe("application/javascript+module");
    expect(dec.decode(await part.arrayBuffer())).toContain("9.9.9");
    expect(form.has("metadata.json")).toBe(false);
    expect(JSON.parse(cf[1].init!.body as string)).toEqual({ strategy: "percentage", versions: [{ version_id: "ver-" + versions, percentage: 100 }] });
    // what the new Worker serves (a check here would run this test's pinned code, which restores its own release)
    const [row] = await sqlRun("SELECT manifest FROM channels WHERE name = 'ldn-tunnel/release'");
    expect(new Uint8Array(row.manifest as ArrayBuffer)).toEqual(next.manifest);
  });

  it("a tampered Worker bundle is never deployed and the console files stay", async () => {
    await sqlRun("DELETE FROM kv WHERE k = 'installed'");
    await apiJson("/api/release"); // back on the pinned release
    serve(next, true);
    github[gh("v9.9.9", "relay-cloudflare.zip")] = zipSync({ "index.js": enc.encode("evil") });
    calls = [];
    const { status, body } = await apiJson("/api/update", "POST", { version: "9.9.9" });
    expect(status).toBe(502);
    expect(body.error).toContain("does not match release.json");
    expect(calls.some((c) => c.url.startsWith("https://api.cloudflare.com/"))).toBe(false);
    const { c } = await connect("a".repeat(64));
    c!.send(PacketId.UpdateCheck, updateCheck(1));
    expect(await c!.expect(PacketId.UpdateManifest)).toEqual(pinned.manifest);
  });

  it("a release signed for another version is refused", async () => {
    serve(next);
    github[gh("v8.0.0", "release.json")] = next.assets["release.json"];
    github[gh("v8.0.0", "release.sig")] = next.assets["release.sig"];
    expect((await apiJson("/api/update", "POST", { version: "8.0.0" })).body.error).toContain("is not release v8.0.0");
  });

  it("roll back deploys the previous deployment's version", async () => {
    expect((await apiJson("/api/rollback", "POST")).body).toEqual({ ok: true, versionId: "ver-old" });
    const last = calls.filter((c) => c.url.startsWith("https://api.cloudflare.com/")).at(-1)!;
    expect(JSON.parse(last.init!.body as string)).toEqual({ strategy: "percentage", versions: [{ version_id: "ver-old", percentage: 100 }] });
  });

  it("a Cloudflare API error is reported, not swallowed", async () => {
    cloudflare = () => Response.json({ success: false, errors: [{ message: "Authentication error" }] }, { status: 403 });
    expect((await apiJson("/api/rollback", "POST")).body.error).toContain("Authentication error");
  });

  it("a 429 is retried after Retry-After, with a User-Agent naming the relay", async () => {
    serve(next);
    const seen = new Set<string>();
    rateLimit = (url) => (seen.has(url) ? undefined : (seen.add(url), tooMany()));
    expect((await apiJson("/api/update", "POST", { version: "9.9.9" })).body).toEqual({ ok: true, version: "9.9.9" });
    const gets = calls.filter((c) => c.url.startsWith("https://github.com/")).map((c) => c.url);
    expect(gets).toEqual([...new Set(gets)].flatMap((u) => [u, u])); // each file: one 429, one retry, one at a time
    expect(gets.filter((u, i) => i % 2 === 0).map((u) => u.split("/").pop())).toEqual(
      ["release.json", "release.sig", "manifest.bin", "exefs.nsp", "ldn-tunnel.ovl", "relay-cloudflare.zip"]);
    expect(new Headers(calls[0].init?.headers).get("User-Agent")).toBe(`ldn-tunnel-relay/${PIN.tag} (+https://github.com/${PIN.repo})`);
  });

  it("downloads that stay rate-limited come through the GitHub API's asset URLs", async () => {
    serve(next);
    const assets = Object.entries(next.assets).map(([name, b], i) => {
      const url = `https://api.github.com/repos/${PIN.repo}/releases/assets/${i}`;
      github[url] = b;
      return { name, url };
    });
    github[`https://api.github.com/repos/${PIN.repo}/releases/tags/v9.9.9`] = enc.encode(JSON.stringify({ assets }));
    rateLimit = (url) => (url.startsWith("https://github.com/") ? tooMany() : undefined);
    expect((await apiJson("/api/update", "POST", { version: "9.9.9" })).body).toEqual({ ok: true, version: "9.9.9" });
    const gh = calls.filter((c) => c.url.includes("github.com/"));
    expect(gh.filter((c) => c.url.startsWith("https://github.com/")).map((c) => c.url)).toEqual(Array(3).fill(gh[0].url)); // release.json only
    const fromApi = gh.filter((c) => c.url.includes("/releases/assets/"));
    expect(fromApi).toHaveLength(Object.keys(next.assets).length);
    expect(fromApi.every((c) => new Headers(c.init?.headers).get("Accept") === "application/octet-stream")).toBe(true);
  });

  it("rate-limited everywhere: nothing is deployed and the error says so", async () => {
    serve(next);
    rateLimit = () => tooMany();
    const { status, body } = await apiJson("/api/update", "POST", {});
    expect(status).toBe(502);
    expect(body.error).toBe(RATE_LIMITED);
    expect(calls.filter((c) => c.url.includes("github.com/"))).toHaveLength(6); // 3 tries direct, 3 via the API
    expect(calls.some((c) => c.url.startsWith("https://api.cloudflare.com/"))).toBe(false);
    rateLimit = () => tooMany("3600");
    calls = [];
    expect((await apiJson("/api/update", "POST", { version: "9.9.9" })).body.error).toBe(RATE_LIMITED);
    expect(calls).toHaveLength(2); // an hour's Retry-After is not waited out
  });

  it("after a rollback the code's own release is served again, from storage; a mismatch shows in /api/release", async () => {
    await sqlRun("DELETE FROM kv WHERE k IN ('installed', 'previous')");
    await apiJson("/api/release"); // the pinned release
    serve(next);
    expect((await apiJson("/api/update", "POST", { version: "9.9.9" })).body.ok).toBe(true);
    // this isolate runs the pinned code, as the rolled-back Worker does: its first ldn-tunnel check restores
    // the pinned release without GitHub
    github = {};
    calls = [];
    const { c } = await connect("a".repeat(64));
    c!.send(PacketId.UpdateCheck, updateCheck(1));
    expect(await c!.expect(PacketId.UpdateManifest)).toEqual(pinned.manifest);
    const { body } = await apiJson("/api/release");
    expect(body).toMatchObject({ deployed: { version: PIN.tag.slice(1), build: 1001 }, consoleFiles: { version: PIN.tag.slice(1), build: 1001 } });
    expect(calls.filter((c) => !c.url.includes("/latest/"))).toEqual([]);

    // without the stored copy (a relay updated before this existed) it downloads, and until then says so
    serve(next);
    await apiJson("/api/update", "POST", { version: "9.9.9" });
    await sqlRun("DELETE FROM kv WHERE k = 'previous'");
    rateLimit = () => tooMany();
    const mixed = (await apiJson("/api/release")).body;
    expect(mixed).toMatchObject({ deployed: { version: PIN.tag.slice(1), build: null }, consoleFiles: { version: "9.9.9", build: 1002 }, installError: RATE_LIMITED });
    rateLimit = () => undefined;
    serve(pinned);
    expect((await apiJson("/api/release")).body).toMatchObject({ deployed: { build: 1001 }, consoleFiles: { build: 1001 } });
  });

  it("no deployer without all three settings", () => {
    expect(cloudflareDeployer({ CF_API_TOKEN: "t", CF_ACCOUNT_ID: "a" }, fetch)).toBeUndefined();
    expect(cloudflareDeployer({ CF_API_TOKEN: "", CF_ACCOUNT_ID: "a", CF_WORKER_NAME: "w" }, fetch)).toBeUndefined();
    expect(cloudflareDeployer({ CF_API_TOKEN: "t", CF_ACCOUNT_ID: "a", CF_WORKER_NAME: "w" }, fetch)).toBeDefined();
  });
});
