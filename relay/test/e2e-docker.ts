// End-to-end run of the Docker path: builds the image, runs it WITHOUT Caddy against a fake GitHub release
// served from a local HTTP server, and drives it like an owner and two consoles would.
//   npm run test:e2e-docker            (needs Docker; ~1 min with a warm image cache)
// Then the same image runs again through the real docker-compose.yml + Caddyfile (TLS from Caddy's own CA for `localhost`).
// Containers/volumes/image are all named ldnt-e2e-* / ldn-tunnel-relay:e2e and removed at the end.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import tls from "node:tls";
import { join, resolve } from "node:path";
import { unzipSync } from "fflate";
import { NetworkInfo, PacketId, ProxyConfig, ProxyDataHeader, SignedManifest, UPDATE_CHUNK_SIZE, UpdateChunkHeader, UpdateChunkRequest, UpdateCheckRequest } from "../src/core/codec/types.ts";
import { authHeaders, connectWs, upgradeStatus, type Conn } from "../tools/client.ts";

const relayDir = resolve(import.meta.dirname, "..");
const repo = resolve(relayDir, "..");
const IMAGE = "ldn-tunnel-relay:e2e", NAME = "ldnt-e2e-relay", VOLUME = "ldnt-e2e-data", CADDY = "ldnt-e2e-caddy"; // CADDY = compose project name
const FIXTURE_KEY = join(repo, "tools/release/test/fixture-key.pem");
const FIXTURE_PUB = "040c81e42dc599eb75436bbe8281aff4c39ac762010a33fbc49c745842d4f811e4b6e9604a819499e3a51887ac1bbe7482b15e5ff9f48f6b941523af586998eff6"; // tools/release/test/fixture-key.pem: .env overrides the built-in publisher key with it
const work = process.env.E2E_DIR ?? mkdtempSync(join(tmpdir(), "ldnt-e2e-"));
mkdirSync(work, { recursive: true });

const sh = (cmd: string, args: string[], opts: { quiet?: boolean } = {}) =>
  execFileSync(cmd, args, { encoding: "utf8", stdio: opts.quiet ? ["ignore", "pipe", "ignore"] : ["ignore", "pipe", "inherit"] });
const sha = (b: Uint8Array) => createHash("sha256").update(b).digest("hex");
const timings: [string, number][] = [];
async function step<T>(name: string, f: () => Promise<T>): Promise<T> {
  const t = Date.now();
  const r = await f();
  timings.push([name, Date.now() - t]);
  console.log(`ok - ${name} (${Date.now() - t} ms)`);
  return r;
}
const release = (...a: string[]) => sh("node", ["--experimental-strip-types", "--disable-warning=ExperimentalWarning", join(repo, "tools/release/release.ts"), ...a], { quiet: true });

const cleanup = () => {
  const cv = ["relay-data", "caddy-data", "caddy-config"].map((v) => `${CADDY}_${v}`);
  for (const a of [["rm", "-f", NAME, `${CADDY}-relay-1`, `${CADDY}-caddy-1`], ["volume", "rm", "-f", VOLUME, ...cv], ["network", "rm", `${CADDY}_default`], ["rmi", "-f", IMAGE]]) {
    try { sh("docker", a, { quiet: true }); } catch {}
  }
};

// ---- a fake GitHub: <base>/download/<TAG>/<file> and <base>/latest/download/<file> ----
const TAG = (JSON.parse(readFileSync(join(relayDir, "release.json"), "utf8")) as { tag: string }).tag; // the release this relay pins
const exefs = randomBytes(9000), overlay = randomBytes(5000); // > 2 chunks, not a chunk multiple
const dir = join(work, "gh/download", TAG);
mkdirSync(dir, { recursive: true });
writeFileSync(join(dir, "exefs.nsp"), exefs);
writeFileSync(join(dir, "ldn-tunnel.ovl"), overlay);
release("sign-manifest", "--exefs", join(dir, "exefs.nsp"), "--overlay", join(dir, "ldn-tunnel.ovl"), "--version", TAG, "--build", "1700000000", "--key-file", FIXTURE_KEY, "--out", join(dir, "manifest.bin"));
release("release-json", "--dir", dir, "--key-file", FIXTURE_KEY);
mkdirSync(join(work, "gh/latest"), { recursive: true });
try { rmSync(join(work, "gh/latest/download"), { recursive: true }); } catch {}
sh("cp", ["-r", dir, join(work, "gh/latest/download")]);
const manifestBin = new Uint8Array(readFileSync(join(dir, "manifest.bin")));

const gh = createServer((q, s) => {
  try {
    s.end(readFileSync(join(work, "gh", decodeURIComponent(q.url!.split("?")[0]).replace(/\.\./g, ""))));
  } catch { s.writeHead(404).end(); }
});
await new Promise<void>((r) => gh.listen(0, "0.0.0.0", r));
const ghPort = (gh.address() as { port: number }).port;

const admin = randomBytes(24).toString("hex");
writeFileSync(join(work, ".env"), `ADMIN=${admin}\nPUBLISHER_KEY=${FIXTURE_PUB}\nRELEASE_BASE_URL=http://host.docker.internal:${ghPort}\n`, { mode: 0o600 });
const hostPort = 20000 + Math.floor(Math.random() * 20000);
const base = `http://127.0.0.1:${hostPort}`;
const api = (path: string, init: RequestInit = {}) =>
  fetch(base + path, { ...init, headers: { Authorization: `Bearer ${admin}`, ...(init.headers as object) } });
const consolesList = async () => (await (await api("/api/consoles")).json()) as { id: string; name: string; online: boolean; version: string | null; runningBuild: number | null }[];

async function waitUp() {
  for (let i = 0; i < 60; i++) {
    try { if ((await fetch(base + "/admin")).status === 200) return; } catch {}
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error("container did not come up:\n" + sh("docker", ["logs", NAME], { quiet: true }));
}
const runContainer = () =>
  sh("docker", ["run", "-d", "--name", NAME, "--env-file", join(work, ".env"), "--add-host", "host.docker.internal:host-gateway", "-p", `127.0.0.1:${hostPort}:8080`, "-v", `${VOLUME}:/data`, IMAGE]);

async function main() {
  cleanup();
  await step("docker build", async () => void sh("docker", ["build", "-q", "-t", IMAGE, relayDir]));
  await step("container up (no Caddy, no TOKEN_*)", async () => { runContainer(); await waitUp(); });

  // ---- admin API ----
  await step("login: wrong secret 401, right secret 204 + cookie, cookie opens the API", async () => {
    const login = (secret: string) => fetch(base + "/admin/login", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ secret }) });
    assert.equal((await login("nope")).status, 401);
    const ok = await login(admin);
    assert.equal(ok.status, 204);
    const cookie = ok.headers.get("set-cookie")!.split(";")[0]; // Secure flag: a browser would refuse it over http, the API does not care
    assert.equal((await fetch(base + "/api/consoles", { headers: { cookie } })).status, 200);
    assert.equal((await fetch(base + "/api/consoles")).status, 401);
  });
  assert.deepEqual(await consolesList(), [], "no TOKEN_* and no invites: no consoles");

  const mkInvite = async (name: string) => {
    const r = await api("/api/invites", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ name }) });
    assert.equal(r.status, 200);
    const { url, expiresAt } = (await r.json()) as { url: string; expiresAt: number };
    assert.ok(expiresAt > Date.now());
    return url;
  };
  const redeem = (url: string) => fetch(url, { method: "POST" });

  const conf = (files: Record<string, Uint8Array>) => {
    const ini = new TextDecoder().decode(files["config/ldn-tunnel/config.ini"]);
    const get = (k: string) => new RegExp(`^${k}\\s*=\\s*(.*)$`, "m").exec(ini)?.[1].trim();
    return { host: get("host")!, port: Number(get("port")), token: get("token")!, caFile: get("ca_file"), ini };
  };
  let a!: ReturnType<typeof conf>, b!: ReturnType<typeof conf>;
  let inviteA = "";
  const zipOf = async (url: string) => {
    const r = await redeem(url);
    assert.equal(r.status, 200, "invite zip: " + (r.status !== 200 ? await r.text() : ""));
    assert.equal(r.headers.get("content-type"), "application/zip");
    return unzipSync(new Uint8Array(await r.arrayBuffer()));
  };

  await step("invite e2e-a: GET page does not consume; POST -> zip with the CONTRACTS.md layout", async () => {
    inviteA = await mkInvite("e2e-a");
    const page = await fetch(inviteA);
    assert.equal(page.status, 200);
    assert.match(await page.text(), /e2e-a/);
    const files = await zipOf(inviteA);
    const dirId = "atmosphere/contents/420000004C444E54/";
    assert.deepEqual(Object.keys(files).sort(), [
      dirId + "exefs.nsp", dirId + "flags/boot2.flag", dirId + "toolbox.json", "config/ldn-tunnel/ca.pem",
      "config/ldn-tunnel/config.ini", "config/ldn-tunnel/gamelist.txt", "switch/.overlays/ldn-tunnel.ovl",
    ].sort());
    assert.deepEqual(files[dirId + "exefs.nsp"], new Uint8Array(exefs));
    assert.deepEqual(files["switch/.overlays/ldn-tunnel.ovl"], new Uint8Array(overlay));
    assert.equal(files[dirId + "flags/boot2.flag"].length, 0);
    assert.equal(JSON.parse(new TextDecoder().decode(files[dirId + "toolbox.json"])).tid, "0x420000004C444E54");
    assert.match(new TextDecoder().decode(files["config/ldn-tunnel/ca.pem"]), /BEGIN CERTIFICATE/);
    assert.ok(files["config/ldn-tunnel/gamelist.txt"].length > 0);
    a = conf(files);
    assert.equal(a.host, "127.0.0.1");
    assert.equal(a.port, hostPort, "port is written because it is not 443");
    assert.match(a.token, /^[0-9a-f]{64}$/);
    assert.equal(a.caFile, "sdmc:/config/ldn-tunnel/ca.pem");
    assert.match(a.ini, /^;path = \/ldn$/m);
  });
  await step("the same invite a second time fails (404, nothing minted)", async () => {
    assert.equal((await redeem(inviteA)).status, 404);
    assert.equal((await fetch(inviteA)).status, 404);
    assert.equal((await consolesList()).length, 1);
  });
  await step("invite e2e-b -> a different token", async () => {
    b = conf(await zipOf(await mkInvite("e2e-b")));
    assert.notEqual(b.token, a.token);
  });

  // ---- consoles ----
  const wsUrl = `ws://${a.host}:${a.port}${"/ldn"}`;
  const lcid = BigInt("0x" + randomBytes(7).toString("hex"));
  let A!: Conn, B!: Conn, hostIp = 0, joinIp = 0;
  await step("auth: invite tokens open /ldn, an unknown token and the admin secret do not", async () => {
    assert.equal(await upgradeStatus(wsUrl, authHeaders(a.token)), 101);
    assert.equal(await upgradeStatus(wsUrl, authHeaders("0".repeat(64))), 404);
    assert.equal(await upgradeStatus(wsUrl, authHeaders(admin)), 404);
  });
  await step("A creates a network, B scans/sees/joins, ProxyData both ways", async () => {
    A = await connectWs(wsUrl, authHeaders(a.token));
    B = await connectWs(wsUrl, authHeaders(b.token));
    await A.initialize();
    await B.initialize();
    A.createAp({ name: "E2E-A", lcid });
    hostIp = ProxyConfig.decode(await A.expect(PacketId.ProxyConfig)).proxy_ip;
    await A.expect(PacketId.Connected);
    const found = await B.scanAll(lcid);
    assert.equal(found.length, 1);
    B.connect(found[0], { name: "E2E-B" });
    joinIp = ProxyConfig.decode(await B.expect(PacketId.ProxyConfig)).proxy_ip;
    assert.equal(NetworkInfo.decode(await B.expect(PacketId.Connected)).ldn.node_count, 2);
    assert.equal(NetworkInfo.decode(await A.expect(PacketId.SyncNetwork)).ldn.node_count, 2);
    B.proxyData(0, hostIp, new TextEncoder().encode("ping"));
    const p = await A.expect(PacketId.ProxyData);
    assert.equal(ProxyDataHeader.decode(p).info.source_ipv4, joinIp);
    assert.equal(new TextDecoder().decode(p.subarray(ProxyDataHeader.size)), "ping");
    A.proxyData(hostIp, joinIp, new TextEncoder().encode("pong"));
    assert.equal(new TextDecoder().decode((await B.expect(PacketId.ProxyData)).subarray(ProxyDataHeader.size)), "pong");
  });

  // ---- update channel (module 1 = ldn-tunnel) ----
  await step("UpdateCheck (reserved[0]=1) -> the pinned release's manifest; UpdateChunk -> blobs with matching hashes", async () => {
    const label = new TextEncoder().encode("e2e-b");
    B.send(PacketId.UpdateCheck, UpdateCheckRequest.encode({
      running_build: 5, rejected_build: 0, channel: 1, label_len: label.length, reserved: new Uint8Array([1, 0]), label, version: new TextEncoder().encode("v0.0.0-old"),
    }));
    const m = await B.expect(PacketId.UpdateManifest);
    assert.deepEqual(m, manifestBin, "byte-identical to the release's manifest.bin");
    const { manifest } = SignedManifest.decode(m);
    const fetchBlob = async (hash: Uint8Array, size: number) => {
      const out = Buffer.alloc(size);
      for (let off = 0; off < size; off += UPDATE_CHUNK_SIZE) {
        B.send(PacketId.UpdateChunk, UpdateChunkRequest.encode({ sha256: hash, offset: off, length: Math.min(UPDATE_CHUNK_SIZE, size - off) }));
        const p = await B.expect(PacketId.UpdateChunkData);
        const h = UpdateChunkHeader.decode(p);
        assert.equal(h.offset, off);
        assert.equal(h.total_size, size);
        out.set(p.subarray(UpdateChunkHeader.size), off);
      }
      assert.equal(sha(out), Buffer.from(hash).toString("hex"));
      return out;
    };
    assert.deepEqual(await fetchBlob(manifest.exefs_sha256, manifest.exefs_size), exefs);
    assert.deepEqual(await fetchBlob(manifest.overlay_sha256, manifest.overlay_size), overlay);
    // an old-module check (reserved[0]=0) has no channel published here: empty manifest, not ours
    B.send(PacketId.UpdateCheck, UpdateCheckRequest.encode({
      running_build: 5, rejected_build: 0, channel: 1, label_len: label.length, reserved: new Uint8Array([0, 0]), label, version: new TextEncoder().encode("v0.0.0-old"),
    }));
    assert.equal((await B.expect(PacketId.UpdateManifest)).length, 0);
  });

  await step("admin API lists both consoles online with names and version; B's DebugLog shows in /logs", async () => {
    const dbg = new TextEncoder();
    const lbl = dbg.encode("e2e-b");
    B.send(PacketId.DebugLog, new Uint8Array([lbl.length, ...lbl, ...dbg.encode("hello from e2e-b\nsecond line")]));
    await new Promise((r) => setTimeout(r, 300));
    const list = await consolesList();
    assert.deepEqual(list.map((c) => [c.name, c.online]).sort(), [["e2e-a", true], ["e2e-b", true]]);
    const cb = list.find((c) => c.name === "e2e-b")!;
    assert.equal(cb.version, "v0.0.0-old");
    const logs = (await (await api(`/api/consoles/${cb.id}/logs`)).json()) as { line: string }[];
    assert.deepEqual(logs.map((l) => l.line), ["hello from e2e-b", "second line"]);
  });

  await step("revoke B: socket closes, reconnect refused, A unaffected", async () => {
    const cb = (await consolesList()).find((c) => c.name === "e2e-b")!;
    assert.equal((await api(`/api/consoles/${cb.id}/revoke`, { method: "POST" })).status, 200);
    await assert.rejects(() => B.next(2000), /closed/);
    assert.equal(await upgradeStatus(wsUrl, authHeaders(b.token)), 404);
    assert.equal(await upgradeStatus(wsUrl, authHeaders(a.token)), 101);
    assert.deepEqual((await consolesList()).map((c) => c.name), ["e2e-a"]);
  });

  // ---- restart ----
  const inviteC = await mkInvite("e2e-c"); // minted before the restart, redeemed after it
  A.close();
  await step("docker restart: tokens, consumed and unconsumed invites persist", async () => {
    sh("docker", ["restart", "-t", "5", NAME], { quiet: true });
    await waitUp();
    assert.equal(await upgradeStatus(wsUrl, authHeaders(a.token)), 101, "A's token survives");
    assert.equal(await upgradeStatus(wsUrl, authHeaders(b.token)), 404, "revoked B stays revoked");
    assert.equal((await redeem(inviteA)).status, 404, "consumed invite stays consumed");
    assert.deepEqual((await consolesList()).map((c) => c.name), ["e2e-a"]);
    const c = conf(await zipOf(inviteC));
    assert.equal(await upgradeStatus(wsUrl, authHeaders(c.token)), 101, "pending invite still redeemable");
  });
  await step("after restart, A still plays: a fresh network and scan work", async () => {
    A = await connectWs(wsUrl, authHeaders(a.token));
    await A.initialize();
    A.createAp({ name: "E2E-A2", lcid: lcid + 1n });
    await A.expect(PacketId.ProxyConfig);
    A.close();
  });
}

// ---- the self-hoster's stack: docker-compose.yml + Caddyfile, RELAY_DOMAIN=localhost (Caddy signs with its internal CA) ----
async function viaCaddy() {
  const dir = join(work, "caddy"), [p80, p443] = [hostPort + 1, hostPort + 2];
  mkdirSync(dir, { recursive: true });
  copyFileSync(join(relayDir, "Caddyfile"), join(dir, "Caddyfile"));
  writeFileSync(join(dir, ".env"), readFileSync(join(work, ".env"), "utf8") + "RELAY_DOMAIN=localhost\n", { mode: 0o600 });
  // the image is already built; only the published ports and the host alias for the fake GitHub differ from the shipped file
  writeFileSync(join(dir, "override.yml"), `services:
  relay: { image: ${IMAGE}, build: !reset null, pull_policy: never, extra_hosts: ["host.docker.internal:host-gateway"] }
  caddy: { ports: !override ["127.0.0.1:${p80}:80", "127.0.0.1:${p443}:443"] }
`);
  const dc = (...a: string[]) => sh("docker", ["compose", "-p", CADDY, "--project-directory", dir, "-f", join(relayDir, "docker-compose.yml"), "-f", join(dir, "override.yml"), ...a], { quiet: true });
  const root = join(dir, "root.crt"), site = `https://localhost:${p443}`;
  await step("compose up (relay + Caddy): HTTP redirects to HTTPS, /admin over TLS from Caddy's CA, relay port not published", async () => {
    dc("up", "-d");
    for (let i = 0; ; i++) {
      try { dc("cp", "caddy:/data/caddy/pki/authorities/local/root.crt", root); tls.setDefaultCACertificates([readFileSync(root, "utf8")]); if ((await fetch(site + "/admin")).status === 200) break; } catch (e) {
        if (i > 60) throw new Error("caddy did not come up:\n" + dc("logs", "--tail", "30") + e);
      }
      await new Promise((r) => setTimeout(r, 500));
    }
    assert.equal((await fetch(`http://localhost:${p80}/admin`, { redirect: "manual" })).status, 308);
    assert.ok(!dc("ps", "relay", "--format", "{{.Ports}}").includes("->"), "the relay's own port must not be published");
  });
  const login = (secret: string, origin = site, xff?: string) =>
    fetch(site + "/admin/login", { method: "POST", headers: { origin, "content-type": "application/json", ...(xff && { "x-forwarded-for": xff }) }, body: JSON.stringify({ secret }) });
  let cookie = "";
  await step("login over TLS (cross-site Origin refused), invite -> zip names localhost:port, both tokens play over wss", async () => {
    assert.equal((await login(admin, "https://evil.example")).status, 403);
    const ok = await login(admin);
    assert.equal(ok.status, 204);
    cookie = ok.headers.get("set-cookie")!.split(";")[0];
    const tokens: string[] = [];
    for (const name of ["caddy-a", "caddy-b"]) {
      const r = await fetch(site + "/api/invites", { method: "POST", headers: { cookie, origin: site, "content-type": "application/json" }, body: JSON.stringify({ name }) });
      const { url } = (await r.json()) as { url: string };
      assert.ok(url.startsWith(site + "/invite/"), "invite link uses the public scheme and host: " + url);
      const z = await fetch(url, { method: "POST" });
      assert.equal(z.status, 200);
      const ini = new TextDecoder().decode(unzipSync(new Uint8Array(await z.arrayBuffer()))["config/ldn-tunnel/config.ini"]);
      assert.match(ini, /^host = localhost$/m);
      assert.match(ini, new RegExp(`^port = ${p443}$`, "m"));
      tokens.push(/^token = ([0-9a-f]{64})$/m.exec(ini)![1]);
    }
    const url = `wss://localhost:${p443}/ldn`, id = BigInt("0x" + randomBytes(7).toString("hex"));
    const [A, B] = [await connectWs(url, authHeaders(tokens[0])), await connectWs(url, authHeaders(tokens[1]))];
    await A.initialize();
    await B.initialize();
    A.createAp({ name: "CADDY-A", lcid: id });
    const hostIp = ProxyConfig.decode(await A.expect(PacketId.ProxyConfig)).proxy_ip;
    await A.expect(PacketId.Connected);
    const found = await B.scanAll(id);
    assert.equal(found.length, 1);
    B.connect(found[0], { name: "CADDY-B" });
    await B.expect(PacketId.ProxyConfig);
    await B.expect(PacketId.Connected);
    await A.expect(PacketId.SyncNetwork);
    B.proxyData(0, hostIp, new TextEncoder().encode("over caddy"));
    assert.equal(new TextDecoder().decode((await A.expect(PacketId.ProxyData)).subarray(ProxyDataHeader.size)), "over caddy");
    A.close();
    B.close();
    assert.equal(await upgradeStatus(url, authHeaders("0".repeat(64))), 404);
  });
  await step("TRUST_PROXY: a client-sent X-Forwarded-For does not dodge the login limiter behind Caddy", async () => {
    const codes: number[] = [];
    for (let i = 1; i <= 13; i++) codes.push((await login("nope", site, `9.9.9.${i}`)).status); // rotating spoofed hops
    assert.deepEqual([...new Set(codes.slice(0, 10))], [401]);
    assert.ok(codes.includes(429), "Caddy replaces the header, so every attempt counts against one client: " + codes);
  });
}

let failed = false;
try {
  await main();
  await viaCaddy();
} catch (e) {
  failed = true;
  console.error(e);
  try { console.error("--- container log ---\n" + sh("docker", ["logs", "--tail", "40", NAME], { quiet: true })); } catch {}
} finally {
  gh.close();
  if (!process.env.E2E_KEEP) cleanup();
  if (!process.env.E2E_DIR) rmSync(work, { recursive: true, force: true });
}
console.log(timings.map(([n, ms]) => `${String(ms).padStart(6)} ms  ${n}`).join("\n"));
console.log(failed ? "e2e-docker: FAILED" : "e2e-docker: all passed");
process.exit(failed ? 1 : 0);
