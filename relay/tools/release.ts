// Uploads a sysmodule + overlay and publishes the signed manifest to a module's test channel.
//   npm run release -- --repo <ryu_ldn_nx checkout> [--skip-build] [--url <relay>]
//   npm run release -- --module ldn-tunnel --exefs <exefs.nsp> --overlay <ldn-tunnel.ovl> --version <v> --build <n> [--url <relay>]
// ryu_ldn_nx is built here from --repo (build = now, passed to its make); ldn-tunnel takes the files its own build
// produced, so --build must be the LDNT_BUILD that exefs was compiled with: it is baked in at compile time, and a
// manifest with a different number would make the console re-install the same build or reject it as not newer.
// The admin token and signing key are read from secrets/ and never printed.
import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { parseArgs } from "node:util";
import { encodeManifest, moduleOf, signManifest } from "./update-manifest.ts";

const secrets = new URL("../../secrets/", import.meta.url).pathname;
const { values } = parseArgs({
  options: {
    module: { type: "string" },
    repo: { type: "string" },
    exefs: { type: "string" },
    overlay: { type: "string" },
    version: { type: "string" },
    build: { type: "string" },
    url: { type: "string", default: process.env.RELAY_URL },
    "skip-build": { type: "boolean" },
    "token-file": { type: "string", default: secrets + "update-admin.token" },
    "key-file": { type: "string", default: secrets + "update-signing-key.pem" },
  },
});
const mod = moduleOf(values.module);
if (!values.url) throw new Error("pass --url <relay> or set RELAY_URL");
let build = Math.floor(Date.now() / 1000);
if (mod.id !== 0) {
  if (!/^[1-9]\d*$/.test(values.build ?? "") || Number(values.build) > 0xffffffff) throw new Error("ldn-tunnel needs --build <n>, the LDNT_BUILD its exefs was compiled with (1..4294967295)");
  build = Number(values.build);
} else if (values.build) throw new Error("--build is only for --module ldn-tunnel; ryu_ldn_nx is built here with the current time");
let version = values.version;
let exefs: Buffer, overlay: Buffer;
if (mod.id === 0) {
  if (!values.repo) throw new Error("pass --repo <ryu_ldn_nx checkout>");
  const repo = values.repo;
  const git = (...a: string[]) => execFileSync("git", ["-C", repo, ...a], { encoding: "utf8" }).trim();
  version ??= git("describe", "--always", "--dirty", "--tags");
  if (git("status", "--porcelain")) console.warn(`warning: ${repo} has uncommitted changes (version is ${version})`);
  if (!values["skip-build"]) {
    // make does not see a changed build number: drop the objects that embed it (they are root-owned, so via the container)
    const stale = ["main", "update_worker", "update_swap", "update_manifest", "config_ipc_service"].map((o) => `sysmodule/build/${o}.o`);
    spawnSync("docker", ["compose", "run", "--rm", "build", `rm -f ${stale.join(" ")}`], { cwd: repo, stdio: "inherit" });
    const r = spawnSync("docker", ["compose", "run", "--rm", "build"], {
      cwd: repo,
      stdio: "inherit",
      env: { ...process.env, RYU_UPDATE_BUILD: String(build), RYU_UPDATE_VERSION: version },
    });
    if (r.status !== 0) throw new Error(`build failed (exit ${r.status})`);
  }
  exefs = readFileSync(`${repo}/output/atmosphere/contents/4200000000000010/exefs.nsp`);
  overlay = readFileSync(`${repo}/output/switch/.overlays/ryu_ldn_nx_overlay.ovl`);
} else {
  if (!values.exefs || !values.overlay || !version) throw new Error("ldn-tunnel needs --exefs, --overlay, --version and --build");
  exefs = readFileSync(values.exefs);
  overlay = readFileSync(values.overlay);
}
const sha = (b: Uint8Array) => createHash("sha256").update(b).digest();
const token = readFileSync(values["token-file"]!, "utf8").trim();

async function put(path: string, body: Uint8Array) {
  // a fresh copy: fetch's BodyInit wants a plain ArrayBuffer-backed view, not a Buffer slice of the pool
  const res = await fetch(values.url + path, { method: "PUT", headers: { Authorization: `Bearer ${token}` }, body: new Uint8Array(body) });
  if (!res.ok) throw new Error(`PUT ${path} -> ${res.status} ${await res.text()}`);
}

for (const b of [exefs, overlay]) await put(`/update/blob/${sha(b).toString("hex")}`, b);
const manifest = encodeManifest({
  build,
  version,
  exefs: { size: exefs.length, sha256: sha(exefs) },
  overlay: { size: overlay.length, sha256: sha(overlay) },
}, mod.format);
await put(`/update/${mod.prefix}channel/test`, signManifest(manifest, readFileSync(values["key-file"]!, "utf8")));
console.log(`released build ${build} (${version}) to ${mod.prefix}test: exefs ${exefs.length} B, overlay ${overlay.length} B`);
