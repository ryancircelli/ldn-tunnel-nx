// Publisher-signed releases (docs/relay-releases.md). GitHub Release `v<version>` of release.json's repo:
//   release.json   {"version":"v1.2.3","build":<n>,"assets":{"<name>":{"sha256":"<hex>","size":<n>},...}}
//   release.sig    64 bytes: ECDSA P-256 / SHA-256 over release.json, raw r || s, publisher key
//   manifest.bin   the 192-byte signed console manifest (format 2) for exefs.nsp + ldn-tunnel.ovl
//   exefs.nsp, ldn-tunnel.ovl
//   relay-cloudflare.zip   the built Worker (modules + metadata.json); only the Cloudflare self-update uses it
// A relay serves the console files of its own tag (relay/release.json) and checks everything against the
// publisher key before storing or deploying it.
import pin from "../../release.json" with { type: "json" };
import { SignedManifest, UPDATE_MANIFEST_MAGIC, UpdateManifest } from "./codec/types.ts";
import { PUBLISHER_KEY } from "./publisher_key.ts";
import { sha256Hex } from "./auth.ts";
import { RELEASE_CHANNEL, hex, unhex, type Relay } from "./relay.ts";

/** The release this code is (`v<version>`): CI writes the tag before it builds the relay. */
export const PIN = pin as { repo: string; tag: string };
const MAX_FILE = 8 << 20;
const LATEST_TTL = 3600_000;
const CONSOLE_FILES = ["manifest.bin", "exefs.nsp", "ldn-tunnel.ovl"] as const;
const RELAY_BUNDLE = "relay-cloudflare.zip";

interface ReleaseDoc {
  version: string;
  build: number;
  assets: Record<string, { sha256: string; size: number }>;
}
interface Fetched {
  tag: string;
  build: number;
  manifest: Uint8Array; // 192 bytes, as the console receives it
  exefs: Uint8Array;
  overlay: Uint8Array;
  relay?: Uint8Array; // relay-cloudflare.zip
}

const kvGet = (r: Relay, k: string) => r.sql.exec<{ v: string }>("SELECT v FROM kv WHERE k = ?", k)[0]?.v;
const kvSet = (r: Relay, k: string, v: string) => r.sql.exec("INSERT OR REPLACE INTO kv (k, v) VALUES (?, ?)", k, v);
// RELEASE_BASE_URL (env) replaces "https://github.com/<repo>/releases": a mirror, or a local server in the Docker smoke test.
const base = (r: Relay, tag: string) =>
  `${String(r.host.env.RELEASE_BASE_URL || `https://github.com/${PIN.repo}/releases`).replace(/\/+$/, "")}/${tag === "latest" ? "latest/download" : `download/${encodeURIComponent(tag)}`}/`;
/** CI writes the tag ("v1.2.3") as the version; a bare "1.2.3" is accepted too. */
export const tagOf = (version: string) => "v" + version.replace(/^v/, "");

async function get(r: Relay, url: string, max = MAX_FILE): Promise<Uint8Array> {
  const res = await r.host.fetch(url, { headers: { "User-Agent": "ldn-tunnel-relay" } });
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  if (Number(res.headers.get("content-length")) > max) throw new Error(`${url}: larger than ${max} bytes`);
  const b = new Uint8Array(await res.arrayBuffer());
  if (b.length > max) throw new Error(`${url}: larger than ${max} bytes`);
  return b;
}

async function verify(r: Relay, data: Uint8Array, sig: Uint8Array): Promise<boolean> {
  // PUBLISHER_KEY (env) overrides the built-in key for self-built forks and the tests; setting it needs the
  // same dashboard access that could replace the code anyway. Consoles check their own baked-in key regardless.
  const k = (r.host.env.PUBLISHER_KEY as string | undefined) || PUBLISHER_KEY;
  if (!/^04[0-9a-f]{128}$/i.test(k)) throw new Error("this relay has no publisher key (src/core/publisher_key.ts)");
  const key = await crypto.subtle.importKey("raw", unhex(k), { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  return sig.length === 64 && crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, sig, data);
}

/** The signed release.json of `tag` ("latest": GitHub's latest release, no API call and no rate limit). */
async function releaseDoc(r: Relay, tag: string): Promise<ReleaseDoc> {
  const doc = await get(r, base(r, tag) + "release.json", 64 << 10);
  if (!(await verify(r, doc, await get(r, base(r, tag) + "release.sig", 64)))) throw new Error("release.json: bad publisher signature");
  const d = JSON.parse(new TextDecoder().decode(doc)) as ReleaseDoc;
  if (typeof d.version !== "string" || !d.assets || (tag !== "latest" && tagOf(d.version) !== tag)) throw new Error(`release.json is not release ${tag}`);
  return d;
}

async function asset(r: Relay, d: ReleaseDoc, name: string): Promise<Uint8Array> {
  const want = d.assets[name];
  if (!want) throw new Error(`release v${d.version} has no ${name}`);
  const b = await get(r, base(r, tagOf(d.version)) + name);
  if (b.length !== want.size || (await sha256Hex(b)) !== want.sha256) throw new Error(`${name}: size or sha256 does not match release.json`);
  return b;
}

/** Downloads and verifies a release: release.json signature, every file's hash, the console manifest's signature. */
async function fetchRelease(r: Relay, tag: string, withRelay: boolean): Promise<Fetched> {
  const d = await releaseDoc(r, tag);
  const [manifest, exefs, overlay] = await Promise.all(CONSOLE_FILES.map((n) => asset(r, d, n)));
  if (manifest.length !== SignedManifest.size) throw new Error("manifest.bin: wrong size");
  const { manifest: m, signature } = SignedManifest.decode(manifest);
  if (m.magic !== UPDATE_MANIFEST_MAGIC || m.format !== 2 || m.build < 1) throw new Error("manifest.bin: not an ldn-tunnel manifest");
  if (!(await verify(r, manifest.subarray(0, UpdateManifest.size), signature))) throw new Error("manifest.bin: bad publisher signature");
  if (m.exefs_size !== exefs.length || hex(m.exefs_sha256) !== (await sha256Hex(exefs)) || m.overlay_size !== overlay.length || hex(m.overlay_sha256) !== (await sha256Hex(overlay))) {
    throw new Error("manifest.bin does not name these console files");
  }
  return { tag: tagOf(d.version), build: d.build, manifest, exefs, overlay, relay: withRelay ? await asset(r, d, RELAY_BUNDLE) : undefined };
}

/** Stores the console files, runs `deploy` (if any), then points the release channel at them. */
async function install(r: Relay, f: Fetched, deploy?: () => Promise<unknown>) {
  for (const b of [f.exefs, f.overlay]) {
    const res = await r.putBlob(await sha256Hex(b), b);
    if (!res.ok) throw new Error(await res.text());
  }
  await deploy?.();
  r.store(RELEASE_CHANNEL, f.manifest);
  kvSet(r, "installed", JSON.stringify({ tag: f.tag, build: f.build }));
}

/** Tag and build of the console files on the release channel. */
export const installed = (r: Relay): { tag: string; build: number } | undefined => {
  const v = kvGet(r, "installed");
  return v ? JSON.parse(v) : undefined;
};

let pending: Promise<void> | undefined;
/** Makes sure the console files of this relay's own release are stored. Throws with a readable reason. */
export function ensureInstalled(r: Relay): Promise<void> {
  if (installed(r)?.tag === PIN.tag) return Promise.resolve();
  // one download at a time per isolate
  return (pending ??= fetchRelease(r, PIN.tag, false).then((f) => install(r, f)).finally(() => (pending = undefined)));
}

/** The publisher's latest release, verified, cached for an hour; undefined when GitHub is unreachable. */
export async function latest(r: Relay, now = Date.now()): Promise<{ tag: string; build: number } | undefined> {
  const cached = kvGet(r, "latest");
  if (cached) {
    const c = JSON.parse(cached) as { tag: string; build: number; at: number };
    if (now - c.at < LATEST_TTL) return c;
  }
  try {
    const d = await releaseDoc(r, "latest");
    const c = { tag: tagOf(d.version), build: d.build, at: now };
    kvSet(r, "latest", JSON.stringify(c));
    return c;
  } catch {
    return undefined;
  }
}

/** Cloudflare self-update: verify release `tag`, store its console files, deploy its Worker, then serve them. */
export async function update(r: Relay, tag: string) {
  const d = r.host.deployer;
  if (!d) throw new Error("this relay cannot redeploy itself");
  const f = await fetchRelease(r, tag, true);
  await install(r, f, () => d.deploy(f.relay!));
}
