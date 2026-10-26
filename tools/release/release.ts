// Build, sign and verify the release bundle (docs/CONTRACTS.md "Release bundle").
// Node >= 24, no dependencies:  node --experimental-strip-types tools/release/release.ts <command> ...
//   gen-key        --out <key.pem>                      new P-256 key; prints the public key
//   sign-manifest  --exefs --overlay --version [--build] [--key-file | $PUBLISHER_KEY] --out manifest.bin
//   release-json   --dir <bundle dir> [--key-file | $PUBLISHER_KEY]   writes release.json + release.sig
//   verify         --dir <bundle dir> --pubkey <hex | file with 0x.. bytes>
// The private key is a PEM (PKCS#8 or SEC1) or 64 hex chars (raw scalar), from a file or the env.
import {
  createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify,
  type KeyObject,
} from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { parseArgs } from "node:util";

const MAGIC = 0x4d554c52; // "RLUM" little-endian
const FORMAT = 2; // ldn-tunnel (1 = ryu_ldn_nx)
export const ASSETS = ["exefs.nsp", "ldn-tunnel.ovl", "manifest.bin", "relay-cloudflare.zip"];
const sha256 = (b: Uint8Array) => createHash("sha256").update(b).digest();

export function privateKey(s: string): KeyObject {
  s = s.trim();
  if (/^[0-9a-fA-F]{64}$/.test(s)) {
    // PKCS#8 header for a bare P-256 scalar
    const der = Buffer.concat([Buffer.from("3041020100301306072a8648ce3d020106082a8648ce3d030107042730250201010420", "hex"), Buffer.from(s, "hex")]);
    return createPrivateKey({ key: der, format: "der", type: "pkcs8" });
  }
  return createPrivateKey(s);
}

export function publicHex(k: KeyObject): string {
  const j = createPublicKey(k).export({ format: "jwk" });
  return Buffer.concat([Buffer.from([4]), Buffer.from(j.x!, "base64url"), Buffer.from(j.y!, "base64url")]).toString("hex");
}

/** A hex string, or a file (hex, or Rust/TS source) holding the 65 bytes as 0x.. literals or a quoted hex string. */
export function readPubkey(arg: string): Buffer {
  let s = arg;
  if (existsSync(arg)) {
    s = readFileSync(arg, "utf8");
    const lits = s.match(/0x[0-9a-fA-F]{2}\b/g);
    const quoted = s.match(/"(04[0-9a-fA-F]{128})"/);
    const hex = s.match(/["']([0-9a-fA-F]{130})["']/);
    if (lits) s = lits.map((l) => l.slice(2)).join("");
    else if (hex) s = hex[1];
    else if (quoted?.[1]) s = quoted[1];
  }
  s = s.trim();
  if (!/^[0-9a-fA-F]{130}$/.test(s) || !s.startsWith("04")) throw new Error("public key must be 65 bytes (04 || x || y)");
  return Buffer.from(s, "hex");
}

function verifyingKey(pub: Buffer): KeyObject {
  return createPublicKey({ key: { kty: "EC", crv: "P-256", x: pub.subarray(1, 33).toString("base64url"), y: pub.subarray(33).toString("base64url") }, format: "jwk" });
}
const ecdsa = (data: Uint8Array, k: KeyObject) => sign("sha256", data, { key: k, dsaEncoding: "ieee-p1363" });
const ecdsaOk = (data: Uint8Array, sig: Uint8Array, pub: Buffer) =>
  verify("sha256", data, { key: verifyingKey(pub), dsaEncoding: "ieee-p1363" }, sig);

export interface Release { build: number; version: string; exefs: Uint8Array; overlay: Uint8Array }

/** The 128 signed bytes (crates/core/src/wire.rs UpdateManifest). */
export function encodeManifest(r: Release): Buffer {
  const v = Buffer.from(r.version);
  if (v.length > 32) throw new Error(`version "${r.version}" is longer than 32 bytes`);
  if (!Number.isInteger(r.build) || r.build <= 0 || r.build > 0xffffffff) throw new Error("build must be a positive u32");
  const b = Buffer.alloc(128);
  b.writeUInt32LE(MAGIC, 0);
  b.writeUInt32LE(FORMAT, 4);
  b.writeUInt32LE(r.build, 8);
  b.writeUInt32LE(r.exefs.length, 12);
  sha256(r.exefs).copy(b, 16);
  b.writeUInt32LE(r.overlay.length, 48);
  sha256(r.overlay).copy(b, 52);
  v.copy(b, 84);
  return b; // reserved (116..128) stays zero
}

/** 128 manifest bytes + raw r||s signature = 192 bytes. */
export function signManifest(r: Release, key: KeyObject): Buffer {
  const m = encodeManifest(r);
  return Buffer.concat([m, ecdsa(m, key)]);
}

/** Sorted keys: the same bundle always gives the same release.json bytes. */
export function releaseJson(dir: string): { json: Buffer; build: number } {
  const manifest = readFileSync(join(dir, "manifest.bin"));
  const build = manifest.readUInt32LE(8);
  const version = manifest.subarray(84, 116).toString().replace(/\0+$/, "");
  const assets: Record<string, { sha256: string; size: number }> = {};
  for (const name of ASSETS) {
    const p = join(dir, name);
    if (!existsSync(p)) continue;
    const data = readFileSync(p);
    assets[name] = { sha256: sha256(data).toString("hex"), size: data.length };
  }
  return { json: Buffer.from(JSON.stringify({ version, build, assets }, null, 2) + "\n"), build };
}

/** Returns the problems found (empty = the bundle is good). */
export function verifyBundle(dir: string, pub: Buffer): string[] {
  const bad: string[] = [];
  const read = (n: string) => (existsSync(join(dir, n)) ? readFileSync(join(dir, n)) : undefined);
  const json = read("release.json"), sig = read("release.sig"), man = read("manifest.bin");
  if (!json || !sig || !man) return ["release.json, release.sig and manifest.bin are required"];
  if (sig.length !== 64 || !ecdsaOk(json, sig, pub)) bad.push("release.sig does not verify release.json");
  if (man.length !== 192) return [...bad, "manifest.bin is not 192 bytes"];
  if (man.readUInt32LE(0) !== MAGIC || man.readUInt32LE(4) !== FORMAT) bad.push("manifest.bin: bad magic/format");
  if (!ecdsaOk(man.subarray(0, 128), man.subarray(128), pub)) bad.push("manifest.bin signature does not verify");
  let rel: { version: string; build: number; assets: Record<string, { sha256: string; size: number }> };
  try { rel = JSON.parse(json.toString()); } catch { return [...bad, "release.json is not JSON"]; }
  const fromManifest = JSON.parse(releaseJson(dir).json.toString());
  if (rel.version !== fromManifest.version || rel.build !== fromManifest.build) bad.push("release.json version/build differ from manifest.bin");
  for (const name of ["exefs.nsp", "ldn-tunnel.ovl", "manifest.bin"]) if (!rel.assets?.[name]) bad.push(`release.json lacks ${name}`);
  for (const [name, a] of Object.entries(rel.assets ?? {})) {
    const d = read(name);
    if (!d) bad.push(`${name} is listed but missing`);
    else if (d.length !== a.size || sha256(d).toString("hex") !== a.sha256) bad.push(`${name}: size/sha256 differ from release.json`);
  }
  const exefs = read("exefs.nsp"), ovl = read("ldn-tunnel.ovl");
  if (exefs && (man.readUInt32LE(12) !== exefs.length || !sha256(exefs).equals(man.subarray(16, 48)))) bad.push("manifest.bin does not match exefs.nsp");
  if (ovl && (man.readUInt32LE(48) !== ovl.length || !sha256(ovl).equals(man.subarray(52, 84)))) bad.push("manifest.bin does not match ldn-tunnel.ovl");
  return bad;
}

function keyFromArgs(keyFile?: string): KeyObject {
  const s = keyFile ? readFileSync(keyFile, "utf8") : process.env.PUBLISHER_KEY;
  if (!s) throw new Error("pass --key-file <pem|hex file> or set PUBLISHER_KEY");
  return privateKey(s);
}

function main(argv: string[]) {
  const [cmd, ...rest] = argv;
  const { values: v } = parseArgs({
    args: rest,
    options: { out: { type: "string" }, exefs: { type: "string" }, overlay: { type: "string" }, version: { type: "string" },
      build: { type: "string" }, "key-file": { type: "string" }, dir: { type: "string" }, pubkey: { type: "string" } },
  });
  const need = <T>(x: T | undefined, n: string): T => { if (x === undefined) throw new Error(`--${n} is required`); return x; };
  switch (cmd) {
    case "gen-key": {
      const { privateKey: k } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
      writeFileSync(need(v.out, "out"), k.export({ format: "pem", type: "pkcs8" }), { mode: 0o600, flag: "wx" });
      const hex = publicHex(k);
      console.log(`private key: ${v.out} (0600; never commit it)\npublic key (65 bytes): ${hex}`);
      console.log("as bytes: " + (hex.match(/../g) ?? []).map((b) => "0x" + b).join(", "));
      return;
    }
    case "sign-manifest": {
      const build = v.build ? Number(v.build) : Math.floor(Date.now() / 1000);
      const m = signManifest({ build, version: need(v.version, "version"), exefs: readFileSync(need(v.exefs, "exefs")), overlay: readFileSync(need(v.overlay, "overlay")) }, keyFromArgs(v["key-file"]));
      writeFileSync(need(v.out, "out"), m);
      console.log(`${v.out}: build ${build}, ${m.length} bytes`);
      return;
    }
    case "release-json": {
      const dir = need(v.dir, "dir");
      const { json } = releaseJson(dir);
      writeFileSync(join(dir, "release.json"), json);
      writeFileSync(join(dir, "release.sig"), ecdsa(json, keyFromArgs(v["key-file"])));
      console.log(json.toString());
      return;
    }
    case "verify": {
      const bad = verifyBundle(need(v.dir, "dir"), readPubkey(need(v.pubkey, "pubkey")));
      if (bad.length) { console.error(bad.map((b) => "FAIL " + b).join("\n")); process.exit(1); }
      console.log("release bundle ok");
      return;
    }
    default:
      console.error("usage: release.ts gen-key|sign-manifest|release-json|verify (see the header of this file)");
      process.exit(2);
  }
}

if (import.meta.main) main(process.argv.slice(2));
