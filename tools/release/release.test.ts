import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { privateKey, publicHex, readPubkey, verifyBundle } from "./release.ts";

const here = import.meta.dirname;
const tool = (...a: string[]) => execFileSync("node", [join(here, "release.ts"), ...a], { encoding: "utf8" });
const fixtureKey = join(here, "test/fixture-key.pem");
const fixturePub = readPubkey(publicHex(privateKey(readFileSync(fixtureKey, "utf8"))));

function bundle(key = fixtureKey) {
  const d = mkdtempSync(join(tmpdir(), "rel-"));
  writeFileSync(join(d, "exefs.nsp"), "exefs bytes");
  writeFileSync(join(d, "ldn-tunnel.ovl"), "overlay bytes");
  writeFileSync(join(d, "relay-cloudflare.zip"), "zip bytes");
  tool("sign-manifest", "--exefs", join(d, "exefs.nsp"), "--overlay", join(d, "ldn-tunnel.ovl"), "--version", "v1.2.3", "--build", "1700000000", "--key-file", key, "--out", join(d, "manifest.bin"));
  tool("release-json", "--dir", d, "--key-file", key);
  return d;
}

test("sign, release-json, verify round trip", () => {
  const d = bundle();
  assert.equal(statSync(join(d, "manifest.bin")).size, 192);
  const rel = JSON.parse(readFileSync(join(d, "release.json"), "utf8"));
  assert.equal(rel.build, 1700000000);
  assert.equal(rel.version, "v1.2.3");
  assert.deepEqual(Object.keys(rel.assets), ["exefs.nsp", "ldn-tunnel.ovl", "manifest.bin", "relay-cloudflare.zip"]);
  assert.deepEqual(verifyBundle(d, fixturePub), []);
  assert.match(tool("verify", "--dir", d, "--pubkey", fixturePub.toString("hex")), /ok/);
});

test("private key may be hex via the env", () => {
  const d = mkdtempSync(join(tmpdir(), "rel-"));
  const k = join(d, "k.pem");
  tool("gen-key", "--out", k);
  assert.equal(statSync(k).mode & 0o777, 0o600);
  const pem = readFileSync(k, "utf8");
  const pub = publicHex(privateKey(pem));
  const jwk = (await_jwk(pem));
  writeFileSync(join(d, "a"), "a");
  const run = (env: string) => execFileSync("node", [join(here, "release.ts"), "sign-manifest", "--exefs", join(d, "a"), "--overlay", join(d, "a"), "--version", "v", "--build", "5", "--out", join(d, "m")], { env: { ...process.env, PUBLISHER_KEY: env } });
  run(pem);
  const viaPem = readFileSync(join(d, "m"));
  run(jwk);
  assert.equal(readFileSync(join(d, "m")).subarray(0, 128).toString("hex"), viaPem.subarray(0, 128).toString("hex"));
  assert.equal(pub.length, 130);
});
function await_jwk(pem: string): string {
  return Buffer.from(privateKey(pem).export({ format: "jwk" }).d!, "base64url").toString("hex");
}

test("verify catches a tampered asset, wrong key, and edited release.json", () => {
  const d = bundle();
  const other = join(mkdtempSync(join(tmpdir(), "rel-")), "o.pem");
  tool("gen-key", "--out", other);
  const otherPub = readPubkey(publicHex(privateKey(readFileSync(other, "utf8"))));
  assert.ok(verifyBundle(d, otherPub).length > 0);
  writeFileSync(join(d, "exefs.nsp"), "exefs byteX");
  assert.ok(verifyBundle(d, fixturePub).some((p) => p.includes("exefs.nsp")));
  const d2 = bundle();
  writeFileSync(join(d2, "release.json"), readFileSync(join(d2, "release.json"), "utf8").replace("1.2.3", "9.9.9"));
  assert.ok(verifyBundle(d2, fixturePub).some((p) => p.includes("release.sig")));
});

test("version over 32 bytes is rejected", () => {
  const d = mkdtempSync(join(tmpdir(), "rel-"));
  writeFileSync(join(d, "a"), "a");
  assert.throws(() => tool("sign-manifest", "--exefs", join(d, "a"), "--overlay", join(d, "a"), "--version", "v".repeat(33), "--key-file", fixtureKey, "--out", join(d, "m")));
});

test("relay and core hold the same publisher key, never the committed fixture key", () => {
  const pub = readPubkey(join(here, "../../relay/src/core/publisher_key.ts"));
  assert.ok(pub.equals(readPubkey(join(here, "../../crates/core/src/update_pubkey.rs"))), "update_pubkey.rs and publisher_key.ts differ");
  assert.ok(!pub.equals(fixturePub), "publisher_key.ts holds the fixture key, whose private half is committed");
});
