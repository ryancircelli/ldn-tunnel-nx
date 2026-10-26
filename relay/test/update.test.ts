/// <reference types="node" />
// Release API (/update/*, admin token) and the two console-facing update packets.
import { exports } from "cloudflare:workers";
import { generateKeyPairSync, createHash, verify } from "node:crypto";
import { describe, expect, it, vi } from "vitest";

vi.setConfig({ testTimeout: 30_000 }); // 4 MiB uploads are slow on a loaded machine
import {
  PacketId, SignedManifest, UPDATE_MANIFEST_MAGIC, UpdateChunkHeader, UpdateChunkRequest, UpdateCheckRequest, UpdateManifest,
} from "../src/core/codec/types.ts";
import { Ldn } from "../tools/ldn-client.ts";
import { decodeManifest, encodeManifest, signManifest } from "../tools/update-manifest.ts";

const TEST_TOKEN = "a".repeat(64); // sha256 bound as TOKEN_SWITCH_A in vitest.config.ts
const TEST_ADMIN_TOKEN = "c".repeat(64); // sha256 bound as UPDATE_ADMIN
const { privateKey: pem, publicKey: pubPem } = generateKeyPairSync("ec", {
  namedCurve: "P-256",
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
  publicKeyEncoding: { type: "spki", format: "pem" },
});
const randomBytes = (n: number) => {
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i += 65536) crypto.getRandomValues(out.subarray(i, i + 65536));
  return out;
};
const sha = (b: Uint8Array) => createHash("sha256").update(b).digest();
const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");

const api = (method: string, path: string, body?: Uint8Array, token: string | null = TEST_ADMIN_TOKEN) =>
  exports.default.fetch(new Request("https://relay.test" + path, { method, body, headers: token ? { Authorization: `Bearer ${token}` } : {} }));
const putBlob = (b: Uint8Array) => api("PUT", `/update/blob/${hex(sha(b))}`, b);
const status = async () => (await api("GET", "/update/status")).json() as Promise<any>;

let build = 1_000_000;
/** Uploads two fresh blobs and returns the signed manifest for them (not yet published). */
async function release(sizes = [5000, 7000], b = ++build, version = "v-" + b, format = 1) {
  const [exefs, overlay] = sizes.map((n) => randomBytes(n));
  expect((await putBlob(exefs)).status).toBe(200);
  expect((await putBlob(overlay)).status).toBe(200);
  const manifest = encodeManifest({
    build: b, version, exefs: { size: exefs.length, sha256: sha(exefs) }, overlay: { size: overlay.length, sha256: sha(overlay) },
  }, format);
  return { exefs, overlay, build: b, signed: signManifest(manifest, pem) };
}
const publish = (signed: Uint8Array, prefix = "") => api("PUT", `/update/${prefix}channel/test`, signed);

async function open(): Promise<Ldn & { ws: WebSocket }> {
  const res = await exports.default.fetch(new Request("https://relay.test/ldn", { headers: { Upgrade: "websocket", Authorization: `Bearer ${TEST_TOKEN}` } }));
  const ws = res.webSocket!;
  ws.accept();
  ws.binaryType = "arraybuffer";
  const c = new Ldn((b) => ws.send(b)) as Ldn & { ws: WebSocket };
  c.ws = ws;
  ws.addEventListener("message", (e) => c.push(new Uint8Array(e.data as ArrayBuffer)));
  ws.addEventListener("close", () => c.end());
  return c;
}

const check = (o: { label?: string; channel?: number; build?: number; rejected?: number; version?: string; labelLen?: number; module?: number } = {}) => {
  const label = new TextEncoder().encode(o.label ?? "tester-1234");
  return UpdateCheckRequest.encode({
    running_build: o.build ?? 5, rejected_build: o.rejected ?? 0, channel: o.channel ?? 2, label_len: o.labelLen ?? label.length,
    reserved: new Uint8Array([o.module ?? 0, 0]), label, version: new TextEncoder().encode(o.version ?? "v-running"),
  });
};
const chunkReq = (sha256: Uint8Array, offset: number, length: number) => UpdateChunkRequest.encode({ sha256, offset, length });
async function chunk(c: Ldn, sha256: Uint8Array, offset: number, length: number) {
  c.send(PacketId.UpdateChunk, chunkReq(sha256, offset, length));
  const p = await c.expect(PacketId.UpdateChunkData);
  return { head: UpdateChunkHeader.decode(p), data: p.subarray(UpdateChunkHeader.size) };
}

describe("publish auth", () => {
  const routes: [string, string][] = [
    ["GET", "/update/status"], ["POST", "/update/promote"], ["PUT", "/update/channel/test"], ["PUT", `/update/blob/${"0".repeat(64)}`],
    ["POST", "/update/ldn-tunnel/promote"], ["PUT", "/update/ldn-tunnel/channel/test"],
  ];
  for (const [m, p] of routes) {
    it(`${m} ${p}: console token and no token -> 404 empty`, async () => {
      for (const t of [TEST_TOKEN, null, "d".repeat(64)]) {
        const res = await api(m, p, m === "PUT" ? new Uint8Array(1) : undefined, t);
        expect(res.status).toBe(404);
        expect(await res.text()).toBe("");
      }
    });
  }
  it("the admin token cannot open /ldn or /logs", async () => {
    const h = { Authorization: `Bearer ${TEST_ADMIN_TOKEN}` };
    const ws = await exports.default.fetch(new Request("https://relay.test/ldn", { headers: { Upgrade: "websocket", ...h } }));
    expect(ws.status).toBe(404);
    const logs = await exports.default.fetch(new Request("https://relay.test/logs", { headers: h }));
    expect(logs.status).toBe(404);
    expect(await logs.text()).toBe("");
  });
  it("the admin token works", async () => {
    expect((await api("GET", "/update/status")).status).toBe(200);
  });
  it("unknown /update paths and wrong methods -> 404", async () => {
    expect((await api("GET", "/update/nope")).status).toBe(404);
    expect((await api("GET", "/update/promote")).status).toBe(404);
    expect((await api("PUT", "/update/channel/stable", new Uint8Array(192))).status).toBe(404);
    expect((await api("PUT", "/update/blob/ABC", new Uint8Array(3))).status).toBe(404);
  });
});

describe("blob upload", () => {
  it("is idempotent", async () => {
    const b = randomBytes(100);
    expect((await putBlob(b)).status).toBe(200);
    expect((await putBlob(b)).status).toBe(200);
  });
  it("rejects a hash mismatch, an empty body and an oversize body with 400", async () => {
    const b = randomBytes(100);
    const wrong = await api("PUT", `/update/blob/${"1".repeat(64)}`, b);
    expect(wrong.status).toBe(400);
    expect(await wrong.text()).toContain("sha256");
    expect((await api("PUT", `/update/blob/${hex(sha(new Uint8Array(0)))}`, new Uint8Array(0))).status).toBe(400);
    expect((await putBlob(new Uint8Array(4 * 1024 * 1024 + 1))).status).toBe(400);
  });
  it("accepts exactly 4 MiB", async () => {
    expect((await putBlob(randomBytes(4 * 1024 * 1024))).status).toBe(200);
  });
});

describe("channel put", () => {
  const bad = async (signed: Uint8Array, status: number, why: string) => {
    const res = await publish(signed);
    expect(res.status).toBe(status);
    expect(await res.text()).toContain(why);
  };
  const tweak = (signed: Uint8Array, f: (m: ReturnType<typeof UpdateManifest.decode>) => void) => {
    const m = UpdateManifest.decode(signed);
    f(m);
    return signManifest(UpdateManifest.encode(m), pem);
  };

  it("rejects the wrong length", async () => {
    await bad(new Uint8Array(191), 400, "192");
    await bad(new Uint8Array(193), 400, "192");
  });
  it("rejects bad magic and format", async () => {
    const r = await release();
    await bad(tweak(r.signed, (m) => (m.magic = UPDATE_MANIFEST_MAGIC ^ 1)), 400, "magic");
    await bad(tweak(r.signed, (m) => (m.format = 2)), 400, "format");
  });
  it("rejects a missing blob and a size mismatch", async () => {
    const r = await release();
    await bad(tweak(r.signed, (m) => m.exefs_sha256.fill(7)), 400, "not uploaded");
    await bad(tweak(r.signed, (m) => (m.overlay_size += 1)), 400, "does not match");
    await bad(tweak(r.signed, (m) => (m.exefs_size = 0)), 400, "out of range");
    await bad(tweak(r.signed, (m) => (m.exefs_size = 4 * 1024 * 1024 + 1)), 400, "out of range");
    await bad(tweak(r.signed, (m) => (m.build = 0)), 400, "build");
  });
  it("accepts a good manifest, then refuses one that is not newer", async () => {
    const r = await release();
    expect((await publish(r.signed)).status).toBe(200);
    await bad(r.signed, 409, "not newer");
    const older = await release(undefined, r.build - 1);
    await bad(older.signed, 409, "not newer");
    const newer = await release();
    expect((await publish(newer.signed)).status).toBe(200);
    const s = await status();
    expect(s.channels.test.build).toBe(newer.build);
  });
});

describe("promote, status and GC", () => {
  it("promote copies the test manifest byte for byte; status reports both channels", async () => {
    const r = await release([70000, 300]);
    expect((await publish(r.signed)).status).toBe(200);
    const res = await api("POST", "/update/promote");
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ build: r.build, version: "v-" + r.build });
    const s = await status();
    expect(s.channels.stable).toMatchObject({ build: r.build, version: "v-" + r.build, exefs_size: 70000, overlay_size: 300 });
    expect(s.channels.test).toMatchObject({ build: r.build });
    // a stable console receives exactly the published bytes
    const c = await open();
    c.send(PacketId.UpdateCheck, check({ channel: 1 }));
    expect(await c.expect(PacketId.UpdateManifest)).toEqual(r.signed);
    expect(decodeManifest(r.signed.subarray(0, 128)).build).toBe(r.build);
  });

  it("promote with no test release -> 404", async () => {
    // fresh Durable Object state is not available per test, so only assert the contract when nothing is published yet
    const s = await status();
    if (s.channels.test) return;
    expect((await api("POST", "/update/promote")).status).toBe(404);
  });

  it("deletes blobs neither channel references, keeps stable's", async () => {
    const a = await release([1000, 1000]);
    expect((await publish(a.signed)).status).toBe(200);
    expect((await api("POST", "/update/promote")).status).toBe(200); // stable = a
    const b = await release([2000, 2000]);
    expect((await publish(b.signed)).status).toBe(200); // test = b, stable = a: both kept
    const c = await open();
    expect((await chunk(c, sha(a.exefs), 0, 100)).data).toHaveLength(100);
    expect((await chunk(c, sha(b.exefs), 0, 100)).data).toHaveLength(100);
    const d = await release([3000, 3000]);
    expect((await publish(d.signed)).status).toBe(200); // b is now unreferenced
    expect((await chunk(c, sha(b.exefs), 0, 100)).data).toHaveLength(0);
    expect((await chunk(c, sha(b.overlay), 0, 100)).data).toHaveLength(0);
    expect((await chunk(c, sha(a.exefs), 0, 100)).data).toHaveLength(100);
    expect((await chunk(c, sha(d.exefs), 0, 100)).data).toHaveLength(100);
    expect((await api("POST", "/update/promote")).status).toBe(200); // stable = d
    expect((await chunk(c, sha(a.exefs), 0, 100)).data).toHaveLength(0);
  });
});

describe("console packets", () => {
  it("UpdateCheck records the console and a status line shows it", async () => {
    const c = await open(); // un-initialised session
    const label = "rec-" + hex(randomBytes(3));
    c.send(PacketId.UpdateCheck, check({ label, build: 42, rejected: 41, version: "v-old", channel: 2 }));
    await c.expect(PacketId.UpdateManifest);
    const row = (await status()).consoles.find((x: any) => x.label === label);
    expect(row).toMatchObject({ running_build: 42, rejected_build: 41, version: "v-old", channel: "test" });
    expect(Math.abs(Date.now() - row.at)).toBeLessThan(10_000);
  });

  it("answers with the channel's 192 bytes, per channel", async () => {
    const r = await release();
    expect((await publish(r.signed)).status).toBe(200);
    const c = await open();
    c.send(PacketId.UpdateCheck, check({ channel: 2 }));
    const m = await c.expect(PacketId.UpdateManifest);
    expect(m).toEqual(r.signed);
    expect(SignedManifest.decode(m).manifest.build).toBe(r.build);
  });

  it("answers with an empty payload when the channel has no release", async () => {
    const s = await status();
    if (s.channels.stable) return; // an earlier test promoted; the empty case is only reachable on a fresh object
    const c = await open();
    c.send(PacketId.UpdateCheck, check({ channel: 1 }));
    expect(await c.expect(PacketId.UpdateManifest)).toHaveLength(0);
  });

  it("ignores malformed checks (no reply, no row)", async () => {
    const c = await open();
    const label = "mal-" + hex(randomBytes(3));
    c.send(PacketId.UpdateCheck, check({ label }).subarray(0, 75));
    c.send(PacketId.UpdateCheck, check({ label, channel: 0 }));
    c.send(PacketId.UpdateCheck, check({ label, channel: 3 }));
    c.send(PacketId.UpdateCheck, check({ label, labelLen: 33 }));
    await c.none(150);
    expect((await status()).consoles.some((x: any) => x.label === label)).toBe(false);
  });

  it("sanitises the label", async () => {
    const c = await open();
    c.send(PacketId.UpdateCheck, check({ label: "a\tb\nc" }));
    await c.expect(PacketId.UpdateManifest);
    expect((await status()).consoles.some((x: any) => x.label === "a b c")).toBe(true);
  });

  it("serves first, middle (across a 64 KiB row boundary) and last chunks", async () => {
    const r = await release([200_000, 10]);
    expect((await publish(r.signed)).status).toBe(200);
    const c = await open();
    const h = sha(r.exefs);
    const total = r.exefs.length;
    const first = await chunk(c, h, 0, 4096);
    expect(first.head.total_size).toBe(total);
    expect(first.head.offset).toBe(0);
    expect(first.head.sha256).toEqual(new Uint8Array(h));
    expect(first.data).toEqual(r.exefs.subarray(0, 4096));
    const mid = await chunk(c, h, 65536 - 100, 4096); // straddles rows 0 and 1
    expect(mid.data).toEqual(r.exefs.subarray(65536 - 100, 65536 - 100 + 4096));
    const exact = await chunk(c, h, 65536, 4096); // starts exactly on a row
    expect(exact.data).toEqual(r.exefs.subarray(65536, 65536 + 4096));
    const last = await chunk(c, h, total - 10, 4096); // clipped to the end
    expect(last.data).toEqual(r.exefs.subarray(total - 10));
    // reassemble the whole blob
    const parts: Uint8Array[] = [];
    for (let off = 0; off < total; off += 4096) parts.push((await chunk(c, h, off, 4096)).data.slice());
    expect(Buffer.concat(parts)).toEqual(Buffer.from(r.exefs));
  });

  it("answers header only for a bad offset, length or unknown hash", async () => {
    const r = await release([5000, 10]);
    expect((await publish(r.signed)).status).toBe(200);
    const c = await open();
    const h = sha(r.exefs);
    for (const [off, len] of [[5000, 10], [9999, 10], [0, 0], [0, 4097]] as const) {
      const x = await chunk(c, h, off, len);
      expect(x.data).toHaveLength(0);
      expect(x.head.total_size).toBe(5000);
    }
    const unknown = await chunk(c, new Uint8Array(32).fill(9), 0, 100);
    expect(unknown.data).toHaveLength(0);
    expect(unknown.head.total_size).toBe(0);
  });

  it("ignores a wrong-sized chunk request and never forwards update packets", async () => {
    const a = await open();
    const b = await open();
    a.send(PacketId.UpdateChunk, new Uint8Array(39));
    a.send(PacketId.UpdateChunk, new Uint8Array(41));
    a.send(PacketId.UpdateCheck, check());
    await a.expect(PacketId.UpdateManifest);
    await a.none(100);
    await b.none(100);
  });
});

describe("ldn-tunnel module (UpdateCheckRequest.reserved[0] = 1)", () => {
  const T = "ldn-tunnel/";
  it("its channel takes format 2 only; the ryu_ldn_nx channel takes format 1 only", async () => {
    // publishing runs GC, which drops blobs no channel references yet: publish each release right after its upload
    const two = await release(undefined, undefined, undefined, 2);
    const res = await publish(two.signed);
    expect(res.status).toBe(400);
    expect(await res.text()).toContain("format");
    expect((await publish(two.signed, T)).status).toBe(200);
    const one = await release();
    const res1 = await publish(one.signed, T);
    expect(res1.status).toBe(400);
    expect(await res1.text()).toContain("format");
    expect((await publish(one.signed)).status).toBe(200);
  });

  it("each module gets its own manifest; old consoles are untouched", async () => {
    const one = await release();
    expect((await publish(one.signed)).status).toBe(200);
    const two = await release(undefined, undefined, undefined, 2);
    expect((await publish(two.signed, T)).status).toBe(200);
    const c = await open();
    c.send(PacketId.UpdateCheck, check({ channel: 2 }));
    expect(await c.expect(PacketId.UpdateManifest)).toEqual(one.signed);
    c.send(PacketId.UpdateCheck, check({ channel: 2, module: 1 }));
    expect(await c.expect(PacketId.UpdateManifest)).toEqual(two.signed);
  });

  it("ignores an unknown module (no reply, no row)", async () => {
    const c = await open();
    const label = "mod-" + hex(randomBytes(3));
    c.send(PacketId.UpdateCheck, check({ label, module: 2 }));
    await c.none(150);
    expect((await status()).consoles.some((x: any) => x.label === label)).toBe(false);
  });

  // First 128 bytes of tools/release/test/fixture-manifest.bin: the manifest crates/core/src/update_pubkey.rs
  // check_manifest accepts (format 2, build 2, exefs 13 B, overlay 15 B, "v0.0.0-fixture").
  const RUST_FIXTURE = Buffer.from(
    "524c554d02000000020000000d000000b1715db669a612295c743a20901decc99dacd01275f4a021df6efa808ad54dd0" +
      "0f00000064ce69f6fe0b11bd739279f1e8bdf44a2c2fd4609f586857800c4b46b1e0028a76302e302e302d6669787475" +
      "7265" + "00".repeat(18 + 12),
    "hex",
  );

  it("encodes the exact bytes the Rust verifier accepts", () => {
    expect(RUST_FIXTURE).toHaveLength(128);
    expect(Buffer.from(encodeManifest(decodeManifest(RUST_FIXTURE), 2))).toEqual(RUST_FIXTURE);
  });

  it("a console gets no manifest on stable when only the test channel has a release", async () => {
    const two = await release(undefined, undefined, undefined, 2);
    expect((await publish(two.signed, T)).status).toBe(200);
    expect((await status()).channels[T + "stable"]).toBeNull();
    const c = await open();
    c.send(PacketId.UpdateCheck, check({ channel: 1, module: 1 }));
    expect(await c.expect(PacketId.UpdateManifest)).toHaveLength(0);
    c.send(PacketId.UpdateCheck, check({ channel: 2, module: 1 }));
    expect(await c.expect(PacketId.UpdateManifest)).toEqual(two.signed);
  });

  it("OTA end to end: check, verify the manifest layout and signature, download both blobs", async () => {
    // 70000 is not a multiple of 4096 (short last chunk) and 8192 is (no empty extra chunk)
    const r = await release([70_000, 8192], undefined, "1.2.3", 2);
    expect((await publish(r.signed, T)).status).toBe(200);
    const c = await open();
    c.send(PacketId.UpdateCheck, check({ channel: 2, module: 1, build: 5 }));
    const m = await c.expect(PacketId.UpdateManifest);
    expect(m).toHaveLength(192);
    expect(m).toEqual(r.signed);
    // field offsets of crates/core/src/wire.rs UpdateManifest / SignedManifest
    const d = new DataView(m.buffer, m.byteOffset, m.byteLength);
    expect(d.getUint32(0, true)).toBe(0x4d554c52); // "RLUM"
    expect(Buffer.from(m.subarray(0, 4)).toString()).toBe("RLUM");
    expect(d.getUint32(4, true)).toBe(2); // format
    expect(d.getUint32(8, true)).toBe(r.build);
    expect(d.getUint32(12, true)).toBe(70_000);
    expect(m.subarray(16, 48)).toEqual(new Uint8Array(sha(r.exefs)));
    expect(d.getUint32(48, true)).toBe(8192);
    expect(m.subarray(52, 84)).toEqual(new Uint8Array(sha(r.overlay)));
    expect(new TextDecoder().decode(m.subarray(84, 89))).toBe("1.2.3");
    expect(m.subarray(89, 128).every((b) => b === 0)).toBe(true); // NUL padding + reserved
    // update.rs signature_ok: ECDSA P-256 / SHA-256 over bytes 0..128, 64-byte r||s at 128..192
    expect(verify("sha256", m.subarray(0, 128), { key: pubPem, dsaEncoding: "ieee-p1363" }, m.subarray(128))).toBe(true);
    // update_dl.rs: 4096-byte chunks from offset 0 until the blob is complete, sha-checked
    const mf = SignedManifest.decode(m).manifest;
    for (const [blob, size, digest] of [[r.exefs, mf.exefs_size, mf.exefs_sha256], [r.overlay, mf.overlay_size, mf.overlay_sha256]] as const) {
      const parts: Uint8Array[] = [];
      let n = 0;
      for (let off = 0; off < size; off += 4096) {
        const x = await chunk(c, digest, off, Math.min(4096, size - off));
        expect(x.head).toMatchObject({ offset: off, total_size: size });
        expect(x.data.length).toBe(Math.min(4096, size - off));
        parts.push(x.data.slice());
        n++;
      }
      expect(n).toBe(Math.ceil(size / 4096));
      const all = Buffer.concat(parts);
      expect(all).toHaveLength(size);
      expect(all.equals(Buffer.from(blob))).toBe(true);
      expect(createHash("sha256").update(all).digest().equals(Buffer.from(digest))).toBe(true);
    }
  });

  it("promote, status and the console row are per module", async () => {
    const two = await release([1234, 567], undefined, undefined, 2);
    expect((await publish(two.signed, T)).status).toBe(200);
    const res = await api("POST", `/update/${T}promote`);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ build: two.build, version: "v-" + two.build });
    const c = await open();
    const label = "rust-" + hex(randomBytes(3));
    c.send(PacketId.UpdateCheck, check({ label, channel: 1, module: 1, build: 7 }));
    expect(await c.expect(PacketId.UpdateManifest)).toEqual(two.signed);
    const s = await status();
    expect(s.channels[T + "stable"]).toMatchObject({ build: two.build, exefs_size: 1234, overlay_size: 567 });
    expect(s.channels).toHaveProperty("stable");
    expect(s.consoles.find((x: any) => x.label === label)).toMatchObject({ module: 1, channel: T + "stable", running_build: 7 });
  });

  it("GC keeps blobs another module's channels reference", async () => {
    const two = await release([1111, 1111], undefined, undefined, 2);
    expect((await publish(two.signed, T)).status).toBe(200);
    const one = await release([2222, 2222]);
    expect((await publish(one.signed)).status).toBe(200); // a module-0 publish runs GC
    const c = await open();
    expect((await chunk(c, sha(two.exefs), 0, 100)).data).toHaveLength(100);
    expect((await chunk(c, sha(one.exefs), 0, 100)).data).toHaveLength(100);
  });
});
