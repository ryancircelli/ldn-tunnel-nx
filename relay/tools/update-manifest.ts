/// <reference types="node" />
// Release manifest encode/sign/decode, shared by the release CLI and the tests.
import { sign } from "node:crypto";
import {
  SignedManifest, UPDATE_MANIFEST_FORMAT, UPDATE_MANIFEST_MAGIC, UpdateManifest,
} from "../src/core/codec/types.ts";

interface Release {
  build: number;
  version: string;
  exefs: { size: number; sha256: Uint8Array };
  overlay: { size: number; sha256: Uint8Array };
}

/** The modules the relay serves: UpdateCheckRequest.reserved[0], channel prefix, manifest format. */
const MODULES = {
  "ryu_ldn_nx": { id: 0, prefix: "", format: UPDATE_MANIFEST_FORMAT },
  "ldn-tunnel": { id: 1, prefix: "ldn-tunnel/", format: 2 },
} as const;
type ModuleName = keyof typeof MODULES;

/** `--module` value -> module; throws on anything else. */
export function moduleOf(name = "ryu_ldn_nx") {
  if (!(name in MODULES)) throw new Error(`--module must be one of ${Object.keys(MODULES).join(", ")}`);
  return MODULES[name as ModuleName];
}

/** The 128 signed bytes. */
export function encodeManifest(r: Release, format: number = UPDATE_MANIFEST_FORMAT): Uint8Array {
  return UpdateManifest.encode({
    magic: UPDATE_MANIFEST_MAGIC,
    format,
    build: r.build,
    exefs_size: r.exefs.size,
    exefs_sha256: r.exefs.sha256,
    overlay_size: r.overlay.size,
    overlay_sha256: r.overlay.sha256,
    version: new TextEncoder().encode(r.version), // NUL-padded, cut at 32
    reserved: new Uint8Array(12),
  });
}

/** 128 manifest bytes + ECDSA P-256/SHA-256 signature (r || s) = 192 bytes. */
export function signManifest(manifest: Uint8Array, privateKeyPem: string): Uint8Array {
  const sig = sign("sha256", manifest, { key: privateKeyPem, dsaEncoding: "ieee-p1363" });
  return SignedManifest.encode({ manifest: UpdateManifest.decode(manifest), signature: new Uint8Array(sig) });
}

export function decodeManifest(bytes: Uint8Array): Release {
  const m = UpdateManifest.decode(bytes);
  const end = m.version.indexOf(0);
  return {
    build: m.build,
    version: new TextDecoder().decode(end < 0 ? m.version : m.version.subarray(0, end)),
    exefs: { size: m.exefs_size, sha256: m.exefs_sha256 },
    overlay: { size: m.overlay_size, sha256: m.overlay_sha256 },
  };
}
