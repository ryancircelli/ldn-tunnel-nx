// Token checks. Tokens are 64 lowercase hex chars; only their SHA-256 is ever stored or compared.
import { hex, type Relay } from "./relay.ts";

const TOKEN = /^[0-9a-f]{64}$/;
const enc = new TextEncoder();

export const sha256Hex = async (s: string | Uint8Array) =>
  hex(new Uint8Array(await crypto.subtle.digest("SHA-256", typeof s === "string" ? enc.encode(s) : s)));

/** Constant-time compare of two hex digests. */
export const same = (a: string, b: string) => {
  const x = enc.encode(a), y = enc.encode(b.trim().toLowerCase());
  if (x.byteLength !== y.byteLength) return false;
  let d = 0;
  for (let i = 0; i < x.length; i++) d |= x[i] ^ y[i];
  return d === 0;
};

/** `Authorization: Bearer <token>` or "". */
export const bearer = (req: Request) => {
  const auth = req.headers.get("Authorization") ?? "";
  return auth.startsWith("Bearer ") ? auth.slice(7) : "";
};

/** Index of the secret (lowercase hex SHA-256) that sha256(token) equals, or -1. No early exit. */
async function matchIndex(token: string, secrets: unknown[]): Promise<number> {
  if (!TOKEN.test(token)) return -1;
  const got = await sha256Hex(token);
  let hit = -1;
  secrets.forEach((secret, i) => {
    if (typeof secret === "string" && same(got, secret) && hit < 0) hit = i;
  });
  return hit;
}

/** True when sha256(token) equals one of the secrets (the release API's UPDATE_ADMIN). */
export const isAdmin = async (token: string, secrets: unknown[]) => (await matchIndex(token, secrets)) >= 0;

/**
 * Which console a token belongs to: "env:<NAME>" for a TOKEN_* secret (the hash set at deploy time),
 * "c:<id>" for a per-console token minted by an invite, null for anything else.
 */
export async function whoIs(r: Relay, token: string): Promise<string | null> {
  const env = Object.entries(r.host.env).filter(([name]) => name.startsWith("TOKEN_"));
  const i = await matchIndex(token, env.map(([, v]) => v));
  if (i >= 0) return "env:" + env[i][0];
  if (!TOKEN.test(token)) return null;
  // ponytail: an indexed lookup, not constant time; it reveals only whether a hash of 256 random bits exists
  const row = r.sql.exec<{ id: string }>("SELECT id FROM tokens WHERE hash = ?", await sha256Hex(token))[0];
  return row ? "c:" + row.id : null;
}
