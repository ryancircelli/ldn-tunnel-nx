// The admin JSON API behind the static admin page (docs/CONTRACTS.md). Auth: POST /admin/login {secret}
// sets an HttpOnly SameSite=Strict session cookie; every /api/* call needs that cookie or
// `Authorization: Bearer <ADMIN secret>`. The ADMIN secret is compared as SHA-256 digests.
import { adminPage, adminCsp } from "./admin/index.ts";
import { same, sha256Hex } from "./auth.ts";
import { createInvite, cleanName } from "./invite.ts";
import { PIN, ensureInstalled, installed, latest, tagOf, update } from "./release.ts";
import { listDrops } from "./drops.ts";
import { notFound, randomHex, text, type Relay, type Session } from "./relay.ts";

const COOKIE = "ldnt_admin";
const SESSION_TTL = 30 * 86400_000;
const MAX_BODY = 16 << 10;
/** The example files' values: a relay still using one has no admin surface until the owner sets their own. */
const PLACEHOLDERS = new Set(["change-me", "choose-a-long-password"]);
const json = (v: unknown, status = 200, headers: Record<string, string> = {}) =>
  Response.json(v, { status, headers: { "cache-control": "no-store", "x-content-type-options": "nosniff", ...headers } });
const fail = (status: number, error: string, headers?: Record<string, string>) => json({ error }, status, headers);

// Failed ADMIN-secret checks (login and bearer), per client and relay-wide. Past `free` failures each
// further one doubles the wait, 1 s up to 15 min; a success, or an hour with no failure, clears the count.
// On Cloudflare the client is CF-Connecting-IP (IPv6 by /64); on Node the socket peer, or with
// TRUST_PROXY=1 (Docker behind Caddy) the last X-Forwarded-For hop. A spoofed or rotated address (a
// TRUST_PROXY relay reachable without Caddy) only reaches the relay-wide limit, which also locks the owner out of new logins while it lasts (sessions keep working).
// ponytail: in memory, so a restart or Durable Object eviction resets it; persist it if that is ever abused.
const CLIENT_FREE = 10, GLOBAL_FREE = 1000, MAX_WAIT = 900_000;
const fails = new Map<string, { n: number; until: number; last: number }>();
const v6prefix = (ip: string) => {
  ip = ip.replace(/^::ffff:(?=\d+\.)/i, ""); // IPv4-mapped (Node's dual-stack peer address)
  if (!ip.includes(":")) return ip;
  const [a, b = ""] = ip.split("::");
  const head = a ? a.split(":") : [], tail = b ? b.split(":") : [];
  return [...head, ...Array(Math.max(0, 8 - head.length - tail.length)).fill("0"), ...tail].slice(0, 4).join(":") + "::/64";
};
const clientKey = (r: Relay, req: Request) =>
  "ip:" + v6prefix(r.host.platform === "cloudflare"
    ? req.headers.get("cf-connecting-ip") ?? ""
    : (req.headers.get("x-forwarded-for") ?? "").split(",").pop()!.trim());
/** Milliseconds this client must wait before its next secret check (0: go ahead). */
const waitFor = (key: string, now = Date.now()) =>
  Math.max(0, (fails.get(key)?.until ?? 0) - now, (fails.get("*")?.until ?? 0) - now);
function failed(key: string, free: number, now = Date.now()) {
  if (fails.size > 10_000) fails.forEach((f, k) => f.until < now && k !== "*" && fails.delete(k));
  const f = fails.get(key) ?? { n: 0, until: 0, last: now };
  if (now - f.last > 3600_000) f.n = 0; // an hour without a failure forgives the count
  f.last = now;
  if (++f.n > free) f.until = now + Math.min(1000 * 2 ** (f.n - free - 1), MAX_WAIT);
  fails.set(key, f);
}

/** Checks the ADMIN secret under the attempt limit: true, false, or a 429 to answer. */
async function secretMatches(r: Relay, req: Request, given: unknown): Promise<boolean | Response> {
  const key = clientKey(r, req);
  const wait = waitFor(key);
  if (wait > 0) return fail(429, `too many wrong attempts; try again in ${Math.ceil(wait / 1000)} s`, { "retry-after": String(Math.ceil(wait / 1000)) });
  const secret = r.host.env.ADMIN as string;
  const ok = typeof given === "string" && !!given && same(await sha256Hex(given), await sha256Hex(secret));
  if (ok) fails.delete(key);
  else (failed(key, CLIENT_FREE), failed("*", GLOBAL_FREE));
  return ok;
}

/** Session rows hold sha256(cookie + ADMIN): changing the ADMIN secret signs every session out. */
const sessionHash = (r: Relay, token: string) => sha256Hex(token + "\n" + (r.host.env.ADMIN as string));

async function authed(r: Relay, req: Request): Promise<boolean | Response> {
  const auth = req.headers.get("Authorization") ?? "";
  if (auth.startsWith("Bearer ")) return secretMatches(r, req, auth.slice(7));
  const cookie = /(?:^|;\s*)ldnt_admin=([0-9a-f]{64})/.exec(req.headers.get("Cookie") ?? "")?.[1];
  if (!cookie) return false;
  return r.sql.exec("SELECT 1 FROM admin_sessions WHERE hash = ? AND expires > ?", await sessionHash(r, cookie), Date.now()).length > 0;
}

/** The request body (JSON or form), at most MAX_BODY bytes; throws past that. */
async function body(req: Request): Promise<Record<string, unknown>> {
  const chunks: Uint8Array[] = [];
  let n = 0;
  const reader = req.body?.getReader();
  while (reader) {
    const { done, value } = await reader.read();
    if (done) break;
    if ((n += value.length) > MAX_BODY) {
      reader.cancel().catch(() => {});
      throw new Error("request body too large");
    }
    chunks.push(value);
  }
  const r = new Response(new Blob(chunks), { headers: { "content-type": req.headers.get("content-type") ?? "" } });
  if (req.headers.get("content-type")?.includes("application/json")) return ((await r.json().catch(() => ({}))) ?? {}) as Record<string, unknown>;
  return Object.fromEntries(await r.formData().catch(() => new FormData()));
}

/** /admin, /admin/login and /api/*. A relay without the ADMIN secret has no admin surface (404). */
export async function adminApi(r: Relay, req: Request): Promise<Response> {
  const secret = r.host.env.ADMIN;
  if (typeof secret !== "string" || !secret) return notFound();
  if (PLACEHOLDERS.has(secret.trim())) return text(503, "The ADMIN secret is still the example value. Set your own long password as ADMIN, then reload.");
  const url = new URL(req.url);
  const path = url.pathname;
  const m = req.method;
  // the session cookie is SameSite=Strict; refuse cross-site writes outright as well
  const origin = req.headers.get("Origin");
  if (m !== "GET" && origin && origin !== url.origin) return fail(403, "cross-site request refused");

  if (path === "/admin" && m === "GET") {
    return new Response(adminPage(), {
      headers: {
        "content-type": "text/html; charset=utf-8", "cache-control": "no-store", "x-frame-options": "DENY",
        "x-content-type-options": "nosniff", "referrer-policy": "no-referrer", "content-security-policy": await adminCsp(),
      },
    });
  }
  if (path === "/admin/login" && m === "POST") {
    if (waitFor(clientKey(r, req)) > 0) return (await secretMatches(r, req, "")) as Response; // the 429, before reading the body
    let given: unknown;
    try {
      given = (await body(req)).secret;
    } catch {
      return fail(413, "request body too large");
    }
    const ok = await secretMatches(r, req, given);
    if (ok instanceof Response) return ok;
    if (!ok) return fail(401, "wrong secret");
    const token = randomHex(32);
    r.sql.exec("DELETE FROM admin_sessions WHERE expires <= ?", Date.now());
    r.sql.exec("INSERT INTO admin_sessions (hash, expires) VALUES (?, ?)", await sessionHash(r, token), Date.now() + SESSION_TTL);
    return new Response(null, {
      status: 204,
      headers: { "Set-Cookie": `${COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_TTL / 1000}` },
    });
  }
  if (!path.startsWith("/api/")) return notFound();
  const ok = await authed(r, req);
  if (ok instanceof Response) return ok;
  if (!ok) return fail(401, "login required");

  let a: RegExpMatchArray | null;
  try {
    if (path === "/api/consoles" && m === "GET") return json(consoles(r));
    if ((a = path.match(/^\/api\/consoles\/([^/]+)\/revoke$/)) && m === "POST") return revoke(r, decodeURIComponent(a[1]));
    if ((a = path.match(/^\/api\/consoles\/([^/]+)$/)) && m === "PATCH") return rename(r, decodeURIComponent(a[1]), (await body(req)).name);
    if ((a = path.match(/^\/api\/consoles\/([^/]+)\/logs$/)) && m === "GET") return logs(r, decodeURIComponent(a[1]), url.searchParams.get("limit"));
    if (path === "/api/drops" && m === "GET") return json(listDrops(r.sql, Number(url.searchParams.get("limit")) || undefined));
    if (path === "/api/invites" && m === "POST") return json(await createInvite(r, url.origin, cleanName((await body(req)).name)));
    if (path === "/api/release" && m === "GET") return json(await release(r));
    if (path === "/api/update" && m === "POST") {
      const v = (await body(req)).version;
      const tag = typeof v === "string" && v ? tagOf(v) : (await latest(r))?.tag;
      if (!tag) return fail(502, "could not find the latest release");
      await update(r, tag);
      return json({ ok: true, version: tag.slice(1) });
    }
    if (path === "/api/rollback" && m === "POST") {
      if (!r.host.deployer) return fail(400, "this relay cannot roll itself back");
      return json({ ok: true, versionId: await r.host.deployer.rollback() });
    }
  } catch (e) {
    const msg = (e as Error).message;
    return fail(msg === "request body too large" ? 413 : 502, msg);
  }
  return notFound();
}

/** Console ids: an invite-minted token's id, or "env:<TOKEN_NAME>" for a deploy-time TOKEN_* secret. */
function consoles(r: Relay) {
  const online = new Map<string, number>();
  for (const ws of r.host.conns()) {
    const who = ws.load<Session>()?.who;
    if (who) online.set(who, (online.get(who) ?? 0) + 1);
  }
  const seen = new Map(
    r.sql.exec<{ who: string; at: number; version: string; running_build: number; rejected_build: number }>("SELECT * FROM seen").map((s) => [s.who, s]),
  );
  const row = (who: string, id: string, name: string) => {
    const s = seen.get(who);
    return {
      id, name, version: s?.version ?? null, runningBuild: s?.running_build ?? null, online: (online.get(who) ?? 0) > 0,
      lastSeen: s?.at ?? null, rejectedBuild: s?.rejected_build || null,
    };
  };
  return [
    ...r.sql.exec<{ id: string; name: string }>("SELECT id, name FROM tokens ORDER BY created").map((t) => row("c:" + t.id, t.id, t.name)),
    ...Object.entries(r.host.env)
      .filter(([k, v]) => k.startsWith("TOKEN_") && typeof v === "string" && v.trim())
      .map(([k]) => row("env:" + k, "env:" + k, k)),
  ];
}

function revoke(r: Relay, id: string): Response {
  if (id.startsWith("env:")) return fail(400, `delete the ${id.slice(4)} secret to revoke it`);
  if (!r.sql.exec("DELETE FROM tokens WHERE id = ? RETURNING id", id).length) return fail(404, "no such console");
  r.sql.exec("DELETE FROM seen WHERE who = ?", "c:" + id);
  r.sql.exec("DELETE FROM console_status WHERE who = ?", "c:" + id);
  r.kick("c:" + id);
  return json({ ok: true });
}

function rename(r: Relay, id: string, name: unknown): Response {
  const n = cleanName(name);
  if (!n) return fail(400, "name must not be empty");
  if (id.startsWith("env:")) return fail(400, "deploy-time tokens are named by their secret");
  if (!r.sql.exec("UPDATE tokens SET name = ? WHERE id = ? RETURNING id", n, id).length) return fail(404, "no such console");
  return json({ ok: true, name: n });
}

function logs(r: Relay, id: string, limit: string | null): Response {
  const who = id.startsWith("env:") ? id : "c:" + id;
  const n = Math.min(Math.max(Math.floor(Number(limit)) || 200, 1), 2000);
  const rows = r.sql.exec<{ at: number; label: string; text: string }>("SELECT at, label, text FROM logs WHERE who = ? ORDER BY id DESC LIMIT ?", who, n);
  const lines = rows.reverse().flatMap((l) => l.text.split("\n").map((line) => ({ at: l.at, line })));
  return json(lines.slice(-n));
}

async function release(r: Relay) {
  let error: string | undefined;
  await ensureInstalled(r).catch((e: Error) => (error = e.message));
  const l = await latest(r);
  const docker = r.host.platform === "docker";
  return {
    deployed: { version: PIN.tag.slice(1), build: installed(r)?.build ?? null },
    latest: l && { version: l.tag.slice(1), build: l.build, url: `https://github.com/${PIN.repo}/releases/tag/${l.tag}` },
    platform: r.host.platform,
    canSelfUpdate: !!r.host.deployer,
    updateCommand: docker ? "docker compose pull && docker compose up -d" : undefined,
    installError: error,
  };
}
