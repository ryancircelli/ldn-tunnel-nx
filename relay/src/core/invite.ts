// Invite links: /invite/<token>, one-time, 24 h. GET shows a page with a download button (link previews in
// chat apps only GET, so they never use the invite up); POST consumes it, mints the console's token and
// answers the SD card zip. Only SHA-256 hashes of invite and console tokens are stored.
import { zipSync } from "fflate";
import { sha256Hex } from "./auth.ts";
import { SignedManifest } from "./codec/types.ts";
import { ensureInstalled } from "./release.ts";
import { RELEASE_CHANNEL, hex, notFound, oneLine, randomHex, type Relay } from "./relay.ts";

const PROGRAM_ID = "420000004C444E54"; // crates/core/src/ident.rs PROGRAM_ID_HEX
const INVITE_TTL = 86400_000;

const esc = (s: unknown) => String(s ?? "").replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
export const cleanName = (s: unknown) => oneLine(typeof s === "string" ? s : "").slice(0, 32);

const page = (status: number, body: string) =>
  new Response(
    `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ldn-tunnel</title>
<style>body{font:17px/1.5 system-ui,sans-serif;max-width:34rem;margin:0 auto;padding:1rem;color:#111;background:#fff}
@media (prefers-color-scheme:dark){body{color:#eee;background:#16181c}}button{font:inherit;padding:.6rem 1.2rem}</style>
</head><body>${body}</body></html>`,
    { status, headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", "x-frame-options": "DENY", "referrer-policy": "no-referrer",
      "x-content-type-options": "nosniff", "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'" } },
  );

/** Creates an invite; returns its link and expiry. */
export async function createInvite(r: Relay, origin: string, name: string) {
  const token = randomHex(32);
  const expiresAt = Date.now() + INVITE_TTL;
  r.sql.exec("INSERT INTO invites (hash, name, expires) VALUES (?, ?, ?)", await sha256Hex(token), cleanName(name) || "console", expiresAt);
  return { url: `${origin}/invite/${token}`, expiresAt };
}

export async function invite(r: Relay, req: Request, token: string): Promise<Response> {
  const gone = () => page(404, "<h1>Invite not valid</h1><p>This link was already used or has expired. Ask for a new one.</p>");
  if (!/^[0-9a-f]{64}$/.test(token)) return notFound();
  const hash = await sha256Hex(token);
  const find = () => r.sql.exec<{ name: string }>("SELECT name FROM invites WHERE hash = ? AND expires > ?", hash, Date.now())[0];
  if (req.method === "GET") {
    const inv = find();
    if (!inv) return gone();
    return page(200, `<h1>ldn-tunnel for ${esc(inv.name)}</h1>
<p>This link works once. Download the file, unzip it, and copy everything inside to the root of your Switch's SD card
(merge the folders). Then restart the Switch.</p>
<form method="post"><button>Download for my Switch</button></form>`);
  }
  if (req.method !== "POST") return notFound();
  if (!find()) return gone();
  try {
    await ensureInstalled(r);
  } catch (e) {
    return page(503, `<h1>Not ready yet</h1><p>The relay could not get the console files (${esc((e as Error).message)}). The link still works: try again later.</p>`);
  }
  const consoleToken = randomHex(32);
  const tokenHash = await sha256Hex(consoleToken);
  // No await from here to the end of the transaction: the invite is consumed exactly once.
  const used = r.sql.tx(() => {
    const row = r.sql.exec<{ name: string }>("DELETE FROM invites WHERE hash = ? AND expires > ? RETURNING name", hash, Date.now())[0];
    if (row) r.sql.exec("INSERT INTO tokens (id, hash, name, created) VALUES (?, ?, ?, ?)", randomHex(4), tokenHash, row.name, Date.now());
    return row;
  });
  if (!used) return gone();
  return new Response(consoleZip(r, new URL(req.url), used.name, consoleToken), {
    headers: { "content-type": "application/zip", "content-disposition": 'attachment; filename="ldn-tunnel-sd.zip"', "cache-control": "no-store" },
  });
}

/** The SD card files for one console. */
function consoleZip(r: Relay, url: URL, name: string, token: string): Uint8Array {
  // the owner's relay may publish its own ldn-tunnel stable channel; everyone else serves the installed release
  const signed = r.manifestOf("ldn-tunnel/stable") ?? r.manifestOf(RELEASE_CHANNEL);
  if (!signed) throw new Error("no console files installed");
  const m = SignedManifest.decode(signed).manifest;
  const exefs = r.blob(hex(m.exefs_sha256));
  const overlay = r.blob(hex(m.overlay_sha256));
  if (!exefs || !overlay) throw new Error("console files missing from storage");
  const enc = (s: string) => new TextEncoder().encode(s);
  const port = url.port && url.port !== "443" ? `port = ${url.port}\n` : ";port = 443\n";
  const config = `; ldn-tunnel config for "${oneLine(name)}". Contains this console's secret relay token:
; never share or post this file. Lines starting with ; are comments.

[server]
; Your relay.
host = ${url.hostname}
${port}token = ${token}
;path = /ldn
ca_file = sdmc:/config/ldn-tunnel/ca.pem

[update]
; stable (default) or off.
;channel = stable
`;
  const dir = `atmosphere/contents/${PROGRAM_ID}/`;
  // level 0: the files are already compressed or small, and CPU time is what the platforms bill
  return zipSync(
    {
      [dir + "exefs.nsp"]: exefs,
      [dir + "flags/boot2.flag"]: new Uint8Array(0),
      [dir + "toolbox.json"]: enc(JSON.stringify({ name: "ldn-tunnel", tid: "0x" + PROGRAM_ID, requires_reboot: true }, null, 4) + "\n"),
      "switch/.overlays/ldn-tunnel.ovl": overlay,
      "config/ldn-tunnel/config.ini": enc(config),
      "config/ldn-tunnel/ca.pem": enc(r.host.assets.ca),
      "config/ldn-tunnel/gamelist.txt": enc(r.host.assets.gamelist),
    },
    { level: 0 },
  );
}
