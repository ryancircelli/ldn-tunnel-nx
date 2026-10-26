// The admin page: one self-contained HTML string, served at GET /admin (it holds no secrets; the /api/*
// routes it calls are cookie-gated). Works on Workers and Node alike: no fs, no eval.
// The relay must send adminCsp() with it: the page's one script and one style are allowed by hash, so an
// injected inline script or event handler never runs even if some value escaped the escaping.
import { APP_SRC } from "./app.ts";
import { LOGIC_SRC } from "./logic.ts";
import { STYLE } from "./style.ts";

const SCRIPT = LOGIC_SRC + APP_SRC;
const b64sha = async (s: string) =>
  btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s)))));
let csp: Promise<string> | undefined;
export const adminCsp = () =>
  (csp ??= Promise.all([b64sha(SCRIPT), b64sha(STYLE)]).then(
    ([js, css]) =>
      `default-src 'none'; script-src 'sha256-${js}'; style-src 'sha256-${css}'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`,
  ));

export function adminPage(): string {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark"><title>ldn-tunnel relay</title><style>${STYLE}</style></head><body>
<h1>ldn-tunnel relay</h1>
<section id="login" hidden><form id="login-form"><p>Admin secret</p>
<input type="password" id="secret" autocomplete="current-password" required> <button type="submit">Sign in</button>
<p class="err" id="lerr"></p></form></section>
<main id="dash" hidden>
<h2>Release</h2><div class="card"><div id="rel-text">Loading...</div>
<div class="acts"><button id="btn-update" hidden>Update</button> <button id="btn-rollback" hidden>Roll back</button></div>
<div id="cmd-box" hidden><p class="muted">Run this on the relay host:</p><code class="cmd" id="cmd"></code><button id="copy-cmd">Copy</button></div>
<p class="err" id="rel-err"></p></div>
<h2>Consoles</h2><div id="consoles"></div><p class="err" id="cerr"></p>
<h2>Invite a console</h2><div class="card"><input type="text" id="inv-name" placeholder="Name (optional)" maxlength="32"> <button id="btn-invite">Create invite link</button>
<div id="inv-out" hidden><code class="link" id="link"></code><button id="copy-link">Copy</button><p class="muted" id="inv-hint"></p></div>
<p class="err" id="ierr"></p></div>
</main>
<script>${SCRIPT}</script></body></html>`;
}
