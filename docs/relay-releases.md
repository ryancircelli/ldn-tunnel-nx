# Relay releases and update channels

How a relay gets the console files it serves, and how the publisher's CI must build a release so relays
accept it. Code: `relay/src/core/release.ts`, `relay/src/core/relay.ts` (channels),
`relay/src/cloudflare/lobby.ts` (self-update). Hosting facts: [relay-hosting.md](relay-hosting.md).

## Update channels per module

`UpdateCheckRequest.reserved[0]` names the module that is asking. The C++ module always sends 0.

| Module | id | Channel rows | Manifest format |
|---|---|---|---|
| ryu_ldn_nx (C++) | 0 | `stable`, `test` (unchanged) | 1 |
| ldn-tunnel | 1 | `ldn-tunnel/stable`, `ldn-tunnel/test`, then `ldn-tunnel/release` | 2 |

- A check from an unknown module id is ignored, the same as an unknown channel.
- For ldn-tunnel, a channel the owner published by hand (`npm run release -- --module ldn-tunnel`)
  wins. Otherwise the relay serves `ldn-tunnel/release`: the console files of its own pinned release.
- Owner routes, with the `UPDATE_ADMIN` bearer:
  - `PUT /update/channel/test` and `POST /update/promote`;
  - `PUT /update/ldn-tunnel/channel/test` and `POST /update/ldn-tunnel/promote`;
  - `GET /update/status` lists every channel.
- The blob GC keeps any blob that some channel row still references. Publish right after each upload:
  an upload that is not yet published is collected by the next publish.

## What a relay trusts

`relay/release.json` is `{"repo": "ryancircelli/ldn-tunnel-nx", "tag": "v<semver>"}`. It is the release this
relay code *is*: bump it in the commit you tag (CI refuses a tag that differs). Deploy-button copies of
`main` read it too, and fail to install console files until that release is published. A relay serves the console files of that tag, and
nothing else, unless the owner publishes a channel. It downloads them on first need: the first admin
release view, the first ldn-tunnel update check, or the first invite.

All files come from `https://github.com/<repo>/releases/download/<tag>/<asset>`, or
`…/releases/latest/download/…` for "latest" (no GitHub API, no rate limit). Each must pass:

1. `release.sig`: 64 bytes, ECDSA P-256 / SHA-256 over the exact bytes of `release.json`, raw r‖s. It is
   checked against the publisher key, a 65-byte point (`04‖X‖Y`) given in hex in
   `relay/src/core/publisher_key.ts`. The env `PUBLISHER_KEY` overrides it, for forks and tests.
2. `release.json`: `{"version": "v1.2.3", "build": <n>, "assets": {"<name>": {"sha256": "<hex>",
   "size": <n>}}}`. The version, with or without its leading `v`, must equal the tag that was asked for.
3. Every asset fetched must match its `sha256` and `size` in `release.json`.
4. `manifest.bin` is 192 bytes, with magic `RLUM`, format 2, build ≥ 1. Its own signature, made with the
   same key, covers its first 128 bytes. It must name exactly `exefs.nsp` and `ldn-tunnel.ovl` (size +
   SHA-256). The console checks this signature again with its compiled-in key (`LDNT_UPDATE_PUBKEY`,
   `crates/sys/src/update_io.rs`), which CI takes from `publisher_key.ts`.

`relay-cloudflare.zip` is fetched only by `POST /api/update` on Cloudflare. It holds the output of
`wrangler deploy --dry-run` and `metadata.json`:

- the output is `worker.js`, `worker.js.map`, and the hashed `*-ca.pem` and `*-gamelist.txt` text modules;
- `metadata.json` is `{"main_module": "worker.js", "compatibility_date": "…"}`.

The adapter uploads every file in the zip as a module. From `metadata.json` it reads only `main_module`,
`compatibility_date` and `compatibility_flags`; it adds the bindings and `keep_bindings` itself. Extra
keys, such as `migrations`, are ignored. A version upload cannot run migrations anyway
(relay-hosting.md).

## CI steps (tag `v<semver>`, `.github/workflows/release.yml`)

The private key is the GitHub Actions secret `PUBLISHER_KEY`. Its public half is committed as
`relay/src/core/publisher_key.ts`, the single source for both the relay and the console. The signing tool
is `tools/release` (Rust, package `ldn-tunnel-release`: `gen-key`, `sign-manifest`, `release-json`, `verify`). No workflow deploys a relay.

1. **Check the pin:** `relay/release.json` must be `{repo: <this repository>, tag: <the pushed tag>}`.
2. **Build the module** with `LDNT_UPDATE_PUBKEY` = the point in `publisher_key.ts` (refused if it is the
   test fixture), `LDNT_VERSION` = the tag and `LDNT_BUILD` = the run's unix time; `make nsp`.
3. **Build the overlay** (`make overlay-rs`, then `make -C overlay` in `devkitpro/devkita64`) and **the Worker**
   (`cd relay && npm ci && npm test && npm run bundle -- --out relay-cloudflare.zip`). Use the bundle script,
   not a hand-made zip: Wrangler names the entry module `worker.js` and the two text modules must be in it.
4. **Sign:** `sign-manifest --build <LDNT_BUILD of step 2>` (format 2) → `manifest.bin`; then
   `release-json` → `release.json` + `release.sig`. The console installs only a build higher than its own,
   and only if the manifest's build is the one compiled into the exefs.
5. **Verify** against `publisher_key.ts`. A `PUBLISHER_KEY` secret that is not that key fails here instead of
   on users' relays and consoles.
6. **SD-card zip:** `make dist` → `ldn-tunnel-<version>.zip` (module, overlay, `config.ini` template,
   `gamelist.txt`, `ca.pem`), for installs without an invite.
7. **Draft release** `v<semver>` with `release.json`, `release.sig`, `manifest.bin`, `exefs.nsp`,
   `ldn-tunnel.ovl`, `relay-cloudflare.zip` and the SD-card zip. The owner publishes it by hand; it must
   be *published*, and not a pre-release, for `latest/download` to resolve.
8. **Docker image** `ghcr.io/<owner>/ldn-tunnel-relay:v<semver>` and `:latest`.
