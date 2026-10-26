# Hosting and updating a relay

Each friend group runs its own relay: on Cloudflare (Deploy button, free plan) or with Docker. The
user-facing steps are in `relay/README.md`. This page records the platform facts those steps depend on,
with the source of each one. Facts were checked on 2026-10-24. Items marked *inferred* are not stated
outright in the source.

## Deploy button

- The button **clones** the repository into the user's GitHub or GitLab account. It does not fork it.
  The copy has no upstream link, so GitHub's "Sync fork" is not available for it. The source repository
  must be public.
  <https://developers.cloudflare.com/workers/platform/deploy-buttons/>
- A subdirectory URL deploys only that folder, and the folder becomes the root of the new repository.
  The app must be self-contained in it (relay/ is). Syntax, *inferred* from the page's monorepo example:
  `https://deploy.workers.cloudflare.com/?url=https://github.com/<owner>/<repo>/tree/<branch>/relay`
  (same page).
- The button sets up Workers Builds on the new repository: each push to its production branch builds
  and deploys. The deploy command defaults to `npx wrangler deploy`, and the `build`/`deploy` scripts in
  `package.json` are used if present.
  <https://developers.cloudflare.com/workers/ci-cd/builds/>
- Secrets and variables are asked for during setup. Their names come from `.dev.vars.example` (or
  `.env.example`), and their descriptions from `cloudflare.bindings` in `package.json`. The user can
  rename the Worker on that form. The page does not say which file wins when both exist, so `relay/` has
  only `.dev.vars.example`; the Docker example is `docker.env.example`.
  <https://developers.cloudflare.com/changelog/post/2025-07-01-workers-deploy-button-supports-environment-variables-and-secrets/>
- GitHub's sync for real forks, for contrast:
  <https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/working-with-forks/syncing-a-fork>

## Free plan limits that matter

- Durable Objects on Workers Free: SQLite-backed classes only (ours is `new_sqlite_classes`),
  100,000 requests a day, 5 GB of storage.
  <https://developers.cloudflare.com/durable-objects/platform/pricing/>
- Workers Free: 10 ms of CPU per request, 50 subrequests per request, and a 64 MiB Worker size limit
  (uncompressed; the page says there is no compressed limit).
  <https://developers.cloudflare.com/workers/platform/limits/>
  Because of the CPU limit, the Worker only forwards requests. Downloads, hashing, signature checks and
  zipping all happen in the Durable Object. *Not measured:* how much CPU an install or an invite zip
  uses on a deployed free-plan relay. Zips are stored, not compressed, to keep that cost low.

## One-click update from the admin page (Cloudflare)

The relay replaces its own code through the Cloudflare API. This needs two secrets the user enters on
the Deploy form, `CF_API_TOKEN` and `CF_ACCOUNT_ID`, plus the variable `CF_WORKER_NAME`
(`wrangler.toml` sets it to `ldn-tunnel`).

- **Token.** "Workers Scripts Write" at account level, or "Workers Scripts Edit" in the dashboard's
  wording. The narrowest option is the per-Worker role "Individual Workers Editor".
  <https://developers.cloudflare.com/workers/authorization/workers/>
  A link can pre-fill the token form (`permissionGroupKeys=[{"key":"workers_scripts","type":"edit"}]`).
  The README links to:
  `https://dash.cloudflare.com/?to=/:account/api-tokens&permissionGroupKeys=%5B%7B%22key%22%3A%22workers_scripts%22%2C%22type%22%3A%22edit%22%7D%5D&name=ldn-tunnel%20relay`
  <https://developers.cloudflare.com/fundamentals/api/how-to/account-owned-token-template/>
  Account-owned tokens work for Workers:
  <https://developers.cloudflare.com/fundamentals/api/get-started/account-owned-tokens/>
- **The account id and Worker name must be entered by the user.** A Worker cannot read them at runtime.
  The version metadata binding exposes only `id`, `tag` and `timestamp`.
  <https://developers.cloudflare.com/workers/runtime-apis/bindings/version-metadata/>
- **Upload.** `POST /accounts/{account_id}/workers/scripts/{script_name}/versions`, as multipart form
  data. The `metadata` part is `{main_module, compatibility_date, compatibility_flags, bindings,
  keep_bindings}`, and each module is its own part. Uploading a version does not deploy it.
  <https://developers.cloudflare.com/api/resources/workers/subresources/scripts/subresources/versions/methods/create/>
  <https://developers.cloudflare.com/workers/configuration/multipart-upload-metadata/>
- **Deploy.** `POST /accounts/{account_id}/workers/scripts/{script_name}/deployments` with
  `{"strategy":"percentage","versions":[{"version_id":"…","percentage":100}]}`.
  <https://developers.cloudflare.com/api/resources/workers/subresources/scripts/subresources/deployments/methods/create/>
- **Rollback.** `GET …/deployments` lists the newest first. The adapter deploys the single version of
  the second entry at 100%. Cloudflare keeps the last 100 versions for rollback.
  - Rollback is refused across a change to Durable Object classes (migrations).
  - Rollback needs `force` after a secret change. The adapter does not send it, so the error is shown to
    the user.

  <https://developers.cloudflare.com/workers/versions-and-deployments/rollbacks/>
- **What a version upload cannot do:** change Durable Object classes, i.e. run migrations. A release
  that adds or renames a class must be deployed with `wrangler deploy`, by a push to the user's copy or
  a fresh Deploy button.
  <https://developers.cloudflare.com/workers/versions-and-deployments/deployment-management/>

### How the adapter uses this (`relay/src/cloudflare/lobby.ts`, `relay/src/core/release.ts`)

`POST /api/update {version?}` (default: the latest release) runs these steps:

1. Download `release.json` and `release.sig` of tag `v<version>` from
   `https://github.com/<repo>/releases/download/<tag>/`, or `…/releases/latest/download/` for the latest
   release, with retries and the REST API fallback for GitHub's rate limit (`docs/relay-releases.md`).
2. Check the publisher signature. Then check every asset against `release.json`, and check
   `manifest.bin` (format 2, publisher-signed, naming exactly these console files).
3. Store the console files as blobs.
4. Upload `relay-cloudflare.zip` as a new version and deploy it at 100%.
5. Only then point the `ldn-tunnel/release` channel at the new manifest. The release it replaces stays
   stored as `ldn-tunnel/release-previous` (manifest and blobs), which no console asks for.

The relay and the console module therefore move together. If the deploy fails, consoles keep the old
module. Bindings sent: the `LOBBY` Durable Object. `keep_bindings`: `secret_text`, `secret_key`,
`plain_text`, `json`, so the secrets and variables set on the Deploy form survive the update.

`POST /api/rollback` rolls the Worker back. The rolled-back code then serves its own `release.json` tag
again: on the first admin release view, ldn-tunnel update check or invite, it finds that release in
`ldn-tunnel/release-previous` and swaps the two, with no download (relays updated before this existed
download it). Until then `/api/release` shows the mismatch: `deployed.build` is null and `consoleFiles`
names the release still served. Consoles are not downgraded either way: the module refuses a lower build
(`crates/core/src/update.rs`).

### Caveat: the user's repository copy

A push to the user's copied repository makes Workers Builds deploy the code in that copy. That replaces
any version installed from the admin page. Users who update from the page should not push to their
copy, or should update it to the same release first. *Inferred*: variables in `wrangler.toml` overwrite
the values set in the dashboard on every `wrangler deploy`. That is why `CF_ACCOUNT_ID` is a secret
rather than a `[vars]` entry.

## Docker / Node: client address and the login limiter

- **Client address.** The admin login limiter counts failures per client address. The Node adapter
  uses the socket's peer address unless `TRUST_PROXY=1`; then it uses the last `X-Forwarded-For` hop
  (and `X-Forwarded-Proto` for the same-origin check). `docker-compose.yml` sets `TRUST_PROXY=1`
  because Caddy is the only way in (the relay port is `expose`d, not published) and Caddy's
  `reverse_proxy` sets `X-Forwarded-For` to the peer it sees, ignoring the client's own value unless
  `trusted_proxies` is configured.
  <https://caddyserver.com/docs/caddyfile/directives/reverse_proxy#defaults>
- **One process, one limiter.** The Node adapter is a single process (no cluster or workers), so the
  in-memory limiter sees every attempt. A restart resets it. The per-isolate caveat applies only on
  Cloudflare.

## Docker: what was run end to end

Checked on 2026-10-26 with Docker 27.2 / Compose 2.29 (`npm run test:e2e-docker` repeats the Caddy part: the shipped
`docker-compose.yml` and `Caddyfile`, `RELAY_DOMAIN=localhost`, only the published ports changed).

- `docker compose up -d` brings up relay and Caddy. With `RELAY_DOMAIN=localhost` Caddy signs with its own CA and
  redirects HTTP to HTTPS (308). Login, invite zip, wss play between two consoles, revoke, `docker compose
  restart`, and `down` then `up -d` (no `-v`) all work; tokens, consoles, invites and admin sessions live in
  `relay-data`, the certificate in `caddy-data`.
- The invite zip's `config.ini` names the public host, and `port` only when it is not 443.
- `tls internal` / `localhost`: the root is `caddy/pki/authorities/local/root.crt` inside the `caddy-data` volume
  (`docker compose cp caddy:/data/caddy/pki/authorities/local/root.crt .`). A TLS client given only the kit's
  `ca.pem` fails with `UNABLE_TO_GET_ISSUER_CERT_LOCALLY`; with the root appended it verifies.
- Public domain (checked 2026-10-26: `ghcr.io/ryancircelli/ldn-tunnel-relay:v0.1.0`, the shipped compose file and
  Caddyfile, a real hostname). Let's Encrypt issued over HTTP-01. Caddy serves leaf ← `YE1` ← `Root YE` ←
  `ISRG Root X2` ← `ISRG Root X1` (cross-signs). With ISRG Root X1 as the only trusted root, the chain verifies
  in `openssl s_client -verify_return_error -verify_hostname` and in the console's TLS crate
  (`crates/tls`, rustls-webpki). The kit's `ca.pem` holds X1 among its roots. It has no ZeroSSL root, so the
  Caddyfile pins `acme_ca` to Let's Encrypt. *Inferred:* without that pin, Caddy can fall back to ZeroSSL.
- Two desktop clients completed host, scan, join and ProxyData both ways over the internet
  (`npm run test:e2e -- --url wss://<host>/ldn`). That run reached the box through a Cloudflare Tunnel, not
  port forwarding. Cloudflare's edge terminates TLS with its own certificate, which `ca.pem` also trusts (GTS).
  Behind a TLS-terminating proxy, TLS-ALPN-01 fails (`Cannot negotiate ALPN protocol "acme-tls/1"`) and
  HTTP-01 must reach Caddy's port 80.
- `TRUST_PROXY=1` behind Caddy: 13 wrong logins with a different client-sent `X-Forwarded-For` each are answered
  429 from the 12th, because Caddy replaces the header. Straight at the relay, `TRUST_PROXY=1` lets each of them
  count against a new address (no lockout), and without `TRUST_PROXY` the header is ignored (lockout). Hence the
  relay port is not published.
- Update: with a newer release published, `/api/release` returns `updateCommand` and the admin page shows
  "vX is available." with the command. The relay caches the latest release for an hour (`LATEST_TTL`), so the
  banner can lag a new release by up to that. After the new image is up (`docker compose up -d` recreates
  both containers) `/api/release` shows the new deployed version, consoles and tokens are unchanged, and new
  invite zips carry the new module.

## Recommended update flow

| Host | How the owner updates | What consoles do |
|---|---|---|
| Cloudflare, token set | Admin page: **Update** (and **Roll back**) | Next update check: the new module, same signature check |
| Cloudflare, no token | Update the repository copy to the new release, which redeploys through Workers Builds; or deploy a fresh copy with the button and re-invite | Same |
| Docker | `docker compose pull && docker compose up -d` (shown on the admin page; `RELAY_VERSION` in `.env` pins a tag) | Same |

`GET /api/release` returns `canSelfUpdate`, which tells the admin page which row applies. On Docker it
also returns `updateCommand`.
