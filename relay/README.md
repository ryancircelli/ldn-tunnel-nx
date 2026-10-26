# ldn-tunnel relay

A relay that lets Nintendo Switch consoles play Local Wireless games with each other over the internet.
The consoles run ldn-tunnel, an Atmosphère sysmodule that carries Local Wireless traffic to the relay
over `wss://`. The relay stands in for Ryujinx's LdnServer.

**Each friend group runs its own relay.** There is no shared or public server. You deploy it to your own
Cloudflare account (the free plan is enough for a group of friends) or run it on your own server with
Docker, then invite your friends' consoles from its admin page.

## 1. Deploy

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/ryancircelli/ldn-tunnel-nx/tree/main/relay)

Click the button and sign in to Cloudflare and GitHub (or GitLab). Cloudflare copies this folder into a
new repository of yours, creates the Durable Object, and deploys the Worker. It asks for:

- **ADMIN**: the password for your relay's admin page. Pick a long one.
- **CF_API_TOKEN** and **CF_ACCOUNT_ID** (optional): let the admin page update the relay with one click.
  [Create the token here](https://dash.cloudflare.com/?to=/:account/api-tokens&permissionGroupKeys=%5B%7B%22key%22%3A%22workers_scripts%22%2C%22type%22%3A%22edit%22%7D%5D&name=ldn-tunnel%20relay) (the link pre-fills the Workers Scripts Edit permission; you
  can narrow it to this one Worker on the form). The account ID is on the right of the dashboard's
  Workers & Pages page. Without them, you update by redeploying (see below).
- **CF_WORKER_NAME**: leave it as `ldn-tunnel` unless you renamed the Worker.

Your relay is at `https://ldn-tunnel.<your-subdomain>.workers.dev`. Any address on it other than the
ones below answers an empty 404.

On your own server instead: see [Self-host with Docker](#self-host-with-docker).

## 2. Invite consoles

Open `https://<your relay>/admin` and log in with the ADMIN password. **Invite a console** makes a link
that works once, for 24 hours. Send it to the console's owner. They open it in any browser, press
**Download for my Switch**, unzip the file to the root of the Switch's SD card, and restart. The zip
holds the sysmodule, the overlay, and a `config.ini` that already has this relay's address and a token
just for that console. Nothing needs typing on the Switch.

The admin page lists every console: its name, version, whether it is online, and its recent log.
**Revoke** cuts a console off at once.

## 3. Updates

The relay and the console module are released together. A relay serves its consoles the module of
its own version, signed by the publisher; each console checks that signature with the key built into it.

- **Cloudflare, with CF_API_TOKEN set**: the admin page shows "vX is available." with an Update button. It checks
  the release's signature, stores the new console files, and redeploys the relay. **Roll back** goes back
  to the previous relay version. A push to your copied repository redeploys the copied code, which
  undoes an update made from the page: press the button again afterwards.
- **Cloudflare, without the token**: in the Cloudflare dashboard, open the Worker > Settings > Builds and
  trigger a new deployment after updating your repository copy from this one, or deploy a fresh copy
  with the button.
- **Docker**: the admin page shows the command, `docker compose pull && docker compose up -d`.

Consoles pick up the new module on their next update check, on their own.

## Free plan

- Each incoming WebSocket message counts as 1/20 of a Durable Object request. The free plan allows
  100,000 requests a day, which is about 2 million incoming messages. Outgoing messages are free.
- Game traffic (ProxyData) dominates. Two consoles at 60 packets a second each make about 430,000
  incoming messages an hour, so a fast real-time game gets about 4.5 hours a day. Turn-based games use far less.
- Limits reset at 00:00 UTC. Past them, calls fail; you are not billed.
- The Lobby logs `ldn: N incoming messages in 60s` about once a minute while consoles are connected.
  Watch it with `npx wrangler tail` during a real session before relying on an estimate.
  Workers Paid ($5 a month) lifts the caps.

## Owner tools

The owner's relay also has test and stable channels for both the C++ ryu_ldn_nx (module 0) and
ldn-tunnel (module 1, `UpdateCheckRequest.reserved[0] = 1`), published with `UPDATE_ADMIN` (the SHA-256
of the release admin token) and the tools below. A channel published here takes precedence over the
installed release for ldn-tunnel consoles.

```sh
RELAY_URL=https://<your relay> npm run release -- --repo <ryu_ldn_nx checkout>     # C++ module, test channel
RELAY_URL=https://<your relay> npm run release -- --module ldn-tunnel --exefs exefs.nsp --overlay ldn-tunnel.ovl --version 1.2.3 --build <LDNT_BUILD of that exefs>
RELAY_URL=https://<your relay> npm run promote [-- --module ldn-tunnel]
RELAY_URL=https://<your relay> npm run status  [-- --module ldn-tunnel]
```

Deploy-time `TOKEN_*` secrets (the SHA-256 of a console token) still open `/ldn`, for consoles set up
before invites existed. They show on the admin page; revoke one by deleting its secret.

## How it works

The wire contract with the Switch side is [below](#wire-contract); the HTTP routes, the release layout and
the core interfaces are in the repository's `docs/CONTRACTS.md`.

- `src/core/`: everything that is not Cloudflare or Node: `relay.ts` (a port of
  [LdnServer](https://github.com/Ryujinx/LdnServer)'s handlers and `HostedGame`, the update channels,
  routing), `auth.ts`, `api.ts` (admin JSON API), `invite.ts` (links and the SD card zip), `release.ts`
  (signed releases), `codec/` (the packed structs), `ports.ts` (what a host provides).
- `src/cloudflare/`: the Worker and the `Lobby` Durable Object (hibernation sockets, SQLite, alarms),
  and the self-update over the Cloudflare API.
- `src/node/`: the standalone server for Docker.
- `assets/`: `ca.pem`, the nine CA roots Cloudflare issues workers.dev certificates from (cut from
  Mozilla's bundle, 2026-09-25; sha256 `d2cf9f94c064906549a23ed31931b9db56cfd81b229448e98dec83b36a6e685a`),
  and `gamelist.txt`, the games whose traffic the module carries.

### Wire contract

The console's WebSocket client and the relay must both follow this.

- URL: `wss://<host>/ldn` (port 443). Locally: `ws://127.0.0.1:8787/ldn` via `wrangler dev`.
- Upgrade request headers: `Upgrade: websocket`, `Authorization: Bearer <64 lowercase hex chars>`.
  An `X-Console-Id` header (sent by older builds) is ignored.
- A token is accepted if its lowercase hex SHA-256 matches a console token minted by an invite, or a secret
  named `TOKEN_<anything>` (e.g. `TOKEN_SWITCHES`; the name is only a label). Any failure -> HTTP 404, empty body.
- After 101: binary messages only. One message = exactly one RyuLDN packet: 12-byte LdnHeader
  (magic 0x4E444C52, type u8, version u8 = 1, 2 reserved, dataSize i32 at 0x08) + dataSize payload bytes,
  little-endian, layout exactly as `sysmodule/source/protocol/types.hpp` in [ryu_ldn_nx](https://github.com/Ethiquema/ryu_ldn_nx). Text messages, bad magic/version,
  or dataSize != message length - 12 -> relay closes with code 1002.
- WebSocket-level ping/pong is handled by the platform; LDN `Ping` packets are relayed/answered as LdnServer does.
- Relay never echoes tokens; closes the socket with 1000 on Disconnect handling only if LdnServer would.

## Local testing

```sh
npm test               # typecheck + vitest in workerd: codec layout/round-trips, auth, lobby, hibernation
npm run test:e2e       # starts wrangler dev with throwaway tokens, runs two desktop clients, stops it
npm run test:e2e -- --url wss://<your relay>/ldn   # with LDN_TOKEN_A / LDN_TOKEN_B set
npm run test:e2e -- --tcp 127.0.0.1:30456   # same lobby scenario against a C# LdnServer, for comparison
# Differential: one 40-step session against both servers, every received packet compared in order
LDN_TOKEN_A=.. LDN_TOKEN_B=.. node --experimental-transform-types tools/compare.ts --url ws://127.0.0.1:8787/ldn --tcp 127.0.0.1:30456
```

To run the relay by hand, copy `.dev.vars.example` to `.dev.vars` (gitignored), fill in `ADMIN`, add a
`TOKEN_TEST=<sha256 hex of a test token>` line, and run `npm run dev`. Then:

```sh
LDN_TOKEN=<token a> node --experimental-transform-types tools/client.ts host
LDN_TOKEN=<token b> node --experimental-transform-types tools/client.ts join
# Plain-TCP RyuLDN clients (Ryujinx, the sysmodule's tests/integration) through the relay:
LDN_TOKEN=<token a> node --experimental-transform-types tools/tcp-bridge.ts --listen 30456 --url ws://127.0.0.1:8787/ldn
```

The tools need Node 24 or later. Tokens are read from the environment, never from argv.

If `types.hpp` changes, run `tools/dump-layout.sh [path/to/ryu_ldn_nx]` (needs g++) to regenerate
`test/layout/types.json`. The codec test compares every struct size and field offset against that file.

## Where the relay differs from LdnServer

These differences are deliberate. Everything else follows the C# handlers, including reply order.

- Not ported: P2P / ExternalProxy, the ban list and name filter, Redis analytics, and the game list.
  A host that asks for P2P (`external_proxy_port != 0`) gets `NetworkError PortUnreachable` and a relayed
  game, which is what C# does when it cannot reach the port.
- Scan replies without C#'s 200 ms sleep.
- MAC memory works when a client re-presents its previous session id and MAC. In C#, a hex-case mismatch
  means it never matches. The sysmodule always sends a fixed id, so for it every session gets a fresh MAC, as in C#.
- Short or malformed payloads are dropped silently, as in C#. One case differs: a join into a game whose
  node table is full answers `TooManyPlayers`, where C# throws.
- `ConnectPrivate` is accepted at its wire size, 0xBC. C#'s managed struct is 0xC0 (its `NetworkConfig` is
  8-aligned), so C# silently drops a 0xBC `ConnectPrivate` and private-room joins never work there.
- Liveness: a Durable Object alarm every 10 s replaces the C# ping loop, with the same rules. A session
  idle for more than 10 s gets `Ping{requester=0}`, and one that has not answered by the next tick is closed.
  After the object wakes from hibernation, every session counts as idle once.

## Self-host with Docker

The same relay runs as a plain Node server (SQLite on disk) behind Caddy, which gets the HTTPS certificate.

Prerequisites: Docker with Compose, a hostname whose DNS record points at the machine, and ports 80 and 443 reachable (for a LAN-only relay see the comment in `Caddyfile`: `tls internal`).

```sh
cd relay
cp docker.env.example .env     # set RELAY_DOMAIN, the TOKEN_* hashes and the ADMIN password
docker compose up -d
```

The admin page is `https://<RELAY_DOMAIN>/admin` (log in with the `ADMIN` password); consoles connect to `wss://<RELAY_DOMAIN>/ldn`. The database lives in the `relay-data` volume, certificates in `caddy-data`.

To update: set `RELAY_VERSION` in `.env` to the new `v<semver>` tag (or leave `latest`), then

```sh
docker compose pull && docker compose up -d
```

To run without Docker: `npm ci --omit=dev && PORT=8080 npm run start:node` (Node 24; `DB_PATH` defaults to `./data/relay.sqlite`).
Behind your own TLS proxy, set `TRUST_PROXY=1` so the relay reads the client address and scheme from
`X-Forwarded-For` (last hop) and `X-Forwarded-Proto`. Do so only if that proxy sets or appends the address it
sees and the relay port is reachable through the proxy alone; otherwise a client can pick its own address. Unset,
the relay uses the socket's peer address. `docker-compose.yml` sets it for its Caddy.

## Smoke test (Docker)

`npm run test:e2e-docker` builds the image, runs it without Caddy against a fake GitHub release (signed with the
test fixture key, served from a local HTTP server through `RELEASE_BASE_URL`), and drives it end to end: admin login,
invites and their zips, two simulated consoles playing, the update channel, revoke, and a container restart. It
needs Docker and Node 24, takes about 20 s with a warm image cache, and removes everything it created
(`ldnt-e2e-relay`, volume `ldnt-e2e-data`, image `ldn-tunnel-relay:e2e`).

`RELEASE_BASE_URL` (env, optional) replaces `https://github.com/<repo>/releases` as the place the relay fetches
its release from, so a mirror works too; the files are still checked against the publisher key.

## License

MIT; see [LICENSE](LICENSE). `src/core/relay.ts` is a port of
[LdnServer](https://github.com/Ryujinx/LdnServer) (MIT, Ryujinx Team and Contributors), whose notice is
included in `LICENSE`. `assets/ca.pem` is cut from Mozilla's CA bundle as published by curl
(<https://curl.se/docs/caextract.html>), under the Mozilla Public License 2.0.
