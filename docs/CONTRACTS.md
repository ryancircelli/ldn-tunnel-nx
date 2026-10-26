# Contracts between components

Short, binding interfaces between the parts of the project. A change that must deviate
updates this file in the same commit.

## Console (Rust)

### Threads (crates/sys)
`ldn:u` server thread · `bsd:u` server thread(s) (design: crates/sys/src/server/README.md) ·
`ldnt:cfg` server thread · relay thread (socket + TLS + `core::conn`) · update/maintenance thread
(log idle-close, `Notifier::poll`, update worker). Shared state: `crates/sys/src/state.rs`
`SharedState` (atomics / nx mutex), the only cross-thread data besides the `Router` and the LDN
`Session` (each behind one mutex, never both held at once by the relay thread).

### `core::ldn::Session` (sans-IO; authoritative doc: crates/core/src/ldn/README.md)
IPC entry points one per ICommunication command → `Result<Reply, LdnError>`; relay-bound requests are
two-phase (`Pending` → completed by `on_packet` / `poll(now_ms)`); `on_packet(PacketId, &[u8])`;
`drain_actions()` yields `Action::{SendPacket, SignalStateChange, ProxyConfig, DeliverProxyData,
RelayConnect, RelayDisconnect, Log, Notify(Event)}`.

### `core::conn::Conn` (sans-IO; crates/core/src/conn/)
`on_bytes(&[u8])` (TLS plaintext in) · `next_packet() -> Option<(PacketId, &[u8])>` ·
`send_packet(id, payload, mask, out) -> usize` · `poll(now_ms, out) -> Action` (handshake request,
Initialize, Ping reply, timeouts) · `reconnect::Backoff` · `update_dl::Download` (0xC1–0xC4) ·
`remote_log::flush(&mut LogRing, out)` (0xC0).

### `core::router::Router` (crates/core/src/router/README.md) — `Decision::{Forward, Reply, ReplyAndForward, Emit}`.

### Transport (crates/sys/src/net/)
`BsdSocket: embedded_io::{Read, Write}` over the module's own `bsd:s` sockets; `resolve(host) ->
Ipv4Addr` (how the C++ did it: `network/dns_wrap.cpp`); `TlsStream<BsdSocket>` from `ldn-tunnel-tls`
(`connect(host, ca_pem, transport, now_unix_secs, rng)`); time from the network clock, RNG from csrng.

### config.ini (crates/core/src/config.rs is authoritative)
`[server] host port path token ca_file` · `[ldn] enabled real_wireless_button` ·
`[debug] enabled level remote_log` · `[update] channel` · `[notifications] updates game_start connection`.

## Relay (TypeScript, relay/)

### Layout
`relay/src/core/` platform-neutral (no Cloudflare or Node imports) · `relay/src/cloudflare/` Workers +
Durable Object adapter · `relay/src/node/` Node + `ws` adapter · `relay/test/` one suite run against
the core with fakes and against both adapters.

### Core interfaces — AUTHORITATIVE: `relay/src/core/ports.ts`
`Sql` (synchronous SQLite: one statement per `exec`, `tx`), `Conn` (send, close, load/save session
state), `Host` (sql, conns(), conn(sid), getAlarm/setAlarm, env, fetch, assets {ca, gamelist},
platform "cloudflare" | "docker", optional `Deployer`), `Accept`. Core = `relay/src/core/relay.ts`
class `Relay`: `http(req) -> Response | {accept}`; on accept the adapter does `s = newSession(who)`,
registers the socket under `s.sid`, `await open(conn, s)`; then `message(conn, bytes)`,
`closed(conn)`, `alarm()`. Reference adapter: `relay/src/cloudflare/lobby.ts`.

### HTTP routes (served by `Relay.http`, identical on both adapters)
- `GET /ldn` upgrade → WebSocket (bearer token: a `TOKEN_*` secret holding its SHA-256, or a console token minted by an invite, stored hashed in the `tokens` table). Unchanged wire protocol. Any other path: empty 404.
- `GET /admin` static page; `POST /admin/login` {secret} (JSON or form) → 204 + `ldnt_admin` cookie (HttpOnly, Secure, SameSite=Strict, 30 days); all `/api/*` need the cookie or `Authorization: Bearer <ADMIN secret>`. Cross-site `Origin` on a write → 403. No `ADMIN` secret → the whole admin surface is 404. Errors: `{error}` with 4xx/5xx.
- `GET /api/consoles` → `[{id, name, version, runningBuild, online, lastSeen, rejectedBuild}]` (deploy-time tokens: `id = "env:TOKEN_X"`, cannot be revoked or renamed here → 400)
- `POST /api/consoles/:id/revoke` (closes its sockets) · `PATCH /api/consoles/:id` {name}
- `GET /api/consoles/:id/logs?limit=` → `[{at, line}]` (default 200, max 2000)
- `GET /api/drops?limit=` → newest first, last 500: `{at, ev: "drop", who, by: relay|peer|error, code, reason, clean, colo, country, age_s, frames_in, frames_out, idle_in_ms, idle_out_ms, do_start, same_sec}` , `{at, ev: "relay-start", sockets: 0}`, and the resume outcomes `{at, ev: "resume", awayMs, ..}` / `{at, ev: "leave", why: "not resumed", ..}` / `{at, ev: "resume-refused", ..}` (drop and start rows: Cloudflare only; `relay/src/core/drops.ts`; `npm run drops` lays them next to the consoles' `relay: link ended` lines)
- `POST /api/invites` {name?} → `{url, expiresAt}` · `GET /invite/:token` → HTML page with a download button · `POST /invite/:token` → zip, consumes the invite (one-time, 24 h; a link preview's GET never uses it up)
- `GET /api/release` → `{deployed: {version, build}, latest?: {version, build, url}, platform, canSelfUpdate, updateCommand?, installError?}`
- `POST /api/update` {version?} (default latest; needs a `Deployer`, i.e. Cloudflare with `CF_API_TOKEN` + `CF_ACCOUNT_ID`) · `POST /api/rollback`
- Owner update routes (`UPDATE_ADMIN` bearer), per module by path: `PUT /update/channel/test`, `POST /update/promote` (C++ module), `PUT /update/ldn-tunnel/channel/test`, `POST /update/ldn-tunnel/promote`, `PUT /update/blob/:sha256`, `GET /update/status`. Details: docs/relay-releases.md.

### Invite zip (relay/src/core/invite.ts)
```
atmosphere/contents/420000004C444E54/exefs.nsp
atmosphere/contents/420000004C444E54/flags/boot2.flag
atmosphere/contents/420000004C444E54/toolbox.json
switch/.overlays/ldn-tunnel.ovl
config/ldn-tunnel/config.ini      (host = request hostname, port only if not 443, ;path = /ldn, token = minted, ca_file set)
config/ldn-tunnel/ca.pem          (relay/assets/ca.pem; a Docker relay with a private CA appends its root)
config/ldn-tunnel/gamelist.txt    (relay/assets/gamelist.txt)
```

### Release bundle (GitHub Release of this repo, tag `v<semver>`; docs/relay-releases.md)
Assets: `exefs.nsp`, `ldn-tunnel.ovl`, `manifest.bin` (192-byte SignedManifest, format 2, build =
seconds since epoch), `relay-cloudflare.zip` (`npm run bundle`: `worker.js`, `worker.js.map`, the
`*-ca.pem` / `*-gamelist.txt` text modules, and `metadata.json` `{main_module, compatibility_date}`),
`release.json` `{version: "v<semver>", build, assets: {name: {sha256, size}}}`, `release.sig`
(P-256/SHA-256 over `release.json`, raw r||s). Publisher public key: `relay/src/core/publisher_key.ts`
(the 65-byte point as hex); release CI compiles the same point into the module as `LDNT_UPDATE_PUBKEY`.
`relay/release.json` `{repo, tag}` pins the release a relay is; CI refuses a tag it does not name.
Docker image tag = `v<semver>`.
The bundle is built, signed and checked by `tools/release` (Rust, `ldn-tunnel-release`; manifest layout and
signature check are `crates/core/src/update.rs`).
