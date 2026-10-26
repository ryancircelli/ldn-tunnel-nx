// The relay core: the port of LdnServer's session handlers and HostedGame, plus the relay's own HTTP
// surface (auth, logs, release API, admin page, invites). Platform-neutral: it talks to its host through
// ports.ts. One instance holds every session and game, like the C# process.
//
// State:
//  - per socket: Session in Conn.save (survives Durable Object hibernation)
//  - per game:   row in SQLite (NetworkInfo blob + JSON meta), loaded on wake
//  - MAC memory: SQLite table (MacAddressMemory.cs)
//  - debug log:  SQLite table, one row per DebugLog packet, read through GET /logs
//  - updates:    blobs (64 KiB rows), channel manifests, console check-ins; see the /update/* handlers
//
// Reply order follows the C# handlers. Where C# runs work on Task.Run
// (Disconnect/Close), the order used is the one that thread pool gives in practice.
import {
  ConnectPrivateRequest, ConnectRequest, CreateAccessPointPrivateRequest, CreateAccessPointRequest,
  DisconnectMessage, InitializeMessage, NetworkError, NetworkErrorMessage, NetworkInfo, NodeInfo,
  PacketId, PassphraseMessage, PingMessage, ProxyConfig, ProxyConnectRequest, ProxyConnectResponse,
  ProxyDataHeader, ProxyDisconnectMessage, ScanFilterFlag, ScanFilterFull, SignedManifest, UPDATE_CHUNK_SIZE,
  UPDATE_MANIFEST_FORMAT, UPDATE_MANIFEST_MAGIC, UPDATE_MAX_BLOB_SIZE, UpdateChannel, UpdateCheckRequest,
  UpdateChunkHeader, UpdateChunkRequest, packet, parsePacket,
  type AddressEntry,
} from "./codec/types.ts";
import type { Struct } from "./codec/struct.ts";
import { BROADCAST, NETWORK_MASK, newDhcp, requestIp, returnIp, type Dhcp } from "./dhcp.ts";
import type { Accept, Conn, Host, Sql } from "./ports.ts";
import { bearer, isAdmin, sha256Hex, whoIs } from "./auth.ts";
import { adminApi } from "./api.ts";
import { record } from "./drops.ts";
import { invite } from "./invite.ts";
import { PIN, ensureInstalled, installed } from "./release.ts";

const PING_INTERVAL = 10_000; // LdnServer.InactivityPingFrequency
/**
 * A player whose socket drops (Cloudflare cuts WebSockets under running games, or the object restarts) keeps its
 * node, IP and the game this long, for its console to come back on a new socket and send Resume. The console gives
 * up after 12 s (core ldn RESUME_MS). env RESUME_GRACE_MS overrides it; 0 = leave at once (the C# behaviour).
 */
const RESUME_GRACE_MS = 15_000;
const GHOST_AGE = 16 * 3600_000; // LdnServer.Scan skips games older than this
const MAC_TTL = 30 * 86400_000;
const LOG_TTL = 3 * 86400_000;
const LOG_MAX_ROWS = 20_000;
const LOG_PRUNE_EVERY = 3600_000; // the prune scans the table, so not every alarm
/** A console with a valid token can write rows as fast as it can send; every this many writes, trim. */
const TRIM_EVERY = 1000;
const CONSOLES_MAX_ROWS = 1000; // one UpdateCheck row per (token, module)
const MACS_MAX_ROWS = 10_000; // one per session
const BROADCAST_192 = 0xc0a800ff; // 192.168.0.255
const BLOB_ROW = 65536; // SQLite values max out at 2 MiB; blobs are split into 64 KiB rows
const CHANNELS = { [UpdateChannel.Stable]: "stable", [UpdateChannel.Test]: "test" } as const;
/** UpdateCheckRequest.reserved[0] -> channel row prefix (0 = the C++ ryu_ldn_nx, which always sends 0). */
const MODULES: Record<number, string> = { 0: "", 1: "ldn-tunnel/" };
/** Manifest format each module accepts; a manifest for one module never verifies on the other. */
const FORMATS: Record<number, number> = { 0: UPDATE_MANIFEST_FORMAT, 1: 2 };
/** The ldn-tunnel release this relay installed from GitHub (the default when no manifest was PUT). */
export const RELEASE_CHANNEL = "ldn-tunnel/release";

export interface Session {
  sid: string; // 32 hex chars; also the socket's tag
  who: string; // "env:<TOKEN_NAME>" or "c:<console id>": which token opened it
  mac: string; // 12 hex chars
  ip: number;
  nodeId: number;
  game: string | null;
  init: boolean;
  pass: string;
  wait: number; // ping id we are waiting on, -1 for none
  pingId: number;
}

interface Player {
  sid: string;
  ip: number;
  nodeId: number;
  who?: string; // the token that joined: only the same console may resume the node
  gone?: number; // when its socket dropped: it leaves at gone + grace unless resumed
}

interface Game {
  id: string; // lowercase hex of the LDN session id
  info: NetworkInfo;
  owner: string;
  pass: string;
  createdAt: number;
  players: Player[]; // join order
  dhcp: Dhcp;
  closed: boolean; // closed games stay only while players still reference them, like C#
}

export const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
export const unhex = (s: string) => Uint8Array.from(s.match(/../g) ?? [], (h) => parseInt(h, 16));
export const randomHex = (n: number) => hex(crypto.getRandomValues(new Uint8Array(n)));
/** Control characters would break the tab/line format of GET /logs and the status output. */
const clean = (t: string) => t.replace(/[\x00-\x09\x0b-\x1f\x7f]/g, " ");
export const oneLine = (t: string) => clean(t).replace(/\n/g, " ").trim();
export const text = (status: number, body: string) => new Response(body, { status, headers: { "content-type": "text/plain; charset=utf-8" } });
const eq = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i]);

/** StringUtils.ReadUtf8String: bytes up to the first NUL. */
const readUtf8 = (b: Uint8Array) => {
  const end = b.indexOf(0);
  return new TextDecoder().decode(end < 0 ? b : b.subarray(0, end));
};

/** C# MemoryMarshal.Read throws on short input; the C# server then drops the message. */
const read = <T>(s: Struct<T>, payload: Uint8Array): T | null => (payload.length < s.size ? null : s.decode(payload));

export const notFound = () => new Response(null, { status: 404 });

const SCHEMA = [
  "CREATE TABLE IF NOT EXISTS games (id TEXT PRIMARY KEY, info BLOB NOT NULL, meta TEXT NOT NULL)",
  "CREATE TABLE IF NOT EXISTS macs (id TEXT PRIMARY KEY, mac TEXT NOT NULL, at INTEGER NOT NULL)",
  "CREATE TABLE IF NOT EXISTS logs (id INTEGER PRIMARY KEY AUTOINCREMENT, at INTEGER NOT NULL, label TEXT NOT NULL, text TEXT NOT NULL)",
  "CREATE TABLE IF NOT EXISTS blobs (sha TEXT NOT NULL, idx INTEGER NOT NULL, data BLOB NOT NULL, PRIMARY KEY (sha, idx))",
  "CREATE TABLE IF NOT EXISTS blob_meta (sha TEXT PRIMARY KEY, size INTEGER NOT NULL)",
  "CREATE TABLE IF NOT EXISTS channels (name TEXT PRIMARY KEY, manifest BLOB NOT NULL, at INTEGER NOT NULL)",
  // last UpdateCheck per (token, module); the label is only what the console calls itself, so two may share one
  "CREATE TABLE IF NOT EXISTS console_status (who TEXT NOT NULL, module INTEGER NOT NULL, label TEXT NOT NULL, running_build INTEGER NOT NULL, version TEXT NOT NULL, channel INTEGER NOT NULL, rejected_build INTEGER NOT NULL, at INTEGER NOT NULL, PRIMARY KEY (who, module))",
  // per-console tokens minted by invites: only the SHA-256 is kept
  "CREATE TABLE IF NOT EXISTS tokens (id TEXT PRIMARY KEY, hash TEXT NOT NULL UNIQUE, name TEXT NOT NULL, created INTEGER NOT NULL)",
  "CREATE TABLE IF NOT EXISTS invites (hash TEXT PRIMARY KEY, name TEXT NOT NULL, expires INTEGER NOT NULL)",
  // last connect / update check per console token ("env:<NAME>" or "c:<id>")
  "CREATE TABLE IF NOT EXISTS seen (who TEXT PRIMARY KEY, at INTEGER NOT NULL, version TEXT, running_build INTEGER, rejected_build INTEGER)",
  "CREATE TABLE IF NOT EXISTS admin_sessions (hash TEXT PRIMARY KEY, expires INTEGER NOT NULL)",
  "CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT NOT NULL)",
  // the trims and the prune run inside a message or alarm (10 ms of CPU on the Workers free plan): no full scans
  "CREATE INDEX IF NOT EXISTS logs_at ON logs (at)",
  "CREATE INDEX IF NOT EXISTS macs_at ON macs (at)",
];
/** Columns added after a table first shipped: [table, column, definition]. */
const ADDED_COLUMNS = [
  ["logs", "who", "TEXT"],
] as const;

export class Relay {
  readonly sql: Sql;
  private games = new Map<string, Game>();
  private lastMsg = new Map<string, number>();
  private msgCount = 0;
  private countSince = Date.now();
  private lastPrune = 0;
  private readonly grace: number;
  private writes = 0;
  /** Per game ProxyData counters (memory only), logged when the game ends: `wrangler tail` shows why a room died. */
  private traffic = new Map<string, { routed: number; dropped: number; last: number; maxGapMs: number }>();

  constructor(readonly host: Host) {
    const sql = (this.sql = host.sql);
    this.grace = Number(host.env.RESUME_GRACE_MS ?? RESUME_GRACE_MS) || 0;
    for (const q of SCHEMA) sql.exec(q);
    // the old label-keyed table: pure status, repopulated by each console's next update check
    sql.exec("DROP TABLE IF EXISTS consoles");
    for (const [table, column, def] of ADDED_COLUMNS) {
      if (!sql.exec<{ name: string }>(`PRAGMA table_info(${table})`).some((c) => c.name === column)) {
        sql.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${def}`);
      }
    }
    for (const row of sql.exec<{ id: string; info: ArrayBuffer; meta: string }>("SELECT id, info, meta FROM games")) {
      this.games.set(row.id, { id: row.id, info: NetworkInfo.decode(new Uint8Array(row.info)), ...JSON.parse(row.meta) });
    }
    // a start with games but no sockets = the object was reset under its consoles (all dropped at once)
    console.log({ ev: "relay-start", sockets: host.conns().length, games: this.games.size });
    this.reconcile();
  }

  // ---- plumbing -------------------------------------------------------------

  /**
   * Every HTTP request. A console token opens `GET /ldn` (WebSocket: answered with Accept, the adapter
   * upgrades and calls `open`) and `GET /logs`; UPDATE_ADMIN opens the release API `/update/*`; the ADMIN
   * secret opens the admin page and its JSON API (api.ts); an invite token opens `/invite/<token>`.
   * Any other request, or any failed check, gets an empty 404.
   */
  async http(req: Request): Promise<Response | Accept> {
    const url = new URL(req.url);
    const path = url.pathname;
    const ws = req.headers.get("Upgrade")?.toLowerCase() === "websocket";
    if (path === "/admin" || path === "/admin/login" || path.startsWith("/api/")) return ws ? notFound() : adminApi(this, req);
    if (path.startsWith("/invite/") && !ws) return invite(this, req, path.slice(8));
    const env = this.host.env;
    if (path.startsWith("/update/") && !ws) {
      return (await isAdmin(bearer(req), [env.UPDATE_ADMIN])) ? this.admin(req, path) : notFound();
    }
    if (req.method !== "GET" || !((path === "/ldn" && ws) || (path === "/logs" && !ws))) return notFound();
    const who = await whoIs(this, bearer(req));
    if (!who) return notFound();
    return ws ? { accept: who } : this.logs(url.searchParams);
  }

  /** A fresh session for an accepted upgrade; the adapter tags the socket with `sid`, then calls `open`. */
  newSession(who: string): Session {
    return {
      sid: randomHex(16),
      who,
      mac: randomHex(6),
      ip: 0,
      nodeId: 0,
      game: null,
      init: false,
      pass: "",
      wait: -1,
      pingId: 0,
    };
  }

  async open(ws: Conn, s: Session) {
    ws.save(s);
    this.sql.exec("INSERT INTO seen (who, at) VALUES (?, ?) ON CONFLICT (who) DO UPDATE SET at = excluded.at", s.who, Date.now());
    this.lastMsg.set(s.sid, Date.now());
    if ((await this.host.getAlarm()) === null) await this.host.setAlarm(Date.now() + PING_INTERVAL);
  }

  /** Revokes a console token's live sockets. */
  kick(who: string) {
    for (const ws of this.host.conns()) {
      if (ws.load<Session>()?.who === who) {
        this.hangUp(ws, 1000, "revoked");
        ws.save(null); // inert from now on: frames that arrive while it closes are dropped
      }
    }
  }

  message(ws: Conn, msg: ArrayBuffer | Uint8Array | string) {
    const p = typeof msg === "string" ? null : parsePacket(new Uint8Array(msg));
    if (!p) return this.hangUp(ws, 1002, "protocol error");
    const s = ws.load<Session>();
    if (!s) return;
    this.msgCount++;
    this.lastMsg.set(s.sid, Date.now());
    try {
      this.handle(ws, s, p.type, p.payload);
    } catch (e) {
      // one bad packet must not take the object (Cloudflare) or the process (Node) down with every other socket
      console.error({ ev: "handler-error", who: s.who, sid: s.sid, type: p.type, error: String((e as Error)?.stack ?? e) });
    }
  }

  /** Every relay-side close goes through here, logged, so a drop shows in `wrangler tail` / the Node log. */
  private hangUp(ws: Conn, code: number, reason: string) {
    const s = ws.load<Session>();
    console.log({ ev: "ws-close", by: "relay", code, reason, who: s?.who, sid: s?.sid });
    ws.close(code, reason);
    this.closed(ws);
  }

  /** LdnSession.OnDisconnected (socket closed or errored). A player keeps its node for the grace window. Idempotent. */
  closed(ws: Conn) {
    const s = ws.load<Session>();
    if (!s) return;
    this.lastMsg.delete(s.sid);
    const g = s.game ? this.games.get(s.game) : undefined;
    const p = g && !g.closed && this.grace > 0 ? g.players.find((x) => x.sid === s.sid) : undefined;
    if (!g || !p) return this.disconnectFromGame(ws, s, "socket closed");
    if (p.gone !== undefined) return;
    p.gone = Date.now();
    this.persist(g);
    console.log({ ev: "player-gone", game: g.id, who: s.who, node: p.nodeId, host: g.owner === s.sid, graceMs: this.grace });
    this.armAlarm().catch((e) => console.error({ ev: "alarm-error", error: String(e) }));
  }

  /** Resume (relay-only): a console back on a new socket takes over its old node, IP and game. */
  private resume(ws: Conn, s: Session, payload: Uint8Array) {
    if (payload.length < 32 || s.game || !s.init) return this.error(ws, NetworkError.ConnectNotFound);
    const old = hex(payload.subarray(0, 16));
    const g = this.games.get(hex(payload.subarray(16, 32)));
    const p = g && !g.closed ? g.players.find((x) => x.sid === old && x.who === s.who) : undefined;
    if (!g || !p) {
      record(this.sql, { ev: "resume-refused", who: s.who, game: g?.id ?? null, closed: g?.closed ?? null });
      return this.error(ws, NetworkError.ConnectNotFound);
    }
    const stale = this.host.conn(old); // a socket the runtime has not reported closed yet
    const os = stale?.load<Session>();
    if (stale && os) {
      os.game = null;
      stale.save(os);
      try {
        this.hangUp(stale, 1000, "resumed on a new socket");
      } catch {} // already closing
    }
    const away = p.gone === undefined ? 0 : Date.now() - p.gone;
    if (g.owner === old) g.owner = s.sid;
    p.sid = s.sid;
    delete p.gone;
    s.game = g.id;
    s.ip = p.ip;
    s.nodeId = p.nodeId;
    s.mac = hex(g.info.ldn.nodes[p.nodeId].mac_address);
    s.pass = g.pass;
    ws.save(s);
    this.persist(g);
    record(this.sql, { ev: "resume", game: g.id, who: s.who, node: p.nodeId, host: g.owner === s.sid, awayMs: away });
    this.send(ws, PacketId.ProxyConfig, ProxyConfig, { proxy_ip: s.ip, proxy_subnet_mask: NETWORK_MASK });
    this.send(ws, PacketId.Connected, NetworkInfo, g.info);
  }

  /** Players whose grace ran out leave (a host's game closes); returns the next expiry, if any are still waiting. */
  private expire(now: number): number | undefined {
    let next: number | undefined;
    for (const g of [...this.games.values()]) {
      for (const p of [...g.players]) {
        if (p.gone === undefined) continue;
        const at = p.gone + this.grace;
        if (at > now) {
          next = Math.min(next ?? at, at);
          continue;
        }
        record(this.sql, { ev: "leave", game: g.id, who: p.who, node: p.nodeId, host: g.owner === p.sid, why: "not resumed", left: g.players.length - 1 });
        this.leave(g, p.sid);
        if (g.owner === p.sid) this.close(g);
      }
    }
    return next;
  }

  /** Makes sure the alarm runs (it expires the waiting players), even with no socket left. */
  private async armAlarm() {
    if ((await this.host.getAlarm()) === null) await this.host.setAlarm(Date.now() + PING_INTERVAL);
  }

  /** Replaces BackgroundPingTask + LdnSession.Ping. */
  async alarm() {
    const now = Date.now();
    const sockets = this.host.conns();
    // expiries ride the ping rhythm (an earlier alarm would cut a console that had no time to answer its ping):
    // a node is held 15–25 s
    const waiting = this.expire(now) !== undefined;
    for (const ws of sockets) {
      const s = ws.load<Session>();
      if (!s) continue;
      if (s.wait !== -1) {
        this.hangUp(ws, 1000, "idle"); // the last ping was not answered
      } else if (now - (this.lastMsg.get(s.sid) ?? 0) > PING_INTERVAL) {
        s.wait = s.pingId;
        s.pingId = (s.pingId + 1) & 0xff;
        ws.save(s);
        this.send(ws, PacketId.Ping, PingMessage, { requester: 0, id: s.wait });
      }
    }
    if (now - this.countSince >= 60_000) {
      console.log(`ldn: ${this.msgCount} incoming messages in ${Math.round((now - this.countSince) / 1000)}s, ${sockets.length} sockets`);
      this.msgCount = 0;
      this.countSince = now;
    }
    if (now - this.lastPrune >= LOG_PRUNE_EVERY) {
      this.lastPrune = now;
      this.sql.exec("DELETE FROM logs WHERE at < ?", now - LOG_TTL);
      this.sql.exec("DELETE FROM logs WHERE id <= (SELECT MAX(id) FROM logs) - ?", LOG_MAX_ROWS);
    }
    if (this.host.conns().length > 0 || waiting) await this.host.setAlarm(Date.now() + PING_INTERVAL);
  }

  /**
   * After a restart: players whose sockets are gone get the grace window to resume (the object restarting under its
   * consoles drops every socket); without one they leave, and games whose owner is gone close.
   */
  private reconcile() {
    const live = new Set(this.host.conns().map((ws) => ws.load<Session>()?.sid));
    const now = Date.now();
    let waiting = false;
    for (const g of [...this.games.values()]) {
      for (const p of g.players.filter((p) => !live.has(p.sid))) {
        if (this.grace > 0 && !g.closed) {
          p.gone ??= now;
          waiting = true;
        } else this.leave(g, p.sid);
      }
      const ownerWaits = g.players.some((p) => p.sid === g.owner && p.gone !== undefined);
      if (!live.has(g.owner) && !ownerWaits) this.close(g);
      else if (this.games.has(g.id)) this.persist(g);
    }
    if (waiting) this.armAlarm().catch((e) => console.error({ ev: "alarm-error", error: String(e) }));
  }

  /** False if there was no socket or the send threw. */
  private sendRaw(ws: Conn | undefined, bytes: Uint8Array): boolean {
    try {
      ws?.send(bytes);
      return !!ws;
    } catch {
      return false; // socket already closing; its close handler cleans up
    }
  }

  private send<T>(ws: Conn | undefined, type: PacketId, s?: Struct<T>, v?: T) {
    this.sendRaw(ws, packet(type, s && v ? s.encode(v) : undefined));
  }

  private error(ws: Conn, code: NetworkError) {
    this.send(ws, PacketId.NetworkError, NetworkErrorMessage, { error_code: code });
  }

  private persist(g: Game) {
    const { id, info, ...meta } = g;
    this.sql.exec(
      "INSERT OR REPLACE INTO games (id, info, meta) VALUES (?, ?, ?)",
      id,
      NetworkInfo.encode(info).buffer as ArrayBuffer,
      JSON.stringify(meta),
    );
  }

  private drop(g: Game) {
    console.log({ ev: "game-end", game: g.id, ...this.traffic.get(g.id) });
    this.traffic.delete(g.id);
    this.games.delete(g.id);
    this.sql.exec("DELETE FROM games WHERE id = ?", g.id);
  }

  // ---- dispatch (LdnSession constructor) -----------------------------------

  private handle(ws: Conn, s: Session, type: number, payload: Uint8Array) {
    const game = s.game ? this.games.get(s.game) : undefined;
    switch (type) {
      case PacketId.Initialize: return this.initialize(ws, s, payload);
      case PacketId.Passphrase: return this.passphrase(ws, s, payload);
      case PacketId.CreateAccessPoint: {
        const r = read(CreateAccessPointRequest, payload);
        if (!r) return;
        if (s.game || !s.init) return this.error(ws, NetworkError.Unknown);
        return this.createAccessPoint(ws, s, randomHex(16), r, [], payload.subarray(CreateAccessPointRequest.size));
      }
      case PacketId.CreateAccessPointPrivate: {
        const r = read(CreateAccessPointPrivateRequest, payload);
        if (!r) return;
        if (s.game || !s.init) return this.error(ws, NetworkError.Unknown);
        const id = hex(r.security_parameter.session_id);
        return this.createAccessPoint(ws, s, id, r, r.address_list.addresses, payload.subarray(CreateAccessPointPrivateRequest.size));
      }
      case PacketId.Connect: {
        const r = read(ConnectRequest, payload);
        if (!r) return;
        if (!s.init) return this.error(ws, NetworkError.ConnectFailure);
        return this.connectImpl(ws, s, hex(r.network_info.network_id.session_id), r.user_config.user_name, r.local_communication_version);
      }
      case PacketId.ConnectPrivate: {
        const r = read(ConnectPrivateRequest, payload);
        if (!r) return;
        if (!s.init) return this.error(ws, NetworkError.ConnectFailure);
        return this.connectImpl(ws, s, hex(r.security_parameter.session_id), r.user_config.user_name, r.local_communication_version);
      }
      case PacketId.Scan: return this.scan(ws, s, payload);
      case PacketId.Resume: return this.resume(ws, s, payload);
      case PacketId.Disconnect: {
        if (payload.length < DisconnectMessage.size) return;
        return this.disconnectFromGame(ws, s, "Disconnect");
      }
      case PacketId.Ping: {
        const r = read(PingMessage, payload);
        if (r && r.requester === 0 && r.id === s.wait) {
          s.wait = -1;
          ws.save(s);
        }
        return;
      }
      case PacketId.Reject: return game && this.reject(ws, s, game, payload);
      case PacketId.SetAcceptPolicy: {
        if (!game || payload.length < 1 || s.sid !== game.owner) return;
        game.info.ldn.station_accept_policy = payload[0];
        return this.syncNetwork(game);
      }
      case PacketId.SetAdvertiseData: {
        if (!game || s.sid !== game.owner) return;
        game.info.ldn.advertise_data_size = payload.length & 0xffff;
        game.info.ldn.advertise_data = payload.slice(0, 0x180);
        return this.syncNetwork(game);
      }
      case PacketId.ProxyConnect: return game && this.route(s, game, type, payload, ProxyConnectRequest.size);
      case PacketId.ProxyConnectReply: return game && this.route(s, game, type, payload, ProxyConnectResponse.size);
      case PacketId.ProxyData: return game && this.route(s, game, type, payload, ProxyDataHeader.size);
      case PacketId.ProxyDisconnect: return game && this.route(s, game, type, payload, ProxyDisconnectMessage.size);
      case PacketId.DebugLog: return this.debugLog(s, payload);
      case PacketId.UpdateCheck: return this.updateCheck(ws, s, payload);
      case PacketId.UpdateChunk: return this.updateChunk(ws, payload);
      // ExternalProxy* (P2P) and everything else: ignored.
    }
  }

  // ---- handlers -------------------------------------------------------------

  /** DebugLog (relay-only extension): [u8 label_len][label][text]. Stored, never answered or forwarded. */
  private debugLog(s: Session, payload: Uint8Array) {
    const n = payload[0];
    if (payload.length > 2048 || !n || n > 32 || payload.length < 1 + n) return;
    const dec = new TextDecoder();
    const label = clean(dec.decode(payload.subarray(1, 1 + n))).trim().slice(0, 32) || "?";
    const text = clean(dec.decode(payload.subarray(1 + n)).replace(/\r\n/g, "\n")).replace(/\n+$/, "");
    if (!text.trim()) return;
    this.sql.exec("INSERT INTO logs (at, label, text, who) VALUES (?, ?, ?, ?)", Date.now(), label, text, s.who);
    this.wrote();
  }

  /** Bounds the tables a console fills, so a hostile one cannot use up the relay's storage between prunes. */
  private wrote() {
    if (++this.writes % TRIM_EVERY) return;
    const sql = this.sql;
    sql.exec("DELETE FROM logs WHERE id <= (SELECT MAX(id) FROM logs) - ?", LOG_MAX_ROWS);
    sql.exec("DELETE FROM console_status WHERE rowid NOT IN (SELECT rowid FROM console_status ORDER BY at DESC LIMIT ?)", CONSOLES_MAX_ROWS);
    sql.exec("DELETE FROM macs WHERE at < (SELECT at FROM macs ORDER BY at DESC LIMIT 1 OFFSET ?)", MACS_MAX_ROWS - 1);
  }

  // ---- updates ----------------------------------------------------------------

  /** UpdateCheck (relay-only extension): record the console, answer with its channel's manifest (empty = none). */
  private updateCheck(ws: Conn, s: Session, payload: Uint8Array) {
    const r = read(UpdateCheckRequest, payload);
    if (!r || r.label_len > 32 || (r.channel !== UpdateChannel.Stable && r.channel !== UpdateChannel.Test)) return;
    const module = r.reserved[0];
    if (!(module in MODULES)) return;
    const label = oneLine(new TextDecoder().decode(r.label.subarray(0, r.label_len))); // "" = none: status() names it
    const sql = this.sql;
    sql.exec(
      "INSERT OR REPLACE INTO console_status (who, module, label, running_build, version, channel, rejected_build, at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
      s.who, module, label, r.running_build, oneLine(readUtf8(r.version)), r.channel, r.rejected_build, Date.now(),
    );
    sql.exec(
      "INSERT OR REPLACE INTO seen (who, at, version, running_build, rejected_build) VALUES (?, ?, ?, ?, ?)",
      s.who, Date.now(), oneLine(readUtf8(r.version)), r.running_build, r.rejected_build,
    );
    this.wrote();
    // a new relay version fetches its console files on the first ldn-tunnel check; this one answers with what is there
    if (module === 1 && installed(this)?.tag !== PIN.tag) ensureInstalled(this).catch((e: Error) => console.log(`release: ${e.message}`));
    // ldn-tunnel: a channel the owner published to, else the release this relay installed (release.ts)
    const manifest = this.manifestOf(MODULES[module] + CHANNELS[r.channel]) ?? (module === 1 ? this.manifestOf(RELEASE_CHANNEL) : undefined);
    this.sendRaw(ws, packet(PacketId.UpdateManifest, manifest));
  }

  /** UpdateChunk: header + bytes, or the header alone for an unknown blob or a bad range. */
  private updateChunk(ws: Conn, payload: Uint8Array) {
    if (payload.length !== UpdateChunkRequest.size) return;
    const r = UpdateChunkRequest.decode(payload);
    const sha = hex(r.sha256);
    const sql = this.sql;
    const total = this.blobSize(sha) ?? 0;
    let data = new Uint8Array(0);
    if (total && r.length >= 1 && r.length <= UPDATE_CHUNK_SIZE && r.offset < total) {
      const end = Math.min(r.offset + r.length, total);
      const first = Math.floor(r.offset / BLOB_ROW);
      const last = Math.floor((end - 1) / BLOB_ROW);
      const buf = new Uint8Array((last - first + 1) * BLOB_ROW);
      for (const row of sql.exec<{ idx: number; data: ArrayBuffer }>("SELECT idx, data FROM blobs WHERE sha = ? AND idx BETWEEN ? AND ? ORDER BY idx", sha, first, last)) {
        buf.set(new Uint8Array(row.data), (row.idx - first) * BLOB_ROW);
      }
      data = buf.subarray(r.offset - first * BLOB_ROW, end - first * BLOB_ROW);
    }
    const head = UpdateChunkHeader.encode({ sha256: r.sha256, offset: r.offset, total_size: total });
    this.sendRaw(ws, packet(PacketId.UpdateChunkData, new Uint8Array([...head, ...data])));
  }

  /** Admin HTTP API; the Worker has already authenticated the admin token. */
  private async admin(req: Request, path: string): Promise<Response> {
    const m = req.method;
    let sha: RegExpMatchArray | null;
    if (m === "GET" && path === "/update/status") return this.status();
    for (const [module, prefix] of Object.entries(MODULES)) {
      if (m === "POST" && path === `/update/${prefix}promote`) return this.promote(prefix);
      if (m === "PUT" && path === `/update/${prefix}channel/test`) return this.putTest(Number(module), new Uint8Array(await req.arrayBuffer()));
    }
    if (m === "PUT" && (sha = path.match(/^\/update\/blob\/([0-9a-f]{64})$/))) return this.putBlob(sha[1], new Uint8Array(await req.arrayBuffer()));
    return notFound();
  }

  async putBlob(sha: string, body: Uint8Array): Promise<Response> {
    if (body.length < 1 || body.length > UPDATE_MAX_BLOB_SIZE) return text(400, "blob size must be 1 byte to 4 MiB");
    if ((await sha256Hex(body)) !== sha) return text(400, "sha256 mismatch");
    const sql = this.sql;
    this.sql.tx(() => {
      sql.exec("DELETE FROM blobs WHERE sha = ?", sha);
      for (let i = 0; i * BLOB_ROW < body.length; i++) {
        sql.exec("INSERT INTO blobs (sha, idx, data) VALUES (?, ?, ?)", sha, i, body.slice(i * BLOB_ROW, (i + 1) * BLOB_ROW));
      }
      sql.exec("INSERT OR REPLACE INTO blob_meta (sha, size) VALUES (?, ?)", sha, body.length);
    });
    return text(200, "ok");
  }

  private blobSize(sha: string): number | undefined {
    return this.sql.exec<{ size: number }>("SELECT size FROM blob_meta WHERE sha = ?", sha)[0]?.size;
  }

  /** A whole stored blob, or undefined. */
  blob(sha: string): Uint8Array | undefined {
    const size = this.blobSize(sha);
    if (size === undefined) return undefined;
    const out = new Uint8Array(size);
    for (const row of this.sql.exec<{ idx: number; data: ArrayBuffer }>("SELECT idx, data FROM blobs WHERE sha = ? ORDER BY idx", sha)) {
      out.set(new Uint8Array(row.data), row.idx * BLOB_ROW);
    }
    return out;
  }

  manifestOf(name: string): Uint8Array | undefined {
    const row = this.sql.exec<{ manifest: ArrayBuffer }>("SELECT manifest FROM channels WHERE name = ?", name)[0];
    return row && new Uint8Array(row.manifest);
  }

  private putTest(module: number, body: Uint8Array): Response {
    if (body.length !== SignedManifest.size) return text(400, `manifest must be ${SignedManifest.size} bytes`);
    const m = SignedManifest.decode(body).manifest;
    if (m.magic !== UPDATE_MANIFEST_MAGIC || m.format !== FORMATS[module]) return text(400, "bad manifest magic or format");
    if (m.build < 1) return text(400, "build must be at least 1");
    for (const [what, size, sha] of [["exefs", m.exefs_size, m.exefs_sha256], ["overlay", m.overlay_size, m.overlay_sha256]] as const) {
      if (size < 1 || size > UPDATE_MAX_BLOB_SIZE) return text(400, `${what} size out of range`);
      const stored = this.blobSize(hex(sha));
      if (stored === undefined) return text(400, `${what} blob not uploaded`);
      if (stored !== size) return text(400, `${what} size does not match the uploaded blob`);
    }
    const test = MODULES[module] + "test";
    const cur = this.manifestOf(test);
    if (cur && m.build <= SignedManifest.decode(cur).manifest.build) return text(409, "build is not newer than the current test build");
    this.store(test, body);
    return text(200, "ok");
  }

  private promote(prefix: string): Response {
    const cur = this.manifestOf(prefix + "test");
    if (!cur) return text(404, "no test release");
    this.store(prefix + "stable", cur);
    const m = SignedManifest.decode(cur).manifest;
    return Response.json({ build: m.build, version: oneLine(readUtf8(m.version)) });
  }

  /** Sets a channel's manifest, then deletes blobs no channel references. */
  store(name: string, manifest: Uint8Array) {
    const sql = this.sql;
    this.sql.tx(() => {
      sql.exec("INSERT OR REPLACE INTO channels (name, manifest, at) VALUES (?, ?, ?)", name, manifest, Date.now());
      const keep = sql.exec<{ manifest: ArrayBuffer }>("SELECT manifest FROM channels").flatMap((row) => {
        const m = SignedManifest.decode(new Uint8Array(row.manifest)).manifest;
        return [hex(m.exefs_sha256), hex(m.overlay_sha256)];
      });
      const not = `NOT IN (${keep.map(() => "?").join(",")})`;
      sql.exec(`DELETE FROM blobs WHERE sha ${not}`, ...keep);
      sql.exec(`DELETE FROM blob_meta WHERE sha ${not}`, ...keep);
    });
  }

  private status(): Response {
    const sql = this.sql;
    const channel = (name: string) => {
      const row = sql.exec<{ manifest: ArrayBuffer; at: number }>("SELECT manifest, at FROM channels WHERE name = ?", name)[0];
      if (!row) return null;
      const m = SignedManifest.decode(new Uint8Array(row.manifest)).manifest;
      return { build: m.build, version: oneLine(readUtf8(m.version)), exefs_size: m.exefs_size, overlay_size: m.overlay_size, at: row.at };
    };
    const consoles = sql
      .exec<{ label: string; running_build: number; version: string; channel: number; rejected_build: number; at: number; module: number }>(
        // no label of its own (ldn-tunnel sends none; "?" = rows from before): the token's name, as on /admin
        `SELECT CASE WHEN c.label IN ('', '?') THEN COALESCE(t.name, replace(c.who, 'env:', '')) ELSE c.label END AS label,
           c.running_build, c.version, c.channel, c.rejected_build, c.at, c.module
         FROM console_status c LEFT JOIN tokens t ON c.who = 'c:' || t.id ORDER BY c.at DESC`,
      )
      .map((c) => ({ ...c, channel: MODULES[c.module] + CHANNELS[c.channel as keyof typeof CHANNELS] }));
    const names = [...Object.values(MODULES).flatMap((p) => [p + "stable", p + "test"]), RELEASE_CHANNEL];
    return Response.json({ channels: Object.fromEntries(names.map((n) => [n, channel(n)])), consoles });
  }

  /** GET /logs: `<id>\t<time>\t<label>\t<line>` per stored line. */
  private logs(q: URLSearchParams): Response {
    const after = Number(q.get("after")) || 0;
    const limit = Math.min(Math.max(Math.floor(Number(q.get("limit"))) || 500, 1), 2000);
    const label = q.get("label");
    const rows = this.sql
      .exec<{ id: number; at: number; label: string; text: string }>(
        "SELECT id, at, label, text FROM logs WHERE id > ? AND (? IS NULL OR label = ?) ORDER BY id LIMIT ?",
        after,
        label,
        label,
        limit,
      );
    const out = rows.flatMap((r) =>
      r.text.split("\n").map((line) => `${r.id}\t${new Date(r.at).toISOString()}\t${r.label}\t${line}`),
    );
    return text(200, out.map((l) => l + "\n").join(""));
  }

  /** Handlers/Initialize.cs + MacAddressMemory.TryFind */
  private initialize(ws: Conn, s: Session, payload: Uint8Array) {
    if (s.init) return;
    const m = read(InitializeMessage, payload);
    if (!m) return;
    const sql = this.sql;
    const now = Date.now();
    sql.exec("DELETE FROM macs WHERE at < ?", now - MAC_TTL);
    const known = sql.exec<{ mac: string }>("SELECT mac FROM macs WHERE id = ?", hex(m.id))[0];
    // Same id + same MAC as a previous session: keep the MAC. Otherwise a fresh one never handed out before.
    let mac = known?.mac === hex(m.mac_address) ? known.mac : "";
    while (!mac) {
      const c = randomHex(6);
      if (!sql.exec("SELECT 1 FROM macs WHERE mac = ?", c).length) mac = c;
    }
    sql.exec("INSERT OR IGNORE INTO macs (id, mac, at) VALUES (?, ?, ?)", s.sid, mac, now);
    this.wrote();
    s.mac = mac;
    s.init = true;
    ws.save(s);
    this.send(ws, PacketId.Initialize, InitializeMessage, { id: unhex(s.sid), mac_address: unhex(mac) });
  }

  /** Handlers/Passphrase.cs */
  private passphrase(ws: Conn, s: Session, payload: Uint8Array) {
    const m = read(PassphraseMessage, payload);
    if (!m) return;
    const p = readUtf8(m.passphrase);
    s.pass = p === "" || (p.length === 16 && /Ryujinx-[0-9a-f]{8}/.test(p)) ? p : "";
    ws.save(s);
  }

  /** Handlers/CreateAccessPoint.cs AccessPointConfigToNetworkInfo */
  private createAccessPoint(
    ws: Conn,
    s: Session,
    id: string,
    r: Pick<ReturnType<typeof CreateAccessPointRequest.decode>, "security_config" | "user_config" | "network_config" | "ryu_network_config">,
    dhcpConfig: AddressEntry[],
    advertise: Uint8Array,
  ) {
    if (advertise.length > 0x180) return; // C# CopyTo throws; the message is dropped
    const nc = r.network_config;
    const info = NetworkInfo.zero();
    info.network_id.intent_id.local_communication_id = nc.intent_id.local_communication_id;
    info.network_id.intent_id.scene_id = nc.intent_id.scene_id;
    info.network_id.session_id = unhex(id);
    info.common.channel = nc.channel;
    info.common.link_level = 3;
    info.common.network_type = 2;
    info.common.mac_address = unhex(s.mac);
    info.common.ssid.length = 32;
    info.common.ssid.name = new TextEncoder().encode("12345678123456781234567812345678");
    info.ldn.security_mode = r.security_config.security_mode;
    info.ldn.node_count_max = nc.node_count_max;
    info.ldn.advertise_data_size = advertise.length;
    info.ldn.advertise_data = advertise.slice();

    const me = NodeInfo.zero();
    me.mac_address = unhex(s.mac);
    me.is_connected = 1;
    me.user_name = r.user_config.user_name;
    me.local_communication_version = nc.local_communication_version;

    // P2P is not supported: treat the host's external proxy as unreachable, as C# does when it cannot reach it.
    if (r.ryu_network_config.external_proxy_port !== 0) this.error(ws, NetworkError.PortUnreachable);

    // LdnServer.CreateGame: an id clash is only allowed to replace the caller's own game.
    const old = this.games.get(id);
    if (old && !old.closed) {
      if (old.owner !== s.sid) return this.error(ws, NetworkError.Unknown);
      this.close(old);
      if (old.players.length) this.games.delete(old.id); // detach; still-joined players keep a dangling game id
    }
    const g: Game = {
      id,
      info,
      owner: s.sid,
      pass: s.pass,
      createdAt: Date.now(),
      players: [],
      dhcp: newDhcp(dhcpConfig),
      closed: false,
    };
    this.games.set(id, g);
    if (!this.join(ws, s, g, me)) this.games.delete(id); // node_count_max 0: not even the host fits
  }

  /** Handlers/Connect.cs ConnectImpl */
  private connectImpl(ws: Conn, s: Session, id: string, userName: Uint8Array, version: number) {
    const g = this.games.get(id);
    if (!g || g.closed) return this.error(ws, NetworkError.ConnectNotFound);
    const hostVersion = g.info.ldn.nodes[0].local_communication_version;
    if (version > hostVersion) return this.error(ws, NetworkError.VersionTooHigh);
    if (version < hostVersion) return this.error(ws, NetworkError.VersionTooLow);
    const node = NodeInfo.zero();
    node.mac_address = unhex(s.mac);
    node.is_connected = 1;
    node.user_name = userName;
    node.local_communication_version = version & 0xffff;
    if (!this.join(ws, s, g, node)) this.error(ws, NetworkError.TooManyPlayers);
  }

  /** HostedGame.Connect */
  private join(ws: Conn, s: Session, g: Game, node: NodeInfo): boolean {
    const ldn = g.info.ldn;
    const nodeId = ldn.nodes.findIndex((n) => n.is_connected === 0);
    if (g.closed || ldn.node_count === ldn.node_count_max || nodeId < 0) return false;

    s.ip = requestIp(g.dhcp, unhex(s.mac));
    this.send(ws, PacketId.ProxyConfig, ProxyConfig, { proxy_ip: s.ip, proxy_subnet_mask: NETWORK_MASK });

    node.ipv4_address = s.ip;
    node.node_id = nodeId;
    ldn.node_count++;
    ldn.nodes[nodeId] = node;
    s.nodeId = nodeId;

    this.syncNetwork(g); // to the players already in the game
    s.game = g.id;
    g.players.push({ sid: s.sid, ip: s.ip, nodeId, who: s.who });
    ws.save(s);
    this.persist(g);
    this.send(ws, PacketId.Connected, NetworkInfo, g.info);
    return true;
  }

  /** LdnServer.Scan + Handlers/Scan.cs (without the 200 ms sleep) */
  private scan(ws: Conn, s: Session, payload: Uint8Array) {
    const f = read(ScanFilterFull, payload);
    if (!f) return;
    const flag = f.flag & 0xff;
    const minTime = Date.now() - GHOST_AGE;
    const replies: Uint8Array[] = [];
    for (const g of this.games.values()) {
      if (g.closed || g.pass !== s.pass || g.id === s.game) continue;
      if (g.createdAt < minTime) continue;
      const info = g.info;
      if (info.ldn.station_accept_policy === 1) continue;
      const want = f.network_id.intent_id;
      const have = info.network_id.intent_id;
      if (flag & ScanFilterFlag.LocalCommunicationId && have.local_communication_id !== want.local_communication_id) continue;
      if (flag & ScanFilterFlag.SceneId && have.scene_id !== want.scene_id) continue;
      if (flag & ScanFilterFlag.SessionId && !eq(info.network_id.session_id, f.network_id.session_id)) continue;
      if (flag & ScanFilterFlag.Ssid) {
        const a = info.common.ssid, b = f.ssid;
        if (a.length > 33 || b.length > 33) return; // C# span slice throws: no replies at all
        if (!eq(a.name.subarray(0, a.length), b.name.subarray(0, b.length))) continue;
      }
      if (flag & ScanFilterFlag.NetworkType && info.common.network_type !== (f.network_type & 0xff)) continue;
      if (g.players.length === 0) continue;
      replies.push(packet(PacketId.ScanReply, NetworkInfo.encode(info)));
    }
    for (const r of replies) this.sendRaw(ws, r);
    this.send(ws, PacketId.ScanReplyEnd);
  }

  /** HostedGame.HandleReject */
  private reject(ws: Conn, s: Session, g: Game, payload: Uint8Array) {
    if (payload.length < 8) return;
    const nodeId = new DataView(payload.buffer, payload.byteOffset).getUint32(0, true);
    // by node id, not join order: ids are sparse after a leave. The host cannot reject itself (its game would
    // lose its owner and never close).
    const target = s.sid === g.owner ? g.players.find((p) => p.nodeId === nodeId && p.sid !== s.sid) : undefined;
    if (target) this.detach(target.sid);
    else this.error(ws, NetworkError.RejectFailed);
    this.send(ws, PacketId.RejectReply);
    // C# runs the removal on Task.Run, after the reply above is queued.
    if (target) this.leave(g, target.sid);
  }

  /** LdnSession.DisconnectFromGame */
  private disconnectFromGame(ws: Conn, s: Session, why: string) {
    const g = s.game ? this.games.get(s.game) : undefined;
    if (!s.game) return;
    s.game = null;
    ws.save(s);
    if (!g) return;
    console.log({ ev: "leave", game: g.id, who: s.who, node: s.nodeId, host: g.owner === s.sid, why, left: g.players.length - 1 });
    this.leave(g, s.sid);
    if (g.owner === s.sid) this.close(g);
  }

  /** Clears a session's game pointer (HostedGame.Disconnect's synchronous part). */
  private detach(sid: string) {
    const ws = this.host.conn(sid);
    const s = ws?.load<Session>();
    if (ws && s) {
      s.game = null;
      ws.save(s);
    }
  }

  /** HostedGame.DisconnectInternal */
  private leave(g: Game, sid: string) {
    const p = g.players.find((x) => x.sid === sid);
    if (!p) return;
    g.players = g.players.filter((x) => x !== p);
    returnIp(g.dhcp, p.ip);
    // RemoveFromInfo. C# scans only the first node_count slots, which misses a node above a freed slot (3 players:
    // the 2nd leaves, then the 3rd) and leaves a ghost in the game; every connected slot is checked here.
    const ldn = g.info.ldn;
    for (const n of ldn.nodes) {
      if (n.is_connected && n.ipv4_address === p.ip) {
        ldn.node_count--;
        n.is_connected = 0;
      }
    }
    this.syncNetwork(g);
  }

  /** LdnServer.CloseGame + HostedGame.CloseInternal */
  private close(g: Game) {
    if (!g.closed) {
      g.closed = true;
      const bye = packet(PacketId.Disconnect, DisconnectMessage.encode({ disconnect_ip: 0 }));
      for (const p of g.players) this.sendRaw(this.host.conn(p.sid), bye);
    }
    if (g.players.length === 0) this.drop(g);
    else this.persist(g);
  }

  /** BroadcastNetworkInfoInLock, then persist (every caller has just changed the game). */
  private syncNetwork(g: Game) {
    const msg = packet(PacketId.SyncNetwork, NetworkInfo.encode(g.info));
    for (const p of g.players) this.sendRaw(this.host.conn(p.sid), msg);
    if (g.closed && g.players.length === 0) this.drop(g);
    else this.persist(g);
  }

  /** HostedGame.RouteMessage */
  private route(s: Session, g: Game, type: PacketId, payload: Uint8Array, size: number) {
    const now = Date.now();
    let t = this.traffic.get(g.id);
    if (!t) this.traffic.set(g.id, (t = { routed: 0, dropped: 0, last: now, maxGapMs: 0 }));
    t.maxGapMs = Math.max(t.maxGapMs, now - t.last);
    t.last = now;
    t.dropped++; // undone below once the packet is delivered
    if (payload.length < size) return;
    // C# re-encodes the struct; ProxyData keeps the trailing data.
    const msg = packet(type, type === PacketId.ProxyData ? payload : payload.subarray(0, size));
    const dv = new DataView(msg.buffer, 12);
    const src = dv.getUint32(0, true);
    if (src === 0) dv.setUint32(0, s.ip, true); // bound on 0.0.0.0: others see the sender's IP
    else if (src !== s.ip) return; // can't pretend to be somebody else
    let dest = dv.getUint32(6, true);
    if (dest === BROADCAST_192) dest = BROADCAST; // routing only; the packet keeps 192.168.0.255
    let sent = false;
    if (dest === BROADCAST) {
      for (const p of g.players) sent = this.sendRaw(this.host.conn(p.sid), msg) || sent; // includes the sender, as in C#
    } else {
      const p = g.players.find((x) => x.ip === dest);
      sent = !!p && this.sendRaw(this.host.conn(p.sid), msg);
    }
    if (sent) {
      t.dropped--;
      t.routed++;
    }
  }
}
