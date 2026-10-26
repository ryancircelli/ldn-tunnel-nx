// Standalone Node adapter: HTTP + WebSocket (`ws`) in front of the relay core, SQLite on node:sqlite.
// Plain HTTP only; TLS is the reverse proxy's job (Caddyfile). Env: PORT (8080), DB_PATH (./data/relay.sqlite),
// TRUST_PROXY (set to 1 only behind a proxy that overwrites X-Forwarded-For, like the Caddy in docker-compose),
// plus the same TOKEN_*, ADMIN, UPDATE_ADMIN, PUBLISHER_KEY the Cloudflare adapter reads.
import { createServer, type IncomingMessage, type Server } from "node:http";
import { mkdirSync, readFileSync } from "node:fs";
import { dirname } from "node:path";
import { Readable } from "node:stream";
import { DatabaseSync, type SQLInputValue } from "node:sqlite";
import { WebSocketServer, type WebSocket } from "ws";
import { Relay } from "../core/relay.ts";
import { MAX_PACKET_SIZE } from "../core/codec/types.ts";
import type { Conn, Host } from "../core/ports.ts";

const asset = (name: string) => readFileSync(new URL(`../../assets/${name}`, import.meta.url), "utf8");

export interface Options {
  port?: number;
  dbPath?: string; // ":memory:" works for tests
  env?: Record<string, unknown>;
}

export function startServer(o: Options = {}): Promise<{ server: Server; port: number; close(): Promise<void> }> {
  const env = o.env ?? process.env;
  const dbPath = o.dbPath ?? process.env.DB_PATH ?? "./data/relay.sqlite";
  if (dbPath !== ":memory:") mkdirSync(dirname(dbPath), { recursive: true });
  const db = new DatabaseSync(dbPath);
  db.exec("PRAGMA journal_mode = WAL");

  const conns = new Map<string, Conn>(); // sid -> Conn
  let alarm: number | null = null;
  let timer: NodeJS.Timeout | undefined;
  let depth = 0;
  let stopping = false; // shutdown leaves the games as they are; the next start reconciles them

  const wrap = (ws: WebSocket): Conn => {
    let state: unknown = null;
    return {
      send: (b) => ws.send(b),
      close: (code, reason) => ws.close(code, reason),
      load: <T>() => state as T | null,
      save: (s) => void (state = s),
    };
  };

  const host: Host = {
    sql: {
      exec: <T>(q: string, ...b: unknown[]) => db.prepare(q).all(...b.map((v) => (v instanceof ArrayBuffer ? new Uint8Array(v) : v) as SQLInputValue)) as T[],
      tx: (fn) => {
        if (depth++ > 0) { try { return fn(); } finally { depth--; } } // nested: the outer one commits
        db.exec("BEGIN");
        try {
          const r = fn();
          db.exec("COMMIT");
          return r;
        } catch (e) {
          db.exec("ROLLBACK");
          throw e;
        } finally {
          depth = 0;
        }
      },
    },
    conns: () => [...conns.values()],
    conn: (sid) => conns.get(sid),
    getAlarm: async () => alarm,
    setAlarm: async (at) => {
      alarm = at;
      clearTimeout(timer);
      timer = setTimeout(() => {
        alarm = null;
        relay.alarm().catch((e) => console.error("alarm", e));
      }, Math.max(0, at - Date.now()));
    },
    env,
    fetch: (...a) => fetch(...a),
    assets: { ca: asset("ca.pem"), gamelist: asset("gamelist.txt") },
    platform: "docker",
  };
  const relay = new Relay(host);

  // Without a trusted proxy any client could send X-Forwarded-* and pick the address the login limiter counts.
  const trustProxy = env.TRUST_PROXY === "1" || env.TRUST_PROXY === "true";
  const toRequest = (req: IncomingMessage): Request => {
    const headers = { ...req.headers } as Record<string, string>;
    // the admin login limiter keys on the last X-Forwarded-For hop: the proxy's, else this socket's peer
    if (!trustProxy || !headers["x-forwarded-for"]) headers["x-forwarded-for"] = req.socket.remoteAddress ?? "";
    const init: RequestInit & { duplex?: "half" } = { method: req.method, headers };
    if (req.method !== "GET" && req.method !== "HEAD") Object.assign(init, { body: Readable.toWeb(req), duplex: "half" });
    // the proxy terminates TLS: the admin page's same-origin check compares against the public scheme
    const proto = trustProxy && req.headers["x-forwarded-proto"] === "https" ? "https" : "http";
    return new Request(`${proto}://${req.headers.host ?? "localhost"}${req.url}`, init);
  };

  // one message is one packet, and the core refuses packets this big anyway (ws's default is 100 MiB)
  const wss = new WebSocketServer({ noServer: true, maxPayload: MAX_PACKET_SIZE });
  const server = createServer(async (req, res) => {
    try {
      const r = await relay.http(toRequest(req));
      if (!(r instanceof Response)) return void res.writeHead(404).end(); // an upgrade-less accept cannot happen
      res.writeHead(r.status, Object.fromEntries(r.headers));
      res.end(Buffer.from(await r.arrayBuffer()));
    } catch (e) {
      console.error(e);
      if (!res.headersSent) res.writeHead(500);
      res.end();
    }
  });

  server.on("upgrade", async (req, socket, head) => {
    const refuse = (status: number) => socket.end(`HTTP/1.1 ${status} X\r\nContent-Length: 0\r\nConnection: close\r\n\r\n`);
    try {
      if (req.method !== "GET") return refuse(404);
      const r = await relay.http(toRequest(req));
      if (r instanceof Response) return refuse(r.status);
      wss.handleUpgrade(req, socket, head, async (ws) => {
        const s = relay.newSession(r.accept);
        const c = wrap(ws);
        conns.set(s.sid, c);
        ws.on("message", (data, isBinary) => {
          const b = data as Buffer;
          relay.message(c, isBinary ? new Uint8Array(b) : b.toString("utf8"));
        });
        const gone = () => {
          if (conns.get(s.sid) !== c) return;
          conns.delete(s.sid);
          if (!stopping) relay.closed(c);
        };
        ws.on("close", gone);
        ws.on("error", gone);
        await relay.open(c, s);
      });
    } catch (e) {
      console.error(e);
      socket.destroy();
    }
  });

  return new Promise((resolve) => {
    server.listen(o.port ?? Number(process.env.PORT ?? 8080), () => {
      resolve({
        server,
        port: (server.address() as { port: number }).port,
        close: () => {
          stopping = true;
          clearTimeout(timer);
          for (const c of conns.values()) c.close(1001, "shutdown");
          const done = new Promise<void>((r) => server.close(() => (db.close(), r())));
          server.closeIdleConnections(); // keep-alive HTTP clients would otherwise hold the stop until Docker's SIGKILL
          setTimeout(() => (wss.clients.forEach((w) => w.terminate()), server.closeAllConnections()), 1000).unref(); // a peer that never answers the close frame
          return done;
        },
      });
    });
  });
}

if (import.meta.main) {
  const { port, close } = await startServer();
  console.log(`relay listening on :${port}`);
  for (const sig of ["SIGTERM", "SIGINT"]) process.on(sig, () => close().then(() => process.exit(0)));
}
