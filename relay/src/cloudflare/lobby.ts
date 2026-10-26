// Durable Object adapter: one object ("main") runs the relay core on the hibernation WebSocket API and
// the object's SQLite storage. Also the self-update deployer (Cloudflare API, docs/relay-hosting.md).
import { DurableObject } from "cloudflare:workers";
import { unzipSync } from "fflate";
import { Relay, type Session } from "../core/relay.ts";
import type { Conn, Deployer, Host } from "../core/ports.ts";
import { Drops, type Edge } from "../core/drops.ts";
import ca from "../../assets/ca.pem";
import gamelist from "../../assets/gamelist.txt";
import { COMPATIBILITY_DATE } from "./compat.ts";

type Tagged = Session & { edge?: Edge };
const conn = (ws: WebSocket, drops?: Drops): Conn => ({
  send: (b) => (drops?.out(ws), ws.send(b)),
  close: (code, reason) => {
    const s = ws.deserializeAttachment() as Tagged | null;
    drops?.ended(ws, "relay", code, reason, true, s?.who, s?.edge);
    ws.close(code, reason);
  },
  load: <T>() => ws.deserializeAttachment() as T | null,
  save: (s) => ws.serializeAttachment(s),
});

/** Content type of each uploaded module, by extension. */
const TYPES: Record<string, string> = {
  ".js": "application/javascript+module", ".mjs": "application/javascript+module", ".map": "application/source-map",
  ".wasm": "application/wasm", ".txt": "text/plain", ".pem": "text/plain",
};
/** Must match wrangler.toml: every self-uploaded version restates the bindings that are not secrets or vars. */
const BINDINGS = [{ type: "durable_object_namespace", name: "LOBBY", class_name: "Lobby" }];

export function cloudflareDeployer(env: Record<string, unknown>, f: typeof fetch): Deployer | undefined {
  const { CF_API_TOKEN: token, CF_ACCOUNT_ID: account, CF_WORKER_NAME: name } = env;
  if (typeof token !== "string" || !token || typeof account !== "string" || !account || typeof name !== "string" || !name) return undefined;
  const api = async (path: string, init: RequestInit = {}) => {
    const res = await f(`https://api.cloudflare.com/client/v4/accounts/${encodeURIComponent(account)}/workers/scripts/${encodeURIComponent(name)}${path}`, {
      ...init,
      headers: { Authorization: `Bearer ${token}`, ...init.headers },
    });
    const body = (await res.json().catch(() => ({}))) as { success?: boolean; result?: any; errors?: { message: string }[] };
    if (!res.ok || !body.success) throw new Error(`Cloudflare API ${path}: ${body.errors?.map((e) => e.message).join("; ") || "HTTP " + res.status}`);
    return body.result;
  };
  const deployVersion = (id: string) =>
    api("/deployments", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ strategy: "percentage", versions: [{ version_id: id, percentage: 100 }] }) });
  return {
    async deploy(zip) {
      // relay-cloudflare.zip (docs/relay-releases.md): the bundled modules + metadata.json {main_module, compatibility_date, compatibility_flags}
      const files = unzipSync(zip);
      const meta = JSON.parse(new TextDecoder().decode(files["metadata.json"] ?? new Uint8Array())) as {
        main_module?: string; compatibility_date?: string; compatibility_flags?: string[];
      };
      if (!meta.main_module || !files[meta.main_module]) throw new Error("relay bundle: metadata.json names no main module in the zip");
      const form = new FormData();
      form.set("metadata", new Blob([JSON.stringify({
        main_module: meta.main_module,
        compatibility_date: meta.compatibility_date ?? COMPATIBILITY_DATE,
        compatibility_flags: meta.compatibility_flags ?? [],
        // a version upload replaces the bindings: restate the Durable Object, keep secrets and vars
        bindings: BINDINGS,
        keep_bindings: ["secret_text", "secret_key", "plain_text", "json"],
      })], { type: "application/json" }));
      for (const [name, data] of Object.entries(files)) {
        if (name === "metadata.json" || name.endsWith("/")) continue;
        form.append(name, new Blob([data], { type: TYPES[name.slice(name.lastIndexOf("."))] ?? "application/octet-stream" }), name);
      }
      const v = await api("/versions", { method: "POST", body: form });
      await deployVersion(v.id);
      return v.id as string;
    },
    async rollback() {
      const { deployments } = (await api("/deployments")) as { deployments: { versions: { version_id: string }[] }[] };
      const prev = deployments[1]?.versions[0]?.version_id; // [0] is the active deployment
      if (!prev) throw new Error("no previous deployment to go back to");
      await deployVersion(prev);
      return prev;
    },
  };
}

export class Lobby extends DurableObject<Env> {
  private relay: Relay;
  private drops: Drops;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    const e = env as unknown as Record<string, unknown>;
    const f: typeof fetch = (...a) => fetch(...a);
    const host: Host = {
      sql: {
        exec: <T>(q: string, ...b: unknown[]) => ctx.storage.sql.exec(q, ...(b as SqlStorageValue[])).toArray() as T[],
        tx: (fn) => ctx.storage.transactionSync(fn),
      },
      conns: () => ctx.getWebSockets().map((ws) => conn(ws, this.drops)),
      conn: (sid) => {
        const ws = ctx.getWebSockets(sid)[0];
        return ws && conn(ws, this.drops);
      },
      getAlarm: () => ctx.storage.getAlarm(),
      setAlarm: (at) => ctx.storage.setAlarm(at),
      env: e,
      fetch: f,
      assets: { ca, gamelist },
      platform: "cloudflare",
      deployer: cloudflareDeployer(e, f),
    };
    this.drops = new Drops(host.sql, ctx.getWebSockets().length);
    this.relay = new Relay(host);
  }

  async fetch(req: Request): Promise<Response> {
    const r = await this.relay.http(req);
    if (r instanceof Response) return r;
    const [client, server] = Object.values(new WebSocketPair());
    const s: Tagged = { ...this.relay.newSession(r.accept), edge: { at: Date.now(), colo: req.cf?.colo as string, country: req.cf?.country as string } };
    this.ctx.acceptWebSocket(server, [s.sid]);
    await this.relay.open(conn(server, this.drops), s);
    return new Response(null, { status: 101, webSocket: client });
  }

  async webSocketMessage(ws: WebSocket, msg: ArrayBuffer | string) {
    this.drops.in(ws);
    this.relay.message(conn(ws, this.drops), msg);
  }

  async webSocketClose(ws: WebSocket, code: number, reason: string, wasClean: boolean) {
    const s = conn(ws).load<Tagged>();
    this.drops.ended(ws, "peer", code, reason, wasClean, s?.who, s?.edge);
    this.relay.closed(conn(ws, this.drops));
  }

  async webSocketError(ws: WebSocket, error: unknown) {
    const s = conn(ws).load<Tagged>();
    this.drops.ended(ws, "error", 1006, String(error), false, s?.who, s?.edge);
    this.relay.closed(conn(ws, this.drops));
  }

  async alarm() {
    await this.relay.alarm();
  }
}
