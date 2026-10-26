// What the platform-neutral relay core needs from its host (Cloudflare Durable Object or the Node server).
// No platform imports here or anywhere under src/core: Web standard APIs only (fetch, Request, Response,
// crypto.subtle, TextEncoder), which both workerd and Node provide.

/**
 * SQLite, synchronously. Both targets are SQLite (Durable Object storage, node:sqlite), so the core keeps
 * its tables in SQL rather than behind a key-value interface. One statement per exec. BLOB columns come
 * back as ArrayBuffer or Uint8Array depending on the host: wrap them in `new Uint8Array(...)`.
 */
export interface Sql {
  exec<T = Record<string, unknown>>(query: string, ...bindings: unknown[]): T[];
  /** Runs fn atomically. */
  tx<T>(fn: () => T): T;
}

/** One console WebSocket. `load`/`save` keep the per-socket session (survives Durable Object hibernation). */
export interface Conn {
  send(bytes: Uint8Array): void;
  close(code: number, reason: string): void;
  load<T>(): T | null;
  save<T>(state: T): void;
}

/** Replaces the Worker script with a new bundle and rolls it back (Cloudflare only; Docker updates by image). */
export interface Deployer {
  /** Uploads the verified relay-cloudflare.zip as a new version and deploys it at 100%; returns its id. */
  deploy(bundle: Uint8Array): Promise<string>;
  /** Deploys the version before the active one at 100%; returns its id. */
  rollback(): Promise<string>;
}

export interface Host {
  sql: Sql;
  /** Every open console socket. */
  conns(): Conn[];
  /** The open socket of a session id, if any. */
  conn(sid: string): Conn | undefined;
  getAlarm(): Promise<number | null>;
  setAlarm(at: number): Promise<void>;
  /** Secrets and settings: TOKEN_*, UPDATE_ADMIN, ADMIN, PUBLISHER_KEY. */
  env: Record<string, unknown>;
  fetch: typeof fetch;
  /** Text files shipped in every console zip. */
  assets: { ca: string; gamelist: string };
  platform: "cloudflare" | "docker";
  deployer?: Deployer;
}

/** What `Relay.http` answers to an authenticated WebSocket upgrade: the adapter opens the socket. */
export interface Accept {
  accept: string; // who: "env:<TOKEN_NAME>" or "c:<console id>"
}
