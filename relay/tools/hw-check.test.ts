// hw-check against a fake admin API: one console with a good session, one with an error and no datagram.
//   node --experimental-transform-types --test tools/hw-check.test.ts   (make test-relay)
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { test } from "node:test";
import { run, type Opts } from "./hw-check.ts";

const SECRET = "correct horse";
const T0 = 1_800_000_000_000;
const good = [
  "[     1.200] [INFO] ldn-tunnel 0.2.0 (build 1761500000) starting",
  "[     1.300] [INFO] mem: heap high=262144 of 1048576 proc=4194304 of 8388608",
  "[     9.000] [INFO] ldn: relay handshake done",
  "[    20.000] [INFO] bsd: client 3 fd 5 tracked (type 2)",
  "[    21.000] [INFO] ldn: connected: 1/8 nodes, local node 0",
  "[    22.000] [INFO] bsd: client 3 fd 5 bound to the LDN proxy (port 12345)",
  "[    30.000] [INFO] ldn: connected: 2/8 nodes, local node 0",
  "[    31.000] [INFO] bsd: first ProxyData out: 0A720001:12345 -> 0A720002:12345, 64 bytes",
  "[    31.100] [INFO] bsd: first ProxyData in: 0A720002:12345 -> 0A720001:12345, 80 bytes, queued on 1 sockets",
  "[    31.200] [INFO] bsd: client 3 first datagram from the relay (80 bytes)",
  "[    32.000] [WARN] relay: link down (Some(Closed))",
];
const bad = good.filter((l) => !l.includes("datagram from")).concat("[    40.000] [ERROR] ldn: relay NetworkError Some(1)");
const logs: Record<string, string[]> = { a: good, b: bad };

const server = createServer((req, res) => {
  const send = (status: number, body?: unknown, headers: Record<string, string> = {}) =>
    res.writeHead(status, { "content-type": "application/json", ...headers }).end(body === undefined ? undefined : JSON.stringify(body));
  if (req.url === "/admin/login" && req.method === "POST") {
    let b = "";
    req.on("data", (c) => (b += c)).on("end", () => {
      if (!req.headers.origin) return send(403);
      if (JSON.parse(b).secret !== SECRET) return send(401);
      send(204, undefined, { "set-cookie": `ldnt_admin=${"f".repeat(64)}; Path=/; HttpOnly; Secure; SameSite=Strict` });
    });
    return;
  }
  if (req.headers.cookie !== `ldnt_admin=${"f".repeat(64)}`) return send(401);
  if (req.url === "/api/consoles") {
    return send(200, [
      { id: "a", name: "Switch A", version: "0.2.0", lastSeen: T0 + 60_000 },
      { id: "b", name: "Switch B", version: "0.2.0", lastSeen: T0 + 60_000 },
      { id: "old", name: "Spare", version: "0.1.0", lastSeen: T0 - 86_400_000 },
    ]);
  }
  const m = /^\/api\/consoles\/(\w+)\/logs\?limit=\d+$/.exec(req.url ?? "");
  if (m && logs[m[1]]) {
    // one line from before the window (an older boot) that must not count
    return send(200, [{ at: T0 - 1000, line: "[ 99.000] [ERROR] old boot" }, ...logs[m[1]].map((line, i) => ({ at: T0 + i, line }))]);
  }
  send(404);
});

test("hw-check: PASS/FAIL per console from the admin API", async () => {
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  const o: Opts = { since: T0, version: "v0.2.0", allow: [/link down \(Some\(Closed\)\)/], heapMax: 896 * 1024, nodes: 2 };
  try {
    const r = await run(base, SECRET, o, [], 2000);
    const out = r.out.join("\n");
    assert.equal(r.ok, false, out);
    assert.match(out, /^PASS {2}Switch A \(a\)/m);
    assert.match(out, /^FAIL {2}Switch B \(b\)/m);
    assert.match(out, /FAIL {2}datagram from relay/);
    assert.match(out, /FAIL {2}no errors +1: .*NetworkError/);
    assert.doesNotMatch(out, /Spare|old boot/);

    // only the good console, by name; without --allow its "link down" fails it
    assert.equal((await run(base, SECRET, o, ["Switch A", "a"], 2000)).ok, false, "a session needs 2 consoles");
    const strict = await run(base, SECRET, { ...o, allow: [] }, ["Switch A"], 2000);
    assert.match(strict.out.join("\n"), /FAIL {2}no errors +1: .*link down/);
    // wrong version
    const v = await run(base, SECRET, { ...o, version: "0.3.0" }, ["a"], 2000);
    assert.match(v.out.join("\n"), /FAIL {2}started +version 0\.2\.0, expected 0\.3\.0/);
    await assert.rejects(run(base, "wrong", o, [], 2000), /login -> 401/);
  } finally {
    server.close();
  }
});
