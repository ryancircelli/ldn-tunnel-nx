// End-to-end check with two desktop clients.
//   npm run test:e2e                         starts `wrangler dev` with throwaway tokens, tests it, stops it
//   npm run test:e2e -- --url wss://host/ldn uses LDN_TOKEN_A (and LDN_TOKEN_B, default A) against a running relay
//   npm run test:e2e -- --tcp 127.0.0.1:30456 runs the lobby part against a C# LdnServer, for comparison
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { parseArgs } from "node:util";
import { NetworkInfo, PacketId, ProxyConfig, ProxyDataHeader } from "../src/core/codec/types.ts";
import { ip } from "./ldn-client.ts";
import { authHeaders, connectTcp, connectWs, upgradeStatus, type Conn } from "./client.ts";

const { values } = parseArgs({ options: { url: { type: "string" }, tcp: { type: "string" } } });

async function step(name: string, f: () => Promise<void>) {
  await f();
  console.log(`ok - ${name}`);
}

async function authChecks(url: string, tokenA: string) {
  const status = (h: Record<string, string>) => upgradeStatus(url, h);
  await step("missing token -> 404", async () => assert.equal(await status({}), 404));
  await step("wrong token -> 404", async () => assert.equal(await status(authHeaders("0".repeat(64))), 404));
  await step("legacy X-Console-Id header is ignored -> 101", async () =>
    assert.equal(await status({ ...authHeaders(tokenA), "X-Console-Id": "anything" }), 101));
  await step("right token -> 101", async () => assert.equal(await status(authHeaders(tokenA)), 101));
}

async function lobby(open: (who: "a" | "b") => Promise<Conn>) {
  const lcid = BigInt("0x" + randomBytes(7).toString("hex")); // not seen by anyone else's scans
  const a = await open("a");
  const b = await open("b");
  await a.initialize();
  await b.initialize();

  let hostIp = 0, joinIp = 0;
  await step("A creates an access point", async () => {
    a.createAp({ name: "E2E-A", lcid });
    hostIp = ProxyConfig.decode(await a.expect(PacketId.ProxyConfig)).proxy_ip;
    assert.equal(NetworkInfo.decode(await a.expect(PacketId.Connected)).ldn.node_count, 1);
  });
  let found: NetworkInfo[] = [];
  await step("B's scan sees it", async () => {
    found = await b.scanAll(lcid);
    assert.equal(found.length, 1);
    assert.equal(found[0].ldn.nodes[0].ipv4_address, hostIp);
  });
  await step("B connects; A gets SyncNetwork", async () => {
    b.connect(found[0], { name: "E2E-B" });
    joinIp = ProxyConfig.decode(await b.expect(PacketId.ProxyConfig)).proxy_ip;
    assert.equal(NetworkInfo.decode(await b.expect(PacketId.Connected)).ldn.node_count, 2);
    assert.equal(NetworkInfo.decode(await a.expect(PacketId.SyncNetwork)).ldn.node_count, 2);
  });
  await step("ProxyData B -> A, source stamped", async () => {
    b.proxyData(0, hostIp, new TextEncoder().encode("hello"));
    const p = await a.expect(PacketId.ProxyData);
    assert.equal(ProxyDataHeader.decode(p).info.source_ipv4, joinIp);
    assert.equal(new TextDecoder().decode(p.subarray(ProxyDataHeader.size)), "hello");
  });
  await step("ProxyData A -> B", async () => {
    a.proxyData(hostIp, joinIp, new TextEncoder().encode("world"));
    const p = await b.expect(PacketId.ProxyData);
    assert.equal(new TextDecoder().decode(p.subarray(ProxyDataHeader.size)), "world");
  });
  await step("spoofed source IP is dropped", async () => {
    b.proxyData(hostIp, hostIp, new Uint8Array([1]));
    b.proxyData(ip("10.114.9.9"), hostIp, new Uint8Array([2]));
    await a.none(500);
  });
  await step("A leaves: B gets SyncNetwork then Disconnect", async () => {
    a.send(PacketId.Disconnect, new Uint8Array(4));
    assert.equal(NetworkInfo.decode(await b.expect(PacketId.SyncNetwork)).ldn.node_count, 1);
    await b.expect(PacketId.Disconnect);
  });
  a.close();
  b.close();
}

if (values.tcp) {
  const [host, port] = values.tcp.split(":");
  await lobby(() => connectTcp(host, Number(port)));
} else if (values.url) {
  const tokens = { a: process.env.LDN_TOKEN_A ?? "", b: process.env.LDN_TOKEN_B || process.env.LDN_TOKEN_A || "" };
  await authChecks(values.url, tokens.a);
  await lobby((who) => connectWs(values.url!, authHeaders(tokens[who])));
} else {
  const tokens = { a: randomBytes(32).toString("hex"), b: randomBytes(32).toString("hex") };
  const sha = (t: string) => createHash("sha256").update(t).digest("hex");
  const port = 18787 + Math.floor(Math.random() * 1000);
  const url = `ws://127.0.0.1:${port}/ldn`;
  const dev = spawn(
    "npx",
    ["wrangler", "dev", "--ip", "127.0.0.1", "--port", String(port),
      "--var", `TOKEN_SWITCH_A:${sha(tokens.a)}`, "--var", `TOKEN_SWITCH_B:${sha(tokens.b)}`],
    { detached: true, stdio: ["ignore", "ignore", "inherit"] },
  );
  const stop = () => {
    try {
      process.kill(-dev.pid!, "SIGTERM");
    } catch {}
  };
  try {
    for (let i = 0; ; i++) {
      try {
        await upgradeStatus(url, {});
        break;
      } catch {
        if (i > 120) throw new Error("wrangler dev did not start");
        await new Promise((r) => setTimeout(r, 500));
      }
    }
    await authChecks(url, tokens.a);
    await lobby((who) => connectWs(url, authHeaders(tokens[who])));
  } finally {
    stop();
  }
}
console.log("e2e: all passed");
