// Copies the test release to the stable channel.   npm run promote [-- --url <relay>] [-- --module ryu_ldn_nx|ldn-tunnel]
import { readFileSync } from "node:fs";
import { parseArgs } from "node:util";
import { moduleOf } from "./update-manifest.ts";

const { values } = parseArgs({
  options: {
    module: { type: "string" },
    url: { type: "string", default: process.env.RELAY_URL },
    "token-file": { type: "string", default: new URL("../../secrets/update-admin.token", import.meta.url).pathname },
  },
});
if (!values.url) throw new Error("pass --url <relay> or set RELAY_URL");
const token = readFileSync(values["token-file"]!, "utf8").trim();
const { prefix } = moduleOf(values.module);
const res = await fetch(`${values.url}/update/${prefix}promote`, { method: "POST", headers: { Authorization: `Bearer ${token}` } });
if (!res.ok) throw new Error(`POST /update/${prefix}promote -> ${res.status} ${await res.text()}`);
const r = (await res.json()) as { build: number; version: string };
console.log(`promoted build ${r.build} (${r.version}) to ${prefix}stable`);
