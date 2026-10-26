// Shows a module's channels and the consoles running it.   npm run status [-- --url <relay>] [-- --module ryu_ldn_nx|ldn-tunnel]
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
const { id, prefix } = moduleOf(values.module);
const res = await fetch(values.url + "/update/status", { headers: { Authorization: `Bearer ${token}` } });
if (!res.ok) throw new Error(`GET /update/status -> ${res.status}`);

type Channel = { build: number; version: string; exefs_size: number; overlay_size: number; at: number } | null;
const s = (await res.json()) as {
  channels: Record<string, Channel>;
  consoles: { label: string; running_build: number; version: string; channel: string; rejected_build: number; at: number; module: number }[];
};

const ago = (t: number) => {
  const sec = Math.max(0, Math.round((Date.now() - t) / 1000));
  if (sec < 90) return `${sec} s ago`;
  if (sec < 5400) return `${Math.round(sec / 60)} min ago`;
  if (sec < 129600) return `${Math.round(sec / 3600)} h ago`;
  return `${Math.round(sec / 86400)} days ago`;
};
const red = (t: string) => (process.stdout.isTTY ? `\x1b[1;31m${t}\x1b[0m` : t);

for (const name of [prefix + "stable", prefix + "test"]) {
  const c = s.channels[name];
  console.log(`${name.padEnd(17)} ${c ? `build ${c.build} (${c.version}), exefs ${c.exefs_size} B, overlay ${c.overlay_size} B, published ${ago(c.at)}` : "none"}`);
}
console.log();
const consoles = s.consoles.filter((c) => c.module === id);
if (!consoles.length) console.log("no consoles have checked in yet");
for (const c of consoles) {
  const want = s.channels[c.channel]?.build;
  const behind = want !== undefined && c.running_build !== want;
  const line = `${c.label.padEnd(24)} ${c.channel.padEnd(17)} running ${c.running_build} (${c.version || "?"})${behind ? ` != ${want}` : ""}${
    c.rejected_build ? ` REJECTED ${c.rejected_build}` : ""
  }, checked ${ago(c.at)}`;
  console.log(behind || c.rejected_build ? red(line) : line);
}
