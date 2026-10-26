// Reads the consoles' debug log from the relay (GET /logs).
//   npm run logs [-- --follow] [-- --label <name>] [-- --since-minutes <n>]
// The console token comes from LDN_TOKEN and only ever goes in the Authorization header.
import { parseArgs } from "node:util";

const { values } = parseArgs({
  options: { follow: { type: "boolean" }, label: { type: "string" }, "since-minutes": { type: "string" }, url: { type: "string" } },
});
const base = values.url ?? (process.env.RELAY_URL ? process.env.RELAY_URL + "/logs" : "");
if (!base) throw new Error("pass --url <relay>/logs or set RELAY_URL");
const token = process.env.LDN_TOKEN ?? "";
if (!token) throw new Error("set LDN_TOKEN to a console token");
const since = values["since-minutes"] ? Date.now() - Number(values["since-minutes"]) * 60_000 : 0;

let after = 0;
async function poll(): Promise<number> {
  const q = new URLSearchParams({ after: String(after), limit: "2000" });
  if (values.label) q.set("label", values.label);
  const res = await fetch(`${base}?${q}`, { headers: { Authorization: `Bearer ${token}` } });
  if (!res.ok) throw new Error(`GET /logs -> ${res.status}`);
  const lines = (await res.text()).split("\n").filter(Boolean);
  for (const l of lines) {
    const [id, time] = l.split("\t");
    after = Math.max(after, Number(id));
    if (Date.parse(time) >= since) console.log(l);
  }
  return lines.length;
}

// a full page means more is waiting: drain before sleeping
while ((await poll()) >= 2000 || values.follow) {
  if (values.follow) await new Promise((r) => setTimeout(r, 2000));
}
