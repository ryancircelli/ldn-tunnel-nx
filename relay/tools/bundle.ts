// Builds relay-cloudflare.zip, the Worker that a relay's update button deploys (docs/relay-releases.md):
// `wrangler deploy --dry-run` output (worker.js, its source map, text modules) + metadata.json.
//   npm run bundle -- [--out relay-cloudflare.zip]
// Write the release tag into release.json first: the bundle carries it as the relay's version.
import { execFileSync } from "node:child_process";
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseArgs } from "node:util";
import { zipSync } from "fflate";
import { COMPATIBILITY_DATE } from "../src/cloudflare/compat.ts";

const { values } = parseArgs({ options: { out: { type: "string", default: "relay-cloudflare.zip" } } });
const dir = mkdtempSync(join(tmpdir(), "relay-bundle-"));
try {
  execFileSync("npx", ["wrangler", "deploy", "--dry-run", "--outdir", dir], { stdio: ["ignore", "ignore", "inherit"] });
  const files: Record<string, Uint8Array> = {};
  for (const name of readdirSync(dir)) if (name !== "README.md") files[name] = readFileSync(join(dir, name));
  if (!files["worker.js"]) throw new Error("wrangler produced no worker.js");
  files["metadata.json"] = new TextEncoder().encode(JSON.stringify({ main_module: "worker.js", compatibility_date: COMPATIBILITY_DATE }));
  writeFileSync(values.out!, zipSync(files));
  console.log(`${values.out}: ${Object.keys(files).join(", ")}`);
} finally {
  rmSync(dir, { recursive: true, force: true });
}
