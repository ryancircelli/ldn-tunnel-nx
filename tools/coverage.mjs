// `make coverage` runs the suites with coverage on, then this prints the line coverage. With a directory
// argument it also writes the shields.io endpoint badges CI publishes on the badges branch (docs/testing.md).
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";

const json = (path) => JSON.parse(readFileSync(path, "utf8"));
const llvm = (path) => json(path).data[0].totals.lines; // cargo llvm-cov --json --summary-only
const vitest = (path) => { const l = json(path).total.lines; return { count: l.total, covered: l.covered, percent: l.pct }; };

const rows = [
  ["crates/core", llvm("target/coverage/core.json"), "rust-core.json", "coverage (Rust core)"],
  ["crates/tls", llvm("target/coverage/tls.json")],
  ["vendor/nx IPC layer (crates/ipc-tests)", llvm("target/coverage/ipc.json")],
  ["relay/src", vitest("relay/coverage/coverage-summary.json"), "relay.json", "coverage (relay)"],
];

for (const [name, l] of rows) console.log(`${name.padEnd(40)} ${l.percent.toFixed(1).padStart(5)}%  (${l.covered}/${l.count} lines)`);

const out = process.argv[2];
if (out) {
  mkdirSync(out, { recursive: true });
  for (const [, l, file, label] of rows.filter((r) => r[2])) {
    const pct = Math.floor(l.percent);
    const color = pct >= 80 ? "brightgreen" : pct >= 60 ? "yellow" : "red";
    writeFileSync(`${out}/${file}`, JSON.stringify({ schemaVersion: 1, label, message: `${pct}%`, color }) + "\n");
  }
}
