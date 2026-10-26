import { describe, expect, it } from "vitest";
import { adminPage } from "../src/core/admin/index.ts";
import { LOGIC_SRC } from "../src/core/admin/logic.ts";

const L = new Function(`${LOGIC_SRC}; return { renderConsoles, renderLogs, releaseState, inviteHint, ago };`)() as any;

describe("adminPage", () => {
  const html = adminPage();
  it("is a full page with every id the script uses", () => {
    expect(html.startsWith("<!doctype html>")).toBe(true);
    const used = [...html.matchAll(/\$\("([\w-]+)"\)/g)].map((m) => m[1]);
    expect(used.length).toBeGreaterThan(10);
    for (const id of new Set(used)) expect(html, id).toContain(`id="${id}"`);
  });
  it("has no external assets and a script that parses", () => {
    expect(html).not.toMatch(/(src|href)="https?:/);
    const js = html.match(/<script>([\s\S]*)<\/script>/)![1];
    expect(() => new Function(js)).not.toThrow();
  });
});

describe("logic", () => {
  const now = 1_000_000_000_000;
  it("renders consoles, escaping names", () => {
    const h = L.renderConsoles([{ id: "a1", name: '<b>"x"', version: "1.2.0", runningBuild: 7, online: false, lastSeen: now - 3 * 3600_000 }], now);
    expect(h).not.toContain("<b>");
    expect(h).toContain("last seen 3 h ago");
    expect(h).toContain("v1.2.0");
    expect(h).toContain('data-id="a1"');
    expect(L.renderConsoles([], now)).toContain("No consoles");
  });
  it("greys out deploy-time tokens", () => {
    const h = L.renderConsoles([{ id: "env:TOKEN_A", name: "TOKEN_A", online: false }], now);
    expect(h).toContain("readonly");
    expect(h).toContain("disabled");
  });
  it("shows online and rejected builds", () => {
    const h = L.renderConsoles([{ id: "a", name: "n", online: true, rejectedBuild: 9 }], now);
    expect(h).toContain("dot on");
    expect(h).toContain("rejected build 9");
  });
  it("lists logs newest first", () => {
    const t = L.renderLogs([{ at: 1000, line: "old" }, { at: 5000, line: "new" }]);
    expect(t.indexOf("new")).toBeLessThan(t.indexOf("old"));
  });
  it("release state per platform", () => {
    const dep = { version: "1.0.0", build: 10 };
    const cf = L.releaseState({ deployed: dep, latest: { version: "1.1.0", build: 20, url: "u" }, platform: "cloudflare", canSelfUpdate: true });
    expect(cf).toMatchObject({ newer: true, canUpdate: true, canRollback: true, latest: "v1.1.0", showCommand: false });
    const dk = L.releaseState({ deployed: dep, latest: { version: "1.1.0", build: 20, url: "u" }, platform: "docker", updateCommand: "docker pull x" });
    expect(dk).toMatchObject({ canUpdate: false, canRollback: false, showCommand: true, command: "docker pull x" });
    const same = L.releaseState({ deployed: dep, latest: { version: "1.0.0", build: 10, url: "u" }, platform: "cloudflare" });
    expect(same).toMatchObject({ newer: false, canUpdate: false });
    expect(same.text).toContain("Up to date");
    expect(L.releaseState({ deployed: dep, platform: "cloudflare" }).newer).toBe(false);
  });
  it("falls back to semver without builds", () => {
    expect(L.releaseState({ deployed: { version: "1.9.0" }, latest: { version: "1.10.0" }, platform: "cloudflare" }).newer).toBe(true);
  });
  it("invite hint mentions SD card and expiry", () => {
    const h = L.inviteHint({ url: "u", expiresAt: Date.UTC(2026, 0, 2, 3, 4) });
    expect(h).toContain("SD card root");
    expect(h).toContain("2026-01-02 03:04 UTC");
  });
});
