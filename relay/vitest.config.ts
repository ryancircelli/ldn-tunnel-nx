import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { generateKeyPairSync } from "node:crypto";
import { defineConfig } from "vitest/config";

// A throwaway publisher key for the release tests: the relay gets the public half (PUBLISHER_KEY overrides
// release.json), the tests sign with the private half.
const publisher = generateKeyPairSync("ec", {
  namedCurve: "P-256",
  publicKeyEncoding: { type: "spki", format: "der" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

export default defineConfig({
  test: {
    // `npm run coverage` (`make coverage`): relay/src line coverage across both projects
    coverage: { provider: "v8", include: ["src/**"], reporter: ["text-summary", "json-summary"] },
    projects: [
      {
        // Cloudflare: the Durable Object adapter inside workerd
        plugins: [
          cloudflareTest({
            wrangler: { configPath: "./wrangler.toml" },
            miniflare: {
              compatibilityFlags: ["nodejs_compat"], // the update tests sign manifests with node:crypto
              bindings: {
                UPDATE_ADMIN: "52b6419d27bd7f547cee3b92f8c17a908b8a49601ecbec161e5030de1dfe9e0a", // "c" * 64, the release API admin token
                TOKEN_SWITCH_A: "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb", // "a" * 64
                TOKEN_SWITCH_B: "", // an empty secret must never match
                ADMIN: "correct horse", // the /admin password
                PUBLISHER_KEY: publisher.publicKey.subarray(-65).toString("hex"), // the raw point: SPKI DER ends with it
                TEST_PUBLISHER_PRIVATE_PEM: publisher.privateKey,
                CF_API_TOKEN: "cf-test-token",
                CF_ACCOUNT_ID: "acct123",
                RESUME_GRACE_MS: "0", // the C# behaviour (leave at once); the resume tests turn the grace on
                TOKEN_FRIEND: "4ac281b4c9cf420d4641ab1644ce13cfde53b857ff57ac7a7ce8b09d9b52d7b9", // "b" * 63 + "c"
              },
            },
          }),
        ],
        test: { name: "cloudflare", include: ["test/**/*.test.ts"], exclude: ["test/node*.test.ts", "test/admin-page*.test.ts"] },
      },
      // Node: the standalone server in plain Node
      { test: { name: "node", environment: "node", include: ["test/node*.test.ts", "test/admin-page*.test.ts"] } },
    ],
  },
});
