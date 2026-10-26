// The publisher's P-256 public key: the 65-byte uncompressed point (04 || X || Y) as hex. Releases (relay code
// and console files) must verify against it. The release workflow compiles the same point into the console
// module (LDNT_UPDATE_PUBKEY), so relays and consoles trust one key. PUBLISHER_KEY (env) overrides it for forks
// and tests; the tests sign with throwaway keys and never with the key behind this one.
export const PUBLISHER_KEY = "047392680b151ed353a7c8c357e7d511e581838c1a949731965ceae6a68ea824d5dc42337a1b747d681997104cf97d8de95aea87a9a14f2e3eb07a3c64e12f0cba";
