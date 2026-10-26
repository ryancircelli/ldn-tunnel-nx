//! The release publisher's public key: the uncompressed P-256 point (04 || x || y) that
//! `update::check_manifest` verifies manifests against. Same bytes as
//! `relay/src/core/publisher_key.ts` (`tools/release/release.test.ts` checks). The console build
//! takes its key from `LDNT_UPDATE_PUBKEY` (`crates/sys/src/update_io.rs`), which release CI sets
//! from `publisher_key.ts`. Tests sign with the fixture key in `tools/release/test/`, never this one.

pub const PUBLISHER_PUBKEY: [u8; 65] = [
    0x04, 0x73, 0x92, 0x68, 0x0b, 0x15, 0x1e, 0xd3, 0x53, 0xa7, 0xc8, 0xc3, 0x57,
    0xe7, 0xd5, 0x11, 0xe5, 0x81, 0x83, 0x8c, 0x1a, 0x94, 0x97, 0x31, 0x96, 0x5c,
    0xea, 0xe6, 0xa6, 0x8e, 0xa8, 0x24, 0xd5, 0xdc, 0x42, 0x33, 0x7a, 0x1b, 0x74,
    0x7d, 0x68, 0x19, 0x97, 0x10, 0x4c, 0xf9, 0x7d, 0x8d, 0xe9, 0x5a, 0xea, 0x87,
    0xa9, 0xa1, 0x4f, 0x2e, 0x3e, 0xb0, 0x7a, 0x3c, 0x64, 0xe1, 0x2f, 0x0c, 0xba,
];

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use crate::update::{ManifestResult, check_manifest};

    /// Produced by the old TypeScript `release.ts sign-manifest` with the fixture key (build 2).
    /// Pins the TypeScript signer to the Rust verifier; independent of PUBLISHER_PUBKEY.
    const FIXTURE_MANIFEST: &[u8] = include_bytes!("../../../tools/release/test/fixture-manifest.bin");
    const FIXTURE_PUBKEY: [u8; 65] = *include_bytes!("../../../tools/release/test/fixture-pubkey.bin");

    #[test]
    fn tool_signed_manifest_verifies() {
        let m = check_manifest(FIXTURE_MANIFEST, &FIXTURE_PUBKEY, 1, 0, 0).unwrap();
        assert_eq!({ m.build }, 2);
        assert_eq!({ m.exefs_size }, 13);
        assert_eq!(check_manifest(FIXTURE_MANIFEST, &FIXTURE_PUBKEY, 2, 0, 0), Err(ManifestResult::NotNewer));
    }

    #[test]
    fn publisher_key_is_a_valid_point() {
        assert!(p256::ecdsa::VerifyingKey::from_sec1_bytes(&super::PUBLISHER_PUBKEY).is_ok());
    }
}
