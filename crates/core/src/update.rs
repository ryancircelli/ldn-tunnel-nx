//! Signed update manifest verification and the probation/rejected state files (port of
//! `update/update_manifest.cpp`, the codecs of `update_swap.cpp`, and `Status` in `update.hpp`).
//!
//! Wire structs come from `crate::wire`.
use core::fmt::Write;

use heapless::String;
use zerocopy::FromBytes;
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};

pub use crate::wire::{SignedManifest, UPDATE_MANIFEST_FORMAT, UPDATE_MANIFEST_MAGIC, UPDATE_MAX_BLOB_SIZE, UpdateManifest};

pub const UNSIGNED_LEN: usize = 128;
pub const SIGNED_LEN: usize = 192;
pub const PUBKEY_LEN: usize = 65;

/// Variant order is the check order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManifestResult {
    Ok,
    BadSize,
    BadMagic,
    BadSignature,
    BadSizes,
    /// build <= running build, or running build is 0 (dev build).
    NotNewer,
    /// build == the build the last rollback removed.
    Rejected,
    /// build == the build already installed and waiting for a restart.
    AlreadyStaged,
}

/// ECDSA P-256 / SHA-256 over `signed`, `sig` raw r || s (64 bytes). Also used by `tools/release`.
pub fn signature_ok(signed: &[u8], sig: &[u8], pubkey: &[u8; PUBKEY_LEN]) -> bool {
    let Ok(key) = VerifyingKey::from_sec1_bytes(pubkey) else { return false };
    let Ok(sig) = Signature::from_slice(sig) else { return false };
    key.verify(signed, &sig).is_ok()
}

/// Checks in the C++ order: size, magic/format, signature, blob sizes, anti-downgrade,
/// rejected, already staged. `rejected_build`/`staged_build` are 0 when absent.
pub fn check_manifest(
    bytes: &[u8],
    pubkey: &[u8; PUBKEY_LEN],
    running_build: u32,
    rejected_build: u32,
    staged_build: u32,
) -> Result<UpdateManifest, ManifestResult> {
    use ManifestResult as R;
    if bytes.len() != SIGNED_LEN {
        return Err(R::BadSize);
    }
    let Ok(sm) = SignedManifest::read_from_bytes(bytes) else { return Err(R::BadSize) };
    let m = sm.manifest;
    if m.magic != UPDATE_MANIFEST_MAGIC || m.format != UPDATE_MANIFEST_FORMAT {
        return Err(R::BadMagic);
    }
    let sig_ok = match (bytes.get(..UNSIGNED_LEN), bytes.get(UNSIGNED_LEN..)) {
        (Some(signed), Some(sig)) => signature_ok(signed, sig, pubkey),
        _ => false,
    };
    if !sig_ok {
        return Err(R::BadSignature);
    }
    let bad = |n: u32| n == 0 || n > UPDATE_MAX_BLOB_SIZE;
    if bad(m.exefs_size) || bad(m.overlay_size) {
        return Err(R::BadSizes);
    }
    if running_build == 0 || m.build <= running_build {
        return Err(R::NotNewer);
    }
    if m.build == rejected_build {
        return Err(R::Rejected);
    }
    if m.build == staged_build {
        return Err(R::AlreadyStaged);
    }
    Ok(m)
}

impl ManifestResult {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "Ok",
            Self::BadSize => "BadSize",
            Self::BadMagic => "BadMagic",
            Self::BadSignature => "BadSignature",
            Self::BadSizes => "BadSizes",
            Self::NotNewer => "NotNewer",
            Self::Rejected => "Rejected",
            Self::AlreadyStaged => "AlreadyStaged",
        }
    }
}

/// In-memory update status (`update::Status`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Status {
    pub running_build: u32,
    /// Installed and waiting for a restart (probation boots == 0), else 0.
    pub staged_build: u32,
    /// From the `rejected` file, else 0.
    pub rejected_build: u32,
    /// This boot runs a build whose probation has not ended.
    pub on_probation: bool,
    /// boot_check restored the backup during this boot.
    pub rolled_back: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Probation {
    pub build: u32,
    pub boots: u32,
}

fn parse_u32(p: &mut &[u8]) -> Option<u32> {
    let n = p.iter().take(10).take_while(|b| b.is_ascii_digit()).count();
    if n == 0 {
        return None;
    }
    let (digits, rest) = p.split_at(n);
    let v = digits.iter().try_fold(0u64, |a, &d| a.checked_mul(10)?.checked_add(u64::from(d.wrapping_sub(b'0'))))?;
    *p = rest;
    u32::try_from(v).ok()
}

fn lit(p: &mut &[u8], s: &[u8]) -> Option<()> {
    *p = p.strip_prefix(s)?;
    Some(())
}

/// Strict: anything but `build=<n>\nboots=<k>\n` (a torn write) reads as absent.
pub fn parse_probation(data: &[u8]) -> Option<Probation> {
    let mut p = data;
    lit(&mut p, b"build=")?;
    let build = parse_u32(&mut p)?;
    lit(&mut p, b"\nboots=")?;
    let boots = parse_u32(&mut p)?;
    lit(&mut p, b"\n")?;
    p.is_empty().then_some(Probation { build, boots })
}

pub fn format_probation(build: u32, boots: u32) -> String<40> {
    let mut s = String::new();
    let _ = write!(s, "build={build}\nboots={boots}\n"); // max 34 bytes: fits
    s
}

/// `"<build>\n"` or 0 when absent/torn.
pub fn parse_rejected(data: &[u8]) -> u32 {
    let mut p = data;
    match (parse_u32(&mut p), lit(&mut p, b"\n")) {
        (Some(b), Some(())) if p.is_empty() => b,
        _ => 0,
    }
}

pub fn format_rejected(build: u32) -> String<16> {
    let mut s = String::new();
    let _ = writeln!(s, "{build}"); // max 11 bytes
    s
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use p256::ecdsa::{SigningKey, signature::Signer};

    fn key(seed: u8) -> (SigningKey, [u8; PUBKEY_LEN]) {
        let sk = SigningKey::from_bytes(&[seed; 32].into()).unwrap();
        let pk: [u8; PUBKEY_LEN] = sk.verifying_key().to_sec1_point(false).as_bytes().try_into().unwrap();
        (sk, pk)
    }

    fn manifest(build: u32, format: u32, exefs: u32, overlay: u32) -> [u8; UNSIGNED_LEN] {
        let mut m = [0u8; UNSIGNED_LEN];
        m[0..4].copy_from_slice(&UPDATE_MANIFEST_MAGIC.to_le_bytes());
        m[4..8].copy_from_slice(&format.to_le_bytes());
        m[8..12].copy_from_slice(&build.to_le_bytes());
        m[12..16].copy_from_slice(&exefs.to_le_bytes());
        m[16..48].fill(0xAA);
        m[48..52].copy_from_slice(&overlay.to_le_bytes());
        m[52..84].fill(0xBB);
        m[84..90].copy_from_slice(b"v1.2.3");
        m
    }

    fn sign(sk: &SigningKey, m: &[u8; UNSIGNED_LEN]) -> [u8; SIGNED_LEN] {
        let sig: Signature = sk.sign(m);
        let mut out = [0u8; SIGNED_LEN];
        out[..UNSIGNED_LEN].copy_from_slice(m);
        out[UNSIGNED_LEN..].copy_from_slice(&sig.to_bytes());
        out
    }

    #[test]
    fn every_result() {
        use ManifestResult as R;
        let (sk, pk) = key(7);
        let ok = sign(&sk, &manifest(200, 2, 1000, 2000));
        let m = check_manifest(&ok, &pk, 100, 0, 0).unwrap();
        assert_eq!((m.build, m.exefs_size, m.overlay_size, m.format), (200, 1000, 2000, 2));
        let v = m.version;
        assert_eq!(&v[..6], b"v1.2.3");
        // Format 1 is the C++ module's: the original relay serves it to every console.
        let cpp = sign(&sk, &manifest(200, 1, 1000, 2000));
        assert_eq!(check_manifest(&cpp, &pk, 100, 0, 0).unwrap_err(), R::BadMagic);

        let err = |b: &[u8], run, rej, stg| check_manifest(b, &pk, run, rej, stg).unwrap_err();
        assert_eq!(err(&ok[..191], 100, 0, 0), R::BadSize);
        assert_eq!(err(&[], 100, 0, 0), R::BadSize);
        assert_eq!(err(&sign(&sk, &manifest(200, 3, 1, 1)), 100, 0, 0), R::BadMagic);
        let mut bad_magic = ok;
        bad_magic[0] ^= 1;
        assert_eq!(err(&bad_magic, 100, 0, 0), R::BadMagic);
        let mut tampered = ok;
        tampered[9] ^= 1;
        assert_eq!(err(&tampered, 100, 0, 0), R::BadSignature);
        let mut bad_sig = ok;
        bad_sig[150] ^= 1;
        assert_eq!(err(&bad_sig, 100, 0, 0), R::BadSignature);
        let (_, other_pk) = key(9);
        assert_eq!(check_manifest(&ok, &other_pk, 100, 0, 0).unwrap_err(), R::BadSignature);
        assert_eq!(check_manifest(&ok, &[0u8; PUBKEY_LEN], 100, 0, 0).unwrap_err(), R::BadSignature);
        for (e, o) in [(0, 1), (1, 0), (UPDATE_MAX_BLOB_SIZE + 1, 1), (1, UPDATE_MAX_BLOB_SIZE + 1)] {
            assert_eq!(err(&sign(&sk, &manifest(200, 2, e, o)), 100, 0, 0), R::BadSizes);
        }
        assert!(check_manifest(&sign(&sk, &manifest(200, 2, UPDATE_MAX_BLOB_SIZE, 1)), &pk, 100, 0, 0).is_ok());
        assert_eq!(err(&ok, 200, 0, 0), R::NotNewer);
        assert_eq!(err(&ok, 300, 0, 0), R::NotNewer);
        assert_eq!(err(&ok, 0, 0, 0), R::NotNewer);
        assert_eq!(err(&ok, 100, 200, 0), R::Rejected);
        assert_eq!(err(&ok, 100, 0, 200), R::AlreadyStaged);
        assert_eq!(err(&ok, 100, 200, 200), R::Rejected);
        assert_eq!(R::Ok.as_str(), "Ok");
    }

    #[test]
    fn state_files() {
        assert_eq!(format_probation(7, 1).as_str(), "build=7\nboots=1\n");
        assert_eq!(parse_probation(b"build=7\nboots=1\n"), Some(Probation { build: 7, boots: 1 }));
        assert_eq!(parse_probation(format_probation(u32::MAX, u32::MAX).as_bytes()), Some(Probation { build: u32::MAX, boots: u32::MAX }));
        for torn in [&b"build=7\nboots=1"[..], b"build=7\n", b"build=\nboots=1\n", b"build=7\nboots=1\nx", b"build=4294967296\nboots=1\n", b""] {
            assert_eq!(parse_probation(torn), None);
        }
        assert_eq!(format_rejected(42).as_str(), "42\n");
        assert_eq!(parse_rejected(b"42\n"), 42);
        for torn in [&b"42"[..], b"", b"x\n", b"42\n\n", b"99999999999\n"] {
            assert_eq!(parse_rejected(torn), 0);
        }
    }

    #[test]
    fn random_input_does_not_panic() {
        let (_, pk) = key(7);
        let mut x = 0x1234_5678_9ABC_DEF1u64;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for _ in 0..300 {
            let mut b = [0u8; SIGNED_LEN];
            b.iter_mut().for_each(|v| *v = next() as u8);
            b[..4].copy_from_slice(&UPDATE_MANIFEST_MAGIC.to_le_bytes());
            b[4] = 1;
            b[5..8].fill(0);
            let _ = check_manifest(&b, &pk, 1, 0, 0);
            let _ = parse_probation(&b[..(next() % 192) as usize]);
            let _ = parse_rejected(&b[..(next() % 192) as usize]);
        }
    }
}
