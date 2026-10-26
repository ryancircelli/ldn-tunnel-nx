//! The release tool end to end, through the binary. Fixtures in tools/release/test/:
//!   fixture-key.pem       throwaway key whose private half is committed (the placeholder publisher key)
//!   fixture-manifest.bin  signed by the former TypeScript tool (also pinned in crates/core)
//!   bundle-ts/            manifest.bin, release.json, release.sig as the TypeScript tool wrote them
//!   bundle-rs/            the same for this tool; the relay's node test serves it (relay/test/node.test.ts)
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use ldn_tunnel_core::update::{ManifestResult, check_manifest};
use p256::ecdsa::SigningKey;
use p256::pkcs8::DecodePrivateKey;

const BIN: &str = env!("CARGO_BIN_EXE_ldn-tunnel-release");

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}
fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("test")
}
fn fixture_key() -> PathBuf {
    fixtures().join("fixture-key.pem")
}
fn fixture_pub() -> [u8; 65] {
    fs::read(fixtures().join("fixture-pubkey.bin")).unwrap().try_into().unwrap()
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn dir(name: &str) -> PathBuf {
    let d = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}
fn run(args: &[&str], env: &[(&str, &str)]) -> Output {
    Command::new(BIN).args(args).env_remove("PUBLISHER_KEY").envs(env.iter().copied()).output().unwrap()
}
fn tool(args: &[&str]) -> String {
    let o = run(args, &[]);
    assert!(o.status.success(), "{args:?}: {}", String::from_utf8_lossy(&o.stderr));
    String::from_utf8(o.stdout).unwrap()
}
fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

/// The inputs every golden file was made from.
fn inputs(d: &Path) {
    fs::write(d.join("exefs.nsp"), "exefs bytes").unwrap();
    fs::write(d.join("ldn-tunnel.ovl"), "overlay bytes").unwrap();
    fs::write(d.join("relay-cloudflare.zip"), "zip bytes").unwrap();
}
fn sign(d: &Path, version: &str, key: &Path) {
    tool(&["sign-manifest", "--exefs", s(&d.join("exefs.nsp")), "--overlay", s(&d.join("ldn-tunnel.ovl")), "--version", version, "--build", "1700000000", "--key-file", s(key), "--out", s(&d.join("manifest.bin"))]);
    tool(&["release-json", "--dir", s(d), "--key-file", s(key)]);
}
fn bundle(name: &str, key: &Path) -> PathBuf {
    let d = dir(name);
    inputs(&d);
    sign(&d, "v1.2.3", key);
    d
}
fn verify(d: &Path, pubkey: &str) -> Output {
    run(&["verify", "--dir", s(d), "--pubkey", pubkey], &[])
}

#[test]
fn sign_release_json_verify_round_trip() {
    let d = bundle("round-trip", &fixture_key());
    assert_eq!(fs::metadata(d.join("manifest.bin")).unwrap().len(), 192);
    let rel: serde_json::Value = serde_json::from_slice(&fs::read(d.join("release.json")).unwrap()).unwrap();
    assert_eq!((rel["build"].as_u64(), rel["version"].as_str()), (Some(1_700_000_000), Some("v1.2.3")));
    let names: Vec<_> = rel["assets"].as_object().unwrap().keys().map(String::as_str).collect();
    assert_eq!(names, ["exefs.nsp", "ldn-tunnel.ovl", "manifest.bin", "relay-cloudflare.zip"]);
    let o = verify(&d, &hex(&fixture_pub()));
    assert!(o.status.success());
    assert!(String::from_utf8_lossy(&o.stdout).contains("release bundle ok"));
}

#[test]
fn gen_key_is_private_and_private_key_may_be_pem_sec1_or_hex_via_the_env() {
    let d = dir("keys");
    let pem_path = d.join("k.pem");
    let out = tool(&["gen-key", "--out", s(&pem_path)]);
    assert!(out.contains("public key (65 bytes): 04") && out.contains("as bytes: 0x04, "));
    assert!(!run(&["gen-key", "--out", s(&pem_path)], &[]).status.success(), "gen-key must not overwrite a key");
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(fs::metadata(&pem_path).unwrap().permissions().mode() & 0o777, 0o600);
    let pem = fs::read_to_string(&pem_path).unwrap();
    let scalar = hex(&SigningKey::from_pkcs8_pem(&pem).unwrap().to_bytes());
    let sec1 = p256::SecretKey::from_pkcs8_pem(&pem).unwrap().to_sec1_pem(p256::pkcs8::LineEnding::LF).unwrap();
    inputs(&d);
    let mut made = Vec::new();
    for key in [pem.as_str(), scalar.as_str(), sec1.as_str()] {
        let m = d.join("m.bin");
        let o = run(&["sign-manifest", "--exefs", s(&d.join("exefs.nsp")), "--overlay", s(&d.join("ldn-tunnel.ovl")), "--version", "v", "--build", "5", "--out", s(&m)], &[("PUBLISHER_KEY", key)]);
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
        made.push(fs::read(&m).unwrap());
    }
    assert!(made.iter().all(|m| *m == made[0]), "same key, same bytes (RFC 6979 signatures)");
    let none = run(&["sign-manifest", "--exefs", s(&d.join("exefs.nsp")), "--overlay", s(&d.join("exefs.nsp")), "--version", "v", "--out", s(&d.join("n"))], &[]);
    assert!(String::from_utf8_lossy(&none.stderr).contains("PUBLISHER_KEY"));
}

#[test]
fn verify_catches_a_tampered_asset_wrong_key_and_edited_release_json() {
    let d = bundle("tamper", &fixture_key());
    let pubhex = hex(&fixture_pub());
    let other = dir("tamper-other").join("o.pem");
    let out = tool(&["gen-key", "--out", s(&other)]);
    let other_pub = out.lines().find_map(|l| l.strip_prefix("public key (65 bytes): ")).unwrap();
    let wrong = verify(&d, other_pub);
    assert!(!wrong.status.success());
    assert!(String::from_utf8_lossy(&wrong.stderr).contains("FAIL release.sig does not verify release.json"));

    fs::write(d.join("exefs.nsp"), "exefs byteX").unwrap();
    let bad = verify(&d, &pubhex);
    assert!(!bad.status.success() && String::from_utf8_lossy(&bad.stderr).contains("exefs.nsp"));

    let d2 = bundle("tamper2", &fixture_key());
    let json = fs::read_to_string(d2.join("release.json")).unwrap();
    fs::write(d2.join("release.json"), json.replace("1.2.3", "9.9.9")).unwrap();
    let bad = verify(&d2, &pubhex);
    assert!(String::from_utf8_lossy(&bad.stderr).contains("release.sig"));

    let d3 = bundle("tamper3", &fixture_key());
    let mut m = fs::read(d3.join("manifest.bin")).unwrap();
    m[9] ^= 1; // build
    fs::write(d3.join("manifest.bin"), m).unwrap();
    assert!(String::from_utf8_lossy(&verify(&d3, &pubhex).stderr).contains("manifest.bin signature does not verify"));
}

#[test]
fn version_over_32_bytes_is_rejected() {
    let d = dir("version");
    inputs(&d);
    let long = "v".repeat(33);
    let o = run(&["sign-manifest", "--exefs", s(&d.join("exefs.nsp")), "--overlay", s(&d.join("exefs.nsp")), "--version", &long, "--key-file", s(&fixture_key()), "--out", s(&d.join("m"))], &[]);
    assert!(!o.status.success() && !d.join("m").exists());
    let ok = run(&["sign-manifest", "--exefs", s(&d.join("exefs.nsp")), "--overlay", s(&d.join("exefs.nsp")), "--version", &"v".repeat(32), "--key-file", s(&fixture_key()), "--out", s(&d.join("m"))], &[]);
    assert!(ok.status.success());
}

#[test]
fn usage_errors() {
    assert_eq!(run(&[], &[]).status.code(), Some(2));
    assert_eq!(run(&["bogus"], &[]).status.code(), Some(2));
    assert_eq!(run(&["verify", "--dir"], &[]).status.code(), Some(1));
    assert_eq!(run(&["verify", "--nope", "x"], &[]).status.code(), Some(1));
}

/// The relay and the console hold one publisher key, and it is never the fixture key (whose private half is
/// committed: release.yml refuses a build that has it).
#[test]
fn committed_public_keys_agree_and_are_not_the_fixture_key() {
    let (rs, ts) = ("crates/core/src/update_pubkey.rs", "relay/src/core/publisher_key.ts");
    let d = bundle("committed-keys", &fixture_key());
    for f in [rs, ts] {
        // `verify` reads the key out of the source file; the bundle is signed with the fixture key
        assert!(!verify(&d, s(&root().join(f))).status.success(), "{f} holds the fixture key");
    }
    let text = |f: &str| fs::read_to_string(root().join(f)).unwrap();
    let from_ts = text(ts).split('"').find(|p| p.len() == 130 && p.starts_with("04")).unwrap().to_string();
    let from_rs: String = text(rs).split("0x").skip(1).take(65).map(|b| &b[..2]).collect();
    assert_eq!(from_ts, from_rs, "update_pubkey.rs and publisher_key.ts differ");
    assert!(verify(&d, &hex(&fixture_pub())).status.success());
    assert!(!verify(&d, &format!("04{}", "00".repeat(64))).status.success());
    assert!(!verify(&d, "04ab").status.success());
}

/// What the console runs (ldn_tunnel_core::update::check_manifest) accepts what this tool signs, and what the
/// TypeScript tool signed is accepted by the tool's own verify.
#[test]
fn module_verify_path_accepts_the_tools_manifests() {
    let d = bundle("module", &fixture_key());
    let m = fs::read(d.join("manifest.bin")).unwrap();
    let parsed = check_manifest(&m, &fixture_pub(), 1, 0, 0).unwrap();
    assert_eq!(({ parsed.build }, { parsed.exefs_size }, { parsed.overlay_size }), (1_700_000_000, 11, 13));
    assert_eq!(check_manifest(&m, &[4; 65], 1, 0, 0), Err(ManifestResult::BadSignature));
    let ts = fs::read(fixtures().join("fixture-manifest.bin")).unwrap();
    assert!(check_manifest(&ts, &fixture_pub(), 1, 0, 0).is_ok());
}

/// Bytes written by the TypeScript tool: this tool verifies them, regenerates the same manifest body, and
/// regenerates the same release.json from the same manifest.bin. (The signatures differ by design: the
/// TypeScript tool's ECDSA was randomised, this one's is deterministic.)
#[test]
fn typescript_tool_output_is_reproduced_and_accepted() {
    let d = dir("ts-golden");
    inputs(&d);
    for f in ["manifest.bin", "release.json", "release.sig"] {
        fs::copy(fixtures().join("bundle-ts").join(f), d.join(f)).unwrap();
    }
    assert!(verify(&d, &hex(&fixture_pub())).status.success());

    let mine = dir("ts-golden-mine");
    inputs(&mine);
    sign(&mine, "v0.0.0", &fixture_key());
    assert_eq!(fs::read(mine.join("manifest.bin")).unwrap()[..128], fs::read(d.join("manifest.bin")).unwrap()[..128]);

    tool(&["release-json", "--dir", s(&d), "--key-file", s(&fixture_key())]);
    assert_eq!(fs::read(d.join("release.json")).unwrap(), fs::read(fixtures().join("bundle-ts/release.json")).unwrap());
}

/// bundle-rs/ is this tool's output (deterministic); the relay's TypeScript verifier is tested against it.
/// To regenerate after a deliberate format change: run `sign-manifest` and `release-json` as in `sign` above.
#[test]
fn rust_golden_bundle_is_reproducible() {
    let d = dir("rs-golden");
    inputs(&d);
    sign(&d, "v0.1.1", &fixture_key());
    for f in ["manifest.bin", "release.json", "release.sig"] {
        assert_eq!(fs::read(d.join(f)).unwrap(), fs::read(fixtures().join("bundle-rs").join(f)).unwrap(), "{f} differs from test/bundle-rs");
    }
}
