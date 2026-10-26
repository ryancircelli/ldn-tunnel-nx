//! Build, sign and verify the release bundle (docs/CONTRACTS.md "Release bundle").
//!   gen-key        --out <key.pem>                      new P-256 key; prints the public key
//!   sign-manifest  --exefs --overlay --version [--build] [--key-file | $PUBLISHER_KEY] --out manifest.bin
//!   release-json   --dir <bundle dir> [--key-file | $PUBLISHER_KEY]   writes release.json + release.sig
//!   verify         --dir <bundle dir> --pubkey <hex | file with 0x.. bytes>
//! The private key is a PEM (PKCS#8 or SEC1) or 64 hex chars (raw scalar), from a file or the env.
//! The manifest format and its signature check are `ldn_tunnel_core::update`, the code the console runs.
use std::collections::HashMap;
use std::fmt::Write as _;
use std::fs;
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use ldn_tunnel_core::update::{
    PUBKEY_LEN, SIGNED_LEN, SignedManifest, UNSIGNED_LEN, UPDATE_MANIFEST_FORMAT, UPDATE_MANIFEST_MAGIC, UpdateManifest, signature_ok,
};
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use p256::elliptic_curve::Generate;
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding};
use serde_json::Value;
use sha2::{Digest, Sha256};
use zerocopy::{FromBytes, IntoBytes};

/// In release.json (and the GitHub Release) order.
const ASSETS: [&str; 4] = ["exefs.nsp", "ldn-tunnel.ovl", "manifest.bin", "relay-cloudflare.zip"];
const FLAGS: [&str; 8] = ["out", "exefs", "overlay", "version", "build", "key-file", "dir", "pubkey"];

type R<T> = Result<T, String>;

fn sha256(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

fn hex(b: &[u8]) -> String {
    b.iter().fold(String::new(), |mut s, x| {
        let _ = write!(s, "{x:02x}");
        s
    })
}

fn unhex(s: &str) -> Vec<u8> {
    s.as_bytes().as_chunks::<2>().0.iter().filter_map(|c| u8::from_str_radix(std::str::from_utf8(c).ok()?, 16).ok()).collect()
}

fn is_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn read(p: &Path) -> R<Vec<u8>> {
    fs::read(p).map_err(|e| format!("{}: {e}", p.display()))
}

fn read_opt(dir: &Path, name: &str) -> Option<Vec<u8>> {
    fs::read(dir.join(name)).ok()
}

fn write(p: &Path, data: &[u8]) -> R<()> {
    fs::write(p, data).map_err(|e| format!("{}: {e}", p.display()))
}

/// A PEM (PKCS#8 or SEC1) or 64 hex chars (a bare P-256 scalar). Errors never echo the key.
fn signing_key(s: &str) -> R<SigningKey> {
    let s = s.trim();
    if is_hex(s, 64) {
        return SigningKey::from_slice(&unhex(s)).map_err(|_| "private key: not a valid P-256 scalar".into());
    }
    SigningKey::from_pkcs8_pem(s)
        .or_else(|_| p256::SecretKey::from_sec1_pem(s).map(Into::into))
        .map_err(|_| "private key: not a PKCS#8/SEC1 PEM or 64 hex chars".into())
}

fn key_from_args(key_file: Option<&String>) -> R<SigningKey> {
    let s = match key_file {
        Some(f) => String::from_utf8(read(Path::new(f))?).map_err(|_| format!("{f}: not text"))?,
        None => std::env::var("PUBLISHER_KEY").map_err(|_| "pass --key-file <pem|hex file> or set PUBLISHER_KEY".to_string())?,
    };
    signing_key(&s)
}

fn public_bytes(k: &SigningKey) -> R<[u8; PUBKEY_LEN]> {
    k.verifying_key().to_sec1_point(false).as_bytes().try_into().map_err(|_| "public key is not 65 bytes".to_string())
}

/// The `0xNN` literals (two hex digits, then a non-word char), in order.
fn hex_literals(s: &str) -> String {
    s.split("0x")
        .skip(1)
        .filter_map(|rest| {
            let (digits, after) = (rest.get(..2)?, rest.get(2..)?);
            let word = after.chars().next().is_some_and(|c| c.is_ascii_alphanumeric() || c == '_');
            (is_hex(digits, 2) && !word).then_some(digits)
        })
        .collect()
}

/// The first `"<130 hex>"` or `'<130 hex>'`: a piece between two quote characters.
fn quoted_hex(s: &str) -> Option<&str> {
    let parts: Vec<&str> = s.split(['"', '\'']).collect();
    parts.get(1..parts.len().saturating_sub(1))?.iter().copied().find(|p| is_hex(p, 130))
}

/// A hex string, or a file (hex, or Rust/TS source) holding the 65 bytes as 0x.. literals or a quoted hex string.
fn read_pubkey(arg: &str) -> R<[u8; PUBKEY_LEN]> {
    let text = if Path::new(arg).exists() {
        let s = String::from_utf8(read(Path::new(arg))?).map_err(|_| format!("{arg}: not text"))?;
        let lits = hex_literals(&s);
        if !lits.is_empty() {
            lits
        } else {
            let q = quoted_hex(&s).map(str::to_string);
            q.unwrap_or(s)
        }
    } else {
        arg.to_string()
    };
    let t = text.trim();
    if !is_hex(t, 130) || !t.starts_with("04") {
        return Err("public key must be 65 bytes (04 || x || y)".into());
    }
    unhex(t).try_into().map_err(|_| "public key must be 65 bytes (04 || x || y)".into())
}

struct Release<'a> {
    build: u32,
    version: &'a str,
    exefs: &'a [u8],
    overlay: &'a [u8],
}

/// The 192 bytes of a SignedManifest: 128 signed bytes (crates/core/src/wire.rs UpdateManifest) + raw r || s.
fn sign_manifest(r: &Release, key: &SigningKey) -> R<Vec<u8>> {
    let mut version = [0u8; 32];
    version.get_mut(..r.version.len()).ok_or(format!("version \"{}\" is longer than 32 bytes", r.version))?.copy_from_slice(r.version.as_bytes());
    if r.build == 0 {
        return Err("build must be a positive u32".into());
    }
    let size = |b: &[u8]| u32::try_from(b.len()).map_err(|_| "file larger than 4 GiB".to_string());
    let m = UpdateManifest {
        magic: UPDATE_MANIFEST_MAGIC,
        format: UPDATE_MANIFEST_FORMAT,
        build: r.build,
        exefs_size: size(r.exefs)?,
        exefs_sha256: sha256(r.exefs),
        overlay_size: size(r.overlay)?,
        overlay_sha256: sha256(r.overlay),
        version,
        reserved: [0; 12],
    };
    let mut out = m.as_bytes().to_vec();
    let sig: Signature = key.sign(&out);
    out.extend_from_slice(&sig.to_bytes());
    Ok(out)
}

fn parse_manifest(bytes: &[u8]) -> R<(UpdateManifest, String)> {
    let (m, _) = UpdateManifest::read_from_prefix(bytes).map_err(|_| "manifest.bin is shorter than 128 bytes".to_string())?;
    let v = m.version;
    Ok((m, String::from_utf8_lossy(&v).trim_end_matches('\0').to_string()))
}

/// Same bytes for the same bundle (fixed key order, assets in `ASSETS` order); JSON.stringify(_, null, 2) layout.
fn release_json(dir: &Path) -> R<String> {
    let (m, version) = parse_manifest(&read(&dir.join("manifest.bin"))?)?;
    let mut assets = Vec::new();
    for name in ASSETS {
        if let Some(d) = read_opt(dir, name) {
            assets.push(format!("    \"{name}\": {{\n      \"sha256\": \"{}\",\n      \"size\": {}\n    }}", hex(&sha256(&d)), d.len()));
        }
    }
    let assets = if assets.is_empty() { "{}".into() } else { format!("{{\n{}\n  }}", assets.join(",\n")) };
    let version = serde_json::to_string(&version).map_err(|e| e.to_string())?;
    Ok(format!("{{\n  \"version\": {version},\n  \"build\": {},\n  \"assets\": {assets}\n}}\n", { m.build }))
}

/// The problems found (empty = the bundle is good).
fn verify_bundle(dir: &Path, pubkey: &[u8; PUBKEY_LEN]) -> Vec<String> {
    let mut bad = Vec::new();
    let (Some(json), Some(sig), Some(man)) = (read_opt(dir, "release.json"), read_opt(dir, "release.sig"), read_opt(dir, "manifest.bin")) else {
        return vec!["release.json, release.sig and manifest.bin are required".into()];
    };
    if sig.len() != 64 || !signature_ok(&json, &sig, pubkey) {
        bad.push("release.sig does not verify release.json".into());
    }
    let Ok(sm) = SignedManifest::read_from_bytes(&man) else {
        bad.push("manifest.bin is not 192 bytes".into());
        return bad;
    };
    let m = sm.manifest;
    if m.magic != UPDATE_MANIFEST_MAGIC || m.format != UPDATE_MANIFEST_FORMAT {
        bad.push("manifest.bin: bad magic/format".into());
    }
    let signed_ok = man.get(..UNSIGNED_LEN).zip(man.get(UNSIGNED_LEN..SIGNED_LEN)).is_some_and(|(d, s)| signature_ok(d, s, pubkey));
    if !signed_ok {
        bad.push("manifest.bin signature does not verify".into());
    }
    let Ok(rel) = serde_json::from_slice::<Value>(&json) else {
        bad.push("release.json is not JSON".into());
        return bad;
    };
    let version = String::from_utf8_lossy(&m.version).trim_end_matches('\0').to_string();
    if rel.get("version").and_then(Value::as_str) != Some(&version) || rel.get("build").and_then(Value::as_u64) != Some(u64::from(m.build)) {
        bad.push("release.json version/build differ from manifest.bin".into());
    }
    let assets = rel.get("assets").and_then(Value::as_object);
    for name in ["exefs.nsp", "ldn-tunnel.ovl", "manifest.bin"] {
        if assets.and_then(|a| a.get(name)).is_none_or(Value::is_null) {
            bad.push(format!("release.json lacks {name}"));
        }
    }
    for (name, a) in assets.into_iter().flatten() {
        match read_opt(dir, name) {
            None => bad.push(format!("{name} is listed but missing")),
            Some(d) if a.get("size").and_then(Value::as_u64) != Some(d.len() as u64) || a.get("sha256").and_then(Value::as_str) != Some(&hex(&sha256(&d))) => {
                bad.push(format!("{name}: size/sha256 differ from release.json"));
            }
            Some(_) => {}
        }
    }
    let blob = |name, size: u32, digest: [u8; 32]| {
        read_opt(dir, name).filter(|d| d.len() as u64 != u64::from(size) || sha256(d) != digest).map(|_| format!("manifest.bin does not match {name}"))
    };
    bad.extend(blob("exefs.nsp", m.exefs_size, m.exefs_sha256));
    bad.extend(blob("ldn-tunnel.ovl", m.overlay_size, m.overlay_sha256));
    bad
}

fn parse_flags(args: &[String]) -> R<HashMap<&str, String>> {
    let mut flags = HashMap::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let flag = a.strip_prefix("--").ok_or(format!("unexpected argument {a}"))?;
        let (k, v) = match flag.split_once('=') {
            Some((k, v)) => (k, v.to_string()),
            None => (flag, it.next().ok_or(format!("--{flag} needs a value"))?.clone()),
        };
        let k = FLAGS.iter().find(|f| **f == k).ok_or(format!("unknown option --{k}"))?;
        flags.insert(*k, v);
    }
    Ok(flags)
}

fn run(cmd: &str, args: &[String]) -> R<bool> {
    let v = parse_flags(args)?;
    let need = |n: &str| v.get(n).ok_or(format!("--{n} is required"));
    match cmd {
        "gen-key" => {
            let out = need("out")?;
            let key = SigningKey::try_generate().map_err(|e| e.to_string())?;
            let pem = key.to_pkcs8_pem(LineEnding::LF).map_err(|e| e.to_string())?;
            let mut f = fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(out).map_err(|e| format!("{out}: {e}"))?;
            f.write_all(pem.as_bytes()).map_err(|e| format!("{out}: {e}"))?;
            let pubkey = public_bytes(&key)?;
            let bytes: Vec<String> = pubkey.iter().map(|b| format!("0x{b:02x}")).collect();
            println!("private key: {out} (0600; never commit it)\npublic key (65 bytes): {}\nas bytes: {}", hex(&pubkey), bytes.join(", "));
        }
        "sign-manifest" => {
            let build = match v.get("build").filter(|b| !b.is_empty()) {
                Some(b) => b.parse::<u32>().map_err(|_| "build must be a positive u32".to_string())?,
                None => SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs()).try_into().unwrap_or(0),
            };
            let (out, exefs, overlay) = (need("out")?, read(Path::new(need("exefs")?))?, read(Path::new(need("overlay")?))?);
            let m = sign_manifest(&Release { build, version: need("version")?, exefs: &exefs, overlay: &overlay }, &key_from_args(v.get("key-file"))?)?;
            write(Path::new(out), &m)?;
            println!("{out}: build {build}, {} bytes", m.len());
        }
        "release-json" => {
            let dir = Path::new(need("dir")?);
            let json = release_json(dir)?;
            let sig: Signature = key_from_args(v.get("key-file"))?.sign(json.as_bytes());
            write(&dir.join("release.json"), json.as_bytes())?;
            write(&dir.join("release.sig"), &sig.to_bytes())?;
            println!("{json}");
        }
        "verify" => {
            let bad = verify_bundle(Path::new(need("dir")?), &read_pubkey(need("pubkey")?)?);
            if !bad.is_empty() {
                eprintln!("{}", bad.iter().map(|b| format!("FAIL {b}")).collect::<Vec<_>>().join("\n"));
                return Ok(false);
            }
            println!("release bundle ok");
        }
        _ => return Err(format!("unknown command {cmd}")),
    }
    Ok(true)
}

fn main() {
    let args: Vec<String> = std::env::args_os().skip(1).map(|a| a.to_string_lossy().into_owned()).collect();
    let Some((cmd, rest)) = args.split_first().filter(|(c, _)| ["gen-key", "sign-manifest", "release-json", "verify"].contains(&c.as_str())) else {
        eprintln!("usage: ldn-tunnel-release gen-key|sign-manifest|release-json|verify (see the header of tools/release/src/main.rs)");
        std::process::exit(2);
    };
    match run(cmd, rest) {
        Ok(true) => {}
        Ok(false) => std::process::exit(1),
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
}
