//! Sizes and field offsets of every wire struct against `layout_types.json`,
//! the C++ compiler's own sizeof/offsetof dump (copy of relay/test/layout/types.json).
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::expect_used,
    clippy::panic
)]

use std::collections::BTreeMap;

use ldn_tunnel_core::wire::*;

type Fields = BTreeMap<String, usize>;

/// One line per struct: `"Name": {"$size": N, "field": off, ...},`
fn parse(json: &str) -> BTreeMap<String, Fields> {
    let mut out = BTreeMap::new();
    for line in json.lines().filter(|l| l.contains(": {")) {
        let (name, body) = line.trim().split_once(": {").unwrap();
        let body = body.trim_end_matches(',').trim_end_matches('}');
        let fields = body
            .split(',')
            .map(|kv| {
                let (k, v) = kv.split_once(':').unwrap();
                (
                    k.trim().trim_matches('"').to_string(),
                    v.trim().parse().unwrap(),
                )
            })
            .collect();
        out.insert(name.trim_matches('"').to_string(), fields);
    }
    out
}

/// `type_` is the Rust spelling of C++ `type`; `r#x` raw idents lose their prefix.
fn cpp_name(rust: &str) -> &str {
    let n = rust.strip_prefix("r#").unwrap_or(rust);
    if n == "type_" { "type" } else { n }
}

fn check<T: Layout>(cpp: &BTreeMap<String, Fields>, seen: &mut Vec<&'static str>) {
    seen.push(T::NAME);
    let Some(want) = cpp.get(T::NAME) else { return }; // not in the dump (ExternalProxy*, ScanFilter, ...)
    assert_eq!(T::SIZE, want["$size"], "{}: size", T::NAME);
    let got: Fields = T::FIELDS
        .iter()
        .map(|(n, o)| (cpp_name(n).to_string(), *o))
        .collect();
    let mut want = want.clone();
    want.remove("$size");
    assert_eq!(got, want, "{}: field offsets", T::NAME);
}

#[test]
fn matches_cpp_dump() {
    let cpp = parse(include_str!("layout_types.json"));
    assert!(cpp.len() > 30);
    let mut seen = Vec::new();
    macro_rules! all { ($($t:ty),*) => { $(check::<$t>(&cpp, &mut seen);)* } }
    all!(
        LdnHeader,
        MacAddress,
        SessionId,
        IntentId,
        NetworkId,
        Ssid,
        NodeInfo,
        CommonNetworkInfo,
        LdnNetworkInfo,
        NetworkInfo,
        InitializeMessage,
        PassphraseMessage,
        PingMessage,
        DisconnectMessage,
        NetworkErrorMessage,
        ScanFilter,
        ProxyInfo,
        ProxyDataHeader,
        ProxyConfig,
        ProxyConnectRequest,
        ProxyConnectResponse,
        ProxyDisconnectMessage,
        ExternalProxyConfig,
        ExternalProxyToken,
        ExternalProxyConnectionState,
        SecurityConfig,
        SecurityParameter,
        AddressEntry,
        AddressList,
        UserConfig,
        NetworkConfig,
        RyuNetworkConfig,
        CreateAccessPointRequest,
        CreateAccessPointPrivateRequest,
        ConnectPrivateRequest,
        ScanFilterFull,
        ConnectRequest,
        SetAcceptPolicyRequest,
        RejectRequest,
        UpdateCheckRequest,
        UpdateManifest,
        SignedManifest,
        UpdateChunkRequest,
        UpdateChunkHeader
    );
    // MacAddress/SessionId are single-array structs the dump has no entry for: only the
    // dump's structs must all be covered.
    for name in cpp.keys() {
        assert!(
            seen.contains(&name.as_str()),
            "{name} is in the C++ dump but not in wire.rs"
        );
    }
}
