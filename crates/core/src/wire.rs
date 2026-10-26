//! Every packet payload struct of the RyuLdn protocol, byte-exact with
//! `sysmodule/source/protocol/types.hpp` (C++ `__attribute__((packed))`).
//!
//! All structs are `repr(C, packed)` (alignment 1) with native-endian integers:
//! the Switch and every host that runs the tests are little-endian, like the
//! wire. Read a field by value (`{ s.field }` / `let x = s.field;`), never by
//! reference. Structs made only of bytes also derive `Unaligned`; zerocopy
//! cannot derive it for multi-byte integer fields, but a packed struct has
//! alignment 1 anyway, so `ref_from_bytes` works on any slice.
//!
//! Use `T::new_zeroed()` (zerocopy `FromZeros`) for an all-zero value and
//! `T::read_from_bytes` / `as_bytes` for the wire. The LDN structs (NetworkInfo,
//! NodeInfo, Ssid, MacAddress, ...) are defined here; `ldn_types.rs` from the
//! ldn-ifaces helper had not landed when this was written, so the integrator
//! dedups.

use core::mem::{offset_of, size_of};

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

const _: () = assert!(
    cfg!(target_endian = "little"),
    "wire structs assume a little-endian host"
);

pub const MAX_NODES: usize = 8;

/// Size and field offsets of a wire struct, for the layout test against the
/// C++ dump (`tests/layout_types.json`).
pub trait Layout {
    const NAME: &'static str;
    const SIZE: usize;
    const FIELDS: &'static [(&'static str, usize)];
}

macro_rules! wire_struct {
    ($(#[$m:meta])* $name:ident, $size:literal, [$($extra:ident),*], { $( $(#[$fm:meta])* $f:ident : $t:ty ),* $(,)? }) => {
        $(#[$m])*
        #[repr(C, packed)]
        #[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout $(, $extra)*)]
        pub struct $name { $( $(#[$fm])* pub $f: $t ),* }
        const _: () = assert!(size_of::<$name>() == $size);
        impl Layout for $name {
            const NAME: &'static str = stringify!($name);
            const SIZE: usize = $size;
            const FIELDS: &'static [(&'static str, usize)] = &[$((stringify!($f), offset_of!($name, $f))),*];
        }
    };
}

macro_rules! wire_enum {
    ($(#[$m:meta])* $name:ident : $repr:ty { $( $(#[$vm:meta])* $v:ident = $val:expr ),* $(,)? }) => {
        $(#[$m])*
        #[repr($repr)]
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum $name { $( $(#[$vm])* $v = $val ),* }
        impl $name {
            /// `None` for a value the protocol does not define.
            pub const fn from_raw(raw: $repr) -> Option<Self> {
                match raw { $( $val => Some(Self::$v), )* _ => None }
            }
            pub const fn raw(self) -> $repr { self as $repr }
        }
    };
}

wire_enum! {
    /// `LdnHeader.type`. 0xC0..=0xC4 are relay extensions (not in Ryujinx).
    PacketId: u8 {
        Initialize = 0,
        Passphrase = 1,
        CreateAccessPoint = 2,
        CreateAccessPointPrivate = 3,
        ExternalProxy = 4,
        ExternalProxyToken = 5,
        ExternalProxyState = 6,
        SyncNetwork = 7,
        Reject = 8,
        RejectReply = 9,
        Scan = 10,
        ScanReply = 11,
        ScanReplyEnd = 12,
        Connect = 13,
        ConnectPrivate = 14,
        Connected = 15,
        Disconnect = 16,
        ProxyConfig = 17,
        ProxyConnect = 18,
        ProxyConnectReply = 19,
        ProxyData = 20,
        ProxyDisconnect = 21,
        SetAcceptPolicy = 22,
        SetAdvertiseData = 23,
        /// Console -> relay: log lines.
        DebugLog = 0xC0,
        /// Console -> relay: [`UpdateCheckRequest`].
        UpdateCheck = 0xC1,
        /// Relay -> console: [`SignedManifest`] bytes, or empty if the channel has no release.
        UpdateManifest = 0xC2,
        /// Console -> relay: [`UpdateChunkRequest`].
        UpdateChunk = 0xC3,
        /// Relay -> console: [`UpdateChunkHeader`] + data.
        UpdateChunkData = 0xC4,
        Ping = 254,
        NetworkError = 255,
    }
}

wire_enum! {
    ProtocolType: i32 {
        Unknown = -1,
        Unspecified = 0,
        Icmp = 1,
        Igmp = 2,
        Ggp = 3,
        IPv4 = 4,
        Tcp = 6,
        Pup = 12,
        Udp = 17,
        Idp = 22,
        IPv6 = 41,
        IPv6RoutingHeader = 43,
        IPv6FragmentHeader = 44,
        IPSecEncapsulatingSecurityPayload = 50,
        IPSecAuthenticationHeader = 51,
        IcmpV6 = 58,
        IPv6NoNextHeader = 59,
        IPv6DestinationOptions = 60,
        ND = 77,
        Raw = 255,
        Ipx = 1000,
        Spx = 1256,
        SpxII = 1257,
    }
}

wire_enum! {
    AcceptPolicy: u8 { AcceptAll = 0, RejectAll = 1, BlackList = 2, WhiteList = 3 }
}

wire_enum! {
    SecurityMode: u16 { Any = 0, Product = 1, Debug = 2 }
}

wire_enum! {
    NetworkType: u8 { None = 0, General = 1, Ldn = 2, All = 3 }
}

wire_enum! {
    DisconnectReason: u32 {
        None = 0,
        User = 1,
        SystemRequest = 2,
        DestroyedByHost = 3,
        DestroyedByAdmin = 4,
        Rejected = 5,
        SignalLost = 6,
    }
}

wire_enum! {
    /// `NetworkErrorMessage.error_code`: LdnServer's `NetworkError`
    /// (Network/Types/NetworkErrorMessage.cs), as the relay sends it. The C++
    /// module's own enum of this name was wrong and never used for comparisons.
    /// Code 1 (PortUnreachable) is not a reply (see ldn/README.md).
    NetworkErrorCode: i32 {
        None = 0,
        PortUnreachable = 1,
        TooManyPlayers = 2,
        VersionTooLow = 3,
        VersionTooHigh = 4,
        ConnectFailure = 5,
        ConnectNotFound = 6,
        ConnectTimeout = 7,
        ConnectRejected = 8,
        RejectFailed = 9,
        BannedByServer = 127,
        Unknown = -1,
    }
}

wire_enum! {
    /// `UpdateCheckRequest.channel`.
    UpdateChannel: u8 {
        Off = 0,
        /// What `promote` published.
        Stable = 1,
        /// What `release` published.
        Test = 2,
    }
}

pub const UPDATE_MANIFEST_MAGIC: u32 = u32::from_le_bytes(*b"RLUM");
/// Manifest format of ldn-tunnel releases. 1 is the C++ ryu_ldn_nx's: an old relay (one that ignores
/// `UpdateCheckRequest.reserved[0]`) answers with that module's manifest, which must never install here.
pub const UPDATE_MANIFEST_FORMAT: u32 = 2;
pub const UPDATE_CHUNK_SIZE: usize = 4096;
pub const UPDATE_MAX_BLOB_SIZE: u32 = 4 * 1024 * 1024;

wire_struct!(
    /// 12-byte packet header. `data_size` sits at offset 8 (load-bearing, matches the C# layout).
    LdnHeader, 12, [], {
        magic: u32,
        type_: u8,
        version: u8,
        reserved: u16,
        data_size: i32,
    }
);

wire_struct!(MacAddress, 6, [Unaligned], { data: [u8; 6] });
wire_struct!(SessionId, 16, [Unaligned], { data: [u8; 16] });

wire_struct!(IntentId, 16, [], {
    local_communication_id: i64,
    reserved1: u16,
    scene_id: u16,
    reserved2: u32,
});

wire_struct!(NetworkId, 32, [], { intent_id: IntentId, session_id: SessionId });

wire_struct!(Ssid, 34, [Unaligned], { length: u8, name: [u8; 33] });

wire_struct!(NodeInfo, 64, [], {
    /// Network byte order.
    ipv4_address: u32,
    mac_address: MacAddress,
    node_id: u8,
    is_connected: u8,
    user_name: [u8; 33],
    reserved1: u8,
    local_communication_version: u16,
    reserved2: [u8; 16],
});

wire_struct!(CommonNetworkInfo, 48, [], {
    mac_address: MacAddress,
    ssid: Ssid,
    channel: u16,
    link_level: u8,
    network_type: u8,
    reserved: u32,
});

wire_struct!(LdnNetworkInfo, 1072, [], {
    security_parameter: [u8; 16],
    security_mode: u16,
    station_accept_policy: u8,
    unknown1: u8,
    reserved1: u16,
    node_count_max: u8,
    node_count: u8,
    nodes: [NodeInfo; MAX_NODES],
    reserved2: u16,
    advertise_data_size: u16,
    advertise_data: [u8; 384],
    unknown2: [u8; 140],
    authentication_id: u64,
});

wire_struct!(NetworkInfo, 1152, [], {
    network_id: NetworkId,
    common: CommonNetworkInfo,
    ldn: LdnNetworkInfo,
});

wire_struct!(InitializeMessage, 22, [Unaligned], { id: SessionId, mac_address: MacAddress });
wire_struct!(PassphraseMessage, 128, [Unaligned], { passphrase: [u8; 128] });
wire_struct!(
    PingMessage, 2, [Unaligned], {
        /// 0 = server requested (echo back), 1 = client requested.
        requester: u8,
        id: u8,
    }
);
wire_struct!(DisconnectMessage, 4, [], { disconnect_ip: u32 });
wire_struct!(NetworkErrorMessage, 4, [], { error_code: i32 });

wire_struct!(ScanFilter, 36, [], { network_id: NetworkId, flag: u32 });

wire_struct!(ProxyInfo, 16, [], {
    source_ipv4: u32,
    source_port: u16,
    dest_ipv4: u32,
    dest_port: u16,
    /// [`ProtocolType`] as i32.
    protocol: i32,
});
wire_struct!(ProxyDataHeader, 20, [], { info: ProxyInfo, data_length: u32 });
wire_struct!(ProxyConfig, 8, [], { proxy_ip: u32, proxy_subnet_mask: u32 });
wire_struct!(ProxyConnectRequest, 16, [], { info: ProxyInfo });
wire_struct!(ProxyConnectResponse, 16, [], { info: ProxyInfo });
wire_struct!(ProxyDisconnectMessage, 20, [], { info: ProxyInfo, disconnect_reason: i32 });

wire_struct!(ExternalProxyConfig, 38, [], {
    proxy_ip: [u8; 16],
    address_family: u32,
    proxy_port: u16,
    token: [u8; 16],
});
wire_struct!(ExternalProxyToken, 40, [], {
    virtual_ip: u32,
    token: [u8; 16],
    physical_ip: [u8; 16],
    address_family: u32,
});
// Not packed in C++ (Pack=4 on the C# side); the layout has no padding either way.
wire_struct!(
    /// `ExternalProxyState` payload.
    ExternalProxyConnectionState, 8, [], {
        ip_address: u32,
        connected: u8,
        _pad: [u8; 3],
    }
);

wire_struct!(SecurityConfig, 68, [], {
    security_mode: u16,
    passphrase_size: u16,
    passphrase: [u8; 64],
});
wire_struct!(SecurityParameter, 32, [Unaligned], { data: [u8; 16], session_id: [u8; 16] });
wire_struct!(AddressEntry, 12, [], { ipv4_address: u32, mac_address: MacAddress, reserved: u16 });
wire_struct!(AddressList, 96, [], { addresses: [AddressEntry; MAX_NODES] });
wire_struct!(UserConfig, 48, [Unaligned], { user_name: [u8; 33], unknown1: [u8; 15] });
wire_struct!(NetworkConfig, 32, [], {
    intent_id: IntentId,
    channel: u16,
    node_count_max: u8,
    reserved1: u8,
    local_communication_version: u16,
    reserved2: [u8; 10],
});
wire_struct!(RyuNetworkConfig, 40, [], {
    game_version: [u8; 16],
    private_ip: [u8; 16],
    address_family: u32,
    external_proxy_port: u16,
    internal_proxy_port: u16,
});

wire_struct!(CreateAccessPointRequest, 188, [], {
    security_config: SecurityConfig,
    user_config: UserConfig,
    network_config: NetworkConfig,
    ryu_network_config: RyuNetworkConfig,
});
wire_struct!(CreateAccessPointPrivateRequest, 316, [], {
    security_config: SecurityConfig,
    security_parameter: SecurityParameter,
    user_config: UserConfig,
    network_config: NetworkConfig,
    address_list: AddressList,
    ryu_network_config: RyuNetworkConfig,
});
wire_struct!(ConnectPrivateRequest, 188, [], {
    security_config: SecurityConfig,
    security_parameter: SecurityParameter,
    user_config: UserConfig,
    local_communication_version: u32,
    option_unknown: u32,
    network_config: NetworkConfig,
});
wire_struct!(ScanFilterFull, 96, [], {
    network_id: NetworkId,
    network_type: u32,
    mac_address: MacAddress,
    ssid: Ssid,
    reserved: [u8; 16],
    flag: u32,
});
wire_struct!(ConnectRequest, 1280, [], {
    security_config: SecurityConfig,
    user_config: UserConfig,
    local_communication_version: u32,
    option_unknown: u32,
    _padding: u32,
    network_info: NetworkInfo,
});
wire_struct!(SetAcceptPolicyRequest, 1, [Unaligned], { accept_policy: u8 });
wire_struct!(RejectRequest, 8, [], { node_id: u32, disconnect_reason: u32 });

// SyncNetwork's payload is a bare NetworkInfo; SetAdvertiseData's is up to 384 raw bytes.

wire_struct!(
    /// `UpdateCheck` (0xC1) payload.
    UpdateCheckRequest, 76, [], {
        /// RYU_UPDATE_BUILD of the running module (0 = developer build).
        running_build: u32,
        /// Build rolled back on this console (0 = none); the relay shows it.
        rejected_build: u32,
        /// [`UpdateChannel`].
        channel: u8,
        /// Bytes used in `label`.
        label_len: u8,
        /// `reserved[0]` is the module id (`ident::UPDATE_MODULE_ID`: 0 = the C++ ryu_ldn_nx,
        /// which always sends zero; 1 = ldn-tunnel). `reserved[1]` is zero.
        reserved: [u8; 2],
        /// Console nickname + last 4 of the serial, not NUL-terminated.
        label: [u8; 32],
        /// Git describe of the running build, NUL-padded.
        version: [u8; 32],
    }
);

wire_struct!(
    UpdateManifest, 128, [], {
        /// [`UPDATE_MANIFEST_MAGIC`].
        magic: u32,
        /// [`UPDATE_MANIFEST_FORMAT`].
        format: u32,
        /// Monotonic build number (seconds since epoch at release).
        build: u32,
        exefs_size: u32,
        exefs_sha256: [u8; 32],
        overlay_size: u32,
        overlay_sha256: [u8; 32],
        /// Git describe, NUL-padded.
        version: [u8; 32],
        reserved: [u8; 12],
    }
);

wire_struct!(SignedManifest, 192, [], { manifest: UpdateManifest, signature: [u8; 64] });
wire_struct!(UpdateChunkRequest, 40, [], {
    sha256: [u8; 32],
    offset: u32,
    /// At most [`UPDATE_CHUNK_SIZE`].
    length: u32,
});
wire_struct!(UpdateChunkHeader, 40, [], {
    sha256: [u8; 32],
    offset: u32,
    /// Size of the whole blob.
    total_size: u32,
});

#[cfg(test)]
mod tests {
    use super::*;
    use zerocopy::{FromZeros, IntoBytes};

    #[test]
    fn enums_roundtrip() {
        for raw in 0..=255u8 {
            if let Some(id) = PacketId::from_raw(raw) {
                assert_eq!(id.raw(), raw);
            }
        }
        assert_eq!(PacketId::from_raw(0xC4), Some(PacketId::UpdateChunkData));
        assert_eq!(PacketId::from_raw(24), None);
        assert_eq!(ProtocolType::from_raw(-1), Some(ProtocolType::Unknown));
        assert_eq!(
            NetworkErrorCode::from_raw(8),
            Some(NetworkErrorCode::ConnectRejected)
        );
        assert_eq!(NetworkErrorCode::from_raw(-1), Some(NetworkErrorCode::Unknown));
        assert_eq!(UPDATE_MANIFEST_MAGIC, 0x4D55_4C52);
    }

    #[test]
    fn header_bytes() {
        let mut h = LdnHeader::new_zeroed();
        h.magic = 0x4E44_4C52;
        h.data_size = 0x0403_0201;
        assert_eq!(h.as_bytes().get(..4), Some(&b"RLDN"[..]));
        assert_eq!(h.as_bytes().get(8..12), Some(&[1, 2, 3, 4][..]));
    }
}
