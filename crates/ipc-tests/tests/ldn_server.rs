//! ldn:u as the MitM serves it (crates/sys/src/ldn/ifaces.rs on nx's ServerManager), with
//! requests built as libnx's `nx/source/services/ldn.c` sends them (argument structs and buffer
//! attributes; struct sizes from `nx/include/switch/services/ldn.h`), Switchbrew "LDN services"
//! for the commands libnx lacks (IClientProcessMonitor, SetProtocol, InitializeSystem2).
//! Argument bytes are synthetic patterns; the handler must see exactly the bytes at the offsets
//! the client put them.

mod common;

#[path = "../../sys/src/ldn/ifaces.rs"]
#[allow(dead_code)]
mod ldn_ifaces;

use common::hipc::{self, Buf};
use common::*;
#[allow(unused_imports)]
use common::compat;
use ldn_ifaces::{IClientProcessMonitorServer, ICommunicationServer, ILdnMitmServiceServer, Raw};
use ldn_tunnel_core::ldn_types::{
    AddressList, ConnectNetworkData, ConnectPrivateData, CreateNetworkConfig,
    CreateNetworkPrivateConfig, NetworkConfig, NetworkInfo, NodeLatestUpdate, ScanFilter,
    SecurityParameter,
};
use nx::ipc::server::{ISessionObject, ServerContext};
use nx::ipc::sf::{self, CopyHandle, ProcessId};
use nx::ipc::CommandProtocol;
use nx::result::Result;
use zerocopy::{FromBytes, Immutable, IntoBytes};

/// crates/sys/src/ldn/mod.rs POINTER_BUFFER_SIZE.
const P: usize = 0x1000;

fn hex<T: IntoBytes + Immutable>(t: &T) -> String {
    format!("{:02x?}", t.as_bytes())
}

/// A synthetic `T` filled with `seed`, seed + 1, ...
fn pattern<T: FromBytes>(seed: u8) -> T {
    let bytes: Vec<u8> = (0..size_of::<T>()).map(|i| seed.wrapping_add(i as u8)).collect();
    T::read_from_bytes(&bytes).unwrap()
}

fn bytes<T: IntoBytes + Immutable>(t: &T) -> Vec<u8> {
    t.as_bytes().to_vec()
}

struct Comm;

impl ISessionObject for Comm {
    fn try_handle_request_by_id(&mut self, id: u32, p: CommandProtocol, ctx: &mut ServerContext) -> Option<Result<()>> {
        <Self as ICommunicationServer>::try_handle_request_by_id(self, id, p, ctx)
    }
}

fn l(s: &str) -> Result<()> {
    log(s.to_string());
    Ok(())
}

impl ICommunicationServer for Comm {
    fn get_state(&mut self) -> Result<u32> {
        log("get_state".into());
        Ok(3)
    }
    fn get_network_info(&mut self, out: sf::OutFixedPointerBuffer<'_, NetworkInfo>) -> Result<()> {
        log(format!("get_network_info {}", out_buf(&out, 0xC1)));
        Ok(())
    }
    fn get_ipv4_address(&mut self) -> Result<(u32, u32)> {
        log("get_ipv4_address".into());
        Ok((0x0A00_0002, 0xFFFF_FF00))
    }
    fn get_disconnect_reason(&mut self) -> Result<u32> {
        log("get_disconnect_reason".into());
        Ok(2)
    }
    fn get_security_parameter(&mut self) -> Result<Raw<SecurityParameter>> {
        log("get_security_parameter".into());
        Ok(Raw(pattern(0x40)))
    }
    fn get_network_config(&mut self) -> Result<Raw<NetworkConfig>> {
        log("get_network_config".into());
        Ok(Raw(pattern(0x60)))
    }
    fn attach_state_change_event(&mut self) -> Result<CopyHandle> {
        log("attach_state_change_event".into());
        Ok(CopyHandle::from(0x66))
    }
    fn get_network_info_latest_update(&mut self, info: sf::OutFixedPointerBuffer<'_, NetworkInfo>, updates: sf::OutPointerBuffer<'_, NodeLatestUpdate>) -> Result<()> {
        log(format!("get_network_info_latest_update {} {}", out_buf(&info, 0xC1), out_buf(&updates, 0xC2)));
        Ok(())
    }
    fn scan(&mut self, channel: u16, pad: Raw<[u8; 6]>, filter: Raw<ScanFilter>, networks: sf::OutAutoSelectBuffer<'_, NetworkInfo>) -> Result<u32> {
        log(format!("scan {channel} {:02x?} {} {}", pad.0, hex(&filter.0), out_buf(&networks, 0xC3)));
        Ok(1)
    }
    fn scan_private(&mut self, channel: u16, pad: Raw<[u8; 6]>, filter: Raw<ScanFilter>, networks: sf::OutAutoSelectBuffer<'_, NetworkInfo>) -> Result<u32> {
        log(format!("scan_private {channel} {:02x?} {} {}", pad.0, hex(&filter.0), out_buf(&networks, 0xC3)));
        Ok(1)
    }
    fn set_wireless_controller_restriction(&mut self) -> Result<()> {
        l("set_wireless_controller_restriction")
    }
    fn set_protocol(&mut self, protocol: u32) -> Result<()> {
        log(format!("set_protocol {protocol}"));
        Ok(())
    }
    fn open_access_point(&mut self) -> Result<()> {
        l("open_access_point")
    }
    fn close_access_point(&mut self) -> Result<()> {
        l("close_access_point")
    }
    fn create_network(&mut self, config: Raw<CreateNetworkConfig>) -> Result<()> {
        log(format!("create_network {}", hex(&config.0)));
        Ok(())
    }
    fn create_network_private(&mut self, config: Raw<CreateNetworkPrivateConfig>, addresses: sf::InPointerBuffer<'_, u8>) -> Result<()> {
        log(format!("create_network_private {} {}", hex(&config.0), in_buf(&addresses)));
        Ok(())
    }
    fn destroy_network(&mut self) -> Result<()> {
        l("destroy_network")
    }
    fn reject(&mut self, node_id: u32) -> Result<()> {
        log(format!("reject {node_id}"));
        Ok(())
    }
    fn set_advertise_data(&mut self, data: sf::InAutoSelectBuffer<'_, u8>) -> Result<()> {
        log(format!("set_advertise_data {}", in_buf(&data)));
        Ok(())
    }
    fn set_station_accept_policy(&mut self, policy: u8) -> Result<()> {
        log(format!("set_station_accept_policy {policy}"));
        Ok(())
    }
    fn add_accept_filter_entry(&mut self) -> Result<()> {
        l("add_accept_filter_entry")
    }
    fn clear_accept_filter(&mut self) -> Result<()> {
        l("clear_accept_filter")
    }
    fn open_station(&mut self) -> Result<()> {
        l("open_station")
    }
    fn close_station(&mut self) -> Result<()> {
        l("close_station")
    }
    fn connect(&mut self, data: Raw<ConnectNetworkData>, network: sf::InFixedPointerBuffer<'_, NetworkInfo>) -> Result<()> {
        log(format!("connect {} {}", hex(&data.0), in_buf(&network).len()));
        Ok(())
    }
    fn connect_private(&mut self, data: Raw<ConnectPrivateData>) -> Result<()> {
        log(format!("connect_private {}", hex(&data.0)));
        Ok(())
    }
    fn disconnect(&mut self) -> Result<()> {
        l("disconnect")
    }
    fn initialize(&mut self, pid: ProcessId) -> Result<()> {
        log(format!("initialize {:#x}", pid.process_id));
        Ok(())
    }
    fn finalize(&mut self) -> Result<()> {
        l("finalize")
    }
    fn initialize_system2(&mut self, unk: u64, pid: ProcessId) -> Result<()> {
        log(format!("initialize_system2 {unk:#x} {:#x}", pid.process_id));
        Ok(())
    }
}

/// Serves `req` on a fresh IUserLocalCommunicationService session.
fn serve(req: Request, out_len: usize) -> (Vec<String>, Vec<u8>, Vec<(u8, Vec<u8>)>, hipc::Hipc) {
    set_version(18);
    let mut s = Server::<P>::new(Comm);
    let (words, x) = req.build(None);
    let reply = s.send(words, x, 0x1234_5678).expect("no reply");
    let out = hipc::cmif_out(&reply, false, out_len);
    assert_eq!((out.magic, out.result), (hipc::SFCO, 0), "reply header");
    (take_log(), out.raw, reply_x(&reply), reply)
}

fn just(cmd: u32) -> Vec<String> {
    serve(Request { cmd, ..Default::default() }, 0).0
}

#[test]
fn libnx_struct_sizes() {
    // ldn.h: LdnScanFilter 0x60, LdnNetworkInfo 0x480, LdnSecurityParameter 0x20,
    // LdnNetworkConfig 0x20, LdnNodeLatestUpdate 8; the in structs of ldnCreateNetwork (0x98),
    // ldnCreateNetworkPrivate (0xB8), ldnConnect (0x7C) and ldnConnectPrivate (0xC0).
    assert_eq!(size_of::<ScanFilter>(), 0x60);
    assert_eq!(size_of::<NetworkInfo>(), 0x480);
    assert_eq!(size_of::<SecurityParameter>(), 0x20);
    assert_eq!(size_of::<NetworkConfig>(), 0x20);
    assert_eq!(size_of::<NodeLatestUpdate>(), 8);
    assert_eq!(size_of::<CreateNetworkConfig>(), 0x98);
    assert_eq!(size_of::<CreateNetworkPrivateConfig>(), 0xB8);
    assert_eq!(size_of::<ConnectNetworkData>(), 0x7C);
    assert_eq!(size_of::<ConnectPrivateData>(), 0xC0);
}

#[test]
fn get_state_and_simple_outs() {
    // ldnGetState: out u32. ldnGetIpv4Address: out { u32 addr; u32 netmask; }.
    // ldnGetDisconnectReason: out u16 (we answer a u32, same first two bytes).
    let (log, out, _, _) = serve(Request { cmd: 0, ..Default::default() }, 4);
    assert_eq!((log, out), (vec!["get_state".to_string()], le!(3u32)));
    let (_, out, _, _) = serve(Request { cmd: 2, ..Default::default() }, 8);
    assert_eq!(out, le!(0x0A00_0002u32, 0xFFFF_FF00u32));
    let (_, out, _, _) = serve(Request { cmd: 3, ..Default::default() }, 2);
    assert_eq!(out, le!(2u16));
}

#[test]
fn get_security_parameter_and_network_config() {
    // ldnGetSecurityParameter: out LdnSecurityParameter; ldnGetNetworkConfig: out LdnNetworkConfig.
    let (_, out, _, _) = serve(Request { cmd: 4, ..Default::default() }, 0x20);
    assert_eq!(out, bytes(&pattern::<SecurityParameter>(0x40)));
    let (_, out, _, _) = serve(Request { cmd: 5, ..Default::default() }, 0x20);
    assert_eq!(out, bytes(&pattern::<NetworkConfig>(0x60)));
}

#[test]
fn get_network_info() {
    // ldnGetNetworkInfo: out LdnNetworkInfo as HipcPointer | Out | FixedSize (a C descriptor,
    // no out-pointer table entry); the reply returns it as X index 0.
    let req = Request { cmd: 1, c: vec![0x480], table: Some(vec![]), ..Default::default() };
    let (log, _, x, _) = serve(req, 0);
    assert_eq!(log, ["get_network_info out[0x480]"]);
    assert_eq!(x, [(0, vec![0xC1; 0x480])]);
}

#[test]
fn get_network_info_latest_update() {
    // ldnGetNetworkInfoLatestUpdate: LdnNetworkInfo (Pointer | Out | FixedSize), then
    // LdnNodeLatestUpdate[count] (Pointer | Out: one table entry). Reply: X 0 and X 1.
    let req = Request { cmd: 101, c: vec![0x480, 8 * 8], table: Some(vec![8 * 8]), ..Default::default() };
    let (log, _, x, _) = serve(req, 0);
    assert_eq!(log, ["get_network_info_latest_update out[0x480] out[0x40]"]);
    assert_eq!(x, [(0, vec![0xC1; 0x480]), (1, vec![0xC2; 0x40])]);
}

#[test]
fn attach_state_change_event() {
    // ldnAttachStateChangeEvent: out copy handle.
    let (log, _, _, reply) = serve(Request { cmd: 100, ..Default::default() }, 0);
    assert_eq!(log, ["attach_state_change_event"]);
    assert_eq!(reply.copy, [0x66]);
}

fn scan_request(cmd: u32) -> (Request, ScanFilter) {
    // _ldnScan: in { s16 channel; u8 pad[6]; LdnScanFilter filter; } (filter at offset 8),
    // network_info out HipcAutoSelect; out u16 count. Bug 4 read the filter at offset 2.
    let filter: ScanFilter = pattern(0x10);
    let raw = [le!(6i16), vec![0; 6], bytes(&filter)].concat();
    (Request { cmd, raw, b: vec![Buf::default()], c: vec![0x480 * 2], ..Default::default() }, filter)
}

#[test]
fn bug4_scan_filter_at_offset_8() {
    for (cmd, name) in [(102, "scan"), (103, "scan_private")] {
        let (req, filter) = scan_request(cmd);
        let (log, out, x, _) = serve(req, 2);
        assert_eq!(log, [format!("{name} 6 [00, 00, 00, 00, 00, 00] {} out[0x900]", hex(&filter))]);
        assert_eq!(out, le!(1u16));
        assert_eq!(x, [(0, vec![0xC3; 0x900])]);
    }
}

#[test]
fn commands_without_arguments() {
    // 104 SetWirelessControllerRestriction (its u32 is ignored), 200/201 Open/CloseAccessPoint,
    // 204 DestroyNetwork, 208 AddAcceptFilterEntry (MAC ignored), 209 ClearAcceptFilter,
    // 300/301 Open/CloseStation, 304 Disconnect, 401 Finalize.
    for (cmd, name) in [
        (104, "set_wireless_controller_restriction"),
        (200, "open_access_point"),
        (201, "close_access_point"),
        (204, "destroy_network"),
        (208, "add_accept_filter_entry"),
        (209, "clear_accept_filter"),
        (300, "open_station"),
        (301, "close_station"),
        (304, "disconnect"),
        (401, "finalize"),
    ] {
        assert_eq!(just(cmd), [name]);
    }
}

#[test]
fn set_protocol_reject_accept_policy() {
    // Switchbrew SetProtocol [18.0.0+]: in u32. ldnReject: in u32 node id.
    // ldnSetStationAcceptPolicy: in u8.
    let (log, ..) = serve(Request { cmd: 106, raw: le!(2u32), ..Default::default() }, 0);
    assert_eq!(log, ["set_protocol 2"]);
    let (log, ..) = serve(Request { cmd: 205, raw: le!(3u32), ..Default::default() }, 0);
    assert_eq!(log, ["reject 3"]);
    let (log, ..) = serve(Request { cmd: 207, raw: vec![1], ..Default::default() }, 0);
    assert_eq!(log, ["set_station_accept_policy 1"]);
}

#[test]
fn create_network() {
    // ldnCreateNetwork: in { LdnSecurityConfig; LdnUserConfig; u8 pad[4]; LdnNetworkConfig; }.
    let cfg: CreateNetworkConfig = pattern(0x20);
    let (log, ..) = serve(Request { cmd: 202, raw: bytes(&cfg), ..Default::default() }, 0);
    assert_eq!(log, [format!("create_network {}", hex(&cfg))]);
}

fn create_network_private_with(entries: usize) -> (String, String) {
    // ldnCreateNetworkPrivate: in { LdnSecurityConfig; LdnSecurityParameter; LdnUserConfig;
    // u8 pad[4]; LdnNetworkConfig; }, LdnAddressEntry[count] (0xC each) In HipcPointer (X 0,
    // count * 0xC bytes).
    let cfg: CreateNetworkPrivateConfig = pattern(0x30);
    let addrs = vec![0x5Au8; 0xC * entries];
    let req = Request { cmd: 203, raw: bytes(&cfg), x: vec![addrs.clone()], ..Default::default() };
    let (log, ..) = serve(req, 0);
    (log[0].clone(), format!("create_network_private {} {:02x?}", hex(&cfg), addrs))
}

#[test]
fn create_network_private() {
    let (got, expect) = create_network_private_with(8);
    assert_eq!(got, expect);
}

#[test]
fn create_network_private_short_address_list() {
    let (got, expect) = create_network_private_with(2);
    assert_eq!(got, expect);
}

#[test]
fn set_advertise_data() {
    // ldnSetAdvertiseData: data In HipcAutoSelect.
    let req = Request { cmd: 206, x: vec![vec![1, 2, 3]], a: vec![Buf::default()], ..Default::default() };
    assert_eq!(serve(req, 0).0, ["set_advertise_data [01, 02, 03]"]);
}

#[test]
fn connect() {
    // ldnConnect: in { LdnSecurityConfig; LdnUserConfig; s32 local_communication_version;
    // u32 option; }, LdnNetworkInfo In HipcPointer | FixedSize (X 0).
    let data: ConnectNetworkData = pattern(0x50);
    let req = Request { cmd: 302, raw: bytes(&data), x: vec![vec![0x77; 0x480]], ..Default::default() };
    let (log, ..) = serve(req, 0);
    assert_eq!(log, [format!("connect {} {}", hex(&data), format!("{:02x?}", vec![0x77u8; 0x480]).len())]);
}

#[test]
fn connect_private() {
    // ldnConnectPrivate: in { LdnSecurityConfig; LdnSecurityParameter; LdnUserConfig;
    // s32 local_communication_version; u32 option; u8 pad[4]?; LdnNetworkConfig; } (0xC0).
    let data: ConnectPrivateData = pattern(0x70);
    let (log, ..) = serve(Request { cmd: 303, raw: bytes(&data), ..Default::default() }, 0);
    assert_eq!(log, [format!("connect_private {}", hex(&data))]);
}

#[test]
fn initialize_and_initialize_system2() {
    // ldnInitialize (_ldnCmdInitialize): in u64 pid placeholder, send pid; the kernel's pid
    // reaches the handler. Switchbrew InitializeSystem2: in { u64 unk; u64 pid placeholder }.
    let (log, ..) = serve(Request { cmd: 400, raw: le!(0u64), pid: Some(0), ..Default::default() }, 0);
    assert_eq!(log, ["initialize 0x12345678"]);
    let (log, ..) = serve(Request { cmd: 402, raw: le!(0xABu64, 0u64), pid: Some(0), ..Default::default() }, 0);
    assert_eq!(log, ["initialize_system2 0xab 0x12345678"]);
}

/// ldn:u itself (IUserServiceCreator) and IClientProcessMonitor.
struct Creator;

impl ISessionObject for Creator {
    fn try_handle_request_by_id(&mut self, id: u32, p: CommandProtocol, ctx: &mut ServerContext) -> Option<Result<()>> {
        <Self as ILdnMitmServiceServer>::try_handle_request_by_id(self, id, p, ctx)
    }
}

impl ILdnMitmServiceServer for Creator {
    fn create_user_local_communication_service(&mut self) -> Result<impl ICommunicationServer + 'static> {
        log("create_user_local_communication_service".into());
        Ok(Comm)
    }
    fn create_client_process_monitor(&mut self) -> Result<impl IClientProcessMonitorServer + 'static> {
        log("create_client_process_monitor".into());
        Ok(Monitor)
    }
}

struct Monitor;

impl ISessionObject for Monitor {
    fn try_handle_request_by_id(&mut self, id: u32, p: CommandProtocol, ctx: &mut ServerContext) -> Option<Result<()>> {
        <Self as IClientProcessMonitorServer>::try_handle_request_by_id(self, id, p, ctx)
    }
}

impl IClientProcessMonitorServer for Monitor {
    fn register_client(&mut self, pid: ProcessId) -> Result<()> {
        log(format!("monitor register_client {:#x}", pid.process_id));
        Ok(())
    }
}

#[test]
fn create_service_returns_a_session() {
    // ldnCreateUserLocalCommunicationService: out session, a move handle on a plain session.
    set_version(18);
    let mut s = Server::<P>::new(Creator);
    let (words, x) = Request { cmd: 0, ..Default::default() }.build(None);
    let reply = s.send(words, x, 0).unwrap();
    assert_eq!(hipc::cmif_out(&reply, false, 0).result, 0);
    assert_eq!(reply.moves.len(), 1);
    assert_eq!(take_log(), ["create_user_local_communication_service"]);
}

#[test]
fn domain_objects() {
    // On a domain (cmif.h): the created service comes back as an out object id in the
    // CmifDomainOutHeader; requests to it carry that id in the CmifDomainInHeader.
    set_version(18);
    let mut s = Server::<P>::new(Creator);
    let root = s.convert_to_domain();
    let mut call = |object: u32, req: Request, out_len: usize| {
        let (words, x) = req.build(Some(object));
        let reply = s.send(words, x, 0x1234_5678).unwrap();
        hipc::cmif_out(&reply, true, out_len)
    };
    let created = call(root, Request { cmd: 0, ..Default::default() }, 0);
    assert_eq!((created.result, created.objects.len()), (0, 1));
    let comm = created.objects[0];
    assert_ne!(comm, root);
    let monitor = call(root, Request { cmd: 1, ..Default::default() }, 0).objects[0];

    let state = call(comm, Request { cmd: 0, ..Default::default() }, 4);
    assert_eq!(state.raw, le!(3u32));
    let (req, filter) = scan_request(102);
    let scan = call(comm, req, 2);
    assert_eq!(scan.raw, le!(1u16));
    call(monitor, Request { cmd: 0, raw: le!(0u64), pid: Some(0), ..Default::default() }, 0);
    assert_eq!(
        take_log(),
        [
            "create_user_local_communication_service".to_string(),
            "create_client_process_monitor".into(),
            "get_state".into(),
            format!("scan 6 [00, 00, 00, 00, 00, 00] {} out[0x900]", hex(&filter)),
            "monitor register_client 0x12345678".into(),
        ]
    );
}
