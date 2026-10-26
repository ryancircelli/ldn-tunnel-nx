//! sm (TIPC), nifm and time as the module sends them, and ldnt:cfg as it serves it.
//! - sm: libnx `nx/source/services/sm.c` TIPC paths (`smGetServiceOriginal`,
//!   `_smRegisterServiceTipc`, `smUnregisterService`, `smDetachClient`) and Atmosphere's
//!   extensions as libstratosphere's `sm_ams.c` sends them (65000 InstallMitm, 65001
//!   UninstallMitm, 65003 AcknowledgeMitmSession, 65004 HasMitm, 65007 ClearFutureMitm);
//!   TIPC framing from libnx `tipc.h` (type = 16 + id, arguments from raw word 0, reply = result
//!   word then output).
//! - nifm / time: libnx `nifm.c` (`_nifmCreateGeneralService`, `nifmGetCurrentIpConfigInfo`)
//!   and `time.c` (GetStandardUserSystemClock / GetStandardNetworkSystemClock,
//!   `timeGetCurrentTime`), definitions in crates/sys/src/net/ipc.rs.
//! - ldnt:cfg: the overlay's client, overlay/source/ldn_tunnel_ipc.c (libnx serviceDispatchIn /
//!   Out), served by crates/sys/src/cfg/ifaces.rs.

mod common;

#[path = "../../sys/src/net/ipc.rs"]
#[allow(dead_code)]
mod net_ipc;

#[path = "../../sys/src/ldn/ifaces.rs"]
#[allow(dead_code)]
pub mod ldn_ifaces;

/// crates/sys/src/cfg/ifaces.rs names `crate::ldn::ifaces::Raw`.
mod ldn {
    pub use super::ldn_ifaces as ifaces;
}

#[path = "../../sys/src/cfg/ifaces.rs"]
#[allow(dead_code)]
mod cfg_ifaces;

use cfg_ifaces::{ICfgServiceServer, TransportStatusBuf, VersionBuf};
use common::hipc::{self, Hipc};
use common::*;
#[allow(unused_imports)]
use common::compat;
use ldn_ifaces::Raw;
use ldn_tunnel_core::cfg_types::{ConfigResult, ServerAddressIpc, SessionInfoIpc, UpdateStatusIpc};
use net_ipc::{INifmGeneralClient, INifmStaticClient, ISystemClockClient, ITimeStaticClient, NifmStatic, TimeStatic};
#[allow(unused_imports)]
use nx::ipc::sf::sm::{IUserInterfaceClient, ServiceName, UserInterface};
use nx::ipc::sf::ProcessId;
use nx::result::Result;
use zerocopy::FromBytes;

fn name(s: &str) -> u64 {
    let mut b = [0u8; 8];
    b[..s.len()].copy_from_slice(s.as_bytes());
    u64::from_le_bytes(b)
}

fn sm() -> UserInterface {
    client(true)
}

fn tipc(raw: Vec<u8>, moves: Vec<u32>) -> Answer {
    Answer { tipc: true, raw, moves, ..Default::default() }
}

#[test]
fn sm_get_service_handle() {
    // smGetServiceOriginal (TIPC): in u64 name; out move handle.
    let (h, sent) = call(tipc(vec![], vec![0x41]), || sm().get_service_handle(ServiceName::new("bsd:s")).unwrap());
    assert_eq!(h.handle, 0x41);
    assert_tipc(&sent[0], Hipc::default(), 1, &le!(name("bsd:s")));
}

#[test]
fn bug2_sm_register_service_tipc_order() {
    // _smRegisterServiceTipc: in { SmServiceName service_name; u32 max_sessions; bool is_light; }
    // (max_sessions at 8, is_light at 12; 16 bytes). Bug 2: nx sent the CMIF order
    // (name, is_light, max_sessions) and sm read max_sessions 0.
    let (h, sent) = call(tipc(vec![], vec![0x42]), || sm().register_service(ServiceName::new("ldnt:cfg"), 2, false).unwrap());
    assert_eq!(h.handle, 0x42);
    assert_tipc(&sent[0], Hipc::default(), 2, &[le!(name("ldnt:cfg"), 2u32), vec![0]].concat());
}

#[test]
fn sm_unregister_service() {
    // smUnregisterService (TIPC): in u64 name.
    let (_, sent) = call(tipc(vec![], vec![]), || sm().unregister_service(ServiceName::new("ldnt:cfg")).unwrap());
    assert_tipc(&sent[0], Hipc::default(), 3, &le!(name("ldnt:cfg")));
}

#[test]
fn sm_register_and_detach_client() {
    // smInitialize's RegisterClient (0) and smDetachClient (4) over TIPC: send pid, no raw data
    // (TIPC has no pid placeholder).
    let (_, sent) = call(tipc(vec![], vec![]), || sm().register_client(ProcessId::new()).unwrap());
    assert_tipc(&sent[0], Hipc { pid: Some(0), ..Default::default() }, 0, &[]);
    set_version(18);
    let (_, sent) = call(tipc(vec![], vec![]), || sm().detach_client(ProcessId::new()).unwrap());
    assert_tipc(&sent[0], Hipc { pid: Some(0), ..Default::default() }, 4, &[]);
}

#[test]
fn sm_atmosphere_mitm_commands() {
    // sm_ams.c: InstallMitm (65000) in name, out two move handles (port, query session);
    // UninstallMitm (65001), ClearFutureMitm (65007): in name; HasMitm (65004): out bool.
    let n = ServiceName::new("ldn:u");
    let ((a, b), sent) = call(tipc(vec![], vec![0x51, 0x52]), || sm().atmosphere_install_mitm(n).unwrap());
    assert_eq!((a.handle, b.handle), (0x51, 0x52));
    assert_tipc(&sent[0], Hipc::default(), 65000, &le!(name("ldn:u")));
    let (_, sent) = call(tipc(vec![], vec![]), || sm().atmosphere_uninstall_mitm(n).unwrap());
    assert_tipc(&sent[0], Hipc::default(), 65001, &le!(name("ldn:u")));
    let (_, sent) = call(tipc(vec![], vec![]), || sm().atmosphere_clear_future_mitm(n).unwrap());
    assert_tipc(&sent[0], Hipc::default(), 65007, &le!(name("ldn:u")));
    let (has, sent) = call(tipc(vec![1], vec![]), || sm().atmosphere_has_mitm(n).unwrap());
    assert!(has);
    assert_tipc(&sent[0], Hipc::default(), 65004, &le!(name("ldn:u")));
}

#[test]
fn sm_atmosphere_acknowledge_mitm_session() {
    // AcknowledgeMitmSession (65003): in name; out { MitmProcessInfo (u64 process_id,
    // u64 program_id, u64 keys_held, u64 override_status) }, move handle (forward session).
    let raw = le!(0x51u64, 0x0100_0000_0000_1000u64, 0u64, 0x10u64);
    let ((info, h), sent) = call(tipc(raw, vec![0x53]), || sm().atmosphere_acknowledge_mitm_session(ServiceName::new("bsd:u")).unwrap());
    assert_eq!((info.process_id, info.override_flags, h.handle), (0x51, 0x10, 0x53));
    assert_tipc(&sent[0], Hipc::default(), 65003, &le!(name("bsd:u")));
}

#[test]
fn nifm_create_general_service() {
    // _nifmCreateGeneralService: in u64 reserved (the pid placeholder), send pid, out object.
    let st: NifmStatic = client(false);
    let answer = Answer { moves: vec![0x61], ..Default::default() };
    let (_, sent) = call(answer, || st.create_general_service(ProcessId::new()).unwrap());
    assert_cmif(&sent[0], Hipc { pid: Some(0), ..Default::default() }, 5, &le!(0u64), &[]);
}

#[test]
fn nifm_get_current_ip_config_info() {
    // nifmGetCurrentIpConfigInfo: out packed { u8; u32 ip; u32 mask; u32 gw; } then packed
    // { u8; u32 dns1; u32 dns2; }: 0x16 bytes, DNS servers at 0x0E and 0x12.
    let general: net_ipc::NifmGeneral = client(false);
    let mut raw = vec![0u8; 0x16];
    raw[0x0E..0x12].copy_from_slice(&[1, 1, 1, 1]);
    raw[0x12..0x16].copy_from_slice(&[8, 8, 4, 4]);
    let (info, sent) = call(Answer { raw, ..Default::default() }, || general.get_current_ip_config_info().unwrap());
    assert_eq!(info.dns(), [core::net::Ipv4Addr::new(1, 1, 1, 1), core::net::Ipv4Addr::new(8, 8, 4, 4)]);
    assert_cmif(&sent[0], Hipc::default(), 15, &[], &[]);
}

#[test]
fn time_clocks() {
    // time.c: IStaticService GetStandardUserSystemClock (0) / GetStandardNetworkSystemClock (1)
    // return an ISystemClock; ISystemClock GetCurrentTime (0): out u64 POSIX seconds.
    let st: TimeStatic = client(false);
    let answer = Answer { moves: vec![0x71], ..Default::default() };
    let (_, sent) = call(answer.clone(), || st.get_standard_user_system_clock().unwrap());
    assert_cmif(&sent[0], Hipc::default(), 0, &[], &[]);
    let (_, sent) = call(answer, || st.get_standard_network_system_clock().unwrap());
    assert_cmif(&sent[0], Hipc::default(), 1, &[], &[]);
    let clock: net_ipc::SystemClock = client(false);
    let (t, sent) = call(Answer { raw: le!(1_700_000_000i64), ..Default::default() }, || clock.get_current_time().unwrap());
    assert_eq!(t, 1_700_000_000);
    assert_cmif(&sent[0], Hipc::default(), 0, &[], &[]);
}

// The real session object (cfg/ifaces.rs `Cfg`) with recording bodies in place of
// cfg/service.rs: every getter answers a distinct value.

fn got(n: u32) -> Result<u32> {
    log(format!("get {n}"));
    Ok(0x100 + n)
}

fn set(n: u32, v: u32) -> Result<()> {
    log(format!("set {n} {v:#x}"));
    Ok(())
}

impl ICfgServiceServer for cfg_ifaces::Cfg {
    fn get_version(&mut self) -> Result<VersionBuf> {
        let mut v = [0u8; 32];
        v[..6].copy_from_slice(b"v1.2.3");
        Ok(v)
    }
    fn get_connection_status(&mut self) -> Result<u32> {
        got(1)
    }
    fn is_service_active(&mut self) -> Result<u32> {
        got(2)
    }
    fn is_game_active(&mut self) -> Result<u32> {
        got(3)
    }
    fn get_ldn_state(&mut self) -> Result<u32> {
        got(4)
    }
    fn get_session_info(&mut self) -> Result<Raw<SessionInfoIpc>> {
        Ok(Raw(SessionInfoIpc { node_count: 2, max_nodes: 8, local_node_id: 1, is_host: 0, reserved: [0; 4] }))
    }
    fn get_active_process_id(&mut self) -> Result<u64> {
        Ok(0x51)
    }
    fn get_debug_enabled(&mut self) -> Result<u32> {
        got(9)
    }
    fn set_debug_enabled(&mut self, v: u32) -> Result<()> {
        set(10, v)
    }
    fn get_debug_level(&mut self) -> Result<u32> {
        got(11)
    }
    fn set_debug_level(&mut self, v: u32) -> Result<()> {
        set(12, v)
    }
    fn save_config(&mut self) -> Result<Raw<ConfigResult>> {
        Ok(Raw(ConfigResult::IoError))
    }
    fn reload_config(&mut self) -> Result<Raw<ConfigResult>> {
        Ok(Raw(ConfigResult::ParseError))
    }
    fn get_server_address(&mut self) -> Result<Raw<ServerAddressIpc>> {
        let mut host = [0u8; 64];
        host[..11].copy_from_slice(b"example.org");
        Ok(Raw(ServerAddressIpc { host, port: 30456, padding: 0 }))
    }
    fn set_server_address(&mut self, a: Raw<ServerAddressIpc>) -> Result<()> {
        let host = a.0.host.iter().take_while(|&&b| b != 0).map(|&b| b as char).collect::<String>();
        log(format!("set_server_address {host} {}", a.0.port));
        Ok(())
    }
    fn get_ldn_enabled(&mut self) -> Result<u32> {
        got(17)
    }
    fn set_ldn_enabled(&mut self, v: u32) -> Result<()> {
        set(18, v)
    }
    fn get_transport_status(&mut self) -> Result<TransportStatusBuf> {
        let mut s = [0u8; 64];
        s[..2].copy_from_slice(b"ok");
        Ok(s)
    }
    fn get_update_status(&mut self) -> Result<Raw<UpdateStatusIpc>> {
        let mut st = UpdateStatusIpc::read_from_bytes(&[0u8; 48]).unwrap();
        st.running_build = 7;
        st.channel = 2;
        st.download = 51;
        Ok(Raw(st))
    }
    fn check_for_updates(&mut self) -> Result<()> {
        log("check_for_updates".into());
        Ok(())
    }
    fn get_notify_flags(&mut self) -> Result<u32> {
        got(28)
    }
    fn set_notify_flags(&mut self, v: u32) -> Result<()> {
        set(29, v)
    }
    fn get_setup_status(&mut self) -> Result<u32> {
        got(30)
    }
    fn prepare_restart(&mut self) -> Result<()> {
        log("prepare_restart".into());
        Ok(())
    }
}

/// crates/sys/src/cfg/mod.rs: ServerManager::<0x100>.
fn cfg(cmd: u32, raw: Vec<u8>, out_len: usize) -> (Vec<String>, Vec<u8>) {
    let mut s = Server::<0x100>::new(cfg_ifaces::Cfg);
    let (words, x) = Request { cmd, raw, ..Default::default() }.build(None);
    let reply = s.send(words, x, 0).unwrap();
    let out = hipc::cmif_out(&reply, false, out_len);
    assert_eq!((out.magic, out.result), (hipc::SFCO, 0), "cmd {cmd}");
    (take_log(), out.raw)
}

#[test]
fn cfg_u32_getters_and_setters() {
    // serviceDispatchOut(.., u32) / serviceDispatchIn(.., u32): a u32 at raw offset 0.
    for n in [1, 2, 3, 4, 9, 11, 17, 28, 30] {
        assert_eq!(cfg(n, vec![], 4), (vec![format!("get {n}")], le!(0x100 + n)));
    }
    for n in [10, 12, 18, 29] {
        assert_eq!(cfg(n, le!(0xA5u32), 0).0, [format!("set {n} 0xa5")]);
    }
}

#[test]
fn cfg_structs() {
    // ldnTunnelGetVersion: char[32]; GetSessionInfo: LdnTunnelSessionInfo (4 x u8 + 4 reserved);
    // GetActiveProcessId: u64; Save/ReloadConfig: u32 result; GetTransportStatus: char[64];
    // GetUpdateStatus: LdnTunnelUpdateStatus (3 x u32, 4 x u8, char[31], u8 download: 48).
    assert_eq!(&cfg(0, vec![], 32).1[..7], b"v1.2.3\0");
    assert_eq!(cfg(5, vec![], 8).1, [2, 8, 1, 0, 0, 0, 0, 0]);
    assert_eq!(cfg(8, vec![], 8).1, le!(0x51u64));
    assert_eq!(cfg(13, vec![], 4).1, le!(3u32));
    assert_eq!(cfg(14, vec![], 4).1, le!(2u32));
    assert_eq!(&cfg(25, vec![], 64).1[..3], b"ok\0");
    let st = cfg(26, vec![], 48).1;
    assert_eq!((&st[0..4], st[14], st[47]), (&le!(7u32)[..], 2, 51));
}

#[test]
fn cfg_server_address() {
    // ldnTunnelGet/SetServerAddress: { char host[64]; u16 port; u16 padding; } (68 bytes).
    let out = cfg(15, vec![], 68).1;
    assert_eq!((&out[..12], &out[64..66]), (&b"example.org\0"[..], &le!(30456u16)[..]));
    let mut host = [0u8; 64];
    host[..9].copy_from_slice(b"relay.lan");
    let raw = [host.to_vec(), le!(443u16, 0u16)].concat();
    assert_eq!(cfg(16, raw, 0).0, ["set_server_address relay.lan 443"]);
}

#[test]
fn cfg_commands_without_data() {
    // ldnTunnelCheckForUpdates / ldnTunnelPrepareRestart: serviceDispatch, no data.
    assert_eq!(cfg(27, vec![], 0).0, ["check_for_updates"]);
    assert_eq!(cfg(31, vec![], 0).0, ["prepare_restart"]);
}
