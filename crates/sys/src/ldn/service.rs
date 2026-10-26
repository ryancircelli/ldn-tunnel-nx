//! `ldn:u` MITM bodies (port of `ldn_mitm_service.cpp` + `ldn_icommunication.cpp`):
//! the route decision, then every ICommunication command on the one
//! `Session` (session.rs). Relay-bound commands are nx deferrals: the request
//! is parked and the ldn:u thread keeps serving everything else.
#![forbid(unsafe_code)]

use zerocopy::{FromZeros, IntoBytes};
use core::sync::atomic::{AtomicU32, Ordering::Relaxed};

use ldn_tunnel_core::ldn::shell::launch_mode;
use ldn_tunnel_core::ldn::{LdnError, NODE_COUNT_MAX, Pending, Session};
use ldn_tunnel_core::ldn_types::{
    AddressList, ConnectNetworkData, ConnectPrivateData, CreateNetworkConfig,
    CreateNetworkPrivateConfig, NetworkConfig, NetworkInfo, NodeLatestUpdate, ScanFilter,
    SecurityParameter,
};
use ldn_tunnel_core::notify::{Event, LdnMode};
use nx::ipc::CommandProtocol;
use nx::ipc::server::{Deferral, IMitmServerObject, IMitmService, ISessionObject, ServerContext};
use nx::ipc::sf::sm::mitm::MitmProcessInfo;
use nx::ipc::sf::sm::mitm::rc::ResultShouldForwardToSession;
use nx::ipc::sf::{self, ProcessId};
use nx::result::{Result, ResultBase, ResultCode};

use super::ifaces::{IClientProcessMonitorServer, ICommunicationServer, ILdnMitmServiceServer, Raw};
use super::monitor::ClientProcessMonitorService;
use super::{nifm, session};
use crate::config_io;
use crate::state::{STATE, uptime_ms};

/// An ldn:u command that held its thread longer than this is logged (`ldn: slow call`).
const SLOW_CALL_MS: u64 = 250;

fn ldn_rc(e: LdnError) -> ResultCode {
    ResultCode::new(e.result_code())
}

/// Session object of `ldn:u` (the root MITM session, one per game connection).
pub struct LdnMitm {
    info: MitmProcessInfo,
}

impl IMitmServerObject for LdnMitm {
    fn new(info: MitmProcessInfo) -> Self {
        STATE.mitm_sessions.fetch_add(1, Relaxed);
        Self { info }
    }
}

impl Drop for LdnMitm {
    fn drop(&mut self) {
        STATE.mitm_sessions.fetch_sub(1, Relaxed);
    }
}

impl ISessionObject for LdnMitm {
    fn try_handle_request_by_id(
        &mut self,
        req_id: u32,
        protocol: CommandProtocol,
        ctx: &mut ServerContext,
    ) -> Option<Result<()>> {
        <Self as ILdnMitmServiceServer>::try_handle_request_by_id(self, req_id, protocol, ctx)
    }
}

fn mode_of(info: &MitmProcessInfo) -> LdnMode {
    let ldn = config_io::get().ldn;
    launch_mode(ldn.enabled, ldn.real_wireless_button, info.npad_buttons.get())
}

impl IMitmService for LdnMitm {
    fn get_name() -> sf::sm::ServiceName {
        sf::sm::ServiceName::new("ldn:u")
    }

    /// Whitelisted games only. `[ldn] enabled = 0` or the real-wireless
    /// button held at launch leave the game on the real ldn:u. No IPC here:
    /// sm waits on this answer.
    fn should_mitm(info: MitmProcessInfo) -> bool {
        let pid = info.process_id;
        let program_id = info.program_id.0;
        if !config_io::is_whitelisted(program_id) || !STATE.ldn_services_allowed() {
            return false;
        }
        let mode = mode_of(&info);
        log!(Info, "ldn:u: {program_id:016X} pid {pid} -> {mode:?}");
        STATE.notify_event(Event::GameStarted { pid, mode });
        mode == LdnMode::Online
    }
}

static NEXT_OWNER: AtomicU32 = AtomicU32::new(1);

impl ILdnMitmServiceServer for LdnMitm {
    /// The route is decided again each time the game starts Local Wireless (as
    /// the C++ did): config changed meanwhile, or the console is offline → the
    /// real service (the relay cannot work without a network).
    fn create_user_local_communication_service(&mut self) -> Result<impl ICommunicationServer + 'static> {
        let online = nifm::current_ip().is_ok_and(|(ip, _)| ip != 0);
        let mode = mode_of(&self.info);
        if mode != LdnMode::Online || !online {
            log!(Info, "ldn:u: {mode:?}, online {online}: real local wireless");
            return ResultShouldForwardToSession::make_err();
        }
        Ok(CommunicationService {
            owner: NEXT_OWNER.fetch_add(1, Relaxed),
            program_id: self.info.program_id.0,
            pid: self.info.process_id,
            first: true,
            defer: None,
        })
    }

    fn create_client_process_monitor(&mut self) -> Result<impl IClientProcessMonitorServer + 'static> {
        Ok(ClientProcessMonitorService::default())
    }
}

/// One game's IUserLocalCommunicationService.
pub struct CommunicationService {
    /// Identifies this service as the session's owner (session.rs).
    owner: u32,
    program_id: u64,
    pid: u64,
    /// This dispatch is not a resume of a deferred request.
    first: bool,
    /// Set by a command that parks its request; handed to nx after dispatch.
    defer: Option<Deferral>,
}

impl ISessionObject for CommunicationService {
    fn try_handle_request_by_id(
        &mut self,
        req_id: u32,
        protocol: CommandProtocol,
        ctx: &mut ServerContext,
    ) -> Option<Result<()>> {
        self.first = !ctx.resumed;
        let t0 = uptime_ms();
        let r = <Self as ICommunicationServer>::try_handle_request_by_id(self, req_id, protocol, ctx);
        if r.is_none() {
            // Not declared in ifaces.rs (likely added by a newer firmware, docs/compatibility.md):
            // nx answers InvalidCommandRequestId; there is no real session to forward it to.
            log!(Warning, "ldn: unknown cmd {req_id}, answered InvalidCommandRequestId");
        }
        let defer = self.defer.take();
        // A game's ldn:u call must not stall behind bsd:u.
        // Parked (deferred) relay waits are not stalls: the thread is free while they wait.
        let ms = uptime_ms().saturating_sub(t0);
        if ms > SLOW_CALL_MS && defer.is_none() {
            log!(Warning, "ldn: slow call {req_id} {ms} ms");
        }
        if matches!(r, Some(Ok(()))) {
            ctx.defer = defer;
        }
        r
    }
}

impl Drop for CommunicationService {
    /// The game closed the service (or exited): its session goes.
    fn drop(&mut self) {
        if session::close(self.owner) && STATE.active_pid() == self.pid {
            STATE.set_game(None);
        }
    }
}

impl CommunicationService {
    fn with<R>(&self, f: impl FnOnce(&mut Session, u64) -> R) -> Result<R> {
        session::with(self.owner, f).map_err(ldn_rc)
    }

    fn call(&self, f: impl FnOnce(&mut Session, u64) -> core::result::Result<(), LdnError>) -> Result<()> {
        self.with(f)?.map_err(ldn_rc)
    }

    /// A relay-bound command: `Ok(true)` when its reply is in (answer now),
    /// `Ok(false)` when the request is parked (the answer is not sent).
    fn request(
        &mut self,
        start: impl FnOnce(&mut Session, u64) -> core::result::Result<Pending, LdnError>,
    ) -> Result<bool> {
        match session::request(self.owner, self.first, start) {
            Ok(reply) => reply.map(|()| true).map_err(ldn_rc),
            Err(deferral) => {
                self.defer = Some(deferral);
                Ok(false)
            }
        }
    }

    fn initialize_for(&mut self, pid: u64) -> Result<()> {
        session::open(self.owner, self.program_id).map_err(ldn_rc)?;
        self.pid = pid;
        STATE.set_game(Some(pid));
        log!(Info, "ldn: Initialize by pid {pid}");
        Ok(())
    }

    fn scan_into(&mut self, networks: &mut sf::OutAutoSelectBuffer<'_, NetworkInfo>, filter: Raw<ScanFilter>) -> Result<u32> {
        let filter = filter.0;
        if !self.request(|s, now| s.scan(&filter, now))? {
            return Ok(0);
        }
        let out = networks.as_maybeuninit_mut()?;
        let cap = out.len();
        let n = self.with(|s, _| {
            let mut n = 0u32;
            for (dst, src) in out.iter_mut().zip(s.scan_results()) {
                dst.write(*src);
                n = n.saturating_add(1);
            }
            n
        });
        log!(Info, "ldn: scan gave the game {n:?} of buffer {cap}");
        n
    }
}

impl ICommunicationServer for CommunicationService {
    fn get_state(&mut self) -> Result<u32> {
        // Always succeeds (Ryujinx); a service that lost its session reads None.
        Ok(self.with(|s, _| s.state() as u32).unwrap_or(0))
    }

    fn get_network_info(&mut self, mut out: sf::OutFixedPointerBuffer<'_, NetworkInfo>) -> Result<()> {
        let info = self.with(|s, _| *s.network_info())?;
        if let Some(dst) = out.as_maybeuninit_mut()?.first_mut() {
            dst.write(info);
        }
        Ok(())
    }

    fn get_ipv4_address(&mut self) -> Result<(u32, u32)> {
        match self.with(|s, _| s.get_ipv4_address())? {
            Some(addr) => Ok(addr),
            None => nifm::current_ip(),
        }
    }

    fn get_disconnect_reason(&mut self) -> Result<u32> {
        self.with(|s, _| s.get_disconnect_reason() as u32)
    }

    fn get_security_parameter(&mut self) -> Result<Raw<SecurityParameter>> {
        self.with(|s, _| Raw(s.get_security_parameter()))
    }

    fn get_network_config(&mut self) -> Result<Raw<NetworkConfig>> {
        self.with(|s, _| Raw(s.get_network_config()))
    }

    fn attach_state_change_event(&mut self) -> Result<sf::CopyHandle> {
        // A copy: the kernel duplicates it for the game; ours stays open.
        Ok(sf::CopyHandle::from(session::STATE_EVENT.handle()))
    }

    fn get_network_info_latest_update(
        &mut self,
        mut info: sf::OutFixedPointerBuffer<'_, NetworkInfo>,
        mut updates: sf::OutPointerBuffer<'_, NodeLatestUpdate>,
    ) -> Result<()> {
        let count = updates.get_count();
        let (network, changes) = self.with(|s, _| {
            let changes = s.get_network_info_latest_update(count.min(NODE_COUNT_MAX));
            (*s.network_info(), changes)
        })?;
        if let Some(dst) = info.as_maybeuninit_mut()?.first_mut() {
            dst.write(network);
        }
        // Entries past the 8 nodes are zeroed (README "IPC buffers").
        for (i, dst) in updates.as_maybeuninit_mut()?.iter_mut().enumerate() {
            let state_change = changes.get(i).map_or(0, |c| *c as u8);
            dst.write(NodeLatestUpdate { state_change, unk: [0; 7] });
        }
        Ok(())
    }

    fn scan(&mut self, _channel: u16, _pad: Raw<[u8; 6]>, filter: Raw<ScanFilter>, mut networks: sf::OutAutoSelectBuffer<'_, NetworkInfo>) -> Result<u32> {
        self.scan_into(&mut networks, filter)
    }

    fn scan_private(&mut self, _channel: u16, _pad: Raw<[u8; 6]>, filter: Raw<ScanFilter>, mut networks: sf::OutAutoSelectBuffer<'_, NetworkInfo>) -> Result<u32> {
        self.scan_into(&mut networks, filter)
    }

    fn set_wireless_controller_restriction(&mut self) -> Result<()> {
        Ok(())
    }

    fn set_protocol(&mut self, protocol: u32) -> Result<()> {
        self.call(|s, _| s.set_protocol(protocol))
    }

    fn open_access_point(&mut self) -> Result<()> {
        self.call(|s, now| s.open_access_point(now))
    }

    fn close_access_point(&mut self) -> Result<()> {
        self.call(|s, now| s.close_access_point(now))
    }

    fn create_network(&mut self, config: Raw<CreateNetworkConfig>) -> Result<()> {
        let c = config.0;
        self.request(|s, now| s.create_network(&c.security_config, &c.user_config, &c.network_config, now))
            .map(drop)
    }

    fn create_network_private(
        &mut self,
        config: Raw<CreateNetworkPrivateConfig>,
        addresses: sf::InPointerBuffer<'_, u8>,
    ) -> Result<()> {
        let c = config.0;
        // Optional, and only `count` entries long (libnx): zero-fill the rest of the list.
        let bytes = addresses.as_slice().unwrap_or(&[]);
        let list = (!bytes.is_empty()).then(|| {
            let mut l = AddressList::new_zeroed();
            l.as_mut_bytes().iter_mut().zip(bytes).for_each(|(d, s)| *d = *s);
            l
        });
        let (security, parameter, user, network) = (c.security_config, c.security_parameter, c.user_config, c.network_config);
        self.request(|s, now| s.create_network_private(&security, &parameter, &user, &network, list.as_ref(), now))
            .map(drop)
    }

    fn destroy_network(&mut self) -> Result<()> {
        self.call(|s, now| s.destroy_network(now))
    }

    fn reject(&mut self, node_id: u32) -> Result<()> {
        self.request(|s, now| s.reject(node_id, now)).map(drop)
    }

    fn set_advertise_data(&mut self, data: sf::InAutoSelectBuffer<'_, u8>) -> Result<()> {
        let bytes = data.as_slice().unwrap_or(&[]);
        self.with(|s, _| s.set_advertise_data(bytes))
    }

    fn set_station_accept_policy(&mut self, policy: u8) -> Result<()> {
        self.with(|s, _| s.set_station_accept_policy(policy))
    }

    fn add_accept_filter_entry(&mut self) -> Result<()> {
        Ok(())
    }

    fn clear_accept_filter(&mut self) -> Result<()> {
        Ok(())
    }

    fn open_station(&mut self) -> Result<()> {
        self.call(|s, now| s.open_station(now))
    }

    fn close_station(&mut self) -> Result<()> {
        self.call(|s, now| s.close_station(now))
    }

    fn connect(&mut self, data: Raw<ConnectNetworkData>, network: sf::InFixedPointerBuffer<'_, NetworkInfo>) -> Result<()> {
        let d = data.0;
        let network = *network.get_var()?;
        self.request(|s, now| {
            s.connect(&d.security_config, &d.user_config, d.local_communication_version, d.option, &network, now)
        })
        .map(drop)
    }

    fn connect_private(&mut self, data: Raw<ConnectPrivateData>) -> Result<()> {
        let d = data.0;
        let (security, parameter, user, network) = (d.security_config, d.security_parameter, d.user_config, d.network_config);
        let (version, option) = (d.local_communication_version, d.option);
        self.request(|s, now| s.connect_private(&security, &parameter, &user, version, option, &network, now))
            .map(drop)
    }

    fn disconnect(&mut self) -> Result<()> {
        self.call(|s, now| s.disconnect(now))
    }

    fn initialize(&mut self, process_id: ProcessId) -> Result<()> {
        self.initialize_for(process_id.process_id)
    }

    fn finalize(&mut self) -> Result<()> {
        let _ = self.with(|s, now| s.finalize(now));
        if STATE.active_pid() == self.pid {
            STATE.set_game(None);
        }
        Ok(())
    }

    fn initialize_system2(&mut self, _unk: u64, process_id: ProcessId) -> Result<()> {
        self.initialize_for(process_id.process_id)
    }
}
