//! `IClientProcessMonitor` (FW 18.0.0+ games register through it and keep the
//! session for their lifetime): its RegisterClient marks the game active, and
//! its close is the "game exited" signal.
#![forbid(unsafe_code)]

use ldn_tunnel_core::notify::Event;
use nx::ipc::CommandProtocol;
use nx::ipc::server::{ISessionObject, ServerContext};
use nx::ipc::sf::ProcessId;
use nx::result::Result;

use super::ifaces::IClientProcessMonitorServer;
use crate::state::STATE;

#[derive(Default)]
pub struct ClientProcessMonitorService {
    /// 0 until RegisterClient.
    pid: u64,
}

impl ISessionObject for ClientProcessMonitorService {
    fn try_handle_request_by_id(
        &mut self,
        req_id: u32,
        protocol: CommandProtocol,
        ctx: &mut ServerContext,
    ) -> Option<Result<()>> {
        <Self as IClientProcessMonitorServer>::try_handle_request_by_id(self, req_id, protocol, ctx)
    }
}

impl IClientProcessMonitorServer for ClientProcessMonitorService {
    fn register_client(&mut self, process_id: ProcessId) -> Result<()> {
        self.pid = process_id.process_id;
        STATE.set_game(Some(self.pid));
        log!(Info, "ldn: RegisterClient pid {}", self.pid);
        Ok(())
    }
}

impl Drop for ClientProcessMonitorService {
    /// The game process closed its monitor session (it exited).
    // ponytail: before FW 18 there is no monitor, so no GameExited; the next
    // game's GameStarted (new pid) replaces the toast session anyway.
    fn drop(&mut self) {
        if self.pid == 0 {
            return;
        }
        if STATE.active_pid() == self.pid {
            STATE.set_game(None);
        }
        STATE.notify_event(Event::GameExited { pid: self.pid });
        log!(Info, "ldn: pid {} exited", self.pid);
    }
}
