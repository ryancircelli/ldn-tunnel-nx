//! `ldnt:cfg`: the service the overlay talks to.

pub mod ifaces;
mod service;

/// Registers `ldnt:cfg` with sm and serves it on the calling thread (its own
/// ServerManager, as the C++ cfg thread). Returns only on an IPC error.
pub fn serve() -> nx::result::Result<()> {
    // 0x100: the largest cfg request is SetServerAddress (68 bytes, inline).
    let mut sm = nx::ipc::server::ServerManager::<0x100>::new()?;
    sm.register_service_server::<ifaces::Cfg>()?;
    log!(Info, "cfg: {} registered", ldn_tunnel_core::ident::CFG_SERVICE);
    sm.loop_process()
}
