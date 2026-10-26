//! IPC server threading: one nx `ServerManager` per service, each on its own
//! thread. Blocking work never runs on a server thread; it is deferred (see
//! README.md for the design and the stall analysis).

pub mod forward;

use nx::ipc::server::ServerManager;
use nx::result::Result;

/// Starts a thread that builds a `ServerManager<P>`, lets `register` add its
/// services, and serves them forever. The manager lives on that thread's
/// stack (it holds the P-byte pointer buffer), so `stack_size` must cover it.
pub fn spawn<const P: usize>(
    name: &'static str,
    stack_size: usize,
    register: fn(&mut ServerManager<P>) -> Result<()>,
) -> Result<()> {
    let handle = nx::thread::Builder::new()
        .name(name)
        .stack_size(stack_size)
        .spawn(move || -> Result<()> {
            let mut manager = ServerManager::<P>::new()?;
            register(&mut manager)?;
            // Returning would drop the manager and close every client session
            // (games abort on the SessionClosed), so an error only costs the
            // request that raised it. ponytail: logs the first 16, then quiet.
            let mut errors = 0u32;
            loop {
                match manager.loop_process() {
                    Ok(()) => return Ok(()),
                    Err(rc) => {
                        errors = errors.saturating_add(1);
                        if errors <= 16 {
                            log!(Error, "{name}: server error {rc:?} ({errors}), still serving");
                        }
                        let _ = nx::thread::sleep(1_000_000); // no hot spin on a repeating error
                    }
                }
            }
        })?;
    // Serves forever (nx never frees a started thread's stack either way).
    core::mem::forget(handle);
    Ok(())
}
