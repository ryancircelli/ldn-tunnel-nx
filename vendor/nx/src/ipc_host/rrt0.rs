//! Host stand-in for `rrt0.rs` (see `ipc_host.rs`): no process start-up.

use crate::result::ResultCode;

pub struct ModulePath;

impl ModulePath {
    pub fn get_name(&self) -> crate::util::ArrayString<0x200> {
        crate::util::ArrayString::new()
    }
}

pub fn get_module_name() -> ModulePath {
    ModulePath
}

pub fn exit(rc: ResultCode) -> ! {
    panic!("rrt0::exit({rc:?})")
}
