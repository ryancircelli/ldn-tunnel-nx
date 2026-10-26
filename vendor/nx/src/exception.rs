//! Exception handling support (stubbed for now).

use crate::result::ResultCode;
use crate::svc;

#[unsafe(no_mangle)]
#[linkage = "weak"]
pub(crate) unsafe extern "C" fn __nx_exception_dispatch(
    _reason: svc::ExceptionType,
    _stack_top: *mut u8,
) -> ! {
    // No handler of our own: report the exception as unhandled (libnx's default,
    // UnhandledUserInterrupt) so the kernel restores the faulting context and stops the
    // process there, and Atmosphere's creport records the original fault.
    svc::return_from_exception(ResultCode::new(0xF801))
}
