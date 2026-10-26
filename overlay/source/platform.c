/**
 * @file platform.c
 * @brief The libnx calls the Rust half (crates/overlay) makes: ldnt:cfg session and dispatch,
 *        pm/pm:shell, nifm, time. Prototypes: ldn_tunnel_overlay.h (generated from
 *        crates/overlay/src/ffi.rs), so a signature change fails here.
 *
 * @copyright Copyright (c) 2026 ldn-tunnel contributors
 * @license GPL-2.0-or-later
 */

#include <switch.h>
#include <time.h>

#include "ldn_tunnel_overlay.h"

static Service g_cfg;

/// Atmosphere's sm extension HasService (cmd 65100). libnx has no wrapper:
/// HOS 12+ talks tipc to sm, older firmware cmif.
static Result HasService(bool* out, const char* name) {
    SmServiceName n = smEncodeName(name);
    if (hosversionAtLeast(12, 0, 0)) {
        return tipcDispatchInOut(smGetServiceSessionTipc(), 65100, n, *out);
    }
    return serviceDispatchInOut(smGetServiceSession(), 65100, n, *out);
}

uint32_t ldnt_os_cfg_open(const char* name) {
    // smGetService blocks until the name is registered, so a missing module would freeze the
    // overlay. Ask sm first; the caller shows "not running".
    bool has = false;
    Result rc = HasService(&has, name);
    if (R_FAILED(rc)) return rc;
    if (!has) return MAKERESULT(Module_Libnx, LibnxError_NotFound);
    return smGetService(&g_cfg, name);
}

void ldnt_os_cfg_close(void) { serviceClose(&g_cfg); }

bool ldnt_os_cfg_registered(const char* name) {
    bool has = false;
    return R_SUCCEEDED(HasService(&has, name)) && has;
}

uint32_t ldnt_os_cfg_dispatch(uint32_t cmd, const void* input, uint32_t in_len, void* out, uint32_t out_len) {
    return serviceDispatchImpl(&g_cfg, cmd, input, in_len, out, out_len, (SfDispatchParams){0});
}

bool ldnt_os_online(void) {
    u32 ip = 0;
    return !serviceIsActive(nifmGetServiceSession_StaticService())
        || (R_SUCCEEDED(nifmGetCurrentIpAddress(&ip)) && ip != 0);
}

// Asked of pm, not the module, so it holds even when the module is hung.
bool ldnt_os_app_pid(uint64_t* pid) { return R_SUCCEEDED(pmdmntGetApplicationProcessId(pid)); }

bool ldnt_os_program_id(uint64_t pid, uint64_t* program_id) {
    return R_SUCCEEDED(pmdmntGetProgramId(program_id, pid));
}

bool ldnt_os_program_running(uint64_t program_id) {
    u64 pid = 0;
    return R_SUCCEEDED(pmdmntGetProcessId(&pid, program_id));
}

uint32_t ldnt_os_terminate_process(uint64_t pid) {
    Result rc = pmshellInitialize();
    if (R_SUCCEEDED(rc)) {
        rc = pmshellTerminateProcess(pid);
        pmshellExit();
    }
    return rc;
}

void ldnt_os_terminate_program(uint64_t program_id) {
    if (R_SUCCEEDED(pmshellInitialize())) {
        pmshellTerminateProgram(program_id);
        pmshellExit();
    }
}

uint32_t ldnt_os_launch_program(uint64_t program_id) {
    const NcmProgramLocation loc = {.program_id = program_id, .storageID = NcmStorageId_None};
    u64 pid = 0;
    Result rc = pmshellInitialize();
    if (R_SUCCEEDED(rc)) {
        rc = pmshellLaunchProgram(0, &loc, &pid);
        pmshellExit();
    }
    return rc;
}

uint64_t ldnt_os_ms(void) { return armTicksToNs(armGetSystemTick()) / 1000000; }

size_t ldnt_os_local_time(uint32_t unix, char* out, size_t len) {
    const time_t t = unix;
    const struct tm* tm = localtime(&t);
    return tm ? strftime(out, len, "%b %d, %H:%M", tm) : 0;
}
