# ldn-tunnel-sys

The Horizon shell: the Atmosphere sysmodule, built on the [`nx`](https://github.com/aarch64-switch-rs/nx) crate.
It is not a member of the root workspace (it needs nightly, `-Zbuild-std` and the Switch target).

## Build

One-time setup (the repo's `rust-toolchain.toml` already selects nightly + `rust-src`):

```sh
cargo +stable install --locked cargo-nx --git https://github.com/aarch64-switch-rs/cargo-nx \
    --rev 0dfe4a3ca6de4dcb0dfabed7dbfe9cacbbe21fcc
```

Then, from the repo root:

```sh
make nsp
```

It writes the SD install set to `crates/sys/target/sd/`:

```
atmosphere/contents/420000004C444E54/exefs.nsp        (PFS0: main + main.npdm)
atmosphere/contents/420000004C444E54/flags/boot2.flag
atmosphere/contents/420000004C444E54/toolbox.json
```

Copy `crates/sys/target/sd/atmosphere` onto the SD root (it merges into the existing `atmosphere/`).
`make clean` runs `cargo clean`.

## How it fits together

- `.cargo/config.toml` (here, so host `cargo test` at the root is unaffected): target
  `aarch64-nintendo-switch-freestanding`, `build-std = core, alloc, compiler_builtins` with
  `compiler-builtins-mem`. The target is built into rustc: it carries its own linker script, links with
  `rust-lld` and is `panic = abort`, so there is no linker or `.ld` to maintain.
- `Cargo.toml` profile: `opt-level = "s"`, `lto = true`, `codegen-units = 1`, `panic = "abort"`. Only the
  release profile is built.
- `main.json` is the NPDM, a copy of the C++ `sysmodule/res/app.json` (all syscalls, `service_access` and
  `service_host` `*`, which covers the ldn:u / bsd:u MITMs, hosting `ldnt:cfg`, fsp-srv, nifm, bsd:s, sm:m,
  spl, pm, ...; full filesystem access; priority 42 on core 3; 0x20000 main-thread stack) with `@NAME@` and
  `@PROGRAM_ID@` placeholders. `make nsp` fills them, and `dist/toolbox.json`, from `crates/core/src/ident.rs`,
  so the id is typed only there.
- cargo-nx's NPDM reader (linkle) wants three deviations from the C++ JSON, all with the same effect:
  `version` and `system_resource_size` as integers, and no `process_category` (linkle aliases it to `version`).
  The decoded NPDM (hactool) is identical to npdmtool's from the C++ JSON; the bytes differ only in section
  padding and the order of the host/access entries in the service list.

### Why cargo-nx and not elf2nso

The built-in target's linker script puts `.bss` in its own `PT_LOAD` segment. devkitPro's `elf2nso` only
reads three segments and writes an NSO with `bss_size = 0`, so the heap would be unmapped memory. linkle
(inside cargo-nx) handles the fourth segment (this build: `.bss` 0x101000). It also makes the NPDM and the
PFS0, so no Docker is needed.

### Memory

- Heap: a 1 MiB static buffer in `.bss` (`HEAP_SIZE` in `src/rt.rs`), handed to nx's allocator. Every
  `Box`/`Vec`/`Arc` and every extra thread's stack come from it. Same size as the C++ malloc buffer.
- Main thread stack: 0x20000 (NPDM), allocated by the loader.
- Statics in `.bss` besides the heap: the gamelist (`Whitelist`, 64 KiB) and the remote-log ring (~17 KiB).
  This build: code+rodata+data 0x23000 (~140 KiB), bss 0x1145d0, main stack 0x20000 ≈ 1.37 MiB, under the 1.5 MiB budget.
- Transient heap use at boot: gamelist.txt is read whole (~92 KiB shipped, capped at 256 KiB) and freed.

### Threads

`nx::thread::Builder::new().name("ldn").stack_size(0x4000).priority(..).core(..).spawn(|| ...)`; the
default stack is 0x8000 and it is allocated from the heap above, so size the heap for the stacks too.
Keep every `JoinHandle` alive: nx frees the thread's stack when the handle drops (`main` holds them and
never returns).

| thread    | svc priority | stack  | does |
|-----------|--------------|--------|------|
| main      | 42 (NPDM)    | 0x20000 | startup, then sleeps forever |
| `ldnt:cfg`| 38 (C++ cfg) | 0x4000 | its own `ServerManager<0x100>` serving the overlay |
| `maint`   | 43           | 0x4000 | every 1 s: write due toasts; every 2 s: flush the log / close it after 5 s idle |

### Panics

`#[panic_handler]` appends `panic: <message>` to `sdmc:/config/ldn-tunnel/ldn-tunnel.log` (once; a nested
panic, or a panic while the logger lock is held, skips the write) and aborts with `svcBreak`, so Atmosphere's creport writes a crash report.

### Patched dependency

`unwinding` 0.2.10 (pulled in by nx) does not build on current nightly (`core::intrinsics::abort` was removed).
`[patch.crates-io]` points at the upstream fix (unreleased, rev `afb810f`); drop it once a release is out.

## Startup (`src/main.rs`, the C++ `main.cpp` order)

1. Mount the SD card (`fsp-srv`, `sdmc:`).
2. `config_io::load_at_boot`: finish a save cut by power loss (`config.ini.tmp` → `config.ini`), or write
   the commented default (`core::config` serializer); load; apply `[debug]` to the logger. Nothing is
   logged before this step.
3. `update_io::boot_check`: probation boots, `.new` recovery, rollback from `.bak` (then
   `STATE.update_stand_down`), "Updated to <version>" toast on the first boot of a new build.
4. `firstboot::run`: rename `contents/4200000000000010/flags/boot2.flag` (ryu_ldn_nx / ldn_mitm) to
   `boot2.flag.ldn-tunnel-disabled` (`.2`…`.9` if that marker already exists; never delete), set
   `STATE.needs_restart`; log any other module whose `mitm.lst` names `ldn:u` (left alone).
5. `config_io::load_whitelist` (gamelist.txt).
6. `notify_io::boot`: delete our unshown `420000004C444E54-*.notify` leftovers in Ultrahand's folder.
7. Spawn the `ldnt:cfg` and `maint` threads; the main thread idles.

The ldn:u / bsd:u MITMs are registered by the server code (not here) and only when
`STATE.ldn_services_allowed()` (no pending restart, no rollback this boot).

## Glue modules

| file | what |
|---|---|
| `rt.rs` | the only `unsafe`: the heap static + `initialize_heap`, the `main` entry symbol, rrt0's module name; the panic handler. The crate root has `#![deny(unsafe_code)]`, `rt.rs` alone re-allows it, every other glue module has `#![forbid(unsafe_code)]`. |
| `fs_util.rs` | `Result` wrappers over nx fs: mount, exists, create_dir_all, read_into, open_append/append_line, write_new, rename, delete, replace (delete + rename: Horizon cannot rename onto a file), recover_tmp, for_each_entry. |
| `log.rs` | `log!(Info, "…")` macro, file at `ident::LOG_PATH`, `[debug] enabled/level/remote_log`, rotation to `.log.1` at 1 MiB, `drain_remote` for the relay's 0xC0 flush. Line: `[  sec.ms ] [LEVEL] text`. |
| `config_io.rs` | live config (`get`/`update`), `load_at_boot`/`reload`/`save` (tmp + delete + rename, buffers that held the token are wiped), gamelist → `is_whitelisted`. |
| `update_io.rs` | `Stager` (begin/append/verify/abort; SHA-256 re-read), `install_staged`, `boot_check`, `mark_healthy`, `get_status`, `check_manifest`, `blob`. The relay download loop drives it (module doc shows the call order). |
| `firstboot.rs` | step 4 above. |
| `state.rs` | `STATE: SharedState`: connection status, ldn state, active pid/game, session info, transport status string, needs_restart, update_stand_down, first_boot_of_build, update check state/progress/request, notifier (`notify_event`; its toggles come from config.ini `[notifications]`), `setup_status()` for cfg 30. |
| `notify_io.rs` | Ultrahand toast files (`.tmp` + rename, only if `config/ultrahand/notifications/` exists). |
| `cfg/service.rs` | `ldnt:cfg` bodies (ids 0–5, 8–18, 25–30). |

Build-time variables (release CI sets them; unset = developer build):

| variable | meaning |
|---|---|
| `LDNT_BUILD` | decimal build number (`update::Status.running_build`; 0 never auto-updates) |
| `LDNT_VERSION` | version string (GetVersion, toasts, log header); default `CARGO_PKG_VERSION` |
| `LDNT_UPDATE_PUBKEY` | publisher key, 130 hex chars (uncompressed P-256). Unset = all zeros: every manifest fails `BadSignature` |

A malformed value fails the build (const evaluation). A build that should take updates signed with your
own key: `LDNT_UPDATE_PUBKEY=$(openssl pkey -in key.pem -pubout -outform DER | tail -c 65 | xxd -p | tr -d '\n')`,
`LDNT_BUILD=$(date +%s)`, and the same `--build` when signing its manifest (docs/relay-releases.md).

## Hardware check (first boot)

Setup: ryu_ldn_nx installed and enabled (`atmosphere/contents/4200000000000010/flags/boot2.flag`
present). Copy `target/sd/atmosphere` onto the SD card, plus `relay/assets/gamelist.txt` and a `config.ini` with
`[debug]` `enabled = 1`, `level = 2` into `sdmc:/config/ldn-tunnel/` (the default config logs nothing:
`enabled = 0`). Restart.

First boot, `sdmc:/config/ldn-tunnel/ldn-tunnel.log` (times vary; the last two lines may swap):

```
=== ldn-tunnel 0.1.0 log started ===
[     t.ttt] [INFO] ldn-tunnel 0.1.0 (build 0) starting
[     t.ttt] [INFO] config: sdmc:/config/ldn-tunnel/config.ini -> Success
[     t.ttt] [INFO] update: build 0
[     t.ttt] [WARN] firstboot: disabled conflicting LDN module 4200000000000010 (sdmc:/atmosphere/contents/4200000000000010/flags/boot2.flag -> sdmc:/atmosphere/contents/4200000000000010/flags/boot2.flag.ldn-tunnel-disabled); restart once to finish setup
[     t.ttt] [INFO] whitelist: <N> games from sdmc:/config/ldn-tunnel/gamelist.txt
[     t.ttt] [WARN] ldn:u/bsd:u stay off this boot (restart pending or update rolled back)
[     t.ttt] [INFO] cfg: ldnt:cfg registered
```

(`<N>` = the number of ids in gamelist.txt, 4000+ for the shipped list.)

- SD card: `boot2.flag` is gone and `boot2.flag.ldn-tunnel-disabled` (0 bytes) is next to it;
  `sdmc:/config/ldn-tunnel/update/` exists (empty).
- Without a config.ini, one is created (the commented default, `host =` empty) and the log stays empty.
- `ldnt:cfg` is registered: an IPC client (the overlay once re-pointed) gets GetVersion `0.1.0`,
  IsServiceActive 1, GetConnectionStatus 0, GetTransportStatus `Restart once to finish setup` on this boot,
  GetNotifyFlags 7, GetSetupStatus 1 (needs_restart), GetUpdateStatus running_build 0 and version `0.1.0`. SetDebugLevel + SaveConfig rewrite
  config.ini with the new level.
- Second boot: the ryu_ldn_nx sysmodule no longer starts; the log has no `firstboot` line and no "stay off"
  line; the transport status is empty.
- Not provable here: ldn:u/bsd:u (other modules), toasts (only "Updated to …" after a real update, which needs
  the relay download loop).
