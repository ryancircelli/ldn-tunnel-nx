# Firmware and Atmosphère compatibility

## Supported range

| | |
|---|---|
| Minimum firmware | 12.0.0 |
| Tested on | firmware 23.x, Atmosphère 1.12.1 (emuMMC) |
| Atmosphère | any release that boots the firmware |

At boot the module logs one line with what it found, for example
`compat: HOS 23.0.1, Atmosphere 1.12.1 (target 23.0.1)`.

- **Below 12.0.0:** the module logs an error and does not install its ldn:u / bsd:u MITMs.
  Games use the real services, so the console behaves as if the module were not there.
  The overlay shows "Firmware too old (needs 12.0.0+)".
- **Newer than the tested major:** the module runs as usual and logs a warning. New firmware
  usually works; run the hardware test (below) and raise the tested version.
- **Atmosphère not detected:** logged as a warning only. Without Atmosphère, sm refuses the
  MITM registration and the module has nothing to do.

## Where the version-dependent code lives

All version decisions are in `crates/core/src/compat.rs` (pure, host-tested). Detection
is in `crates/sys/src/compat.rs`: the firmware version comes from `set:sys` (nx reads it at
process start), Atmosphère's from `spl:` GetConfig(65000, ExosphereApiVersion).

| What | Firmware | Where |
|---|---|---|
| Minimum firmware | 12.0.0 | `compat::MIN_HOS` |
| Newest tested firmware | 23.x | `compat::TESTED_HOS_MAJOR` |
| ldn:u 106 SetProtocol | 18.0.0+ | `compat::LDN_SET_PROTOCOL`, gate in `crates/sys/src/ldn/ifaces.rs` |
| bsd:u 33 RegisterClientShared | 10.0.0+ | `compat::BSD_REGISTER_CLIENT_SHARED`, gate in `crates/sys/src/bsd/ifaces.rs` |

Checked and handled elsewhere, nothing to change per firmware:

- **sm protocol:** TIPC from 12.0.0, CMIF before. nx picks it (`vendor/nx/src/service/sm.rs`).
  Below 12.0.0 is unsupported because our nx IPC fixes (`docs/nx-patches/`) only ever ran
  against TIPC sm.
- **Our own bsd:s client:** nx picks the bsd library version from the firmware
  (`vendor/nx/src/ipc/sf/bsd.rs`, version 10 for 19.0.0+). Firmware accepts older library
  versions, so a newer firmware needs no change.
- **Game bsd:u sessions:** the game's RegisterClient (and its library version) is forwarded
  untouched. Commands we do not declare are forwarded to the real bsd:u and logged once per
  session (`bsd: client N sent cmd X, forwarded untouched`).
- **ldn:u root session:** commands we do not declare are forwarded to the real ldn:u.
- **IUserLocalCommunicationService** (the game's LDN session, served by us): commands we do
  not declare are answered InvalidCommandRequestId and logged (`ldn: unknown cmd N`). Not
  declared today: 105 SetWirelessAudioPolicy (13.1.0+), 403 SetOperationMode (19.0.0+),
  500-505 action frames and 600-601 TX power (18.0.0+). Games have not been seen calling them.
- **IClientProcessMonitor** (ldn:u 1, 18.0.0+): served on every firmware; older games never
  open it.
- **Thread local region:** 21.0.0 and 22.0.0 added kernel fields at TLR+0x108 and +0x110.
  nx only writes its thread variables at +0x1E0..0x200, so nothing changes.
- **nifm:a** CreateGeneralService (3.0.0+) and **time:u**: unchanged since before 12.0.0.

## Adding support for a new firmware or Atmosphère

1. Check what changed: [switchbrew LDN services](https://switchbrew.org/wiki/LDN_services),
   [Sockets services](https://switchbrew.org/wiki/Sockets_services),
   [SM services](https://switchbrew.org/wiki/Services_API) and
   [Thread Local Region](https://switchbrew.org/wiki/Thread_Local_Region), plus the
   Atmosphère and libnx changelogs.
2. Run the hardware test on the new firmware and read the module log for `compat:`,
   `ldn: unknown cmd` and `bsd: ... forwarded untouched` lines.
3. A command the game needs: declare it in `crates/sys/src/ldn/ifaces.rs` (or bsd), gate it
   with `#[version(compat::since(compat::NEW_CONST))]` and add the const to
   `crates/core/src/compat.rs` with the firmware and the source.
4. Raise `TESTED_HOS_MAJOR` and the "Tested on" row above, then run `make test` and
   `make nsp && make check`.
5. An nx change (for example a new sm or TLS layout) goes in `vendor/nx` and is saved as the
   next `docs/nx-patches/00NN-*.patch`.

## Hardware test

See [docs/testing.md](testing.md#hardware-test-two-consoles).
