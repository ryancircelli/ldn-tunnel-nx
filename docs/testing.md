# Testing

Three layers: host tests and lints (anyone, no Switch), binary gates on the built module, and a manual
session on two real consoles that `relay/tools/hw-check.ts` checks from their logs.

## Run everything locally

Setup: Rust via rustup (the repo's `rust-toolchain.toml` selects nightly), Node 24, and for the module
cargo-nx and llvm-tools (see [crates/sys/README.md](../crates/sys/README.md#build)):

```sh
rustup component add llvm-tools
cd relay && npm ci && cd ..
```

| command | what it runs |
|---|---|
| `make test` | every host test suite: `test-core` (crates/core, then again optimised with overflow checks), `test-tls`, `test-ipc` (crates/ipc-tests: the IPC message layouts nx sends and serves, against libnx and Atmosphere), `test-release` (tools/release), `test-relay` (relay typecheck, vitest on workerd and Node, the hw-check unit test) |
| `make lint` | clippy `-D warnings`: `lint-host` (core, tls) and `lint-sys` (the module, with its deny lints) |
| `make nsp` | builds the module: `crates/sys/target/.../release/ldn-tunnel` (ELF) and `ldn-tunnel.nsp` |
| `make check` | the binary gates below, on what `make nsp` built |
| `cd relay && npm run test:e2e-docker` | the relay's Docker image through `docker run` and the real `docker-compose.yml` + Caddy (needs Docker with compose v2.24 or later, about 2 minutes) |
| `docker run --rm -v $PWD:/repo -w /repo devkitpro/devkita64 make -C overlay` | the overlay |

Any single suite runs on its own, e.g. `make test-core`. A new suite is a Makefile target plus its
name in `TESTS`.

## What CI checks

`.github/workflows/ci.yml` runs on every push and pull request. Every job must pass:

- **rust**: `make test-core test-tls test-ipc` and `make lint-host`.
- **module**: `make lint-sys`, `make nsp`, `make check`.
- **overlay**: builds in `devkitpro/devkita64` and fails on any compiler warning.
- **relay**: `npm ci` and `make test-relay`.
- **relay-docker**: `npm run test:e2e-docker`.
- **release-tools**: `make test-release`.
- **licenses**: `cargo deny check licenses` for the three Rust trees.

### Binary gates (`make check`, `tools/check-elf.sh`)

Two kinds of failure only show up on a console, so the gates check the built binary for them:

- **Stack frames.** No function may have a stack frame over `FRAME_MAX` (8 KiB). The module's threads
  have 16 to 32 KiB stacks, and the stack does not grow. A 16 KiB buffer on the stack once made a 32 KiB
  frame that crashed the console. The script adds up each function's prologue in the `llvm-objdump`
  disassembly: the pushes, `sub sp, sp, #N`, and the stack-probe loop LLVM emits for large frames. It
  prints the 10 largest frames. When this gate fails, move the buffer to the heap (`Box`) or into
  a `static`.
- **Size.** `exefs.nsp` may be at most `NSP_MAX` bytes (768 KiB).

Both limits are environment variables, e.g. `FRAME_MAX=16384 make check`. Raising one belongs in its
own commit that says why. `tools/check-elf.sh --self-test` checks the frame parser against small
functions compiled with `llc`.

## Hardware test (two consoles)

Run this before a release, and for any change to `crates/sys`, `vendor/nx` or the relay's LDN path. You
need two Switches with Atmosphère, one local-wireless game on both (a game from `relay/assets/gamelist.txt`), and a
relay you own.

1. Build: `make nsp`, and the overlay if you changed it.
2. On both SD cards, copy `crates/sys/target/sd/atmosphere` to the SD root (and the overlay to
   `switch/.overlays/`). In `config/ldn-tunnel/config.ini` set:

   ```ini
   [debug]
   level = 2
   remote_log = 1
   ```

   Each console needs its own token from your relay's admin page.
3. Note the time (`date -Iseconds`), then restart both consoles. The checks only read lines the relay
   received after this time, so the boot has to come after it.
4. Start the game on both. Console A creates a local-wireless room and console B joins. Play long enough
   that both send and receive data (a match, or a minute in the lobby). Leave the room.
5. On your computer, with the relay's admin password in a file (it is never passed as an argument):

   ```sh
   cd relay
   RELAY_URL=https://<your relay> ADMIN_FILE=~/relay-admin.txt \
     node --experimental-transform-types tools/hw-check.ts --since <time from step 3> --version <version>
   ```

   `--version` is the version you built (the `starting` line of the log shows it; the crate version, or
   `LDNT_VERSION` if you set it). By default it checks every console the relay saw after `--since`. Use
   `--console <id or name>` (repeatable) to pick consoles.

For each console it prints PASS or FAIL for every check, then an overall result (exit code 0 or 1):

| check | log line (`crates/sys/src`, `crates/core/src/ldn`) |
|---|---|
| started | `ldn-tunnel <version> (build N) starting`, with the expected version |
| relay handshake | `ldn: relay handshake done` |
| ldn connected | `ldn: connected: N/M nodes`; N must reach `--nodes` (2) |
| socket tracked | `bsd: client C fd F tracked` |
| bound to proxy | `bsd: client C fd F bound to the LDN proxy` |
| ProxyData out / in | `bsd: first ProxyData out:` and `bsd: first ProxyData in:` |
| datagram from relay | `bsd: client C first datagram from the relay (K bytes)` with K > 0 |
| no errors | no `[ERROR]`, `server error`, `recv buffer empty`, `panic`, `link down` or `relay link lost` |
| heap high-water | the highest `mem: heap high=` value is at most `--heap-max` (896 KiB of the 1 MiB heap) |

The steps must appear in log order (handshake after start, bound after tracked, the datagram after
ProxyData in). If a line is expected in your test, for example a deliberate relay restart, allow it with
`--allow '<regex>'`. If `started` fails, the console probably booted before `--since`, or more than 64
lines were logged before it reached the relay and the oldest were dropped. Attach the hw-check output to
the pull request.
