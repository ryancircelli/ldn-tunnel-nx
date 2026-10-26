# ldn-tunnel

[![ci](https://github.com/ryancircelli/ldn-tunnel-nx/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/ryancircelli/ldn-tunnel-nx/actions/workflows/ci.yml?query=branch%3Amain)
[![coverage (Rust core)](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/ryancircelli/ldn-tunnel-nx/badges/rust-core.json)](docs/testing.md#coverage)
[![coverage (relay)](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/ryancircelli/ldn-tunnel-nx/badges/relay.json)](docs/testing.md#coverage)
[![Rust](https://img.shields.io/badge/Rust-no__std-orange?logo=rust)](crates/sys/README.md)
[![release](https://img.shields.io/github/v/release/ryancircelli/ldn-tunnel-nx)](https://github.com/ryancircelli/ldn-tunnel-nx/releases/latest)
[![license: GPL-2.0-or-later](https://img.shields.io/badge/license-GPL--2.0--or--later-blue)](LICENSE)
[![relay license: MIT](https://img.shields.io/badge/relay%20license-MIT-blue)](relay/LICENSE)

Play Switch local-wireless games with friends over the internet, through a relay that you run
yourself for free on Cloudflare.

The console module is written in Rust (`no_std`) and runs on the Switch as an Atmosphère sysmodule.

## Setup

1. **Deploy your relay.**
   [![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/ryancircelli/ldn-tunnel-nx/tree/main/relay)
   Sign in to Cloudflare and GitHub. The form asks for `ADMIN`: the password for your relay's admin
   page. Pick a long one and keep it. The other fields are optional (see [relay/README.md](relay/README.md)).
2. **Invite a console.** Open `https://<your relay>/admin`, log in, and click **Invite a console**. Open
   the link in any browser and press **Download for my Switch**.
3. **Install.** Unzip the file onto the root of the Switch's SD card and restart the Switch. On its first
   boot ldn-tunnel turns off ldn_mitm or ryu_ldn_nx if one is installed, and asks you to restart once more.

Everyone you play with uses the same relay: invite each of their consoles from your admin page.

## Updating

Consoles update themselves from your relay. To update the relay itself, see
[relay/README.md](relay/README.md#3-updates) (one button on the admin page if you gave it a Cloudflare token).

## Manual setup

The release's `ldn-tunnel-<version>.zip` has the same files without a relay address. Unzip it to the SD
card and edit `config/ldn-tunnel/config.ini`:

- `host`: your relay's address
- `token`: this console's token (the admin page can make one)

## Requirements

- Atmosphère on emuMMC. Not tested on sysNAND.
- Firmware 12.0.0 or newer; tested on 23.x with Atmosphère 1.12.1 ([compatibility](docs/compatibility.md)).
- [Ultrahand](https://github.com/ppkantorski/ultrahand-overlay) to open the overlay (optional).
- A free Cloudflare account, or a server with Docker ([self-host](relay/README.md#self-host-with-docker)).

## For developers

Build: [crates/sys/README.md](crates/sys/README.md); releases: [docs/relay-releases.md](docs/relay-releases.md). Licence: GPL-2.0-or-later, except
`relay/` (MIT); see docs/LICENSING.md and NOTICE.
