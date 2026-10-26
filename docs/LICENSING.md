# Licensing

Sources checked 2026-10-25 (licence files and Cargo.toml `license` fields of the latest
releases; re-check when a dependency is added or bumped).

## Answers

**(a) What must the Rust module carry?** GPL-2.0-or-later. It is a port of ryu_ldn_nx, whose
source headers say GPL-2.0-or-later (its LICENSE file is the plain GPLv2 text and its README says
"v2.0", so the "or later" rests on the headers). It follows ldn_mitm's design, but no ldn_mitm
code is copied: the ryu_ldn_nx sources only cite it for behaviour and command IDs, and ldn_mitm
is GPLv2 with no "or later". If a maintainer finds ldn_mitm text in the lineage, the affected
files are GPL-2.0-only and the whole module must follow (see crate flag below).

**(b) Can relay/ stay MIT?** Yes. Per-directory licences are fine because relay/ is a separate
program (a Cloudflare Worker that talks to the module over a socket), not linked into it. The
relay ports Ryujinx's LdnServer (MIT): keep "Copyright (c) Ryujinx Team and Contributors" and the
MIT permission notice in relay/LICENSE (or in a header of the ported files). relay/LICENSE stays
MIT; it is supplied by the relay copy, not by this file set.

**(c) Overlay?** GPL. It derives from ryu_ldn_nx's overlay (GPL-2.0-or-later headers) and links
libultrahand (GPLv2, no "or later") and libtesla (GPLv2). So the overlay sources may be marked
GPL-2.0-or-later, but the built `.ovl` can only be distributed under GPL-2.0 (only).
libultrahand's `libultra` part is CC-BY-4.0: keep its attribution (SUB_LICENSE). libnx is ISC and
Atmosphere-libs GPLv2, both fine.

**(d) Crates vs GPL-2.0-or-later.**

| Crate | Licence | OK? |
|---|---|---|
| zerocopy | BSD-2-Clause OR Apache-2.0 OR MIT | yes (choose MIT) |
| heapless | MIT OR Apache-2.0 | yes |
| p256 | Apache-2.0 OR MIT | yes |
| sha2 | MIT OR Apache-2.0 | yes |
| rustls | Apache-2.0 OR ISC OR MIT | yes |
| rustls-webpki | ISC | yes |
| nx | MIT | yes |
| fflate (npm, relay tooling) | MIT | yes |
| **embedded-tls** | **Apache-2.0 only** | **flag** |

embedded-tls is the only crate without an MIT/ISC option. Apache-2.0 is incompatible with GPLv2
but compatible with GPLv3, so the module binary is legal only because the module is
GPL-2.0-**or-later** (distribute the combination under GPLv3). If (a)'s caveat ever forces
GPL-2.0-only, embedded-tls cannot be used; use rustls or another TLS crate instead.

## Layout

- Repo root `LICENSE`: GPL v2 text (verbatim, from ryu_ldn_nx). Files carry
  `SPDX-License-Identifier: GPL-2.0-or-later`; `Cargo.toml` already says `license = "GPL-2.0-or-later"`.
- `crates/`: GPL-2.0-or-later.
- `overlay/`: sources GPL-2.0-or-later; the built overlay is GPL-2.0 (see c). Vendored
  libultrahand keeps its own LICENSE and SUB_LICENSE.
- `relay/`: MIT (`relay/LICENSE`).
- `NOTICE`: attributions that must travel with copies.

Releases that ship binaries must offer the corresponding source (link to the tagged repo in the
release page and the relay's download page).
