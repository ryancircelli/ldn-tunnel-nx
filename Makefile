# `make nsp`: build the sysmodule and lay out the SD install set under
# crates/sys/target/sd/. cargo (nightly, build-std, rust-lld) builds the ELF;
# cargo-nx turns it into main (NSO) + main.npdm + exefs.nsp. Name and program
# id come from crates/core/src/ident.rs only. Setup: crates/sys/README.md.

IDENT := crates/core/src/ident.rs
ID    := $(shell sed -n 's/.*PROGRAM_ID_HEX: &str = "\([0-9A-Fa-f]*\)";/\1/p' $(IDENT))
NAME  := $(shell sed -n 's/^pub const NAME: &str = "\(.*\)";/\1/p' $(IDENT))
SYS   := crates/sys
TGT   := $(SYS)/target
NSP   := $(TGT)/aarch64-nintendo-switch-freestanding/release/ldn-tunnel.nsp
SD    := $(TGT)/sd
CONTENTS := $(SD)/atmosphere/contents/$(ID)
FILL  := sed -e 's/@NAME@/$(NAME)/g' -e 's/@PROGRAM_ID@/$(ID)/g'

.PHONY: nsp dist clean
nsp:
	@test -n "$(ID)" -a -n "$(NAME)" || { echo "cannot read NAME/PROGRAM_ID_HEX from $(IDENT)"; exit 1; }
	rm -rf $(SD) $(NSP)
	mkdir -p $(TGT)/nsp $(CONTENTS)/flags
	$(FILL) $(SYS)/main.json > $(TGT)/nsp/main.json
	# plain cargo first: cargo-nx exits 0 even when the build fails
	cd $(SYS) && cargo build --release && cargo nx build --release
	cp $(NSP) $(CONTENTS)/exefs.nsp
	touch $(CONTENTS)/flags/boot2.flag
	$(FILL) dist/toolbox.json > $(CONTENTS)/toolbox.json
	@find $(SD) -type f -printf '%s\t%p\n'

# `make dist`: the SD-card layout and dist/out/ldn-tunnel-<version>.zip from an already built
# exefs.nsp (make nsp) and overlay (overlay/ builds in the devkitpro/devkita64 image).
# Override EXEFS / OVL to take them from elsewhere (CI artifacts).
VERSION := $(shell sed -n '/^\[workspace.package\]/,/^\[/s/^version = "\(.*\)"/\1/p' Cargo.toml)
EXEFS   ?= $(CONTENTS)/exefs.nsp
OVL     ?= overlay/$(NAME).ovl
OUT     := dist/out
ROOT    := $(OUT)/sd
ZIP     := $(OUT)/$(NAME)-$(VERSION).zip

dist:
	@test -n "$(ID)" -a -n "$(NAME)" -a -n "$(VERSION)" || { echo "cannot read NAME/PROGRAM_ID_HEX/version"; exit 1; }
	@test -f "$(EXEFS)" || { echo "missing $(EXEFS): run make nsp"; exit 1; }
	@test -f "$(OVL)" || { echo "missing $(OVL): build the overlay (overlay/Makefile)"; exit 1; }
	rm -rf $(OUT)
	mkdir -p $(ROOT)/atmosphere/contents/$(ID)/flags $(ROOT)/switch/.overlays $(ROOT)/config/$(NAME)
	cp $(EXEFS) $(ROOT)/atmosphere/contents/$(ID)/exefs.nsp
	touch $(ROOT)/atmosphere/contents/$(ID)/flags/boot2.flag
	$(FILL) dist/toolbox.json > $(ROOT)/atmosphere/contents/$(ID)/toolbox.json
	cp $(OVL) $(ROOT)/switch/.overlays/$(NAME).ovl
	cp dist/config.ini relay/assets/gamelist.txt relay/assets/ca.pem $(ROOT)/config/$(NAME)/
	cd $(ROOT) && zip -qr -X ../$(NAME)-$(VERSION).zip .
	@unzip -l $(ZIP)

clean:
	cd $(SYS) && cargo clean

# `make test`: every host test suite (CI runs the same targets; docs/testing.md). A new suite is a
# target below plus its name in TESTS. relay/ needs `npm ci` once.
TESTS := test-core test-tls test-ipc test-release test-relay
.PHONY: test lint lint-host lint-sys check $(TESTS)
test: $(TESTS)
# the second run: the random-input tests optimised, with overflow checks (parsers must not overflow on hostile input)
test-core:
	cargo test -p ldn-tunnel-core
	RUSTFLAGS=-Coverflow-checks=on cargo test --release -p ldn-tunnel-core
test-tls:
	cd crates/tls && cargo test --features std --lib --test heap --test private_ca # net.rs needs internet
# host IPC-layout tests: nx's IPC layer built for the host (vendor/nx/src/ipc_host.rs) against
# libnx/Atmosphere layouts (crates/ipc-tests, a standalone crate like crates/tls)
test-ipc:
	cd crates/ipc-tests && cargo test
test-release:
	cd tools/release && node --test
test-relay:
	cd relay && npm test && node --experimental-transform-types --disable-warning=ExperimentalWarning --test tools/hw-check.test.ts

# clippy -D warnings on our crates (the vendored nx keeps its own warnings)
lint: lint-host lint-sys
lint-host:
	cargo clippy -p ldn-tunnel-core --all-targets -- -D warnings
	cd crates/tls && cargo clippy --features std --all-targets -- -D warnings
# the Horizon shell: also the deny lints in crates/sys/Cargo.toml (unsafe_code, indexing/unwrap/panic)
lint-sys:
	cd $(SYS) && cargo clippy --release -- -D warnings

# `make check`: binary gates on the module `make nsp` built (stack frames, exefs size; tools/check-elf.sh)
check:
	tools/check-elf.sh --self-test
	tools/check-elf.sh
