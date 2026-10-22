TARGETS := x86_64-unknown-none aarch64-unknown-none
# The architecture the Docker-based targets run on: amd64 or arm64.
ARCH ?= amd64
TRIPLE_amd64 := x86_64
TRIPLE_arm64 := aarch64
TRIPLE := $(TRIPLE_$(ARCH))
BIN := target/$(TRIPLE)-unknown-none/release/zrc
SYSBOX_BIN := target/sysbox/$(TRIPLE)-unknown-none/release/zrc
# Docker's default seccomp profile, for the end-to-end tests.
SECCOMP_PROFILE := https://raw.githubusercontent.com/moby/moby/v27.5.1/profiles/seccomp/default.json
E2E_IMAGE := debian:trixie-slim

.PHONY: check build e2e e2e-containerd bench panics

check:
	cargo fmt --check
	$(foreach t,$(TARGETS),cargo clippy --target $(t) -- -D warnings &&) \
	$(foreach t,$(TARGETS),cargo clippy --target $(t) --features sysbox -- -D warnings &&) true

# Release builds fail to link if any panic path is left.
build:
	$(foreach t,$(TARGETS),cargo build --release --target $(t) &&) \
	$(foreach t,$(TARGETS),cargo build --release --target $(t) --features sysbox --target-dir target/sysbox &&) true

# Runs tests/e2e.sh as root in a privileged container.
e2e: build
	docker run --rm --privileged --init --platform linux/$(ARCH) -v "$(CURDIR)":/src:ro $(E2E_IMAGE) sh -c \
		'apt-get update -qq && apt-get install -y -qq busybox-static runc jq curl ca-certificates >/dev/null && \
		mkdir -p /work && curl -fsSL -o /work/default.json $(SECCOMP_PROFILE) && \
		/src/tests/e2e.sh /src/$(BIN) /src/$(SYSBOX_BIN)'

# Runs containers through containerd's runc shim with zrc as the runtime.
e2e-containerd: build
	docker run --rm --privileged --init --platform linux/$(ARCH) -v "$(CURDIR)":/src:ro $(E2E_IMAGE) sh -c \
		'apt-get update -qq && apt-get install -y -qq containerd >/dev/null && /src/tests/containerd.sh /src/$(BIN)'

# Compares zrc with runc and crun.
bench: build
	docker run --rm --privileged --init --platform linux/$(ARCH) -v "$(CURDIR)":/src:ro $(E2E_IMAGE) sh -c \
		'apt-get update -qq && apt-get install -y -qq busybox-static runc crun jq time >/dev/null && \
		runc --version | head -1 && crun --version | head -1 && /src/tests/bench.sh /src/$(BIN)'

# Lists the source lines of panic paths in a release build (which then
# links with a stand-in panic handler).
panics:
	RUSTFLAGS="-C relocation-model=static -C link-arg=--no-pie --cfg zrc_find_panics" \
		CARGO_PROFILE_RELEASE_STRIP=false CARGO_PROFILE_RELEASE_DEBUG=1 \
		cargo build --release --target x86_64-unknown-none --target-dir target/panics
	docker run --rm --platform linux/amd64 -v "$(CURDIR)/target/panics/x86_64-unknown-none/release":/b:ro $(E2E_IMAGE) sh -c \
		'apt-get update -qq && apt-get install -y -qq binutils >/dev/null && \
		objdump -d --no-show-raw-insn /b/zrc | grep -E "call.*<_ZN4core(9panicking|5slice5index|5slice29copy_from_slice|6option13unwrap_failed|6result13unwrap_failed)" \
		| cut -d: -f1 | xargs -r addr2line -e /b/zrc -f -i -C | paste - - | grep -v rustlib'
