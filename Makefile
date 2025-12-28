SHELL := /bin/bash

.PHONY: help fmt clippy build run gdb test-host test-qemu-smoke test-oscomp clean

help:
	@printf "Project Aurora build/test entrypoints\n\n"
	@printf "Targets:\n"
	@printf "  make help\n"
	@printf "  make fmt\n"
	@printf "  make clippy\n"
	@printf "  make build ARCH=riscv64 PLATFORM=qemu\n"
	@printf "  make build ARCH=loongarch64 PLATFORM=qemu\n"
	@printf "  make run ARCH=riscv64 PLATFORM=qemu FS=path/to/ext4.img\n"
	@printf "  make run ARCH=loongarch64 PLATFORM=qemu FS=path/to/ext4.img\n"
	@printf "  make gdb ARCH=riscv64 PLATFORM=qemu\n"
	@printf "  make test-host\n"
	@printf "  make test-qemu-smoke ARCH=riscv64 PLATFORM=qemu FS=path/to/ext4.img\n"
	@printf "  make test-oscomp ARCH=riscv64 PLATFORM=qemu FS=path/to/ext4.img\n"
	@printf "  make clean\n"

fmt:
	@./scripts/fmt.sh

clippy:
	@./scripts/clippy.sh

build:
	@./scripts/build.sh

run:
	@./scripts/run.sh

gdb:
	@./scripts/gdb.sh

test-host:
	@./scripts/test_host.sh

test-qemu-smoke:
	@./scripts/test_qemu_smoke.sh

test-oscomp:
	@./scripts/test_oscomp.sh

clean:
	@./scripts/clean.sh
