# Build Environment

This project targets bare-metal RISC-V64 (QEMU virt) for the initial bring-up.

## Toolchain
- Rust: see `rust-toolchain.toml`
- Target: `riscv64gc-unknown-none-elf`
  - Install with: `rustup target add riscv64gc-unknown-none-elf`

## System Packages (Ubuntu/Debian)
- See `build_env/apt-deps.txt`

## Notes
- QEMU is required for `make run` and `make test-qemu-smoke`.
