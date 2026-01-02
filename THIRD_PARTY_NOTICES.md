# Third-Party Notices

This project utilizes third-party open-source components via Cargo (Rust crates) and requires specific external tools for building and testing. The following lists are derived from `Cargo.lock` and the build environment specifications (`build_env/apt-deps.txt`).

## Rust Crates (Cargo.lock)

Source: crates.io registry (`https://github.com/rust-lang/crates.io-index`).

* **atomic-polyfill** 1.0.3 — License: MIT OR Apache-2.0
* **bitflags** 1.3.2 — License: MIT OR Apache-2.0
* **byteorder** 1.5.0 — License: Unlicense OR MIT
* **cfg-if** 1.0.4 — License: MIT OR Apache-2.0
* **critical-section** 1.2.0 — License: MIT OR Apache-2.0
* **hash32** 0.2.1 — License: MIT OR Apache-2.0
* **heapless** 0.7.17 — License: MIT OR Apache-2.0
* **lock_api** 0.4.14 — License: MIT OR Apache-2.0
* **managed** 0.8.0 — License: 0BSD
* **rustc_version** 0.4.1 — License: MIT OR Apache-2.0
* **scopeguard** 1.2.0 — License: MIT OR Apache-2.0
* **semver** 1.0.27 — License: MIT OR Apache-2.0
* **smoltcp** 0.10.0 — License: 0BSD
* **spin** 0.9.8 — License: MIT
* **stable_deref_trait** 1.2.1 — License: MIT OR Apache-2.0

**Notes:**

* Workspace crates (`axruntime`, `axfs`, `axnet`, `axvfs`) are first-party components and are excluded from this list.
* Applications located in `apps/` are currently `no_std` and do not introduce additional third-party crates beyond those listed above.

## External Tools (Build/Test Environment)

The following tools are required to build and test this project. **They are not bundled with nor distributed as part of this repository.**

* **Rust Toolchain** (rustc, cargo, LLVM) — License: Apache-2.0 with LLVM Exceptions, MIT (varies by component).
* **QEMU** (`qemu-system-riscv64`) — License: GPL-2.0 (per upstream distribution).
* **GDB** (`gdb-multiarch`) — License: GPL-3.0 (per upstream distribution).
* **e2fsprogs** (`mke2fs`) — License: GPL-2.0 (per upstream distribution).
* **Python 3** — License: PSF License (per upstream distribution).
* **Build Utilities** (build-essential, clang, lld) — License: Varies by distribution; please refer to upstream packages.

If additional third-party components are introduced, please update this file to record their versions, licenses, and sources.
