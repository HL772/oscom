# Aurora Self Tests

This directory contains the minimal self-test cases used by `make test-oscomp`.

Cases:
- ramdisk: boot from the built-in FAT32 rootfs, run the user-mode smoke path, and verify a FAT32 write/read marker.
- ext4: boot from an ext4 image created by `scripts/mkfs_ext4.sh` and exec `/init`.
- ext4-init: host-side ext4 image check that enumerates root and `/etc` via `read_dir` offsets, opens `/init`, validates ELF magic, and reads `/etc/issue` + `/etc/large` (multi-block).

Notes:
- ext4-init reads the image path from `AXFS_EXT4_IMAGE` (set by `scripts/test_oscomp.sh`).
- ext4 QEMU runs verify the `vfs: mounted ext4 rootfs` log marker.
- ext4 QEMU runs also verify `/etc/issue` output from `/init`.

Usage:
- `make test-oscomp ARCH=riscv64 PLATFORM=qemu`
- Optional: set `FS=path/to/ext4.img` to reuse an existing image.
- Optional: set `EXPECT_INIT=1` to require the `/init` execve banner.
