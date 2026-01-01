# Aurora Self Tests

This directory contains the minimal self-test cases used by `make test-oscomp`.

Cases:
- ramdisk: boot from the built-in FAT32 rootfs, run the user-mode smoke path, and verify a FAT32 write/read marker.
- ext4: boot from an ext4 image created by `scripts/mkfs_ext4.sh`, exec `/init`, and run the ext4 write smoke path.
- ext4-init: host-side ext4 image check that enumerates root and `/etc` via `read_dir` offsets, opens `/init`, validates ELF magic, and reads `/etc/issue` + `/etc/large` (multi-block).
- net: enable virtio-net and confirm ARP reply from the QEMU user-net gateway.
- net-loopback: run the in-kernel TCP loopback self-test and confirm the loopback banner.
- tcp-echo: build `/tcp_echo`, boot with NET=1 and an ext4 image, and confirm the user echo banner (nonblocking connect + ppoll + SO_ERROR + sendmsg/recvmsg iovec).
- udp-echo: build `/udp_echo`, boot with NET=1 and an ext4 image, confirm the user datagram echo banner, validate recvfrom source addresses, exercise sendmsg/recvmsg/sendmmsg/recvmmsg, and verify SO_RCVTIMEO timeout + SO_SNDTIMEO get/set.

Notes:
- ext4-init reads the image path from `AXFS_EXT4_IMAGE` (set by `scripts/test_oscomp.sh`).
- ext4 QEMU runs verify the `vfs: mounted ext4 rootfs` log marker.
- ext4 QEMU runs also verify `/etc/issue` output from `/init`.
- ext4 QEMU runs require the `ext4: write ok` log marker from the kernel smoke test.
- net/net-loopback/tcp-echo require `NET=1` and QEMU user-net (default in the test script).
- udp-echo requires `NET=1` and QEMU user-net (default in the test script).

Usage:
- `make test-oscomp ARCH=riscv64 PLATFORM=qemu`
- Optional: set `FS=path/to/ext4.img` to reuse an existing image.
- Optional: set `EXPECT_INIT=1` to require the `/init` execve banner.
