# 网络性能基线记录 2026-01-01

## 目标
- 使用 `net_bench` 作为临时 /init，验证 net-perf 脚本闭环与日志采集。

## 环境
- 日期：2026-01-01
- ARCH/PLATFORM：riscv64/qemu
- QEMU 版本：QEMU emulator version 8.2.2 (Debian 1:8.2.2+ds-0ubuntu1.11)
- 内核提交：09ccf9ca2fdccee5efad1b33c883ce9dbdd3f807
- 机器配置（CPU/内存）：Linux x86_64 (WSL2), 具体内存未记录

## 输入
- PERF_INIT_ELF：build/net_bench.elf
- PERF_ROOTFS_DIR：apps/net_bench/rootfs
- PERF_EXPECT：net-bench: ready

## 命令
```bash
PERF_INIT_ELF=build/net_bench.elf \
PERF_ROOTFS_DIR=apps/net_bench/rootfs \
PERF_EXPECT="net-bench: ready" \
PERF_QEMU_TIMEOUT=20 \
make test-net-perf ARCH=riscv64 PLATFORM=qemu
```

```bash
PERF_INIT_ELF=build/net_bench.elf \
PERF_ROOTFS_DIR=apps/net_bench/rootfs \
PERF_EXPECT="net-bench: ready" \
PERF_SEND_BYTES=1048576 \
PERF_QEMU_TIMEOUT=30 \
make test-net-perf ARCH=riscv64 PLATFORM=qemu
```

```bash
OUT_DIR=build/net-perf-4m \
PERF_INIT_ELF=build/net_bench.elf \
PERF_ROOTFS_DIR=apps/net_bench/rootfs \
PERF_EXPECT="net-bench: ready" \
PERF_SEND_BYTES=4194304 \
PERF_SEND_CHUNK=65536 \
PERF_IO_TIMEOUT=20 \
PERF_QEMU_TIMEOUT=60 \
make test-net-perf ARCH=riscv64 PLATFORM=qemu
```

## 结果
- 64K 基线：rx_bytes=65536，sent_bytes=65536，duration_ms=2。
- 64K 基线（PERF_QEMU_TIMEOUT=20）：rx_bytes=65536，sent_bytes=65536，duration_ms=1。
- 1MiB 扩展（PERF_QEMU_TIMEOUT=30）：rx_bytes=1048576，sent_bytes=1048576，duration_ms=245。
- 4MiB 扩展（PERF_QEMU_TIMEOUT=60 + PERF_IO_TIMEOUT=20）：rx_bytes=4194304，sent_bytes=4194304，duration_ms=11635。
- 4MiB 调优（TCP_BUF_LEN=16KB + poll 20ms）：rx_bytes=4194304，sent_bytes=4194304，duration_ms=3444。
- 日志路径：
  - perf.log：build/net-perf/perf.log
  - qemu-smoke.log：build/net-perf/qemu-smoke.log

## 备注
- 当前基线验证覆盖脚本闭环、hostfwd 注入与 /init 替换路径；大负载需提高 PERF_QEMU_TIMEOUT 与 PERF_IO_TIMEOUT。
