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
make test-net-perf ARCH=riscv64 PLATFORM=qemu
```

## 结果
- net_bench 字节统计：未进行吞吐注入，仅确认 ready banner。
- 日志路径：
  - perf.log：build/net-perf/perf.log
  - qemu-smoke.log：build/net-perf/qemu-smoke.log

## 备注
- 当前基线验证覆盖脚本闭环与 /init 替换路径，后续接入 iperf3/redis 后再补充真实吞吐数据。
