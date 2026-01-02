# 网络性能基线记录模板

## 目标
- 记录 iperf3/redis 基线吞吐与资源占用。
- 若暂未移植 iperf3/redis，则使用 `net_bench` 作为临时吞吐接收端验证脚本闭环。
- 为后续优化提供可对比的时间序列数据。

## 环境
- 日期：
- ARCH/PLATFORM：
- QEMU 版本：
- 内核提交：
- 机器配置（CPU/内存）：

## 输入
- PERF_INIT_ELF：
- PERF_ROOTFS_DIR：
- PERF_EXPECT（可选）：

## 命令
```bash
PERF_INIT_ELF=path/to/init.elf \
PERF_ROOTFS_DIR=path/to/rootfs-extra \
PERF_EXPECT="iperf3: ok,redis: ok" \
make test-net-perf ARCH=riscv64 PLATFORM=qemu
```

示例（net_bench）：
```bash
PERF_INIT_ELF=build/net_bench.elf \
PERF_ROOTFS_DIR=apps/net_bench/rootfs \
PERF_EXPECT="net-bench: ready" \
PERF_SEND_BYTES=65536 \
PERF_HOST_PORT=auto \
PERF_READY_TIMEOUT=5 \
PERF_QEMU_TIMEOUT=20 \
make test-net-perf ARCH=riscv64 PLATFORM=qemu
```

备注：
- `scripts/net_perf_baseline.sh` 会自动设置 `USER_TEST=1`、`EXPECT_EXT4=1`、`EXPECT_EXT4_ISSUE=0` 以确保 `/init` 运行且不强制 `/etc/issue` 输出。
- `scripts/net_perf_baseline.sh` 会传递 `INIT_ELF_SKIP_BUILD=1`，避免 `mkfs_ext4.sh` 覆盖自定义 `/init`。
- `scripts/net_perf_send.py` 会通过 hostfwd 连接 `PERF_HOST_PORT` 并发送 `PERF_SEND_BYTES`。
- 当前默认 `PERF_SEND_BYTES=65536`，用于覆盖长流量窗口更新路径；可手动调大继续验证吞吐上限。
- 若使用 1MiB 及以上负载，请增大 `PERF_QEMU_TIMEOUT`（例如 20）。
- `PERF_HOST_PORT=auto` 会自动选择一个可用端口，避免 hostfwd 端口冲突。
- `PERF_READY_TIMEOUT` 控制等待 `net-bench: ready` 的上限（秒）。
- `PERF_QEMU_TIMEOUT` 传递给 QEMU 的整体超时（秒）。
- `net_bench` 期望收到 8 字节大端长度头（由 `net_perf_send.py` 自动发送）。

## 结果
- iperf3 吞吐：
- redis 基线：
- net_bench 字节统计（若使用）：
- 日志路径：
  - perf.log：
  - qemu-smoke.log：
  - sender.log：

## 备注
- 记录失败原因与复现步骤。
