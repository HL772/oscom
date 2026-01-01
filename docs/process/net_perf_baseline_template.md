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
make test-net-perf ARCH=riscv64 PLATFORM=qemu
```

备注：
- `scripts/net_perf_baseline.sh` 会自动设置 `USER_TEST=1`、`EXPECT_EXT4=1`、`EXPECT_EXT4_ISSUE=0` 以确保 `/init` 运行且不强制 `/etc/issue` 输出。
- `scripts/net_perf_baseline.sh` 会传递 `INIT_ELF_SKIP_BUILD=1`，避免 `mkfs_ext4.sh` 覆盖自定义 `/init`。

## 结果
- iperf3 吞吐：
- redis 基线：
- net_bench 字节统计（若使用）：
- 日志路径：
  - perf.log：
  - qemu-smoke.log：

## 备注
- 记录失败原因与复现步骤。
