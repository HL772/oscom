# 10_testing_benchmark.md

## 目标
- 建立可复现的测试矩阵与脚本入口。
- 记录功能与性能测试方法、环境与结论。

## 设计
- 测试分层：host 单测、QEMU 冒烟、自研内核测例、性能基准。
- 脚本化入口统一在 `scripts/`，由 `Makefile` 聚合。
- 测试环境记录包含工具链版本、QEMU 版本与硬件信息。
- QEMU 冒烟测试以启动 banner 为通过条件，允许超时退出以适配早期内核。
- QEMU 脚本固定 `virtio-mmio.force-legacy=false`，确保使用现代 virtio-mmio 接口。
- 自研测例通过 `scripts/test_oscomp.sh` 统一驱动，读取 `tests/self/` 的用例列表，日志输出到 `build/selftest/`，需要时通过 `EXPECT_INIT=1` 检查 `/init` execve banner；ramdisk 用例通过 `EXPECT_FAT32=1` 检查 FAT32 写入回读日志；ext4 用例通过 `EXPECT_EXT4=1` 检查 `vfs: mounted ext4 rootfs` 及用户态 `/etc/issue` 读取日志，必要时启用 `EXT4_WRITE_TEST=1` 并检查 `ext4: write ok`；ext4-init 用例通过 host 侧 VFS 读取验证 `/init` ELF 头、根目录与 `/etc` 的 read_dir offset 枚举、`/etc/issue` 与 `/etc/large` 多块读取；net/net-loopback/tcp-echo/udp-echo 用例通过 `EXPECT_NET`/`EXPECT_NET_LOOPBACK`/`EXPECT_TCP_ECHO`/`EXPECT_UDP_ECHO` 校验 ARP reply、TCP loopback 与用户态 echo 日志；fs-smoke 用例通过 `EXPECT_FS_SMOKE` 校验 lseek/pwrite64/O_APPEND 语义。

## 关键数据结构
- TestConfig：测试目标与参数集合（ARCH/PLATFORM/FS）。
- TestResult：结果汇总（时间、通过率、日志路径）。

## 关键流程图或伪代码
```text
make test-* -> scripts/test_*.sh
  -> run target
  -> collect logs
  -> summarize results
```

## 风险与权衡
- 测试覆盖越高，时间成本越大。
- QEMU/硬件环境差异可能导致结果波动。

## 测试点
- make test-host
- make test-qemu-smoke
- USER_TEST=1 make test-qemu-smoke (验证最小用户态 ecall 路径，覆盖 getdents64(/,/dev)、FAT32 文件写入回读、/dev/null write、ppoll 多 fd sleep-retry 超时、poll/pipe 就绪、futex cleartid 唤醒与 timeout、wait4 与 execve ELF 加载)
- EXT4_WRITE_TEST=1 EXPECT_EXT4=1 make test-qemu-smoke (在 virtio-blk ext4 镜像上执行 create/write 读回路径)
- NET=1 EXPECT_NET=1 make test-qemu-smoke (启用 virtio-net 并确认 ready 日志)
- NET=1 TCP_ECHO_TEST=1 EXPECT_TCP_ECHO=1 make test-qemu-smoke (用户态 TCP echo 覆盖 socket syscall 路径)
- NET=1 UDP_ECHO_TEST=1 EXPECT_UDP_ECHO=1 make test-qemu-smoke (用户态 UDP echo 覆盖 datagram syscall 路径)
- FS_SMOKE_TEST=1 EXPECT_FS_SMOKE=1 make test-qemu-smoke（用户态 fs-smoke 覆盖 lseek/pwrite64/O_APPEND）
- make test-oscomp（运行 tests/self 用例：ramdisk + ext4 + ext4-init + net + net-loopback + tcp-echo + udp-echo + fs-smoke）
- make test-net-baseline（顺序执行 net/net-loopback/tcp-echo/udp-echo 并记录日志）
- make test-net-perf（需要自定义 /init 与用户态二进制，脚本启用 USER_TEST 触发 execve，记录性能基线日志）
- make test-net-perf（通过 hostfwd 触发 net_perf_send 发送端，支持 PERF_HOST_PORT=auto 避免端口冲突）
- make test-net-perf（支持 PERF_QEMU_TIMEOUT 覆盖 QEMU 超时，便于大流量基准）
- make test-net-perf（支持 PERF_IO_TIMEOUT 覆盖发送端 I/O 超时，避免 host 侧提前超时）
- PERF_INIT_ELF=build/net_bench.elf PERF_ROOTFS_DIR=apps/net_bench/rootfs make test-net-perf（net_bench 作为临时吞吐接收端，使用 `scripts/build_net_bench.sh` 生成 ELF）

## 网络基准计划
- 连通性基线：ARP reply 与 UDP echo 持续通过，作为 RX/IRQ 健康指标。
- TCP 基线：tcp_echo 覆盖非阻塞 connect + ppoll + SO_ERROR + sendmsg/recvmsg iovec。
- 性能基线：预留 iperf3 端到端吞吐测试（后续加入脚本与记录模板）。
- 性能基线（临时）：使用 `apps/net_bench` 作为 `/init`，接收 TCP 流量并输出累计字节数，验证 net-perf 脚本闭环。
- 基准脚本：`scripts/net_baseline.sh` 生成 `build/net-baseline/*.log`。
- 性能脚本：`scripts/net_perf_baseline.sh` 生成 `build/net-perf/perf.log`。
