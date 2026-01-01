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
- 自研测例通过 `scripts/test_oscomp.sh` 统一驱动，读取 `tests/self/` 的用例列表，日志输出到 `build/selftest/`，需要时通过 `EXPECT_INIT=1` 检查 `/init` execve banner；ramdisk 用例通过 `EXPECT_FAT32=1` 检查 FAT32 写入回读日志；ext4 用例通过 `EXPECT_EXT4=1` 检查 `vfs: mounted ext4 rootfs` 及用户态 `/etc/issue` 读取日志，必要时启用 `EXT4_WRITE_TEST=1` 并检查 `ext4: write ok`；ext4-init 用例通过 host 侧 VFS 读取验证 `/init` ELF 头、根目录与 `/etc` 的 read_dir offset 枚举、`/etc/issue` 与 `/etc/large` 多块读取；net/net-loopback/tcp-echo 用例通过 `EXPECT_NET`/`EXPECT_NET_LOOPBACK`/`EXPECT_TCP_ECHO` 校验 ARP reply、TCP loopback 与用户态 echo 日志。

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
- make test-oscomp（运行 tests/self 用例：ramdisk + ext4 + ext4-init + net + net-loopback + tcp-echo + udp-echo）

## 网络基准计划
- 连通性基线：ARP reply 与 UDP echo 持续通过，作为 RX/IRQ 健康指标。
- TCP 基线：tcp_echo 覆盖非阻塞 connect + ppoll + SO_ERROR + sendmsg/recvmsg iovec。
- 性能基线：预留 iperf3 端到端吞吐测试（后续加入脚本与记录模板）。
