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
- 自研测例通过 `scripts/test_oscomp.sh` 统一驱动，读取 `tests/self/` 的用例列表，日志输出到 `build/selftest/`，需要时通过 `EXPECT_INIT=1` 检查 `/init` execve banner；ext4 用例通过 `EXPECT_EXT4=1` 检查 `vfs: mounted ext4 rootfs` 及用户态 `/etc/issue` 读取日志；ext4-init 用例通过 host 侧 VFS 读取验证 `/init` ELF 头、根目录与 `/etc` 的 read_dir offset 枚举与 `/etc/issue` 读取。

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
- USER_TEST=1 make test-qemu-smoke (验证最小用户态 ecall 路径，覆盖 getdents64(/,/dev)、ppoll 多 fd sleep-retry 超时、poll/pipe 就绪、futex cleartid 唤醒与 timeout、wait4 与 execve ELF 加载)
- make test-oscomp（运行 tests/self 用例：ramdisk + ext4 + ext4-init）
