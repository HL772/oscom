# 10_testing_benchmark.md

## 目标
- 建立可复现的测试矩阵与脚本入口。
- 记录功能与性能测试方法、环境与结论。

## 设计
- 测试分层：host 单测、QEMU 冒烟、OSComp 测例、性能基准。
- 脚本化入口统一在 `scripts/`，由 `Makefile` 聚合。
- 测试环境记录包含工具链版本、QEMU 版本与硬件信息。
- QEMU 冒烟测试以启动 banner 为通过条件，允许超时退出以适配早期内核。

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
- USER_TEST=1 make test-qemu-smoke (验证最小用户态 ecall 路径，覆盖 ppoll 多 fd sleep-retry 超时、poll/pipe 就绪、clone/wait4 与 execve ELF 加载)
- make test-oscomp
