# phase_6_oscomp_hardening.md

## 目标
- 梳理内核自研测例的系统加固清单与优先级。

## 进展
- 接入 `scripts/test_oscomp.sh`，运行 `tests/self/` 中的自研测例并采集日志。
- 产出日志目录 `build/selftest/`，生成 summary 便于回归记录。
- 扩展自研测例覆盖网络路径：`net`/`net-loopback`/`tcp-echo`/`udp-echo` 用例纳入自测清单。
- tcp-echo 增加连接失败路径校验（SO_ERROR 映射），提升连接错误码一致性覆盖。
- net-perf 基线脚本支持 `PERF_QEMU_TIMEOUT`，避免大流量下 QEMU 超时截断。
- net-perf 增加 `PERF_IO_TIMEOUT` 发送端超时参数，并补充 1MiB/4MiB 基线记录。
- TCP 缓冲区上调至 16KB、idle net poll 间隔调整为 20ms，作为性能调优基线。
- 4MiB net-perf 基线调优后耗时约 3.4s（见 net_perf_baseline_2026-01-01.md）。
- 8MiB/16MiB net-perf 扩展基线分别约 33.4s/80.4s（见 net_perf_baseline_2026-01-01.md）。
- 增加 mmap/munmap/mprotect 最小兼容实现（匿名私有映射 + MAP_FIXED + munmap 回收与空表清理 + mprotect 权限更新），为后续 libc/应用适配打底。

## 问题与定位
- 尚未进入测例加固阶段，暂无问题记录。

## 解决与验证
- `make test-oscomp ARCH=riscv64 PLATFORM=qemu`（可选 `EXPECT_INIT=1` 校验 `/init` execve banner）

## 下一步
- 继续扩展自研测例覆盖面（FS/Net/调度）。
- 完成测例加固后进入交付准备。
- 记录 net-perf 基线与自研测例回归结果，形成周期性对比。
