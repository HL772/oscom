# phase_6_oscomp_hardening.md

## 目标
- 梳理内核自研测例的系统加固清单与优先级。

## 进展
- 接入 `scripts/test_oscomp.sh`，运行 `tests/self/` 中的自研测例并采集日志。
- 产出日志目录 `build/selftest/`，生成 summary 便于回归记录。
- 扩展自研测例覆盖网络路径：`net`/`net-loopback`/`tcp-echo` 用例纳入自测清单。

## 问题与定位
- 尚未进入测例加固阶段，暂无问题记录。

## 解决与验证
- `make test-oscomp ARCH=riscv64 PLATFORM=qemu`（可选 `EXPECT_INIT=1` 校验 `/init` execve banner）

## 下一步
- 继续扩展自研测例覆盖面（FS/Net/调度）。
- 完成测例加固后进入交付准备。
