# phase_3_process_syscall.md

## 目标
- TODO: 进程/线程与系统调用覆盖。

## 进展
- 引入调度请求标志（need_resched），中断仅设置标志，空闲上下文执行切换。
- 早期 RunQueue + dummy task 持续验证上下文切换入口。

## 问题与定位
- 调度仍处于占位阶段，尚未引入用户态/系统调用上下文保存。

## 解决与验证
- 通过 `make test-qemu-smoke ARCH=riscv64 PLATFORM=qemu` 验证启动与 tick 日志。

## 下一步
- 补齐任务切换的 trapframe 保存/恢复与最小用户态切入。
- 进入文件系统阶段前先稳定调度与 syscalls 骨架。
