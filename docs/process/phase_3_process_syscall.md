# phase_3_process_syscall.md

## 目标
- TODO: 进程/线程与系统调用覆盖。

## 进展
- 引入调度请求标志（need_resched），中断仅设置标志，空闲上下文执行切换。
- 早期 RunQueue + dummy task 持续验证上下文切换入口。
- 增加协作式 `yield_now`，用于验证任务与空闲上下文往返切换。
- 增加 RunQueue 轮转指针与第二个 dummy task，验证 RR 顺序。
- 任务栈改为固定大小栈池分配，便于扩展任务数量。
- 增加 TaskTable，RunQueue 仅保存 TaskId，减少 TCB 移动。
- 修复协作式 yield：主动入队并清理当前任务标志，保证空闲调度生效。
- 增加 TaskWaitQueue 与 block/wake 接口，支撑后续阻塞系统调用。
- 引入 SleepQueue 与 sleep_current_ms，tick 到期后唤醒任务。
- 增加 dummy C 使用 sleep_ms 验证睡眠唤醒流程。
- 调整 TaskWaitQueue 为纯 TaskId 容器，状态切换集中在 runtime。

## 问题与定位
- 调度仍处于占位阶段，尚未引入用户态/系统调用上下文保存。

## 解决与验证
- 通过 `make test-qemu-smoke ARCH=riscv64 PLATFORM=qemu` 验证启动与 tick 日志。

## 下一步
- 补齐任务切换的 trapframe 保存/恢复与最小用户态切入。
- 进入文件系统阶段前先稳定调度与 syscalls 骨架。
