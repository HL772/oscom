# weekly_devlog_2025W09.md

## 周目标
- 让等待/超时走调度器阻塞路径，避免忙等。
- 加固任务状态转换，减少过期队列项影响。

## 本周进展
- WaitQueue 改为基于 TaskWaitQueue + SleepQueue 的阻塞等待，返回 WaitResult。
- TaskControlBlock 增加 wait_reason，唤醒时记录通知/超时来源。
- 添加 transition_state 校验，跳过过期等待项并避免错误状态覆盖。
- dummy task 覆盖 wait_timeout/notify 路径，验证通知与超时分支。
- wait_timeout 返回时清理 SleepQueue 条目，避免通知后残留唤醒项。
- 更新 04_task_process 设计与 phase_3 过程文档。
- `make test-qemu-smoke ARCH=riscv64 PLATFORM=qemu` 通过。

## 问题
- 调度仍为协作式，等待超时精度受 tick 影响。

## 下周计划
- 继续完善用户态切入与最小 syscall 骨架。
- 对 wait/timeout 路径补充更系统的自测用例。
