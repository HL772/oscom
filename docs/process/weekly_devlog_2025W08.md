# weekly_devlog_2025W08.md

## 周目标
- 建立仓库最小骨架与交付物入口。

## 本周进展
- 初始化目录结构与 Rust workspace/toolchain。
- 添加 Makefile 与 scripts/ 入口脚本并接入 RISC-V64 QEMU。
- 实现最小内核启动链路与 SBI 控制台输出。
- 选定 MIT License 并补齐第三方声明占位。
- QEMU 冒烟测试已跑通。
- 完成 S 态 trap 基础框架接入。
- 开始内存管理骨架（地址类型、PTE、bump allocator 占位）。
- 接入 DTB 解析以发现内存与 UART 信息。
- DTB 接入后 QEMU 冒烟测试仍通过。
- 建立 Sv39 identity 页表并启用分页。
- 接入 timebase-frequency 并启用定时器 tick。
- 启动后进入 idle 循环等待中断。
- 增加 time 模块维护 tick 计数。
- 增加基于 tick 的 sleep_ms 辅助函数。
- 帧分配器接入 ekernel 之后的可用内存区间。
- 页表页改为从帧分配器动态分配。
- 增加 Waiter 超时等待原型。
- 增加 WaitQueue 原型与 notify 接口。
- 增加 RunQueue/TCB 与调度 tick hook 占位。
- 增加 Context 结构与 context_switch 汇编入口占位。
- 增加 KernelStack 原型（连续页内核栈）。
- 增加 TaskEntry 占位与 dummy task 初始化。
- 增加调度触发周期参数占位（SCHED_INTERVAL_TICKS）。
- 调度触发改为设置 need_resched 标志，在空闲上下文执行切换。
- 增加协作式 yield_now，用于验证空闲与任务上下文往返切换。
- RunQueue 加入轮转指针，增加第二个 dummy task 验证 RR 调度。
- 任务栈改为栈池分配，统一管理早期任务栈。
- 任务改为 TaskTable 管理，RunQueue 保存 TaskId。
- 修复协作式 yield 入队与 current 标志清理，避免切换卡住。
- 增加 TaskWaitQueue 与 block/wake 接口，准备阻塞式同步原语。
- 引入 SleepQueue 与 sleep_current_ms，tick 到期唤醒睡眠任务。
- 增加 dummy C 使用 sleep_ms 验证睡眠唤醒。
- TaskWaitQueue 状态切换调整为由 runtime 统一管理。

## 问题
- OSComp 测例与 FS/Net 尚未接入。
- 多平台支持仍待完善。

## 下周计划
- 完成内存管理与陷入/中断基础框架。
- 接入最小文件系统与用户态加载流程。
