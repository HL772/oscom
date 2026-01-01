# phase_1_bootstrap.md

## 目标
- 完成 RISC-V64 QEMU 的最小启动链路。
- 提供可复现的 build/run/test-qemu-smoke 入口。

## 进展
- 增加 RISC-V64 链接脚本与 entry.S，实现早期启动与 BSS 清理。
- 增加最小内核 crate（axruntime），实现 SBI 控制台输出与 shutdown。
- build/run/gdb/test-qemu-smoke 脚本已接入 RISC-V64 QEMU。
- 修复 panic 输出格式导致的 no_std 宏编译错误。
- 使用 SBI v0.2 System Reset 扩展实现关机以适配 QEMU。
- 增加 S 态 trap 向量与最小 handler，完成寄存器保存与恢复框架。
- 增加 DTB 解析以提取内存与 UART 基础信息。
- 接入 timebase-frequency 并启用定时器 tick。
- 启动后进入 idle 循环，等待中断驱动进一步工作。
- 增加 time 模块维护 tick 计数，为后续调度做准备。
- 增加基于 tick 的 sleep_ms 辅助函数。
- 增加 Waiter 结构，用于超时等待原型。
- 增加 WaitQueue 原型，提供基础 notify 接口。
- 增加最小 RunQueue/TCB 与调度 tick hook 占位。
- 增加 Context 结构与 context_switch 汇编入口占位。
- 增加 KernelStack 原型，使用连续页作为内核栈。
- 增加 TaskEntry 占位与 dummy task 初始化。
- 增加调度触发周期参数，占位可配置调度策略（SCHED_INTERVAL_TICKS）。
- 扩大 boot stack 到 64KB，降低复杂 syscall 路径导致的栈溢出风险。

## 问题与定位
- 当前仅支持单核与 legacy SBI 接口。
- OSComp 测例与 FS/Net 尚未接入。

## 解决与验证
- 冒烟测试以启动 banner 为通过条件，允许超时退出以适配早期内核。
- 已执行 `make test-qemu-smoke ARCH=riscv64 PLATFORM=qemu`，通过。

## 下一步
- 引入平台配置与设备树解析，完善启动参数传递。
- 搭建内存管理与基本陷入处理。
