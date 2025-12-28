# 02_trap_interrupt.md

## 目标
- 完成 S 态陷入/中断/异常的基础框架。
- 提供最小可调试的 trap handler 与寄存器保存逻辑。

## 设计
- 使用 S-mode trap 向量 `stvec` 指向汇编入口 `__trap_vector`。
- 汇编入口保存通用寄存器与关键 CSR（sstatus/sepc/scause/stval），再进入 Rust 处理函数。
- Rust handler 解析 scause，支持基础的 S-mode ecall 跳过与定时器中断重置。
- 当前阶段仅覆盖内核态 trap（无用户态上下文切换）。
- 定时器中断使用 SBI set_timer 重新编程，实现周期性 tick。
- tick 计数在 time 模块中维护，供后续调度与超时使用。
- tick 中断仅设置调度请求标志，由空闲上下文完成切换，避免在 trap 中切换上下文。

## 关键数据结构
- TrapFrame：保存通用寄存器与 CSR 的固定布局结构。
- 关键 CSR：sstatus / sepc / scause / stval。

## 关键流程图或伪代码
```text
trap_entry (__trap_vector)
  -> save GPRs + sstatus/sepc/scause/stval
  -> call trap_handler(&mut TrapFrame)
  -> restore CSR/GPRs
  -> sret
```

## 风险与权衡
- trap 保存/恢复开销影响中断延迟。
- 尚未实现用户态上下文切换与嵌套中断策略。

## 测试点
- QEMU 启动后触发 S 态 ecall 并返回。
- 打开定时器中断并观察 handler 被调用。
- 启动日志打印 timebase 频率与 tick 间隔。
