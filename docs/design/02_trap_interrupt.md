# 02_trap_interrupt.md

## 目标
- 完成 S 态陷入/中断/异常的基础框架。
- 提供最小可调试的 trap handler 与寄存器保存逻辑。

## 设计
- 使用 S-mode trap 向量 `stvec` 指向汇编入口 `__trap_vector`。
- 汇编入口保存通用寄存器与关键 CSR（sstatus/sepc/scause/stval），再进入 Rust 处理函数。
- Rust handler 解析 scause，支持 U-mode ecall 分发与 S-mode ecall 跳过。
- 增加 `__trap_return` 汇编入口，用于从保存的 trapframe 恢复用户态现场并 sret。
- 任务切换时记录 trapframe 指针与用户栈指针，恢复后可继续返回到用户态。
- 定时器中断使用 SBI set_timer 重新编程，实现周期性 tick。
- tick 计数在 time 模块中维护，供后续调度与超时使用。
- tick 中断设置调度请求标志，并在有运行任务时切回空闲上下文，由 idle_loop 执行调度，避免在 trap 中直接选取下个任务。
- 使用 TrapFrameGuard 记录当前 trapframe 指针，为后续抢占保存上下文预留入口。
- trap 入口使用 `sscratch` 交换内核栈指针，确保从 U-mode 进入时切到内核栈。
- page fault 分支尝试处理 CoW 写入异常，成功时直接返回用户态。

## 关键数据结构
- TrapFrame：保存通用寄存器与 CSR 的固定布局结构。
- TrapFrameGuard：记录当前 trapframe 指针（仅在 trap 生命周期内有效）。
- 关键 CSR：sstatus / sepc / scause / stval。

## 关键流程图或伪代码
```text
trap_entry (__trap_vector)
  -> save GPRs + sstatus/sepc/scause/stval
  -> call trap_handler(&mut TrapFrame)
     -> if ecall from U-mode: syscall dispatch
  -> restore CSR/GPRs
  -> sret
```

## 风险与权衡
- trap 保存/恢复开销影响中断延迟。
- 尚未实现用户态上下文切换与嵌套中断策略。

## 测试点
- QEMU 启动后触发 U/S 态 ecall 并返回。
- 打开定时器中断并观察 handler 被调用。
- 启动日志打印 timebase 频率与 tick 间隔。
- USER_TEST=1 冒烟覆盖用户态 ecall + execve 后返回路径。
