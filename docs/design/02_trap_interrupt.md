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
- 定时器抢占仅在从用户态陷入时触发，避免内核态中断打断内核路径导致非可重入切换。
- tick 中断可抢占用户态任务：入队后切回 idle，恢复时根据 trapframe 继续返回用户态。
- 使用 TrapFrameGuard 记录当前 trapframe 指针，为后续抢占保存上下文预留入口。
- trap 入口使用 `sscratch` 交换内核栈指针，确保从 U-mode 进入时切到内核栈。
- trap 入口区分来自 U/S 态：内核态嵌套中断保持使用当前内核栈，用户态陷入时才使用 sscratch 切换；内核运行期间将 sscratch 置零避免嵌套破坏。
- trap 返回用户态时依赖 trapframe 内保存的 user_sp，避免在内核态写 sscratch。
- context_switch 保持 sscratch 为 0，避免内核态切换后误触发用户态栈交换逻辑。
- page fault 分支尝试处理 CoW 写入异常，成功时直接返回用户态。
- 支持 S 态外部中断：通过 PLIC claim/complete 拉取 IRQ 并分发到设备处理函数（如 virtio-blk）。
- 外部中断处理临时切换到内核根页表，确保 PLIC/MMIO 访问不受用户页表缺失影响。
- 外部中断开启 SIE.SEIE，确保设备完成可唤醒阻塞 I/O。

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
- 外部中断依赖 PLIC 寄存器映射，需保证 DTB 提供正确的 MMIO 基址。

## 测试点
- QEMU 启动后触发 U/S 态 ecall 并返回。
- 打开定时器中断并观察 handler 被调用。
- 启动日志打印 timebase 频率与 tick 间隔。
- USER_TEST=1 冒烟覆盖用户态 ecall + execve 后返回路径。
- virtio-blk 读写触发 IRQ 并完成请求（通过 QEMU 日志验证无忙等）。
