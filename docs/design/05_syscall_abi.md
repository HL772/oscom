# 05_syscall_abi.md

## 目标
- 明确 syscall ABI 与寄存器约定，保证与 Linux 语义一致。
- 定义统一的 syscall 分发入口与 errno 映射策略。
- 约束用户态指针与缓冲区访问，避免越权或内核崩溃。

## 设计
- 遵循目标架构的 Linux syscall ABI 约定：寄存器传参、返回值与错误码格式保持一致。
- RISC-V64 ABI：`a7` 为 syscall 号，`a0-a5` 为参数，返回值写回 `a0`，错误返回 `-errno`。
- 将 ABI 细节下沉到架构层（如 `arch/*/syscall.rs`），内核核心只依赖 `SyscallAbi` 抽象。
- syscall 分发采用静态表（数组/切片）索引，避免早期动态分配。
- 统一 errno 处理：内核内部使用 `Result<usize, Errno>`，出口转换为 `-errno` 返回给用户态。
- 用户态内存访问通过 `UserPtr`/`UserSlice` 封装校验范围与页表映射，sys_write 先行接入验证路径。
- 兼容层为关键 syscall 提供 Linux 语义对齐（如 `getdents64`/`ioctl`/`pipe2`/`dup3`）。
- 早期实现 `write` 的用户指针翻译与控制台输出，用于验证 U-mode ecall 链路。
- 早期实现 `read`（fd=0）对接 SBI getchar，暂为非阻塞读取占位。
- 早期实现 `clock_gettime/gettimeofday/getpid`，返回基于 tick 的时间与占位 PID。
- 早期实现 `clock_gettime64`，与 `clock_gettime` 共用时间源。
- 早期实现 `readv/writev`，复用用户指针校验并支持分段缓冲区。
- 早期实现 `uname`，返回最小可用的系统信息占位。
- 早期实现 `getpid/getppid/getuid/geteuid/getgid/getegid` 等身份信息占位。
- 早期实现 `gettid` 与 `sched_yield`，提供最小线程 ID 与让出路径。
- 早期实现 `exit_group`，与 `exit` 同步关机占位。
- 早期实现 `getcwd`，占位返回根路径。

## 关键数据结构
- `SyscallAbi`：抽象获取 syscall 号与参数、设置返回值与 `sepc` 前进。
- `SyscallTable`：以 syscall 号为索引的处理函数表（`fn(SyscallCtx) -> Result<usize, Errno>`）。
- `Errno`：错误码枚举与 Linux 对齐映射（用于转换为 `-errno`）。
- `SyscallCtx`：保存 syscall 号、参数切片、调用进程/线程上下文引用。

## 关键流程图或伪代码
```text
trap_entry
  -> save TrapFrame
  -> if scause == ecall from U-mode:
       ctx = SyscallAbi::from_trapframe(tf)
       ret = syscall_dispatch(ctx)
       SyscallAbi::write_return(tf, ret)
       advance sepc
  -> restore TrapFrame
  -> sret
```

## 风险与权衡
- ABI 细节错配会导致用户态程序崩溃，需严格对齐 Linux 文档。
- syscall 覆盖面大，维护成本高，需要持续回归测试。
- 用户态指针检查不完善会引入安全问题或内核崩溃。

## 测试点
- 基础 syscall：`read/write/open/close` 的返回值与 errno 行为。
- 目录与文件：`getdents64`、`stat`、`fstat` 的结构体布局与字段。
- 管道与重定向：`pipe2`、`dup3` 语义对齐。
- 终端控制：`ioctl` 的常用命令（tty、窗口大小）。
- 竞赛测例：busybox、bash、git、gcc、rustc 的关键路径回归。
