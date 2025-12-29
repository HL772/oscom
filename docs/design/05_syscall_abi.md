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
- 早期实现 `read`（fd=0）对接 SBI getchar，非阻塞无数据返回 EAGAIN。
- 早期实现 `execve`：仅识别 `/init` 内置 ELF 镜像，完成最小 ELF 解析与段映射，并构建 argv/envp 栈布局。
- execve 失败路径释放新地址空间，避免页表页与用户页泄漏。
- 早期实现 `wait4/waitpid`：使用最小进程表与父进程等待队列，支持 WNOHANG 与退出码回收。
- waitpid 采用循环阻塞重试，避免递归等待带来的栈增长。
- 早期实现 `clone`：使用 fork 语义创建子进程，支持 CLONE_PARENT_SETTID/CLONE_CHILD_SETTID/CLONE_CHILD_CLEARTID；其余 flags 返回 EINVAL；返回子 PID 并结合 CoW 页表。
- 早期实现 `clock_gettime/gettimeofday/getpid`，支持 MONOTONIC/RAW/BOOTTIME/COARSE 并返回 timebase 时间。
- 早期实现 `clock_gettime64`，与 `clock_gettime` 共用时间源。
- 早期实现 `clock_getres/clock_getres_time64`，返回 timebase 精度占位。
- 早期实现 `nanosleep`，优先走调度器睡眠；无任务上下文时用 timebase 忙等。
- 早期实现 `readv/writev`，复用用户指针校验并支持分段缓冲区。
- 早期实现 `open/openat/mkdirat/unlinkat/newfstatat/getdents64/faccessat/statx/readlinkat`，占位返回 ENOENT/ENOTDIR，并识别 `/dev/null` 与 `/dev/zero`。
- 早期实现 `mknodat/symlinkat/linkat/renameat/renameat2`，占位仅校验指针与 AT_FDCWD，未提供真实重命名/链接能力。
- 早期实现 `statfs/fstatfs`，占位填充基本文件系统信息。
- 早期实现 `fchmodat/fchownat/utimensat`，占位校验参数与路径，允许根目录与 `/dev` 伪节点。
- 早期实现 `poll/ppoll`，支持 pipe 可读/可写事件与 stdin 就绪检测、单 fd 阻塞等待；多 fd 采用 sleep-retry 轮询重扫，pipe 读写/关闭会唤醒等待者；`nfds=0` 作为睡眠路径，占位忽略 signal mask。
- 早期实现 `uname`，返回最小可用的系统信息占位。
- 早期实现 `getpid/getppid/getuid/geteuid/getgid/getegid/getresuid/getresgid` 等身份信息占位。
- 早期实现 `gettid` 与 `sched_yield`，任务上下文可用时返回 TaskId+1。
- 早期实现 `exit_group`，与 `exit` 同步关机占位。
- 早期实现 `getcwd`，占位返回根路径。
- 早期实现 `set_tid_address`，校验指针可写并记录 clear_tid，返回 TaskId+1。
- 早期实现 `futex`：仅支持 FUTEX_WAIT/FUTEX_WAKE，timeout 返回 ETIMEDOUT，value 不匹配返回 EAGAIN，用于 cleartid 唤醒路径。
- futex 支持 FUTEX_PRIVATE_FLAG：私有等待队列以当前地址空间为 key；共享 futex 以物理地址为 key，避免不同进程同地址别名唤醒。
- FUTEX_WAKE 以 count 为上限唤醒，count 足够大时唤醒全部等待者。
- futex 等待队列使用固定槽位表，等待队列清空后释放地址占用，允许后续地址重用。
- 早期实现 `chdir/fchdir`，仅允许切换到根目录占位。
- 早期实现 `close`，允许关闭标准输入输出。
- 早期实现 `getrlimit/prlimit64`，返回默认无限资源限制占位。
- 早期实现 `ioctl(TIOCGWINSZ/TIOCSWINSZ/TIOCGPGRP/TIOCSPGRP/TIOCSCTTY/TCGETS/TCSETS*)`，为终端提供窗口大小与最小 termios 占位。
- 早期实现 `sysinfo`，提供最小内存与运行时间信息占位。
- 早期实现 `getrandom`，使用轻量伪随机填充。
- 早期实现 `fstat`，为标准输入输出返回字符设备元数据。
- 早期实现 `dup/dup3`，占位支持标准输入输出重定向（dup2 由 dup3 flags=0 兼容）。
- 早期实现 `pipe2`，提供固定大小内存管道，空/满时阻塞或返回 EAGAIN，并在无读端时返回 EPIPE、无写端时读返回 EOF。
- 早期实现 `lseek`，对标准输入输出返回 ESPIPE 占位。
- 早期实现 `set_robust_list/get_robust_list`，占位返回空链表。
- 早期实现 `rt_sigaction/rt_sigprocmask`，占位接受信号配置请求。
- 早期实现 `fcntl`，占位支持标准输入输出标志查询/设置（F_GETFL 返回基础读写模式并包含 O_NONBLOCK）。
- 早期实现 `umask`，返回并更新进程掩码占位。
- 早期实现 `prctl(PR_SET_NAME/PR_GET_NAME)`，占位保存并返回进程名。
- 早期实现 `sched_getaffinity/sched_setaffinity`，占位返回单核亲和性。
- 早期实现 `getcpu`，占位返回 CPU=0/NUMA=0。
- 早期实现 `getrusage`，占位返回零资源统计。
- 早期实现 `setpgid/getpgid/getsid/setsid/getpgrp/setpgrp`，任务上下文可用时返回 TaskId+1。
- 早期实现 `getgroups/setgroups`，占位返回空组列表。

## 关键数据结构
- `SyscallAbi`：抽象获取 syscall 号与参数、设置返回值与 `sepc` 前进。
- `SyscallTable`：以 syscall 号为索引的处理函数表（`fn(SyscallCtx) -> Result<usize, Errno>`）。
- `Errno`：错误码枚举与 Linux 对齐映射（用于转换为 `-errno`）。
- `SyscallCtx`：保存 syscall 号、参数切片、调用进程/线程上下文引用。
- `ProcessTable`：最小进程状态表（state/ppid/exit_code），为 waitpid 提供回收与父子关系。

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
- clone 暂不支持线程类 flags，后续需补齐共享地址空间/文件表语义。

## 测试点
- 基础 syscall：`read/write/open/close` 的返回值与 errno 行为。
- 目录与文件：`getdents64`、`stat`、`fstat` 的结构体布局与字段。
- 管道与重定向：`pipe2`、`dup3` 语义对齐。
- 终端控制：`ioctl` 的常用命令（tty、窗口大小）。
- 竞赛测例：busybox、bash、git、gcc、rustc 的关键路径回归。
