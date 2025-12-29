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
- dummy task 与调度 tick 日志通过 sched-demo feature 开关控制，默认关闭。
- 修复协作式 yield：主动入队并清理当前任务标志，保证空闲调度生效。
- 增加 TaskWaitQueue 与 block/wake 接口，支撑后续阻塞系统调用。
- 引入 SleepQueue 与 sleep_current_ms，tick 到期后唤醒任务。
- 增加 dummy C 使用 sleep_ms 验证睡眠唤醒流程。
- 定时器中断触发抢占：need_resched 置位后，将运行任务回收至 RunQueue 并切回 idle，由 idle_loop 完成 RR 调度。
- 定时器抢占/协作 yield 覆盖用户态任务：恢复入口指向 trapframe，返回用户态前保持 sscratch 的用户栈。
- 调整 TaskWaitQueue 为纯 TaskId 容器，状态切换集中在 runtime。
- 增加 TrapFrameGuard，用于记录当前 trapframe 指针。
- TaskControlBlock 增加 trapframe 指针字段，为抢占保存上下文做准备。
- WaitQueue 改为阻塞式等待，结合 TaskWaitQueue + SleepQueue 支持超时。
- TaskControlBlock 增加 wait_reason，记录等待完成原因。
- 引入 task 状态验证转换（transition_state），跳过过期队列项。
- dummy task 接入 WaitQueue 的 wait_timeout/notify 路径，覆盖通知与超时。
- wait_timeout 返回前清理 SleepQueue 条目，避免通知后残留唤醒项。
- 补充 syscall ABI 设计文档草案（分发入口/errno/用户态指针校验）。
- trap 支持 U-mode ecall 分发，syscall dispatcher 骨架完成。
- trap 入口通过 sscratch 交换内核栈，保证 U-mode trap 使用内核栈。
- 添加用户态测试映射与 enter_user 入口，用于验证 ecall 路径。
- 实现最小 sys_write：翻译用户指针并输出到控制台。
- 实现最小 sys_read：对接 SBI getchar，无输入返回 EAGAIN。
- 增加 UserPtr/UserSlice 封装用户态访问，并在 sys_write 复用分段遍历。
- 增加 user-test feature 与 USER_TEST=1 冒烟校验，便于验证 U-mode ecall 输出与 poll/ppoll 睡眠路径。
- 用户态测试字符串跨页布局，用于覆盖 UserSlice 跨页读路径。
- 增加 clock_gettime/gettimeofday/getpid，占位支持 MONOTONIC/RAW/BOOTTIME/COARSE 时间源。
- 增加 clock_gettime64，占位复用 clock_gettime 逻辑。
- 增加 nanosleep，占位优先走调度器睡眠，否则使用 timebase 忙等。
- 增加 clock_getres/clock_getres_time64，占位返回 timebase 精度。
- 增加 readv/writev，占位支持分段缓冲区访问并允许 iovcnt=0。
- 增加 open/openat/mkdirat/unlinkat/newfstatat/getdents64/faccessat/statx/readlinkat，占位走 VFS 解析 `/`、`/dev`、`/init`、`/dev/null`、`/dev/zero`，同时校验 getdents64 缓冲区。
- openat 路径识别统一走 VFS 挂载解析，保持伪节点一致。
- 增加 mknodat/symlinkat/linkat/renameat/renameat2，占位校验 AT_FDCWD 与路径指针。
- 增加 statfs/fstatfs，占位填充基本文件系统信息。
- 增加 fchmodat/fchownat/utimensat，占位支持根目录与 `/dev` 伪节点。
- 增加 poll/ppoll，支持 pipe 可读/可写事件、单 fd 阻塞等待；多 fd 使用 sleep-retry 轮询重扫，pipe 读写/关闭唤醒等待者，同时保留 `nfds=0` 睡眠路径。
- ppoll 的 sleep-retry 在调度器睡眠不可用时回退到 timebase 忙等，避免超时过早返回。
- stdin 读取加入控制台缓存与睡眠重试，poll 增加 stdin 就绪判断；USER_TEST 覆盖 getdents64(/,/dev)、pipe poll 就绪、ppoll 多 fd sleep-retry 超时与 futex cleartid 唤醒/timeout/EAGAIN 路径。
- 增加 execve `/init` VFS 链路：从 VFS 读取 ELF，解析 PT_LOAD 段并映射，构建 argv/envp 栈布局后切换入口。
- execve 失败路径补充地址空间释放，避免页表与用户页泄漏。
- 增加最小进程表（state/ppid/exit_code），以 TaskId+1 作为早期 PID 占位。
- 增加 wait4/waitpid：父进程阻塞等待队列、WNOHANG 支持、Zombie 回收与 exit_code 回写。
- waitpid 等待改为循环阻塞重试，避免递归栈增长。
- sys_exit 退出时标记 Zombie 并唤醒父进程等待队列。
- 用户任务保存 user root/entry/sp 与 trapframe 指针，支持调度后从 __trap_return 恢复回用户态。
- 增加 clone：复制 trapframe 并创建子任务，结合 CoW 页表返回子 PID。
- clone 支持 CLONE_PARENT_SETTID/CLONE_CHILD_SETTID/CLONE_CHILD_CLEARTID 写回/清零，其他 flags 早期返回 EINVAL。
- set_tid_address 记录 clear_tid，进程退出时清零 child_tid 并唤醒 futex 等待者。
- 增加 futex 最小实现：支持 FUTEX_WAIT/FUTEX_WAKE，timeout 返回 ETIMEDOUT，value 不匹配返回 EAGAIN。
- FUTEX_PRIVATE_FLAG 以地址空间作为 key；共享 futex 以物理地址作为 key，避免跨进程别名误唤醒。
- FUTEX_WAKE 支持 count 足够大时唤醒全部等待者。
- futex 等待队列空闲后回收槽位地址，避免长期占用。
- wait4 在返回子进程状态时可选写入占位 rusage，保持接口兼容。
- getdents64 走 VFS `read_dir` 枚举，覆盖根目录与 /dev。
- clone_user_root 从内核根表构建子页表，只克隆用户映射，避免共享父页表页。
- waitpid 回收 Zombie 时释放子进程的用户页表与物理页。
- 增加 uname，占位返回内核与平台信息。
- 增加 getppid/getuid/geteuid/getgid/getegid/getresuid/getresgid 等身份信息占位。
- 增加 gettid 与 sched_yield，占位支持线程 ID；任务上下文可用时返回 TaskId+1。
- 增加 exit_group，占位同步关机。
- 增加 getcwd，占位返回根路径。
- 增加 set_tid_address，占位返回 TaskId+1 并校验用户指针。
- 增加 chdir/fchdir，占位仅允许目录。
- 增加 close，占位支持标准输入输出关闭。
- 增加 getrlimit/prlimit64，占位返回默认资源限制。
- 增加 ioctl(TIOCGWINSZ/TIOCSWINSZ/TIOCGPGRP/TIOCSPGRP/TIOCSCTTY/TCGETS/TCSETS*)，占位返回窗口大小与最小 termios。
- 增加 sysinfo，占位返回内存与运行时间信息。
- 增加 getrandom，占位返回伪随机数据并校验 flags。
- 增加 fstat，占位返回标准输入输出与 VFS 句柄元数据。
- fstat 时间戳改为基于 timebase 的单调时间，避免 tick 精度影响。
- 增加 dup/dup3，占位支持标准输入输出重定向。
- 增加 pipe2，占位内存管道缓冲区，支持阻塞唤醒与 EPIPE/EOF/EAGAIN。
- fcntl/F_SETFL 支持 O_NONBLOCK，pipe 读写在设置后返回 EAGAIN。
- 增加 lseek，占位返回 ESPIPE 避免误判可寻址。
- 增加 set_robust_list/get_robust_list，占位返回空链表。
- 增加 rt_sigaction/rt_sigprocmask，占位支持信号配置。
- 增加 fcntl，占位支持标准输入输出标志并返回基础读写模式。
- 增加 umask，占位记录进程掩码。
- 增加 prctl(PR_SET_NAME/PR_GET_NAME)，占位保存并返回进程名。
- 增加 sched_getaffinity/sched_setaffinity，占位返回单核亲和性并清空 mask。
- 增加 getcpu，占位返回 CPU=0/NUMA=0。
- 增加 getrusage，占位返回基础 user 时间与零资源统计。
- 增加 setpgid/getpgid/getsid/setsid/getpgrp/setpgrp，占位返回 TaskId+1 作为进程组信息。
- 增加 getgroups/setgroups，占位返回空组列表。

## 问题与定位
- 调度仍为单核占位阶段，未覆盖完整的多核与复杂优先级策略。

## 解决与验证
- 通过 `make test-qemu-smoke ARCH=riscv64 PLATFORM=qemu` 验证启动与 tick 日志。
- 通过 `USER_TEST=1 make test-qemu-smoke ARCH=riscv64 PLATFORM=qemu` 覆盖 getdents64、execve/pipe/poll/ppoll/futex 超时/cleartid/wait4 的用户态路径。

## 下一步
- 补齐任务切换的 trapframe 保存/恢复与最小用户态切入。
- 进入文件系统阶段前先稳定调度与 syscalls 骨架。
