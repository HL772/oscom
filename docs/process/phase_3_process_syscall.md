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
- 实现最小 sys_read：对接 SBI getchar，早期非阻塞返回。
- 增加 UserPtr/UserSlice 封装用户态访问，并在 sys_write 复用分段遍历。
- 增加 user-test feature 与 USER_TEST=1 冒烟校验，便于验证 U-mode ecall 输出。
- 用户态测试字符串跨页布局，用于覆盖 UserSlice 跨页读路径。
- 增加 clock_gettime/gettimeofday/getpid，占位返回 timebase 时间与固定 PID。
- 增加 clock_gettime64，占位复用 clock_gettime 逻辑。
- 增加 nanosleep，占位使用 timebase 时间忙等。
- 增加 clock_getres/clock_getres_time64，占位返回 timebase 精度。
- 增加 readv/writev，占位支持分段缓冲区访问。
- 增加 uname，占位返回内核与平台信息。
- 增加 getppid/getuid/geteuid/getgid/getegid 等身份信息占位。
- 增加 gettid 与 sched_yield，占位支持线程 ID 与让出调度。
- 增加 exit_group，占位同步关机。
- 增加 getcwd，占位返回根路径。
- 增加 set_tid_address，占位返回 TID 并校验用户指针。
- 增加 close，占位支持标准输入输出关闭。
- 增加 getrlimit/prlimit64，占位返回默认资源限制。
- 增加 ioctl(TIOCGWINSZ)，占位返回终端窗口大小。
- 增加 sysinfo，占位返回内存与运行时间信息。
- 增加 getrandom，占位返回伪随机数据。
- 增加 fstat，占位返回标准输入输出元数据。
- 增加 dup/dup3，占位支持标准输入输出重定向。
- 增加 set_robust_list/get_robust_list，占位返回空链表。
- 增加 rt_sigaction/rt_sigprocmask，占位支持信号配置。
- 增加 fcntl，占位支持标准输入输出标志。
- 增加 umask，占位记录进程掩码。
- 增加 prctl(PR_SET_NAME/PR_GET_NAME)，占位设置进程名。
- 增加 sched_getaffinity/sched_setaffinity，占位返回单核亲和性。
- 增加 getrusage，占位返回零资源统计。
- 增加 setpgid/getpgid/setsid，占位返回进程组信息。

## 问题与定位
- 调度仍处于占位阶段，尚未引入用户态/系统调用上下文保存。

## 解决与验证
- 通过 `make test-qemu-smoke ARCH=riscv64 PLATFORM=qemu` 验证启动与 tick 日志。

## 下一步
- 补齐任务切换的 trapframe 保存/恢复与最小用户态切入。
- 进入文件系统阶段前先稳定调度与 syscalls 骨架。
