# 04_task_process.md

## 目标
- 定义进程/线程模型的总体方向（Process/Task 分离）。
- 预留调度与同步原语接口，早期提供时间与等待队列占位。

## 设计
- Process 作为资源拥有者，Task 作为调度单位，后续支持 clone 语义。
- 调度器采用 tick 驱动的时间片抢占，初期可用简单 RR。
- 早期提供 `sleep_ms` 与 `WaitQueue`（阻塞 + 超时等待）辅助，等待由调度器挂起任务。
- 引入最小 `RunQueue` 与 `TaskControlBlock` 作为调度骨架，占位 tick 驱动的轮转逻辑。
- 增加上下文结构与 `context_switch` 汇编入口，当前仅保留接口占位。
- 使用 `need_resched` 标志从 tick 中断发起调度请求，运行中任务先回到空闲上下文，再由 idle_loop 拉起下一任务。
- 增加 `yield_now` 协作式让渡，主动入队并清理 CURRENT_TASK，再切回空闲。
- RunQueue 维护轮转指针，实现最小 RR 顺序。
- RunQueue 保存 `TaskId`，任务实体存放在固定大小的 TaskTable。
- 引入最小进程表（state/ppid/exit_code），以 TaskId+1 作为早期 PID 占位。
- waitpid 使用“父进程专属等待队列”，子进程 exit 进入 Zombie 后唤醒父进程。
- waitpid 回收 Zombie 时释放子进程地址空间与页表页，避免内存泄漏。
- 增加 TaskWaitQueue，使用 TaskId 阻塞/唤醒任务并配合 RunQueue（状态切换由 runtime 负责）。
- 增加 SleepQueue 与 `sleep_current_ms`，由 tick 触发唤醒并回收到 RunQueue。
- WaitQueue 通过 TaskWaitQueue + SleepQueue 实现阻塞等待与超时，WaitReason 由任务表记录。
- 记录 trapframe 指针（TrapFrameGuard），支持抢占时保存/恢复用户态现场。
- 内核栈在早期由帧分配器分配连续页，任务栈来自固定大小的栈池（上限 `MAX_TASKS`）。
- TaskControlBlock 支持入口函数指针与栈顶配置，早期用多 dummy task 验证轮转与睡眠唤醒。
- TaskControlBlock 记录用户态 root/entry/sp 与 trapframe 指针，用于 execve 后切换地址空间与从 trap 返回。
- fork/clone 通过复制 trapframe + CoW 页表生成子任务，父进程返回子 PID，子进程返回 0。
- dummy task 与调度日志通过 `sched-demo` feature 控制，默认构建保持安静。
- 调度触发周期可配置（`SCHED_INTERVAL_TICKS`），避免频繁切换。
- 引入 `transition_state` 校验任务状态转换，避免过期队列项覆盖运行态。

## 关键数据结构
- TaskControlBlock / TaskId / TaskTable：固定槽位管理、状态、上下文与 trapframe 指针。
- RunQueue / TaskWaitQueue / WaitQueue：就绪队列、任务等待队列与阻塞等待队列。
- WaitReason：记录等待完成原因（通知/超时），由任务表维护。
- WaitQueue：固定容量等待队列，支持 notify_one/notify_all。
- Context：保存 callee-saved 寄存器的最小上下文结构。
- KernelStack：基于连续页的内核栈占位实现。
- TaskEntry：任务入口函数类型，占位启动路径。
- ProcState / ProcessTable：最小进程表状态与父子关系，用于 waitpid 回收。

## 关键流程图或伪代码
```text
on_tick
  -> update time ticks
  -> scheduler tick hook

after boot
  -> init run queue
  -> schedule (placeholder)

block_current(waitq)
  -> mark Blocked + enqueue waitq
  -> switch to idle

wake_one(waitq)
  -> dequeue + mark Ready
  -> enqueue run queue

exit_current(code)
  -> mark Zombie + record exit_code
  -> wake parent wait queue

waitpid(pid)
  -> scan children -> reap Zombie
  -> no zombie + WNOHANG -> return 0
  -> block on parent wait queue
```

## 风险与权衡
- WaitQueue 超时依赖 tick 频率，分辨率受限。
- Tick 频率与调度粒度需要平衡延迟与开销。
- RunQueue/WaitQueue 目前无锁，仅用于单核启动阶段。
- 进程表为固定大小数组，需与 MAX_TASKS 同步扩展。

## 测试点
- tick 计数增长与 `sleep_ms` / `wait_timeout_ms` 行为。
- notify_one/notify_all 的唤醒行为与 WaitReason 返回值。
- dummy task 的 wait/notify 组合覆盖通知与超时两种路径。
- scheduler tick hook 的日志输出与周期调度行为。
- 后续 busybox/多任务场景回归。
- fork/clone 后父子进程能分别返回并执行，触发 CoW 写入路径。
