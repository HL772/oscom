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
- 使用 `need_resched` 标志从 tick 中断发起调度请求，切换在空闲上下文执行。
- 增加 `yield_now` 协作式让渡，主动入队并清理 CURRENT_TASK，再切回空闲。
- RunQueue 维护轮转指针，实现最小 RR 顺序。
- RunQueue 保存 `TaskId`，任务实体存放在固定大小的 TaskTable。
- 增加 TaskWaitQueue，使用 TaskId 阻塞/唤醒任务并配合 RunQueue（状态切换由 runtime 负责）。
- 增加 SleepQueue 与 `sleep_current_ms`，由 tick 触发唤醒并回收到 RunQueue。
- WaitQueue 通过 TaskWaitQueue + SleepQueue 实现阻塞等待与超时，WaitReason 由任务表记录。
- 记录 trapframe 指针（TrapFrameGuard），为后续抢占式调度做准备。
- 内核栈在早期由帧分配器分配连续页，任务栈来自固定大小的栈池（上限 `MAX_TASKS`）。
- TaskControlBlock 支持入口函数指针与栈顶配置，早期用多 dummy task 验证轮转与睡眠唤醒。
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
```

## 风险与权衡
- WaitQueue 超时依赖 tick 频率，分辨率受限。
- Tick 频率与调度粒度需要平衡延迟与开销。
- RunQueue/WaitQueue 目前无锁，仅用于单核启动阶段。

## 测试点
- tick 计数增长与 `sleep_ms` / `wait_timeout_ms` 行为。
- notify_one/notify_all 的唤醒行为与 WaitReason 返回值。
- scheduler tick hook 的日志输出与周期调度行为。
- 后续 busybox/多任务场景回归。
