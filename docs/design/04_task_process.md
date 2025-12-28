# 04_task_process.md

## 目标
- 定义进程/线程模型的总体方向（Process/Task 分离）。
- 预留调度与同步原语接口，早期提供时间与等待队列占位。

## 设计
- Process 作为资源拥有者，Task 作为调度单位，后续支持 clone 语义。
- 调度器采用 tick 驱动的时间片抢占，初期可用简单 RR。
- 早期提供 `sleep_ms`、`Waiter`（超时等待）与 `WaitQueue`（等待队列）辅助，后续替换为阻塞原语。
- 引入最小 `RunQueue` 与 `TaskControlBlock` 作为调度骨架，占位 tick 驱动的轮转逻辑。
- 增加上下文结构与 `context_switch` 汇编入口，当前仅保留接口占位。
- 使用 `need_resched` 标志从 tick 中断发起调度请求，切换在空闲上下文执行。
- 增加 `yield_now` 协作式让渡，使用 CURRENT_TASK 保存运行中任务。
- RunQueue 维护轮转指针，实现最小 RR 顺序。
- 内核栈在早期由帧分配器分配连续页，后续与任务生命周期绑定。
- TaskControlBlock 支持入口函数指针与栈顶配置，早期用双 dummy task 验证轮转。
- 调度触发周期可配置（`SCHED_INTERVAL_TICKS`），避免频繁切换。

## 关键数据结构
- TaskControlBlock / ProcessControlBlock：状态、优先级、时间片等字段预留。
- RunQueue / WaitQueue：就绪队列与等待队列（后续实现）。
- Waiter：最小超时等待封装，基于 tick + wfi。
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
```

## 风险与权衡
- 早期 sleep/timeout 采用忙等，会浪费 CPU。
- Tick 频率与调度粒度需要平衡延迟与开销。
- RunQueue/WaitQueue 目前无锁，仅用于单核启动阶段。

## 测试点
- tick 计数增长与 `sleep_ms` / `wait_timeout_ms` 行为。
- notify_one/notify_all 的唤醒行为。
- scheduler tick hook 的日志输出与周期调度行为。
- 后续 busybox/多任务场景回归。
