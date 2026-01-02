# 09_innovations.md

## 目标
- 明确异步内核、eBPF、io_uring-like 与 AIA 的引入动机与收益。
- 给出可落地的阶段性实现路线，避免过度承诺。

## 设计
- **异步内核执行器**：内核服务与驱动 I/O 走 Future/Task，减少阻塞与上下文切换。
- **eBPF 动态观测**：在 syscall、调度、I/O 等关键路径埋点，支持运行时加载程序。
- **io_uring-like 异步接口**：用户态 SQ/CQ 环形队列，减少系统调用开销。
- **RISC-V AIA 用户态中断**：具备硬件支持时直达用户态，缺失时软件模拟。
- 取舍原则：先保证 OSComp 兼容性与可复现交付，再逐步引入创新特性。

## 实现状态
- 已实现最小异步执行器（no-alloc）：
  - `modules/axruntime/src/async_exec.rs` 提供静态任务槽 + 就绪队列 + RawWaker。
  - `idle_loop` 中周期性调用 `async_exec::poll()` 驱动任务推进。
  - 任务通过 `async_exec::spawn(&'static mut Future)` 注册，`yield_now()` 提供协作式让渡。
- 当前限制：
  - 任务槽为固定容量（`MAX_ASYNC_TASKS`），任务需为 `'static`。
  - 暂无取消与任务回收策略，适合内核侧长生命周期任务。
  - 尚未与块设备/网络驱动 I/O 完整联动，后续逐步替换阻塞等待路径。

## 关键数据结构
- `TaskSlot`/`ReadyQueue`/`RawWaker`：静态任务槽、就绪队列与唤醒机制。
- `BpfVm`/`BpfMap`/`Verifier`：eBPF 执行器、映射与验证器。
- `IoUringSq`/`IoUringCq`/`Sqe`/`Cqe`：异步提交与完成队列。
- `AiaCtl`：AIA/IMSIC 配置与用户态中断投递结构。

## 关键流程图或伪代码
```text
user submits SQE
  -> kernel polls SQ
  -> driver issues async I/O and returns Pending
  -> IRQ fires -> waker schedules task
  -> task completes -> CQE pushed
  -> user consumes CQE
```

## 风险与权衡
- 异步与传统同步路径并存，调试成本增加。
- eBPF 验证器与安全边界需要严格实现。
- io_uring 需要共享内存与队列一致性，易出现竞态。
- AIA 硬件支持不一致，需保持可回退路径。

## 测试点
- 最小 async 任务可被 `idle_loop` 驱动完成（spawn + yield_now）。
- 与同步 I/O 的吞吐与延迟对比（iperf/gcc/rustc）。
- eBPF 程序加载与探针执行的正确性与开销。
- io_uring-like 接口的完成率、队列一致性测试。
- AIA 启用/关闭路径在 QEMU 与实板上的回归。
