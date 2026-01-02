#![allow(dead_code)]
//! Runtime configuration constants for the kernel.

/// Default timer tick frequency used by the scheduler.
pub const DEFAULT_TICK_HZ: u64 = 10;
/// Scheduler tick interval (in ticks) before triggering a reschedule.
pub const SCHED_INTERVAL_TICKS: u64 = 100;
/// Maximum number of runnable tasks tracked by the scheduler.
pub const MAX_TASKS: usize = 8;
/// Maximum number of async executor tasks.
pub const MAX_ASYNC_TASKS: usize = 16;
/// 通过 `--features user-test` 启用最小用户态 ecall 验证路径。
pub const ENABLE_USER_TEST: bool = cfg!(feature = "user-test");
/// 通过 `--features sched-demo` 启用调度 demo 任务与日志。
pub const ENABLE_SCHED_DEMO: bool = cfg!(feature = "sched-demo");
/// 通过 `--features ext4-write-test` 启用 ext4 写路径冒烟自测。
pub const ENABLE_EXT4_WRITE_TEST: bool = cfg!(feature = "ext4-write-test");
/// Base virtual address for the built-in user test image.
pub const USER_TEST_BASE: usize = 0x4000_0000;
