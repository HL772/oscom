#![allow(dead_code)]
//! 内核运行时配置常量。

/// 调度器使用的默认定时 tick 频率。
pub const DEFAULT_TICK_HZ: u64 = 10;
/// 触发一次调度前的 tick 间隔（单位：tick）。
pub const SCHED_INTERVAL_TICKS: u64 = 100;
/// 调度器跟踪的可运行任务上限。
pub const MAX_TASKS: usize = 8;
/// 异步执行器任务上限。
pub const MAX_ASYNC_TASKS: usize = 16;
/// 通过 `--features user-test` 启用最小用户态 ecall 验证路径。
pub const ENABLE_USER_TEST: bool = cfg!(feature = "user-test");
/// 通过 `--features user-shell` 启动交互式 shell 作为 /init。
pub const ENABLE_USER_SHELL: bool = cfg!(feature = "user-shell");
/// 通过 `--features sched-demo` 启用调度 demo 任务与日志。
pub const ENABLE_SCHED_DEMO: bool = cfg!(feature = "sched-demo");
/// 通过 `--features ext4-write-test` 启用 ext4 写路径冒烟自测。
pub const ENABLE_EXT4_WRITE_TEST: bool = cfg!(feature = "ext4-write-test");
/// 内置用户态测试镜像的虚拟基址。
pub const USER_TEST_BASE: usize = 0x4000_0000;
