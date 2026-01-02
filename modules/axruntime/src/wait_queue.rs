#![allow(dead_code)]
//! Wait queue facade for runtime blocking operations.

use crate::task_wait_queue::TaskWaitQueue;
use crate::wait::WaitResult;

/// A wait queue that blocks the current task until notified or timed out.
pub struct WaitQueue {
    inner: TaskWaitQueue,
}

impl WaitQueue {
    /// Create an empty wait queue.
    pub const fn new() -> Self {
        Self {
            inner: TaskWaitQueue::new(),
        }
    }

    /// Block the current task on this queue with a millisecond timeout.
    pub fn wait_timeout_ms(&self, timeout_ms: u64) -> WaitResult {
        crate::runtime::wait_timeout_ms(&self.inner, timeout_ms)
    }

    /// Wake a single waiting task, if any.
    pub fn notify_one(&self) -> bool {
        crate::runtime::wake_one(&self.inner)
    }

    /// Wake all waiting tasks until the run queue is full.
    pub fn notify_all(&self) -> usize {
        crate::runtime::wake_all(&self.inner)
    }
}
