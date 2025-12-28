#![allow(dead_code)]

use core::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskState {
    Ready,
    Running,
    Blocked,
}

#[derive(Copy, Clone)]
pub struct TaskControlBlock {
    pub id: u64,
    pub state: TaskState,
}

static NEXT_TASK_ID: AtomicU64 = AtomicU64::new(1);

impl TaskControlBlock {
    pub fn new() -> Self {
        let id = NEXT_TASK_ID.fetch_add(1, Ordering::Relaxed);
        Self {
            id,
            state: TaskState::Ready,
        }
    }
}
