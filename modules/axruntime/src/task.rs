#![allow(dead_code)]

use core::sync::atomic::{AtomicU64, Ordering};

use crate::context::Context;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskState {
    Ready,
    Running,
    Blocked,
}

pub type TaskEntry = fn() -> !;

#[derive(Copy, Clone)]
pub struct TaskControlBlock {
    pub id: u64,
    pub state: TaskState,
    pub context: Context,
    pub entry: Option<TaskEntry>,
}

static NEXT_TASK_ID: AtomicU64 = AtomicU64::new(1);

impl TaskControlBlock {
    pub fn new() -> Self {
        let id = NEXT_TASK_ID.fetch_add(1, Ordering::Relaxed);
        Self {
            id,
            state: TaskState::Ready,
            context: Context::zero(),
            entry: None,
        }
    }

    pub fn with_entry(entry: TaskEntry, stack_top: usize) -> Self {
        let mut task = Self::new();
        task.entry = Some(entry);
        task.context.ra = entry as usize;
        task.context.sp = stack_top;
        task
    }
}
