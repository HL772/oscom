#![allow(dead_code)]
//! Simple run queue and context switch helpers.

use core::cell::UnsafeCell;

use crate::context::Context;
use crate::task::{TaskControlBlock, TaskId};

/// Fixed-size run queue for ready tasks.
pub struct RunQueue {
    slots: UnsafeCell<[Option<TaskId>; RunQueue::MAX_TASKS]>,
    head: UnsafeCell<usize>,
}

impl RunQueue {
    /// Maximum number of tasks tracked by the run queue.
    pub const MAX_TASKS: usize = crate::config::MAX_TASKS;

    /// Create an empty run queue.
    pub const fn new() -> Self {
        Self {
            slots: UnsafeCell::new([None; RunQueue::MAX_TASKS]),
            head: UnsafeCell::new(0),
        }
    }

    /// Push a task onto the run queue.
    pub fn push(&self, task: TaskId) -> bool {
        // Safety: single-hart early use; no concurrent access yet.
        let slots = unsafe { &mut *self.slots.get() };
        for slot in slots.iter_mut() {
            if slot.is_none() {
                *slot = Some(task);
                return true;
            }
        }
        false
    }

    /// Pop the next ready task in round-robin order.
    pub fn pop_ready(&self) -> Option<TaskId> {
        // Safety: single-hart early use; no concurrent access yet.
        let slots = unsafe { &mut *self.slots.get() };
        let head = unsafe { &mut *self.head.get() };
        for _ in 0..Self::MAX_TASKS {
            let idx = *head;
            *head = (*head + 1) % Self::MAX_TASKS;
            if let Some(task_id) = slots[idx].take() {
                if crate::task::is_ready(task_id) {
                    return Some(task_id);
                }
                slots[idx] = Some(task_id);
            }
        }
        None
    }

    /// Push a task onto the tail of the queue.
    pub fn push_back(&self, task: TaskId) {
        let _ = self.push(task);
    }
}

unsafe impl Sync for RunQueue {}

extern "C" {
    fn context_switch(prev: *mut Context, next: *const Context);
}

/// Switch CPU context from `prev` to `next`.
pub fn switch(prev: &mut TaskControlBlock, next: &TaskControlBlock) {
    if prev.id == next.id {
        return;
    }
    if next.context.sp == 0 {
        // 尚未设置上下文时不切换。
        return;
    }
    // Safety: context_switch preserves all callee-saved registers.
    unsafe {
        context_switch(&mut prev.context as *mut Context, &next.context as *const Context);
    }
}
