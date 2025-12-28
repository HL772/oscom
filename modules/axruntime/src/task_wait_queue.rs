#![allow(dead_code)]

use core::cell::UnsafeCell;

use crate::task::TaskId;

// Pure TaskId queue; task state transitions are owned by the runtime layer.
pub struct TaskWaitQueue {
    slots: UnsafeCell<[Option<TaskId>; TaskWaitQueue::MAX_WAITERS]>,
}

impl TaskWaitQueue {
    pub const MAX_WAITERS: usize = crate::config::MAX_TASKS;

    pub const fn new() -> Self {
        Self {
            slots: UnsafeCell::new([None; TaskWaitQueue::MAX_WAITERS]),
        }
    }

    pub fn push(&self, task_id: TaskId) -> bool {
        // Caller must handle state transitions (e.g. Ready -> Blocked) separately.
        // Safety: single-hart early use; no concurrent access yet.
        let slots = unsafe { &mut *self.slots.get() };
        for slot in slots.iter_mut() {
            if slot.is_none() {
                *slot = Some(task_id);
                return true;
            }
        }
        false
    }

    pub fn pop(&self, task_id: TaskId) -> bool {
        // Removes a specific waiter without touching task state.
        // Safety: single-hart early use; no concurrent access yet.
        let slots = unsafe { &mut *self.slots.get() };
        for slot in slots.iter_mut() {
            if slot.map_or(false, |id| id == task_id) {
                *slot = None;
                return true;
            }
        }
        false
    }

    pub fn notify_one(&self) -> Option<TaskId> {
        // Returns a waiter task id; caller is responsible for waking/enqueueing.
        // Safety: single-hart early use; no concurrent access yet.
        let slots = unsafe { &mut *self.slots.get() };
        for slot in slots.iter_mut() {
            if let Some(task_id) = slot.take() {
                return Some(task_id);
            }
        }
        None
    }
}

unsafe impl Sync for TaskWaitQueue {}
