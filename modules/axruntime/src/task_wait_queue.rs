#![allow(dead_code)]

use core::cell::UnsafeCell;

use crate::task::{self, TaskId, TaskState};

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
        if !task::set_state(task_id, TaskState::Blocked) {
            return false;
        }
        // Safety: single-hart early use; no concurrent access yet.
        let slots = unsafe { &mut *self.slots.get() };
        for slot in slots.iter_mut() {
            if slot.is_none() {
                *slot = Some(task_id);
                return true;
            }
        }
        let _ = task::set_state(task_id, TaskState::Ready);
        false
    }

    pub fn pop(&self, task_id: TaskId) -> bool {
        // Safety: single-hart early use; no concurrent access yet.
        let slots = unsafe { &mut *self.slots.get() };
        for slot in slots.iter_mut() {
            if slot.map_or(false, |id| id == task_id) {
                *slot = None;
                let _ = task::set_state(task_id, TaskState::Ready);
                return true;
            }
        }
        false
    }

    pub fn notify_one(&self) -> Option<TaskId> {
        // Safety: single-hart early use; no concurrent access yet.
        let slots = unsafe { &mut *self.slots.get() };
        for slot in slots.iter_mut() {
            if let Some(task_id) = slot.take() {
                let _ = task::set_state(task_id, TaskState::Ready);
                return Some(task_id);
            }
        }
        None
    }
}

unsafe impl Sync for TaskWaitQueue {}
