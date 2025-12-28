#![allow(dead_code)]

use core::cell::UnsafeCell;

use crate::task::{TaskControlBlock, TaskState};

pub struct RunQueue {
    slots: UnsafeCell<[Option<TaskControlBlock>; RunQueue::MAX_TASKS]>,
}

impl RunQueue {
    pub const MAX_TASKS: usize = 8;

    pub const fn new() -> Self {
        Self {
            slots: UnsafeCell::new([None; RunQueue::MAX_TASKS]),
        }
    }

    pub fn push(&self, task: TaskControlBlock) -> bool {
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

    pub fn pop_ready(&self) -> Option<TaskControlBlock> {
        // Safety: single-hart early use; no concurrent access yet.
        let slots = unsafe { &mut *self.slots.get() };
        for slot in slots.iter_mut() {
            if let Some(task) = slot.take() {
                if task.state == TaskState::Ready {
                    return Some(task);
                }
                *slot = Some(task);
            }
        }
        None
    }

    pub fn push_back(&self, task: TaskControlBlock) {
        let _ = self.push(task);
    }
}

unsafe impl Sync for RunQueue {}
