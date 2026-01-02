#![allow(dead_code)]
//! Fixed-size wait queue storing TaskId values.

use core::cell::UnsafeCell;

use crate::task::TaskId;

/// Pure TaskId queue; task state transitions are owned by the runtime layer.
pub struct TaskWaitQueue {
    slots: UnsafeCell<[Option<TaskId>; TaskWaitQueue::MAX_WAITERS]>,
}

impl TaskWaitQueue {
    /// Maximum number of waiters supported by this queue.
    pub const MAX_WAITERS: usize = crate::config::MAX_TASKS;

    /// Create an empty TaskId wait queue.
    pub const fn new() -> Self {
        Self {
            slots: UnsafeCell::new([None; TaskWaitQueue::MAX_WAITERS]),
        }
    }

    /// Enqueue a task ID.
    pub fn push(&self, task_id: TaskId) -> bool {
        // Caller must handle state transitions (e.g. Ready -> Blocked) separately.
        // Safety: single-hart early use; no concurrent access yet.
        let _guard = KernelGuard::new();
        let slots = unsafe { &mut *self.slots.get() };
        for slot in slots.iter_mut() {
            if slot.is_none() {
                *slot = Some(task_id);
                return true;
            }
        }
        false
    }

    /// Remove a specific task ID from the queue.
    pub fn pop(&self, task_id: TaskId) -> bool {
        // Removes a specific waiter without touching task state.
        // Safety: single-hart early use; no concurrent access yet.
        let _guard = KernelGuard::new();
        let slots = unsafe { &mut *self.slots.get() };
        for slot in slots.iter_mut() {
            if slot.map_or(false, |id| id == task_id) {
                *slot = None;
                return true;
            }
        }
        false
    }

    /// Dequeue and return a waiting task ID.
    pub fn notify_one(&self) -> Option<TaskId> {
        // Returns a waiter task id; caller is responsible for waking/enqueueing.
        // Safety: single-hart early use; no concurrent access yet.
        let _guard = KernelGuard::new();
        let slots = unsafe { &mut *self.slots.get() };
        for slot in slots.iter_mut() {
            if let Some(task_id) = slot.take() {
                return Some(task_id);
            }
        }
        None
    }

    /// Return true if the queue holds no waiters.
    pub fn is_empty(&self) -> bool {
        // Safety: single-hart early use; no concurrent access yet.
        let slots = unsafe { &*self.slots.get() };
        slots.iter().all(|slot| slot.is_none())
    }
}

unsafe impl Sync for TaskWaitQueue {}

struct KernelGuard {
    sstatus: usize,
}

impl KernelGuard {
    fn new() -> Self {
        let sstatus: usize;
        // SAFETY: toggling SIE for a short critical section.
        unsafe {
            core::arch::asm!("csrrci {0}, sstatus, 2", out(reg) sstatus);
        }
        Self { sstatus }
    }
}

impl Drop for KernelGuard {
    fn drop(&mut self) {
        if (self.sstatus & 2) != 0 {
            // SAFETY: restore SIE if it was set.
            unsafe {
                core::arch::asm!("csrsi sstatus, 2");
            }
        }
    }
}
