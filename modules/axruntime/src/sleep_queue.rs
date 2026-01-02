#![allow(dead_code)]
//! Sleep queue for delayed wakeups.

use core::cell::UnsafeCell;

use crate::task::TaskId;

#[derive(Clone, Copy)]
struct SleepEntry {
    task_id: TaskId,
    wake_tick: u64,
}

/// Fixed-size sleep queue tracking wakeup ticks.
pub struct SleepQueue {
    slots: UnsafeCell<[Option<SleepEntry>; SleepQueue::MAX_SLEEPERS]>,
}

impl SleepQueue {
    /// Maximum number of sleepers tracked in the queue.
    pub const MAX_SLEEPERS: usize = crate::config::MAX_TASKS;

    /// Create an empty sleep queue.
    pub const fn new() -> Self {
        Self {
            slots: UnsafeCell::new([None; SleepQueue::MAX_SLEEPERS]),
        }
    }

    /// Insert or update a sleeping task with its wake tick.
    pub fn push(&self, task_id: TaskId, wake_tick: u64) -> bool {
        // Wake ticks are absolute tick counters (not durations).
        // Safety: single-hart early use; no concurrent access yet.
        let slots = unsafe { &mut *self.slots.get() };
        for slot in slots.iter_mut() {
            if let Some(entry) = slot {
                if entry.task_id == task_id {
                    entry.wake_tick = wake_tick;
                    return true;
                }
            }
        }
        for slot in slots.iter_mut() {
            if slot.is_none() {
                *slot = Some(SleepEntry { task_id, wake_tick });
                return true;
            }
        }
        false
    }

    /// Pop the next task whose wake tick has passed.
    pub fn pop_ready(&self, now: u64) -> Option<TaskId> {
        // Linear scan is fine for early bring-up; no ordering guarantees.
        // Safety: single-hart early use; no concurrent access yet.
        let slots = unsafe { &mut *self.slots.get() };
        for slot in slots.iter_mut() {
            if let Some(entry) = *slot {
                if entry.wake_tick <= now {
                    *slot = None;
                    return Some(entry.task_id);
                }
            }
        }
        None
    }

    /// Remove a specific task from the sleep queue.
    pub fn remove(&self, task_id: TaskId) -> bool {
        // Remove a specific sleeper to avoid stale wakeups.
        // Safety: single-hart early use; no concurrent access yet.
        let slots = unsafe { &mut *self.slots.get() };
        for slot in slots.iter_mut() {
            if slot.map_or(false, |entry| entry.task_id == task_id) {
                *slot = None;
                return true;
            }
        }
        false
    }
}

unsafe impl Sync for SleepQueue {}
