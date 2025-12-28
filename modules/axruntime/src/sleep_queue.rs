#![allow(dead_code)]

use core::cell::UnsafeCell;

use crate::task::TaskId;

#[derive(Clone, Copy)]
struct SleepEntry {
    task_id: TaskId,
    wake_tick: u64,
}

pub struct SleepQueue {
    slots: UnsafeCell<[Option<SleepEntry>; SleepQueue::MAX_SLEEPERS]>,
}

impl SleepQueue {
    pub const MAX_SLEEPERS: usize = crate::config::MAX_TASKS;

    pub const fn new() -> Self {
        Self {
            slots: UnsafeCell::new([None; SleepQueue::MAX_SLEEPERS]),
        }
    }

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
}

unsafe impl Sync for SleepQueue {}
