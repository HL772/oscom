#![allow(dead_code)]

use core::sync::atomic::{AtomicU64, Ordering};

use crate::scheduler::RunQueue;
use crate::task::{TaskControlBlock, TaskState};

static TICK_COUNT: AtomicU64 = AtomicU64::new(0);
static RUN_QUEUE: RunQueue = RunQueue::new();

pub fn on_tick() {
    let ticks = TICK_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    if ticks % 100 == 0 {
        crate::println!("scheduler: tick={}", ticks);
    }
}

pub fn init() {
    let idle = TaskControlBlock::new();
    RUN_QUEUE.push(idle);
}

pub fn schedule() {
    if let Some(mut task) = RUN_QUEUE.pop_ready() {
        task.state = TaskState::Running;
        RUN_QUEUE.push_back(task);
    }
}
