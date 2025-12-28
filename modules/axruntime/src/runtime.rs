#![allow(dead_code)]

use core::sync::atomic::{AtomicU64, Ordering};

use crate::scheduler::RunQueue;
use crate::stack;
use crate::task::{TaskControlBlock, TaskState};

static TICK_COUNT: AtomicU64 = AtomicU64::new(0);
static RUN_QUEUE: RunQueue = RunQueue::new();
static mut IDLE_TASK: TaskControlBlock = TaskControlBlock {
    id: 0,
    state: TaskState::Running,
    context: crate::context::Context::zero(),
    entry: None,
};

fn dummy_task() -> ! {
    loop {
        crate::cpu::wait_for_interrupt();
    }
}

pub fn on_tick(ticks: u64) {
    TICK_COUNT.store(ticks, Ordering::Relaxed);
    if ticks % 100 == 0 {
        crate::println!("scheduler: tick={}", ticks);
    }
}

pub fn tick_count() -> u64 {
    TICK_COUNT.load(Ordering::Relaxed)
}

pub fn init() {
    let idle = TaskControlBlock::new();
    RUN_QUEUE.push(idle);
    TICK_COUNT.store(0, Ordering::Relaxed);

    if let Some(stack) = stack::init_idle_stack() {
        crate::println!("scheduler: idle stack top={:#x}", stack.top());
    } else {
        crate::println!("scheduler: failed to init idle stack");
    }

    if let Some(stack) = stack::init_task_stack() {
        let task = TaskControlBlock::with_entry(dummy_task, stack.top());
        let ok = RUN_QUEUE.push(task);
        crate::println!("scheduler: dummy task added={}", ok);
    } else {
        crate::println!("scheduler: failed to init dummy task stack");
    }
}

pub fn schedule() {
    if let Some(mut task) = RUN_QUEUE.pop_ready() {
        task.state = TaskState::Running;
        RUN_QUEUE.push_back(task);
    }
}

pub fn schedule_once() {
    let mut next = match RUN_QUEUE.pop_ready() {
        Some(task) => task,
        None => return,
    };

    // Safety: single-hart early use; only switching between idle and next.
    unsafe {
        let prev = &mut IDLE_TASK;
        next.state = TaskState::Running;
        crate::scheduler::switch(prev, &next);
        next.state = TaskState::Ready;
    }

    RUN_QUEUE.push_back(next);
}
