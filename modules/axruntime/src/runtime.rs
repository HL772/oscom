#![allow(dead_code)]

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::scheduler::RunQueue;
use crate::sleep_queue::SleepQueue;
use crate::stack;
use crate::task::{self, TaskControlBlock, TaskId, TaskState};
use crate::task_wait_queue::TaskWaitQueue;
use crate::time;

static TICK_COUNT: AtomicU64 = AtomicU64::new(0);
static NEED_RESCHED: AtomicBool = AtomicBool::new(false);
static RUN_QUEUE: RunQueue = RunQueue::new();
static TASK_WAIT_QUEUE: TaskWaitQueue = TaskWaitQueue::new();
static SLEEP_QUEUE: SleepQueue = SleepQueue::new();
// CURRENT_TASK is valid only while executing inside a task context.
static mut CURRENT_TASK: Option<TaskId> = None;
static mut IDLE_TASK: TaskControlBlock = TaskControlBlock {
    id: crate::config::MAX_TASKS,
    state: TaskState::Running,
    context: crate::context::Context::zero(),
    entry: None,
};

fn dummy_task_a() -> ! {
    let mut last_tick = 0;
    loop {
        let ticks = tick_count();
        if ticks != last_tick && ticks % 50 == 0 {
            crate::println!("dummy(A): block at tick={}", ticks);
            block_current(&TASK_WAIT_QUEUE);
            last_tick = ticks;
        }
        crate::cpu::wait_for_interrupt();
    }
}

fn dummy_task_b() -> ! {
    let mut last_tick = 0;
    loop {
        let ticks = tick_count();
        if ticks != last_tick && ticks % 80 == 0 {
            let woke = wake_one(&TASK_WAIT_QUEUE);
            crate::println!("dummy(B): wake_one={} tick={}", woke, ticks);
            yield_now();
            last_tick = ticks;
        }
        crate::cpu::wait_for_interrupt();
    }
}

fn dummy_task_c() -> ! {
    let mut last_tick = 0;
    loop {
        let ticks = tick_count();
        if ticks != last_tick && ticks % 120 == 0 {
            crate::println!("dummy(C): sleep 200ms at tick={}", ticks);
            crate::sleep::sleep_ms(200);
            last_tick = ticks;
        }
        crate::cpu::wait_for_interrupt();
    }
}

pub fn on_tick(ticks: u64) {
    TICK_COUNT.store(ticks, Ordering::Relaxed);
    if ticks % 100 == 0 {
        crate::println!("scheduler: tick={}", ticks);
    }
    let mut woke_any = false;
    while let Some(task_id) = SLEEP_QUEUE.pop_ready(ticks) {
        if !task::set_state(task_id, TaskState::Ready) {
            continue;
        }
        if RUN_QUEUE.push(task_id) {
            woke_any = true;
        } else {
            // Best-effort fallback: re-block and retry next tick.
            let _ = task::set_state(task_id, TaskState::Blocked);
            let _ = SLEEP_QUEUE.push(task_id, ticks.saturating_add(1));
            crate::println!("scheduler: run queue full for task {}", task_id);
        }
    }
    if woke_any {
        NEED_RESCHED.store(true, Ordering::Relaxed);
    }
}

pub fn tick_count() -> u64 {
    TICK_COUNT.load(Ordering::Relaxed)
}

pub fn init() {
    TICK_COUNT.store(0, Ordering::Relaxed);

    if let Some(stack) = stack::init_idle_stack() {
        crate::println!("scheduler: idle stack top={:#x}", stack.top());
    } else {
        crate::println!("scheduler: failed to init idle stack");
    }

    if let Some(stack) = stack::alloc_task_stack() {
        if let Some(task_id) = task::alloc_task(dummy_task_a, stack.top()) {
            let ok = RUN_QUEUE.push(task_id);
            crate::println!("scheduler: dummy A added={} id={}", ok, task_id);
        } else {
            crate::println!("scheduler: dummy A alloc failed");
        }
    } else {
        crate::println!("scheduler: failed to init dummy task stack");
    }

    if let Some(stack) = stack::alloc_task_stack() {
        if let Some(task_id) = task::alloc_task(dummy_task_b, stack.top()) {
            let ok = RUN_QUEUE.push(task_id);
            crate::println!("scheduler: dummy B added={} id={}", ok, task_id);
        } else {
            crate::println!("scheduler: dummy B alloc failed");
        }
    } else {
        crate::println!("scheduler: failed to init dummy task stack B");
    }

    if let Some(stack) = stack::alloc_task_stack() {
        if let Some(task_id) = task::alloc_task(dummy_task_c, stack.top()) {
            let ok = RUN_QUEUE.push(task_id);
            crate::println!("scheduler: dummy C added={} id={}", ok, task_id);
        } else {
            crate::println!("scheduler: dummy C alloc failed");
        }
    } else {
        crate::println!("scheduler: failed to init dummy task stack C");
    }
}

pub fn schedule_once() {
    let next_id = match RUN_QUEUE.pop_ready() {
        Some(task_id) => task_id,
        None => return,
    };
    let task_ptr = match task::task_ptr(next_id) {
        Some(ptr) => ptr,
        None => return,
    };

    // Safety: single-hart early use; only switching between idle and one task.
    unsafe {
        if CURRENT_TASK.is_some() {
            return;
        }
        CURRENT_TASK = Some(next_id);
        if !task::set_state(next_id, TaskState::Running) {
            CURRENT_TASK = None;
            return;
        }
        crate::scheduler::switch(&mut IDLE_TASK, &*task_ptr);
        if CURRENT_TASK == Some(next_id) {
            CURRENT_TASK = None;
        }
    }
}

pub fn maybe_schedule(ticks: u64, interval: u64) {
    if interval == 0 {
        return;
    }
    if ticks % interval == 0 {
        NEED_RESCHED.store(true, Ordering::Relaxed);
    }
}

pub fn yield_if_needed() {
    while NEED_RESCHED.swap(false, Ordering::Relaxed) {
        // 调度在空闲上下文中执行，避免在 trap 中切换上下文。
        schedule_once();
    }
}

pub fn yield_now() {
    // Cooperative yield: requeue the current task and switch back to idle.
    // Safety: single-hart early use; CURRENT_TASK is only accessed in init/idle/task contexts.
    unsafe {
        let Some(task_id) = CURRENT_TASK else {
            return;
        };
        let Some(task_ptr) = task::task_ptr(task_id) else {
            return;
        };
        if !task::set_state(task_id, TaskState::Ready) {
            return;
        }
        if !RUN_QUEUE.push(task_id) {
            let _ = task::set_state(task_id, TaskState::Running);
            return;
        }
        NEED_RESCHED.store(true, Ordering::Relaxed);
        CURRENT_TASK = None;
        crate::scheduler::switch(&mut *task_ptr, &IDLE_TASK);
    }
}

pub fn sleep_current_ms(ms: u64) -> bool {
    // Tick-based sleep: block the current task and let the timer wake it later.
    if ms == 0 {
        return true;
    }
    let tick_hz = time::tick_hz();
    if tick_hz == 0 {
        return false;
    }
    let mut delta = ms.saturating_mul(tick_hz).saturating_add(999) / 1000;
    if delta == 0 {
        delta = 1;
    }
    let wake_tick = time::ticks().saturating_add(delta);

    // Safety: single-hart early use; CURRENT_TASK is only accessed in init/idle/task contexts.
    unsafe {
        let Some(task_id) = CURRENT_TASK else {
            return false;
        };
        let Some(task_ptr) = task::task_ptr(task_id) else {
            return false;
        };
        if !task::set_state(task_id, TaskState::Blocked) {
            return false;
        }
        if !SLEEP_QUEUE.push(task_id, wake_tick) {
            let _ = task::set_state(task_id, TaskState::Running);
            return false;
        }
        NEED_RESCHED.store(true, Ordering::Relaxed);
        CURRENT_TASK = None;
        crate::scheduler::switch(&mut *task_ptr, &IDLE_TASK);
    }
    true
}

pub fn block_current(queue: &TaskWaitQueue) {
    // Block the current task on a wait queue; caller controls the wake-up.
    // Safety: single-hart early use; CURRENT_TASK is only accessed in init/idle/task contexts.
    unsafe {
        let Some(task_id) = CURRENT_TASK else {
            return;
        };
        let Some(task_ptr) = task::task_ptr(task_id) else {
            return;
        };
        if !task::set_state(task_id, TaskState::Blocked) {
            return;
        }
        if !queue.push(task_id) {
            let _ = task::set_state(task_id, TaskState::Running);
            return;
        }
        NEED_RESCHED.store(true, Ordering::Relaxed);
        CURRENT_TASK = None;
        crate::scheduler::switch(&mut *task_ptr, &IDLE_TASK);
    }
}

pub fn wake_one(queue: &TaskWaitQueue) -> bool {
    // Wake a single waiter and enqueue it for scheduling.
    if let Some(task_id) = queue.notify_one() {
        if !task::set_state(task_id, TaskState::Ready) {
            return false;
        }
        let ok = RUN_QUEUE.push(task_id);
        if !ok {
            let _ = task::set_state(task_id, TaskState::Blocked);
            let retry = queue.push(task_id);
            if !retry {
                crate::println!("scheduler: wait queue full for task {}", task_id);
            }
            crate::println!("scheduler: run queue full for task {}", task_id);
        }
        return ok;
    }
    false
}

pub fn idle_loop() -> ! {
    loop {
        yield_if_needed();
        crate::cpu::wait_for_interrupt();
    }
}
