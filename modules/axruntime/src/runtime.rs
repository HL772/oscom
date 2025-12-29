#![allow(dead_code)]

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::config;
use crate::scheduler::RunQueue;
use crate::sleep_queue::SleepQueue;
use crate::stack;
use crate::task::{self, TaskControlBlock, TaskId, TaskState, WaitReason};
use crate::task_wait_queue::TaskWaitQueue;
use crate::time;
use crate::wait::WaitResult;
use crate::wait_queue::WaitQueue;

static TICK_COUNT: AtomicU64 = AtomicU64::new(0);
static NEED_RESCHED: AtomicBool = AtomicBool::new(false);
static RUN_QUEUE: RunQueue = RunQueue::new();
static SLEEP_QUEUE: SleepQueue = SleepQueue::new();
static WAIT_QUEUE: WaitQueue = WaitQueue::new();
// CURRENT_TASK is valid only while executing inside a task context.
static mut CURRENT_TASK: Option<TaskId> = None;
static mut IDLE_TASK: TaskControlBlock = task::idle_task();

fn dummy_task_a() -> ! {
    let mut last_tick = 0;
    loop {
        let ticks = tick_count();
        if ticks != last_tick && ticks % 50 == 0 {
            let timeout_ms = if ticks % 200 == 0 { 500 } else { 10_000 };
            crate::println!("dummy(A): wait {}ms at tick={}", timeout_ms, ticks);
            let result = WAIT_QUEUE.wait_timeout_ms(timeout_ms);
            crate::println!("dummy(A): wait result={:?} tick={}", result, tick_count());
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
            let woke = WAIT_QUEUE.notify_one();
            crate::println!("dummy(B): notify_one={} tick={}", woke, ticks);
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
    if config::ENABLE_SCHED_DEMO && ticks % 100 == 0 {
        crate::println!("scheduler: tick={}", ticks);
    }
    // Move expired sleepers back to the run queue.
    let mut woke_any = false;
    while let Some(task_id) = SLEEP_QUEUE.pop_ready(ticks) {
        if !task::transition_state(task_id, TaskState::Blocked, TaskState::Ready) {
            continue;
        }
        if RUN_QUEUE.push(task_id) {
            let _ = task::set_wait_reason(task_id, WaitReason::Timeout);
            woke_any = true;
        } else {
            // Best-effort fallback: re-block and retry next tick.
            let _ = task::transition_state(task_id, TaskState::Ready, TaskState::Blocked);
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

pub fn on_trap_entry(tf: &mut crate::trap::TrapFrame) {
    // SAFETY: single-hart early use; current task does not change inside traps.
    unsafe {
        if let Some(task_id) = CURRENT_TASK {
            let _ = task::set_trap_frame(task_id, tf as *mut _ as usize);
        }
    }
}

pub fn on_trap_exit() {
    // SAFETY: single-hart early use; clear any trap frame pointer on exit.
    unsafe {
        if let Some(task_id) = CURRENT_TASK {
            let _ = task::clear_trap_frame(task_id);
        }
    }
}

pub fn init() {
    TICK_COUNT.store(0, Ordering::Relaxed);

    match stack::init_idle_stack() {
        Some(stack) => {
            if config::ENABLE_SCHED_DEMO {
                crate::println!("scheduler: idle stack top={:#x}", stack.top());
            }
        }
        None => {
            crate::println!("scheduler: failed to init idle stack");
        }
    }

    if !config::ENABLE_SCHED_DEMO {
        return;
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

    // SAFETY: single-hart early use; only switching between idle and one task.
    unsafe {
        if CURRENT_TASK.is_some() {
            return;
        }
        CURRENT_TASK = Some(next_id);
        if !task::transition_state(next_id, TaskState::Ready, TaskState::Running) {
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
    // SAFETY: single-hart early use; CURRENT_TASK is only accessed in init/idle/task contexts.
    unsafe {
        let Some(task_id) = CURRENT_TASK else {
            return;
        };
        let Some(task_ptr) = task::task_ptr(task_id) else {
            return;
        };
        // Mark ready before enqueueing; if the queue is full, keep running.
        if !task::transition_state(task_id, TaskState::Running, TaskState::Ready) {
            return;
        }
        if !RUN_QUEUE.push(task_id) {
            let _ = task::transition_state(task_id, TaskState::Ready, TaskState::Running);
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

    // SAFETY: single-hart early use; CURRENT_TASK is only accessed in init/idle/task contexts.
    unsafe {
        let Some(task_id) = CURRENT_TASK else {
            return false;
        };
        let Some(task_ptr) = task::task_ptr(task_id) else {
            return false;
        };
        // Transition to Blocked before enqueueing into the sleep queue.
        if !task::transition_state(task_id, TaskState::Running, TaskState::Blocked) {
            return false;
        }
        if !SLEEP_QUEUE.push(task_id, wake_tick) {
            let _ = task::transition_state(task_id, TaskState::Blocked, TaskState::Running);
            return false;
        }
        NEED_RESCHED.store(true, Ordering::Relaxed);
        CURRENT_TASK = None;
        crate::scheduler::switch(&mut *task_ptr, &IDLE_TASK);
    }
    true
}

/// Block the current task on a wait queue until notified or the timeout elapses.
pub fn wait_timeout_ms(queue: &TaskWaitQueue, timeout_ms: u64) -> WaitResult {
    let tick_hz = time::tick_hz();
    if tick_hz == 0 {
        return WaitResult::Timeout;
    }
    let mut delta = timeout_ms
        .saturating_mul(tick_hz)
        .saturating_add(999)
        / 1000;
    if delta == 0 {
        delta = 1;
    }
    let wake_tick = time::ticks().saturating_add(delta);

    // SAFETY: single-hart early use; CURRENT_TASK is only accessed in init/idle/task contexts.
    unsafe {
        let Some(task_id) = CURRENT_TASK else {
            return WaitResult::Timeout;
        };
        let Some(task_ptr) = task::task_ptr(task_id) else {
            return WaitResult::Timeout;
        };
        let _ = task::set_wait_reason(task_id, WaitReason::None);
        if !task::transition_state(task_id, TaskState::Running, TaskState::Blocked) {
            return WaitResult::Timeout;
        }
        if !queue.push(task_id) {
            let _ = task::transition_state(task_id, TaskState::Blocked, TaskState::Running);
            return WaitResult::Timeout;
        }
        if !SLEEP_QUEUE.push(task_id, wake_tick) {
            let _ = queue.pop(task_id);
            let _ = task::transition_state(task_id, TaskState::Blocked, TaskState::Running);
            return WaitResult::Timeout;
        }
        NEED_RESCHED.store(true, Ordering::Relaxed);
        CURRENT_TASK = None;
        crate::scheduler::switch(&mut *task_ptr, &IDLE_TASK);
        let _ = SLEEP_QUEUE.remove(task_id);
        // Clear any stale wait-queue entry left by timeout or notify races.
        let _ = queue.pop(task_id);
        match task::take_wait_reason(task_id) {
            WaitReason::Notified => WaitResult::Notified,
            _ => WaitResult::Timeout,
        }
    }
}

pub fn block_current(queue: &TaskWaitQueue) {
    // Block the current task on a wait queue; caller controls the wake-up.
    // SAFETY: single-hart early use; CURRENT_TASK is only accessed in init/idle/task contexts.
    unsafe {
        let Some(task_id) = CURRENT_TASK else {
            return;
        };
        let Some(task_ptr) = task::task_ptr(task_id) else {
            return;
        };
        // Transition to Blocked before enqueueing into the wait queue.
        if !task::transition_state(task_id, TaskState::Running, TaskState::Blocked) {
            return;
        }
        if !queue.push(task_id) {
            let _ = task::transition_state(task_id, TaskState::Blocked, TaskState::Running);
            return;
        }
        NEED_RESCHED.store(true, Ordering::Relaxed);
        CURRENT_TASK = None;
        crate::scheduler::switch(&mut *task_ptr, &IDLE_TASK);
    }
}

pub fn wake_one(queue: &TaskWaitQueue) -> bool {
    // Wake a single blocked waiter and enqueue it for scheduling.
    loop {
        let Some(task_id) = queue.notify_one() else {
            return false;
        };
        if !task::transition_state(task_id, TaskState::Blocked, TaskState::Ready) {
            continue;
        }
        if RUN_QUEUE.push(task_id) {
            let _ = task::set_wait_reason(task_id, WaitReason::Notified);
            return true;
        }
        let _ = task::transition_state(task_id, TaskState::Ready, TaskState::Blocked);
        let retry = queue.push(task_id);
        if !retry {
            crate::println!("scheduler: wait queue full for task {}", task_id);
        }
        crate::println!("scheduler: run queue full for task {}", task_id);
        return false;
    }
}

/// Wake all blocked tasks in the queue until the run queue is full.
pub fn wake_all(queue: &TaskWaitQueue) -> usize {
    let mut woke = 0;
    loop {
        let Some(task_id) = queue.notify_one() else {
            break;
        };
        if !task::transition_state(task_id, TaskState::Blocked, TaskState::Ready) {
            continue;
        }
        if RUN_QUEUE.push(task_id) {
            let _ = task::set_wait_reason(task_id, WaitReason::Notified);
            woke += 1;
            continue;
        }
        let _ = task::transition_state(task_id, TaskState::Ready, TaskState::Blocked);
        let retry = queue.push(task_id);
        if !retry {
            crate::println!("scheduler: wait queue full for task {}", task_id);
        }
        crate::println!("scheduler: run queue full for task {}", task_id);
        break;
    }
    woke
}

pub fn idle_loop() -> ! {
    loop {
        yield_if_needed();
        crate::cpu::wait_for_interrupt();
    }
}
