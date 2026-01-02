#![allow(dead_code)]

use core::arch::asm;
use core::mem::size_of;
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use crate::config;
use crate::mm;
use crate::scheduler::RunQueue;
use crate::sleep_queue::SleepQueue;
use crate::stack;
use crate::task::{self, TaskControlBlock, TaskId, TaskState, WaitReason};
use crate::user::UserContext;
use crate::task_wait_queue::TaskWaitQueue;
use crate::time;
use crate::wait::WaitResult;
use crate::wait_queue::WaitQueue;

static TICK_COUNT: AtomicU64 = AtomicU64::new(0);
static NEED_RESCHED: AtomicBool = AtomicBool::new(false);
static IDLE_STACK_TOP: AtomicUsize = AtomicUsize::new(0);
static RUN_QUEUE: RunQueue = RunQueue::new();
static SLEEP_QUEUE: SleepQueue = SleepQueue::new();
static WAIT_QUEUE: WaitQueue = WaitQueue::new();
static NET_WAITERS: TaskWaitQueue = TaskWaitQueue::new();
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
    const NET_POLL_TICK_INTERVAL: u64 = 2;
    TICK_COUNT.store(ticks, Ordering::Relaxed);
    if ticks % NET_POLL_TICK_INTERVAL == 0 {
        axnet::request_poll();
        if let Some(event) = axnet::poll(time::uptime_ms()) {
            log_net_event(event, "tick");
            let _ = wake_all(net_wait_queue());
        }
    }
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

fn log_net_event(event: axnet::NetEvent, tag: &str) {
    match event {
        axnet::NetEvent::IcmpEchoReply { seq, from } => {
            crate::println!("net: icmp echo reply seq={} from={}", seq, from);
        }
        axnet::NetEvent::ArpReply { from } => {
            crate::println!("net: arp reply from {}", from);
        }
        axnet::NetEvent::ArpProbeSent { target } => {
            crate::println!("net: arp probe sent to {}", target);
        }
        axnet::NetEvent::RxFrameSeen => {
            crate::println!("net: rx frame seen");
        }
        axnet::NetEvent::TcpRecvWindow {
            id,
            port,
            window,
            capacity,
            queued,
        } => {
            crate::println!(
                "tcp: recv_win {} id={} port={} win={} cap={} queued={}",
                tag,
                id,
                port,
                window,
                capacity,
                queued
            );
        }
        axnet::NetEvent::Activity => {}
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
            if tf.user_sp != 0 {
                let _ = task::set_user_sp(task_id, tf.user_sp);
            }
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

pub fn current_task_id() -> Option<TaskId> {
    // SAFETY: single-hart early use; read-only access to CURRENT_TASK.
    unsafe { CURRENT_TASK }
}

pub fn init() {
    TICK_COUNT.store(0, Ordering::Relaxed);

    match stack::init_idle_stack() {
        Some(stack) => {
            IDLE_STACK_TOP.store(stack.top(), Ordering::Release);
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

pub fn spawn_user(ctx: UserContext) -> Option<TaskId> {
    let stack = stack::alloc_task_stack()?;
    let task_id = task::alloc_task(user_task_entry, stack.top())?;
    let ok = task::set_user_context(task_id, ctx.root_pa, ctx.entry, ctx.user_sp);
    if !ok {
        return None;
    }
    let _ = crate::process::init_process(task_id, 0, ctx.root_pa);
    crate::syscall::init_fd_table(task_id);
    let _ = task::set_user_sp(task_id, ctx.user_sp);
    let _ = task::set_heap_top(task_id, ctx.heap_top);
    let _ = RUN_QUEUE.push(task_id);
    NEED_RESCHED.store(true, Ordering::Relaxed);
    Some(task_id)
}

pub fn spawn_forked_user(
    parent_tf: &crate::trap::TrapFrame,
    child_root_pa: usize,
    user_sp: usize,
) -> Option<usize> {
    let stack = stack::alloc_task_stack()?;
    let task_id = task::alloc_task(resume_user_from_trap, stack.top())?;
    let kernel_sp = stack.top();
    let trap_frame_ptr = kernel_sp.saturating_sub(size_of::<crate::trap::TrapFrame>());
    // SAFETY: trapframe lives on the child kernel stack top.
    unsafe {
        let child_tf = &mut *(trap_frame_ptr as *mut crate::trap::TrapFrame);
        ptr::copy_nonoverlapping(parent_tf as *const _, child_tf as *mut _, 1);
        child_tf.a0 = 0;
        child_tf.sepc = parent_tf.sepc.wrapping_add(4);
        child_tf.user_sp = user_sp;
    }
    // Ensure the first resume uses the saved trap frame without clobbering it.
    let _ = task::set_context(task_id, resume_user_from_trap as usize, trap_frame_ptr);
    let _ = task::set_trap_frame(task_id, trap_frame_ptr);
    let _ = task::set_user_context(task_id, child_root_pa, parent_tf.sepc.wrapping_add(4), user_sp);
    let _ = task::set_user_sp(task_id, user_sp);
    let parent_pid = crate::process::current_pid()
        .or_else(|| current_task_id().map(|id| id + 1))
        .unwrap_or(1);
    let pid = crate::process::init_process(task_id, parent_pid, child_root_pa);
    if let Some(parent_task_id) = current_task_id() {
        crate::syscall::clone_fd_table(parent_task_id, task_id);
    } else {
        crate::syscall::init_fd_table(task_id);
    }
    let _ = RUN_QUEUE.push(task_id);
    NEED_RESCHED.store(true, Ordering::Relaxed);
    Some(pid)
}

fn user_task_entry() -> ! {
    let Some(task_id) = current_task_id() else {
        crate::println!("user: no current task");
        crate::sbi::shutdown();
    };
    let entry = task::user_entry(task_id).unwrap_or(0);
    let user_sp = task::user_sp(task_id).unwrap_or(0);
    let root_pa = task::user_root_pa(task_id).unwrap_or(0);
    let kernel_sp = task::kernel_sp(task_id).unwrap_or(0);
    if entry == 0 || user_sp == 0 || root_pa == 0 || kernel_sp == 0 {
        crate::println!("user: missing context");
        crate::sbi::shutdown();
    }
    mm::switch_root(root_pa);
    unsafe {
        crate::trap::enter_user(entry, user_sp, mm::satp_for_root(root_pa));
    }
}

fn resume_user_from_trap() -> ! {
    let Some(task_id) = current_task_id() else {
        crate::println!("user: resume with no task");
        crate::sbi::shutdown();
    };
    let trap_frame = task::trap_frame_ptr(task_id).unwrap_or(0);
    let user_sp = task::user_sp(task_id).unwrap_or(0);
    let root_pa = task::user_root_pa(task_id).unwrap_or(0);
    if trap_frame == 0 || user_sp == 0 || root_pa == 0 {
        crate::println!("user: resume missing context");
        crate::sbi::shutdown();
    }
    mm::switch_root(root_pa);
    crate::trap::return_to_user(trap_frame);
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
    // 切换到目标任务地址空间，保证后续用户态访存/恢复路径一致。
    let next_root = task::user_root_pa(next_id).unwrap_or(0);
    if next_root != 0 {
        mm::switch_root(next_root);
    } else {
        mm::switch_root(mm::kernel_root_pa());
    }

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

pub fn preempt_current() {
    if !NEED_RESCHED.load(Ordering::Relaxed) {
        return;
    }
    // SAFETY: single-hart early use; CURRENT_TASK is only accessed in init/idle/task contexts.
    unsafe {
        let Some(task_id) = CURRENT_TASK else {
            return;
        };
        let Some(task_ptr) = task::task_ptr(task_id) else {
            return;
        };
        if !task::transition_state(task_id, TaskState::Running, TaskState::Ready) {
            return;
        }
        if !RUN_QUEUE.push(task_id) {
            let _ = task::transition_state(task_id, TaskState::Ready, TaskState::Running);
            return;
        }
        CURRENT_TASK = None;
        // 切回空闲上下文，由 idle_loop 统一拉起下一任务。
        crate::scheduler::switch(&mut *task_ptr, &IDLE_TASK);
        let root_pa = task::user_root_pa(task_id).unwrap_or(0);
        let trap_frame = task::trap_frame_ptr(task_id).unwrap_or(0);
        if root_pa != 0 && trap_frame != 0 {
            // 用户任务在 trap 中被抢占：恢复后从保存的 trapframe 返回用户态。
            let _ = task::set_context(task_id, resume_user_from_trap as usize, trap_frame);
        }
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
        let root_pa = task::user_root_pa(task_id).unwrap_or(0);
        let trap_frame = task::trap_frame_ptr(task_id).unwrap_or(0);
        if root_pa != 0 && trap_frame != 0 {
            // 用户任务主动让出 CPU 时，确保后续能从 trapframe 返回用户态。
            let _ = task::set_context(task_id, resume_user_from_trap as usize, trap_frame);
        }
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

pub fn exit_current() -> ! {
    // SAFETY: single-hart early use; CURRENT_TASK is only accessed in init/idle/task contexts.
    unsafe {
        let Some(task_id) = CURRENT_TASK else {
            crate::sbi::shutdown();
        };
        let Some(task_ptr) = task::task_ptr(task_id) else {
            crate::sbi::shutdown();
        };
        let _ = task::transition_state(task_id, TaskState::Running, TaskState::Blocked);
        CURRENT_TASK = None;
        crate::scheduler::switch(&mut *task_ptr, &IDLE_TASK);
    }
    loop {
        crate::cpu::wait_for_interrupt();
    }
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

pub fn net_wait_queue() -> &'static TaskWaitQueue {
    &NET_WAITERS
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
            NEED_RESCHED.store(true, Ordering::Relaxed);
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
            NEED_RESCHED.store(true, Ordering::Relaxed);
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
    const NET_POLL_INTERVAL_MS: u64 = 20;
    let mut last_net_poll_ms = 0u64;
    loop {
        let now_ms = crate::time::uptime_ms();
        if now_ms.wrapping_sub(last_net_poll_ms) >= NET_POLL_INTERVAL_MS {
            axnet::request_poll();
            last_net_poll_ms = now_ms;
        }
        if let Some(event) = axnet::poll(now_ms) {
            log_net_event(event, "idle");
            let _ = wake_all(net_wait_queue());
        }
        crate::async_exec::poll();
        yield_if_needed();
        crate::trap::enable_interrupts();
        crate::cpu::wait_for_interrupt();
    }
}

pub fn enter_idle_loop() -> ! {
    let top = IDLE_STACK_TOP.load(Ordering::Acquire);
    if top == 0 {
        idle_loop();
    }
    unsafe {
        asm!(
            "mv sp, {0}",
            "j {1}",
            in(reg) top,
            sym idle_loop,
            options(noreturn)
        );
    }
}
