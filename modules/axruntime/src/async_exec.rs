#![allow(dead_code)]
//! Minimal no-alloc async executor for kernel-side futures.

use core::future::Future;
use core::pin::Pin;
use core::ptr;
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

use crate::config;

const MAX_ASYNC_TASKS: usize = config::MAX_ASYNC_TASKS;

type PollFn = fn(*mut (), &mut Context<'_>) -> Poll<()>;

#[derive(Copy, Clone)]
struct TaskSlot {
    poll_fn: Option<PollFn>,
    data: *mut (),
    active: bool,
    queued: bool,
}

impl TaskSlot {
    const fn empty() -> Self {
        Self {
            poll_fn: None,
            data: ptr::null_mut(),
            active: false,
            queued: false,
        }
    }
}

struct ReadyQueue {
    head: usize,
    tail: usize,
    len: usize,
    slots: [usize; MAX_ASYNC_TASKS],
}

impl ReadyQueue {
    const fn new() -> Self {
        Self {
            head: 0,
            tail: 0,
            len: 0,
            slots: [0; MAX_ASYNC_TASKS],
        }
    }
}

static mut TASKS: [TaskSlot; MAX_ASYNC_TASKS] = [TaskSlot::empty(); MAX_ASYNC_TASKS];
static mut READY_QUEUE: ReadyQueue = ReadyQueue::new();

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
/// Spawn errors for the async executor.
pub enum SpawnError {
    Full,
    AlreadyActive,
}

/// Spawn a `'static` future onto the executor.
pub fn spawn<F>(future: &'static mut F) -> Result<usize, SpawnError>
where
    F: Future<Output = ()> + 'static,
{
    with_no_irq(|| unsafe {
        // SAFETY: interrupts are disabled; TASKS/READY_QUEUE are only mutated here.
        for (idx, slot) in TASKS.iter_mut().enumerate() {
            if slot.active {
                continue;
            }
            if slot.poll_fn.is_some() {
                return Err(SpawnError::AlreadyActive);
            }
            slot.poll_fn = Some(poll_future::<F>);
            slot.data = future as *mut F as *mut ();
            slot.active = true;
            slot.queued = true;
            queue_push(idx);
            return Ok(idx);
        }
        Err(SpawnError::Full)
    })
}

/// Poll all ready tasks; returns true when at least one task made progress.
pub fn poll() -> bool {
    let mut did_work = false;
    while let Some(task_id) = queue_pop() {
        did_work = true;
        let (poll_fn, data) = unsafe {
            // SAFETY: task_id came from READY_QUEUE and TASKS is static.
            let slot = &mut TASKS[task_id];
            (slot.poll_fn, slot.data)
        };
        let Some(poll_fn) = poll_fn else {
            continue;
        };
        let waker = unsafe { Waker::from_raw(raw_waker(task_id)) };
        let mut cx = Context::from_waker(&waker);
        if poll_fn(data, &mut cx).is_ready() {
            unsafe {
                let slot = &mut TASKS[task_id];
                slot.poll_fn = None;
                slot.data = ptr::null_mut();
                slot.active = false;
                slot.queued = false;
            }
        }
    }
    did_work
}

/// Create a future that yields once to the executor.
pub fn yield_now() -> YieldNow {
    YieldNow { yielded: false }
}

/// Future that yields control exactly once.
pub struct YieldNow {
    yielded: bool,
}

impl Future for YieldNow {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.yielded {
            Poll::Ready(())
        } else {
            self.yielded = true;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

fn poll_future<F>(data: *mut (), cx: &mut Context<'_>) -> Poll<()>
where
    F: Future<Output = ()>,
{
    // SAFETY: caller provides a stable future pointer for the lifetime of the task.
    let future = unsafe { &mut *(data as *mut F) };
    // SAFETY: the future is pinned for the executor lifetime.
    unsafe { Pin::new_unchecked(future) }.poll(cx)
}

fn queue_push(task_id: usize) {
    unsafe {
        let queue = &mut READY_QUEUE;
        if queue.len == MAX_ASYNC_TASKS {
            return;
        }
        queue.slots[queue.tail] = task_id;
        queue.tail = (queue.tail + 1) % MAX_ASYNC_TASKS;
        queue.len += 1;
    }
}

fn queue_pop() -> Option<usize> {
    with_no_irq(|| unsafe {
        // SAFETY: interrupts are disabled; READY_QUEUE/TASKS are only mutated here.
        let queue = &mut READY_QUEUE;
        if queue.len == 0 {
            return None;
        }
        let task_id = queue.slots[queue.head];
        queue.head = (queue.head + 1) % MAX_ASYNC_TASKS;
        queue.len -= 1;
        if task_id < MAX_ASYNC_TASKS {
            TASKS[task_id].queued = false;
        }
        Some(task_id)
    })
}

fn queue_wake(task_id: usize) {
    with_no_irq(|| unsafe {
        // SAFETY: interrupts are disabled; TASKS/READY_QUEUE are only mutated here.
        if task_id >= MAX_ASYNC_TASKS {
            return;
        }
        let slot = &mut TASKS[task_id];
        if !slot.active || slot.queued {
            return;
        }
        slot.queued = true;
        queue_push(task_id);
    })
}

unsafe fn raw_waker(task_id: usize) -> RawWaker {
    // SAFETY: task_id is encoded as a pointer-sized token for the waker.
    RawWaker::new(task_id as *const (), &RAW_WAKER_VTABLE)
}

unsafe fn waker_clone(data: *const ()) -> RawWaker {
    // SAFETY: the data pointer carries a task id encoded by raw_waker.
    raw_waker(data as usize)
}

unsafe fn waker_wake(data: *const ()) {
    // SAFETY: the data pointer carries a task id encoded by raw_waker.
    queue_wake(data as usize);
}

unsafe fn waker_wake_by_ref(data: *const ()) {
    // SAFETY: the data pointer carries a task id encoded by raw_waker.
    queue_wake(data as usize);
}

unsafe fn waker_drop(_: *const ()) {}

static RAW_WAKER_VTABLE: RawWakerVTable =
    RawWakerVTable::new(waker_clone, waker_wake, waker_wake_by_ref, waker_drop);

fn with_no_irq<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    let sstatus: usize;
    unsafe {
        // SAFETY: read/modify sstatus to mask interrupts in a short critical section.
        core::arch::asm!("csrr {0}, sstatus", out(reg) sstatus);
        core::arch::asm!("csrci sstatus, 0x2");
    }
    let ret = f();
    unsafe {
        // SAFETY: restore previous interrupt state captured above.
        core::arch::asm!("csrw sstatus, {0}", in(reg) sstatus);
    }
    ret
}
