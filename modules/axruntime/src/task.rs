#![allow(dead_code)]

use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicU8, Ordering};

use crate::config::MAX_TASKS;
use crate::context::Context;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskState {
    Ready,
    Running,
    Blocked,
}

/// Why a wait queue block finished; stored per task for wait timeout reporting.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitReason {
    None = 0,
    Notified = 1,
    Timeout = 2,
}

pub type TaskEntry = fn() -> !;
pub type TaskId = usize;

pub struct TaskControlBlock {
    pub id: TaskId,
    pub state: TaskState,
    pub context: Context,
    pub entry: Option<TaskEntry>,
    // Pointer to the active trap frame on this task's kernel stack.
    // Valid only during trap handling; cleared on trap exit.
    pub trap_frame: Option<usize>,
    // Tracks why a blocked wait completed; only meaningful for wait queue users.
    wait_reason: AtomicU8,
}

const UNINIT_TASK: MaybeUninit<TaskControlBlock> = MaybeUninit::uninit();
static mut TASK_TABLE: [MaybeUninit<TaskControlBlock>; MAX_TASKS] = [UNINIT_TASK; MAX_TASKS];
static mut TASK_USED: [bool; MAX_TASKS] = [false; MAX_TASKS];

impl TaskControlBlock {
    fn new(id: TaskId) -> Self {
        Self {
            id,
            state: TaskState::Ready,
            context: Context::zero(),
            entry: None,
            trap_frame: None,
            wait_reason: AtomicU8::new(WaitReason::None as u8),
        }
    }

    fn with_entry(id: TaskId, entry: TaskEntry, stack_top: usize) -> Self {
        let mut task = Self::new(id);
        task.entry = Some(entry);
        task.context.ra = entry as usize;
        task.context.sp = stack_top;
        task
    }
}

/// Construct the idle task control block for early boot.
pub const fn idle_task() -> TaskControlBlock {
    TaskControlBlock {
        id: MAX_TASKS,
        state: TaskState::Running,
        context: Context::zero(),
        entry: None,
        trap_frame: None,
        wait_reason: AtomicU8::new(WaitReason::None as u8),
    }
}

pub fn alloc_task(entry: TaskEntry, stack_top: usize) -> Option<TaskId> {
    // SAFETY: single-hart early boot; task table is only mutated in init.
    unsafe {
        for (id, used) in TASK_USED.iter_mut().enumerate() {
            if !*used {
                let task = TaskControlBlock::with_entry(id, entry, stack_top);
                TASK_TABLE[id].write(task);
                *used = true;
                return Some(id);
            }
        }
    }
    None
}

pub fn is_ready(id: TaskId) -> bool {
    // SAFETY: read-only access to task state during early boot.
    unsafe {
        if id >= MAX_TASKS || !TASK_USED[id] {
            return false;
        }
        let task = &*TASK_TABLE[id].as_ptr();
        task.state == TaskState::Ready
    }
}

/// Unconditionally update task state; prefer `transition_state` when validating transitions.
pub fn set_state(id: TaskId, state: TaskState) -> bool {
    // SAFETY: single-hart early boot; task slots are stable.
    unsafe {
        if id >= MAX_TASKS || !TASK_USED[id] {
            return false;
        }
        let task = &mut *TASK_TABLE[id].as_mut_ptr();
        task.state = state;
        true
    }
}

/// Transition task state only if the current state matches `from`.
pub fn transition_state(id: TaskId, from: TaskState, to: TaskState) -> bool {
    // SAFETY: single-hart early boot; task slots are stable.
    unsafe {
        if id >= MAX_TASKS || !TASK_USED[id] {
            return false;
        }
        let task = &mut *TASK_TABLE[id].as_mut_ptr();
        if task.state != from {
            return false;
        }
        task.state = to;
        true
    }
}

/// Store the wait completion reason for a task.
pub fn set_wait_reason(id: TaskId, reason: WaitReason) -> bool {
    // SAFETY: single-hart early boot; task slots are stable.
    unsafe {
        if id >= MAX_TASKS || !TASK_USED[id] {
            return false;
        }
        let task = &mut *TASK_TABLE[id].as_mut_ptr();
        task.wait_reason.store(reason as u8, Ordering::Release);
        true
    }
}

/// Consume the last wait reason and reset it to `WaitReason::None`.
pub fn take_wait_reason(id: TaskId) -> WaitReason {
    // SAFETY: single-hart early boot; task slots are stable.
    unsafe {
        if id >= MAX_TASKS || !TASK_USED[id] {
            return WaitReason::None;
        }
        let task = &mut *TASK_TABLE[id].as_mut_ptr();
        match task.wait_reason.swap(WaitReason::None as u8, Ordering::AcqRel) {
            1 => WaitReason::Notified,
            2 => WaitReason::Timeout,
            _ => WaitReason::None,
        }
    }
}

pub fn set_trap_frame(id: TaskId, trap_frame: usize) -> bool {
    // SAFETY: single-hart early boot; trap frames live on the current stack.
    unsafe {
        if id >= MAX_TASKS || !TASK_USED[id] {
            return false;
        }
        let task = &mut *TASK_TABLE[id].as_mut_ptr();
        task.trap_frame = Some(trap_frame);
        true
    }
}

pub fn clear_trap_frame(id: TaskId) -> bool {
    // SAFETY: single-hart early boot; task slots are stable.
    unsafe {
        if id >= MAX_TASKS || !TASK_USED[id] {
            return false;
        }
        let task = &mut *TASK_TABLE[id].as_mut_ptr();
        task.trap_frame = None;
        true
    }
}

pub fn task_ptr(id: TaskId) -> Option<*mut TaskControlBlock> {
    // SAFETY: task slots are initialized once and never freed in early boot.
    unsafe {
        if id >= MAX_TASKS || !TASK_USED[id] {
            return None;
        }
        Some(TASK_TABLE[id].as_mut_ptr())
    }
}
