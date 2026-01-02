#![allow(dead_code)]
//! Task control blocks, task table helpers, and state transitions.

use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicU8, Ordering};

use crate::config::MAX_TASKS;
use crate::context::Context;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Task run state tracked by the scheduler.
pub enum TaskState {
    Ready,
    Running,
    Blocked,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Why a wait queue block finished; stored per task for wait timeout reporting.
pub enum WaitReason {
    None = 0,
    Notified = 1,
    Timeout = 2,
}

/// Task entry function type.
pub type TaskEntry = fn() -> !;
/// Task identifier used by the scheduler.
pub type TaskId = usize;

/// Core task bookkeeping structure stored in the task table.
pub struct TaskControlBlock {
    /// Task identifier.
    pub id: TaskId,
    /// Current scheduler state.
    pub state: TaskState,
    /// Saved CPU context for switches.
    pub context: Context,
    /// Optional entry function for kernel tasks.
    pub entry: Option<TaskEntry>,
    /// Kernel stack pointer.
    pub kernel_sp: usize,
    /// User page table root.
    pub user_root_pa: usize,
    /// User entry point.
    pub user_entry: usize,
    /// User stack pointer.
    pub user_sp: usize,
    /// User heap top (brk) value.
    pub heap_top: usize,
    /// True if this is a user task.
    pub is_user: bool,
    // Pointer to the active trap frame on this task's kernel stack.
    // Valid only during trap handling; cleared on trap exit.
    /// Active trap frame pointer while handling traps.
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
            kernel_sp: 0,
            user_root_pa: 0,
            user_entry: 0,
            user_sp: 0,
            heap_top: 0,
            is_user: false,
            trap_frame: None,
            wait_reason: AtomicU8::new(WaitReason::None as u8),
        }
    }

    fn with_entry(id: TaskId, entry: TaskEntry, stack_top: usize) -> Self {
        let mut task = Self::new(id);
        task.entry = Some(entry);
        task.context.ra = entry as usize;
        task.context.sp = stack_top;
        task.kernel_sp = stack_top;
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
        kernel_sp: 0,
        user_root_pa: 0,
        user_entry: 0,
        user_sp: 0,
        heap_top: 0,
        is_user: false,
        trap_frame: None,
        wait_reason: AtomicU8::new(WaitReason::None as u8),
    }
}

/// Allocate a new task with the given entry and stack top.
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

/// Record user context metadata for a task.
pub fn set_user_context(id: TaskId, root_pa: usize, entry: usize, user_sp: usize) -> bool {
    // SAFETY: single-hart early boot; task slots are stable.
    unsafe {
        if id >= MAX_TASKS || !TASK_USED[id] {
            return false;
        }
        let task = &mut *TASK_TABLE[id].as_mut_ptr();
        task.user_root_pa = root_pa;
        task.user_entry = entry;
        task.user_sp = user_sp;
        task.is_user = true;
        true
    }
}

/// Update the task's user page table root.
pub fn update_user_root(id: TaskId, root_pa: usize) -> bool {
    // SAFETY: single-hart early boot; task slots are stable.
    unsafe {
        if id >= MAX_TASKS || !TASK_USED[id] {
            return false;
        }
        let task = &mut *TASK_TABLE[id].as_mut_ptr();
        task.user_root_pa = root_pa;
        true
    }
}

/// Fetch the user page table root for a task.
pub fn user_root_pa(id: TaskId) -> Option<usize> {
    // SAFETY: read-only access to task slots during early boot.
    unsafe {
        if id >= MAX_TASKS || !TASK_USED[id] {
            return None;
        }
        let task = &*TASK_TABLE[id].as_ptr();
        Some(task.user_root_pa)
    }
}

/// Fetch the recorded user entry point.
pub fn user_entry(id: TaskId) -> Option<usize> {
    // SAFETY: read-only access to task slots during early boot.
    unsafe {
        if id >= MAX_TASKS || !TASK_USED[id] {
            return None;
        }
        let task = &*TASK_TABLE[id].as_ptr();
        Some(task.user_entry)
    }
}

/// Fetch the recorded user stack pointer.
pub fn user_sp(id: TaskId) -> Option<usize> {
    // SAFETY: read-only access to task slots during early boot.
    unsafe {
        if id >= MAX_TASKS || !TASK_USED[id] {
            return None;
        }
        let task = &*TASK_TABLE[id].as_ptr();
        Some(task.user_sp)
    }
}

/// Update the recorded user stack pointer.
pub fn set_user_sp(id: TaskId, user_sp: usize) -> bool {
    // SAFETY: single-hart early boot; task slots are stable.
    unsafe {
        if id >= MAX_TASKS || !TASK_USED[id] {
            return false;
        }
        let task = &mut *TASK_TABLE[id].as_mut_ptr();
        task.user_sp = user_sp;
        true
    }
}

/// Update the recorded heap top (brk) value.
pub fn set_heap_top(id: TaskId, heap_top: usize) -> bool {
    // SAFETY: single-hart early boot; task slots are stable.
    unsafe {
        if id >= MAX_TASKS || !TASK_USED[id] {
            return false;
        }
        let task = &mut *TASK_TABLE[id].as_mut_ptr();
        task.heap_top = heap_top;
        true
    }
}

/// Fetch the recorded heap top (brk) value.
pub fn heap_top(id: TaskId) -> Option<usize> {
    // SAFETY: read-only access to task slots during early boot.
    unsafe {
        if id >= MAX_TASKS || !TASK_USED[id] {
            return None;
        }
        let task = &*TASK_TABLE[id].as_ptr();
        Some(task.heap_top)
    }
}

/// Fetch the kernel stack pointer for a task.
pub fn kernel_sp(id: TaskId) -> Option<usize> {
    // SAFETY: read-only access to task slots during early boot.
    unsafe {
        if id >= MAX_TASKS || !TASK_USED[id] {
            return None;
        }
        let task = &*TASK_TABLE[id].as_ptr();
        Some(task.kernel_sp)
    }
}

/// Update the saved context (ra/sp) for a task.
pub fn set_context(id: TaskId, ra: usize, sp: usize) -> bool {
    // SAFETY: single-hart early boot; task slots are stable.
    unsafe {
        if id >= MAX_TASKS || !TASK_USED[id] {
            return false;
        }
        let task = &mut *TASK_TABLE[id].as_mut_ptr();
        task.context.ra = ra;
        task.context.sp = sp;
        true
    }
}

/// Return true if the task is in the Ready state.
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
/// Unconditionally update task state.
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

/// Record the active trapframe pointer for a task.
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

/// Clear the recorded trapframe pointer.
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

/// Fetch the recorded trapframe pointer.
pub fn trap_frame_ptr(id: TaskId) -> Option<usize> {
    // SAFETY: read-only access to task slots during early boot.
    unsafe {
        if id >= MAX_TASKS || !TASK_USED[id] {
            return None;
        }
        let task = &*TASK_TABLE[id].as_ptr();
        task.trap_frame
    }
}

/// Fetch a mutable pointer to the task control block.
pub fn task_ptr(id: TaskId) -> Option<*mut TaskControlBlock> {
    // SAFETY: task slots are initialized once and never freed in early boot.
    unsafe {
        if id >= MAX_TASKS || !TASK_USED[id] {
            return None;
        }
        Some(TASK_TABLE[id].as_mut_ptr())
    }
}
