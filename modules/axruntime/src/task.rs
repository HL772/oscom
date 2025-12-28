#![allow(dead_code)]

use core::mem::MaybeUninit;

use crate::config::MAX_TASKS;
use crate::context::Context;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskState {
    Ready,
    Running,
    Blocked,
}

pub type TaskEntry = fn() -> !;
pub type TaskId = usize;

pub struct TaskControlBlock {
    pub id: TaskId,
    pub state: TaskState,
    pub context: Context,
    pub entry: Option<TaskEntry>,
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

pub fn alloc_task(entry: TaskEntry, stack_top: usize) -> Option<TaskId> {
    // Safety: single-hart early boot; task table is only mutated in init.
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
    // Safety: read-only access to task state during early boot.
    unsafe {
        if id >= MAX_TASKS || !TASK_USED[id] {
            return false;
        }
        let task = &*TASK_TABLE[id].as_ptr();
        task.state == TaskState::Ready
    }
}

pub fn set_state(id: TaskId, state: TaskState) -> bool {
    // Safety: single-hart early boot; task slots are stable.
    unsafe {
        if id >= MAX_TASKS || !TASK_USED[id] {
            return false;
        }
        let task = &mut *TASK_TABLE[id].as_mut_ptr();
        task.state = state;
        true
    }
}

pub fn task_ptr(id: TaskId) -> Option<*mut TaskControlBlock> {
    // Safety: task slots are initialized once and never freed in early boot.
    unsafe {
        if id >= MAX_TASKS || !TASK_USED[id] {
            return None;
        }
        Some(TASK_TABLE[id].as_mut_ptr())
    }
}
