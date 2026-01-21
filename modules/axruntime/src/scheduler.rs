#![allow(dead_code)]
//! 简单的就绪队列与上下文切换辅助。

use core::cell::UnsafeCell;

use crate::context::Context;
use crate::task::{TaskControlBlock, TaskId};

/// 固定容量的就绪任务队列。
pub struct RunQueue {
    slots: UnsafeCell<[Option<TaskId>; RunQueue::MAX_TASKS]>,
    head: UnsafeCell<usize>,
}

impl RunQueue {
    /// 队列可容纳的最大任务数量。
    pub const MAX_TASKS: usize = crate::config::MAX_TASKS;

    /// 创建空队列。
    pub const fn new() -> Self {
        Self {
            slots: UnsafeCell::new([None; RunQueue::MAX_TASKS]),
            head: UnsafeCell::new(0),
        }
    }

    /// 向队列中加入任务。
    pub fn push(&self, task: TaskId) -> bool {
        // 安全性：单核早期使用，尚无并发访问。
        let slots = unsafe { &mut *self.slots.get() };
        for slot in slots.iter_mut() {
            if slot.is_none() {
                *slot = Some(task);
                return true;
            }
        }
        false
    }

    /// 按轮询顺序取出下一个就绪任务。
    pub fn pop_ready(&self) -> Option<TaskId> {
        // 安全性：单核早期使用，尚无并发访问。
        let slots = unsafe { &mut *self.slots.get() };
        // 安全性：队列 head 只在同一单核保护下被修改。
        let head = unsafe { &mut *self.head.get() };
        for _ in 0..Self::MAX_TASKS {
            let idx = *head;
            *head = (*head + 1) % Self::MAX_TASKS;
            if let Some(task_id) = slots[idx].take() {
                if crate::task::is_ready(task_id) {
                    return Some(task_id);
                }
                slots[idx] = Some(task_id);
            }
        }
        None
    }

    /// 将任务追加到队尾。
    pub fn push_back(&self, task: TaskId) {
        let _ = self.push(task);
    }
}

unsafe impl Sync for RunQueue {}

extern "C" {
    fn context_switch(prev: *mut Context, next: *const Context);
}

/// 从 `prev` 切换 CPU 上下文到 `next`。
pub fn switch(prev: &mut TaskControlBlock, next: &TaskControlBlock) {
    if prev.id == next.id {
        return;
    }
    if next.context.sp == 0 {
        // 尚未设置上下文时不切换。
        return;
    }
    // 安全性：context_switch 会保持所有被调用者保存寄存器。
    unsafe {
        context_switch(&mut prev.context as *mut Context, &next.context as *const Context);
    }
}
