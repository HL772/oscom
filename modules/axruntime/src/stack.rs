#![allow(dead_code)]
//! Kernel stack allocation helpers.

use core::mem::MaybeUninit;

use crate::mm::{self, alloc_contiguous_frames};

const STACK_PAGES: usize = 4;
const PAGE_SIZE: usize = 4096;

#[repr(C)]
/// Kernel stack with a guard page below the usable range.
pub struct KernelStack {
    base: usize,
    size: usize,
}

impl KernelStack {
    /// Allocate a new kernel stack with a guard page.
    pub fn new() -> Option<Self> {
        let alloc_pages = STACK_PAGES + 1;
        let start = alloc_contiguous_frames(alloc_pages)?;
        let start_pa = start.addr().as_usize();
        // Guard page sits below the usable stack range.
        let base = start_pa + PAGE_SIZE;
        let size = STACK_PAGES * PAGE_SIZE;
        // Keep guard page zeroed to detect unexpected writes in debug dumps.
        unsafe {
            core::ptr::write_bytes(start_pa as *mut u8, 0, mm::PAGE_SIZE);
        }
        Some(Self { base, size })
    }

    /// Return the top (stack pointer) address.
    pub fn top(&self) -> usize {
        self.base + self.size
    }
}

static mut IDLE_STACK: MaybeUninit<KernelStack> = MaybeUninit::uninit();
const TASK_STACK_SLOTS: usize = crate::config::MAX_TASKS;
const UNINIT_STACK: MaybeUninit<KernelStack> = MaybeUninit::uninit();
static mut TASK_STACKS: [MaybeUninit<KernelStack>; TASK_STACK_SLOTS] =
    [UNINIT_STACK; TASK_STACK_SLOTS];
static mut TASK_STACKS_USED: usize = 0;

/// Initialize the dedicated idle stack.
pub fn init_idle_stack() -> Option<&'static KernelStack> {
    // Safety: single init during early boot.
    unsafe {
        let stack = KernelStack::new()?;
        IDLE_STACK.write(stack);
        Some(IDLE_STACK.assume_init_ref())
    }
}

/// Allocate a kernel stack for a new task.
pub fn alloc_task_stack() -> Option<&'static KernelStack> {
    // Safety: single-hart early boot; pool index advances monotonically.
    unsafe {
        if TASK_STACKS_USED >= TASK_STACK_SLOTS {
            return None;
        }
        let stack = KernelStack::new()?;
        let idx = TASK_STACKS_USED;
        TASK_STACKS_USED += 1;
        TASK_STACKS[idx].write(stack);
        Some(TASK_STACKS[idx].assume_init_ref())
    }
}
