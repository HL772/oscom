#![allow(dead_code)]
//! 最小化的 futex 等待/唤醒实现。

use crate::mm::{self, UserAccess};
use crate::runtime;
use crate::task_wait_queue::TaskWaitQueue;

const MAX_FUTEXES: usize = crate::config::MAX_TASKS;

#[derive(Clone, Copy, PartialEq, Eq)]
struct FutexKey {
    root_pa: usize,
    uaddr: usize,
}

const EMPTY_KEY: FutexKey = FutexKey {
    root_pa: 0,
    uaddr: 0,
};

// root_pa=0 表示共享 futex（使用物理地址作为 key）；私有 futex 使用当前页表与虚拟地址作为 key。
static mut FUTEX_KEYS: [FutexKey; MAX_FUTEXES] = [EMPTY_KEY; MAX_FUTEXES];
// 与 MAX_TASKS 保持一致，方便在早期固定容量下复用等待队列。
static FUTEX_WAITERS: [TaskWaitQueue; MAX_FUTEXES] = [
    TaskWaitQueue::new(),
    TaskWaitQueue::new(),
    TaskWaitQueue::new(),
    TaskWaitQueue::new(),
    TaskWaitQueue::new(),
    TaskWaitQueue::new(),
    TaskWaitQueue::new(),
    TaskWaitQueue::new(),
];

#[derive(Clone, Copy, Debug)]
/// wait/wake 返回的 futex 错误码。
pub enum FutexError {
    Fault,
    Again,
    Inval,
    NoMem,
    TimedOut,
}

fn validate_uaddr(uaddr: usize) -> Result<(), FutexError> {
    if uaddr == 0 {
        return Err(FutexError::Fault);
    }
    if (uaddr & 0x3) != 0 {
        return Err(FutexError::Inval);
    }
    Ok(())
}

fn make_key(root_pa: usize, addr: usize, private: bool) -> FutexKey {
    FutexKey {
        root_pa: if private { root_pa } else { 0 },
        uaddr: addr,
    }
}

fn slot_for_wait(key: FutexKey) -> Result<usize, FutexError> {
    // 安全性：早期单核阶段，futex 表写入已串行化。
    unsafe {
        for (idx, &exist) in FUTEX_KEYS.iter().enumerate() {
            if exist == key {
                return Ok(idx);
            }
        }
        for (idx, exist) in FUTEX_KEYS.iter_mut().enumerate() {
            if exist.uaddr == 0 {
                *exist = key;
                return Ok(idx);
            }
        }
    }
    Err(FutexError::NoMem)
}

fn slot_for_wake(key: FutexKey) -> Option<usize> {
    // 安全性：早期单核阶段，futex 表读取已串行化。
    unsafe {
        for (idx, &exist) in FUTEX_KEYS.iter().enumerate() {
            if exist == key {
                return Some(idx);
            }
        }
    }
    None
}

fn clear_slot_if_empty(slot: usize) {
    if !FUTEX_WAITERS[slot].is_empty() {
        return;
    }
    // 安全性：早期单核阶段，futex 表写入已串行化。
    unsafe {
        FUTEX_KEYS[slot] = EMPTY_KEY;
    }
}

/// 等待 futex 字值变化或超时。
pub fn wait(
    root_pa: usize,
    uaddr: usize,
    expected: u32,
    timeout_ms: Option<u64>,
    private: bool,
) -> Result<(), FutexError> {
    validate_uaddr(uaddr)?;
    let pa = mm::translate_user_ptr(root_pa, uaddr, 4, UserAccess::Read).ok_or(FutexError::Fault)?;
    // 安全性：已校验的用户指针，且 4 字节对齐。
    let value = unsafe { *(pa as *const u32) };
    if value != expected {
        return Err(FutexError::Again);
    }
    if runtime::current_task_id().is_none() {
        return Err(FutexError::Again);
    }
    let key_addr = if private { uaddr } else { pa };
    let key = make_key(root_pa, key_addr, private);
    let slot = slot_for_wait(key)?;
    match timeout_ms {
        Some(0) => Err(FutexError::TimedOut),
        Some(ms) => match runtime::wait_timeout_ms(&FUTEX_WAITERS[slot], ms) {
            crate::wait::WaitResult::Notified => {
                clear_slot_if_empty(slot);
                Ok(())
            }
            crate::wait::WaitResult::Timeout => {
                clear_slot_if_empty(slot);
                Err(FutexError::TimedOut)
            }
        },
        None => {
            runtime::block_current(&FUTEX_WAITERS[slot]);
            clear_slot_if_empty(slot);
            Ok(())
        }
    }
}

/// 唤醒 futex 上最多 `count` 个等待者。
pub fn wake(root_pa: usize, uaddr: usize, count: usize, private: bool) -> Result<usize, FutexError> {
    validate_uaddr(uaddr)?;
    if count == 0 {
        return Ok(0);
    }
    let pa = mm::translate_user_ptr(root_pa, uaddr, 4, UserAccess::Read).ok_or(FutexError::Fault)?;
    let key_addr = if private { uaddr } else { pa };
    let key = make_key(root_pa, key_addr, private);
    let Some(slot) = slot_for_wake(key) else {
        return Ok(0);
    };
    let woke = if count >= crate::config::MAX_TASKS {
        runtime::wake_all(&FUTEX_WAITERS[slot])
    } else {
        let mut woke = 0usize;
        for _ in 0..count {
            if runtime::wake_one(&FUTEX_WAITERS[slot]) {
                woke += 1;
            } else {
                break;
            }
        }
        woke
    };
    clear_slot_if_empty(slot);
    Ok(woke)
}
