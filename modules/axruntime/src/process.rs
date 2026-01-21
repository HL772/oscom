#![allow(dead_code)]
//! 最小化的进程表与 wait/exit 辅助逻辑。

use crate::futex;
use crate::mm;
use crate::runtime;
use crate::syscall::Errno;
use crate::task::TaskId;
use crate::task_wait_queue::TaskWaitQueue;

const MAX_PROCS: usize = crate::config::MAX_TASKS;

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum ProcState {
    Empty = 0,
    Running = 1,
    Zombie = 2,
}

static mut PROC_STATE: [ProcState; MAX_PROCS] = [ProcState::Empty; MAX_PROCS];
static mut PROC_PPID: [usize; MAX_PROCS] = [0; MAX_PROCS];
static mut PROC_EXIT: [i32; MAX_PROCS] = [0; MAX_PROCS];
static mut PROC_ROOT: [usize; MAX_PROCS] = [0; MAX_PROCS];
static mut PROC_CLEARTID: [usize; MAX_PROCS] = [0; MAX_PROCS];
// 固定大小等待队列：每个父进程一个，用于 waitpid 阻塞。
static PROC_WAITERS: [TaskWaitQueue; MAX_PROCS] = [
    TaskWaitQueue::new(),
    TaskWaitQueue::new(),
    TaskWaitQueue::new(),
    TaskWaitQueue::new(),
    TaskWaitQueue::new(),
    TaskWaitQueue::new(),
    TaskWaitQueue::new(),
    TaskWaitQueue::new(),
];

/// 为任务初始化进程记录。
pub fn init_process(task_id: TaskId, parent_pid: usize, root_pa: usize) -> usize {
    let pid = task_id + 1;
    let idx = task_id;
    // 安全性：早期单核阶段，进程表写入已串行化。
    unsafe {
        if idx < MAX_PROCS {
            PROC_STATE[idx] = ProcState::Running;
            PROC_PPID[idx] = parent_pid;
            PROC_EXIT[idx] = 0;
            PROC_ROOT[idx] = root_pa;
            PROC_CLEARTID[idx] = 0;
        }
    }
    pid
}

/// 返回当前进程 ID（若存在）。
pub fn current_pid() -> Option<usize> {
    let task_id = runtime::current_task_id()?;
    let idx = task_id;
    // 安全性：早期阶段对进程表为只读访问。
    unsafe {
        if idx >= MAX_PROCS || PROC_STATE[idx] == ProcState::Empty {
            None
        } else {
            Some(task_id + 1)
        }
    }
}

/// 将当前进程标记为退出并记录退出码。
pub fn exit_current(code: i32) -> bool {
    let Some(task_id) = runtime::current_task_id() else {
        return false;
    };
    let idx = task_id;
    // 安全性：早期单核阶段，进程表读取已串行化。
    let parent = unsafe { PROC_PPID.get(idx).copied().unwrap_or(0) };
    // 安全性：早期单核阶段，进程表读取已串行化。
    let (root_pa, clear_tid) = unsafe {
        (
            PROC_ROOT.get(idx).copied().unwrap_or(0),
            PROC_CLEARTID.get(idx).copied().unwrap_or(0),
        )
    };
    if root_pa != 0 && clear_tid != 0 {
        // 清零 child_tid 并唤醒 futex 等待者。
        let _ = mm::UserPtr::new(clear_tid).write(root_pa, 0usize);
        let _ = futex::wake(root_pa, clear_tid, 1, true);
    }
    crate::syscall::release_fd_table(task_id);
    // 安全性：早期单核阶段，进程表写入已串行化。
    unsafe {
        if idx >= MAX_PROCS || PROC_STATE[idx] == ProcState::Empty {
            return false;
        }
        PROC_STATE[idx] = ProcState::Zombie;
        PROC_EXIT[idx] = code;
        PROC_CLEARTID[idx] = 0;
    }
    if parent != 0 {
        let parent_idx = parent.saturating_sub(1);
        if parent_idx < MAX_PROCS {
            let _ = crate::runtime::wake_all(&PROC_WAITERS[parent_idx]);
        }
    }
    true
}

/// 更新当前进程的页表根地址。
pub fn update_current_root(root_pa: usize) -> bool {
    let Some(task_id) = runtime::current_task_id() else {
        return false;
    };
    let idx = task_id;
    // 安全性：早期单核阶段，进程表写入已串行化。
    unsafe {
        if idx >= MAX_PROCS || PROC_STATE[idx] == ProcState::Empty {
            return false;
        }
        PROC_ROOT[idx] = root_pa;
        true
    }
}

/// 记录当前进程的 clear_tid 地址。
pub fn set_current_clear_tid(tidptr: usize) -> bool {
    let Some(task_id) = runtime::current_task_id() else {
        return false;
    };
    let idx = task_id;
    // 安全性：早期单核阶段，进程表写入已串行化。
    unsafe {
        if idx >= MAX_PROCS || PROC_STATE[idx] == ProcState::Empty {
            return false;
        }
        PROC_CLEARTID[idx] = tidptr;
        true
    }
}

/// 记录指定进程的 clear_tid 地址。
pub fn set_clear_tid(pid: usize, tidptr: usize) -> bool {
    let idx = pid.saturating_sub(1);
    // 安全性：早期单核阶段，进程表写入已串行化。
    unsafe {
        if idx >= MAX_PROCS || PROC_STATE[idx] == ProcState::Empty {
            return false;
        }
        PROC_CLEARTID[idx] = tidptr;
        true
    }
}

/// 等待子进程退出并回报其状态。
pub fn waitpid(target: isize, status: usize, options: usize) -> Result<usize, Errno> {
    const WNOHANG: usize = 1;
    const WAITPID_RETRY_MS: u64 = 10;
    let Some(parent_pid) = current_pid() else {
        return Err(Errno::Child);
    };
    let root_pa = mm::current_root_pa();
    if status != 0 && root_pa == 0 {
        return Err(Errno::Fault);
    }
    let parent_idx = parent_pid.saturating_sub(1);
    if parent_idx >= MAX_PROCS {
        return Err(Errno::Child);
    }

    // 循环等待，避免递归阻塞导致栈增长。
    loop {
        let mut found_child = false;
        let mut zombie_pid = 0usize;
        let mut zombie_code = 0i32;

        // 安全性：早期单核阶段，进程表读取已串行化。
        unsafe {
            for idx in 0..MAX_PROCS {
                if PROC_STATE[idx] == ProcState::Empty {
                    continue;
                }
                if PROC_PPID[idx] != parent_pid {
                    continue;
                }
                let pid = idx + 1;
                if target > 0 && pid != target as usize {
                    continue;
                }
                found_child = true;
                if PROC_STATE[idx] == ProcState::Zombie {
                    zombie_pid = pid;
                    zombie_code = PROC_EXIT[idx];
                    let root = PROC_ROOT[idx];
                    PROC_STATE[idx] = ProcState::Empty;
                    PROC_PPID[idx] = 0;
                    PROC_EXIT[idx] = 0;
                    PROC_ROOT[idx] = 0;
                    PROC_CLEARTID[idx] = 0;
                    if root != 0 {
                        crate::mm::release_user_root(root);
                    }
                    break;
                }
            }
        }

        if zombie_pid != 0 {
            if status != 0 {
                let code = ((zombie_code as usize) & 0xff) << 8;
                mm::UserPtr::new(status)
                    .write(root_pa, code)
                    .ok_or(Errno::Fault)?;
            }
            return Ok(zombie_pid);
        }

        if !found_child {
            return Err(Errno::Child);
        }
        if (options & WNOHANG) != 0 || !crate::syscall::can_block_current() {
            return Ok(0);
        }
        // 使用超时重试避免错过 wakeup 导致永久阻塞。
        let _ = crate::runtime::wait_timeout_ms(&PROC_WAITERS[parent_idx], WAITPID_RETRY_MS);
    }
}
