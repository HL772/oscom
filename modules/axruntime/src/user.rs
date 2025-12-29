#![allow(dead_code)]

use core::cmp::min;
use core::ptr;

use crate::{config, mm};

pub struct UserContext {
    pub entry: usize,
    pub user_sp: usize,
    pub satp: usize,
}

const PAGE_SIZE: usize = 4096;
const USER_STACK_PAGES: usize = 1;
const USER_STACK_SIZE: usize = USER_STACK_PAGES * PAGE_SIZE;

const USER_CODE_VA: usize = config::USER_TEST_BASE;
const USER_DATA_VA: usize = config::USER_TEST_BASE + PAGE_SIZE;
const USER_STACK_VA: usize = config::USER_TEST_BASE + PAGE_SIZE * 2;
const USER_IOVEC_VA: usize = USER_DATA_VA;
const USER_PIPEFD_VA: usize = USER_DATA_VA + 0x40;
const USER_POLLFD_VA: usize = USER_DATA_VA + 0x50;

const USER_MESSAGE_LEN: usize = 12;
const USER_MESSAGE: &[u8; USER_MESSAGE_LEN] = b"user: hello\n";
const USER_MESSAGE_VA: usize = USER_DATA_VA + PAGE_SIZE - 4;
const USER_MESSAGE_OFFSET: usize = USER_MESSAGE_VA - USER_DATA_VA;
const USER_MESSAGE_SPLIT: usize = PAGE_SIZE - USER_MESSAGE_OFFSET;
const USER_IOV_COUNT: usize = 2;
const USER_POLLIN: i16 = 0x001;

#[repr(C)]
#[derive(Clone, Copy)]
struct UserPollFd {
    fd: i32,
    events: i16,
    revents: i16,
}

// 最小用户态程序：
//   poll(NULL, 0, 1) -> 走一次 poll 休眠路径（1ms 超时）
//   pipe2 + write -> 写入管道
//   poll(pipefd[0], 1, 0) -> 覆盖 pipe 可读就绪路径
//   writev(1, USER_IOVEC_VA, 2) -> 控制台输出（跨页验证 UserSlice）
//   exit(0) -> 关机
const USER_CODE: [u8; 140] = [
    0x13, 0x05, 0x00, 0x00, // addi a0, zero, 0
    0x93, 0x05, 0x00, 0x00, // addi a1, zero, 0
    0x13, 0x06, 0x10, 0x00, // addi a2, zero, 1
    0x93, 0x08, 0x70, 0x00, // addi a7, zero, 7
    0x73, 0x00, 0x00, 0x00, // ecall
    0xb7, 0x16, 0x00, 0x40, // lui a3, 0x40001 (USER_PIPEFD_VA)
    0x93, 0x86, 0x06, 0x04, // addi a3, a3, 0x40
    0x13, 0x85, 0x06, 0x00, // addi a0, a3, 0
    0x93, 0x05, 0x00, 0x00, // addi a1, zero, 0
    0x93, 0x08, 0xb0, 0x03, // addi a7, zero, 59
    0x73, 0x00, 0x00, 0x00, // ecall
    0x03, 0xa5, 0x46, 0x00, // lw a0, 4(a3)
    0xb7, 0x25, 0x00, 0x40, // lui a1, 0x40002 (USER_MESSAGE_VA)
    0x93, 0x85, 0xc5, 0xff, // addi a1, a1, -4
    0x13, 0x06, 0x10, 0x00, // addi a2, zero, 1
    0x93, 0x08, 0x00, 0x04, // addi a7, zero, 64
    0x73, 0x00, 0x00, 0x00, // ecall
    0x83, 0xa7, 0x06, 0x00, // lw a5, 0(a3)
    0x37, 0x17, 0x00, 0x40, // lui a4, 0x40001 (USER_POLLFD_VA)
    0x13, 0x07, 0x07, 0x05, // addi a4, a4, 0x50
    0x23, 0x20, 0xf7, 0x00, // sw a5, 0(a4)
    0x13, 0x05, 0x07, 0x00, // addi a0, a4, 0
    0x93, 0x05, 0x10, 0x00, // addi a1, zero, 1
    0x13, 0x06, 0x00, 0x00, // addi a2, zero, 0
    0x93, 0x08, 0x70, 0x00, // addi a7, zero, 7
    0x73, 0x00, 0x00, 0x00, // ecall
    0x13, 0x05, 0x10, 0x00, // addi a0, zero, 1
    0xb7, 0x15, 0x00, 0x40, // lui a1, 0x40001 (USER_IOVEC_VA)
    0x13, 0x06, 0x20, 0x00, // addi a2, zero, 2
    0x93, 0x08, 0x20, 0x04, // addi a7, zero, 66
    0x73, 0x00, 0x00, 0x00, // ecall
    0x93, 0x08, 0xd0, 0x05, // addi a7, zero, 93
    0x13, 0x05, 0x00, 0x00, // addi a0, zero, 0
    0x73, 0x00, 0x00, 0x00, // ecall
    0x6f, 0x00, 0x00, 0x00, // j .
];

pub fn prepare_user_test() -> Option<UserContext> {
    let root_pa = mm::kernel_root_pa();
    if root_pa == 0 {
        return None;
    }

    let code_frame = mm::alloc_frame()?;
    let data_frame = mm::alloc_frame()?;
    let stack_frame = mm::alloc_frame()?;
    let code_pa = code_frame.addr().as_usize();
    let data_pa = data_frame.addr().as_usize();
    let stack_pa = stack_frame.addr().as_usize();

    // SAFETY: frames are identity-mapped; code/data fit in a single page each.
    unsafe {
        ptr::copy_nonoverlapping(USER_CODE.as_ptr(), code_pa as *mut u8, USER_CODE.len());
        ptr::write_bytes(stack_pa as *mut u8, 0, USER_STACK_SIZE);
        // 将消息拆分写入 data+stack 跨页区域，验证用户态跨页访问。
        let first_len = min(USER_MESSAGE_LEN, USER_MESSAGE_SPLIT);
        ptr::copy_nonoverlapping(
            USER_MESSAGE.as_ptr(),
            (data_pa + USER_MESSAGE_OFFSET) as *mut u8,
            first_len,
        );
        if first_len < USER_MESSAGE_LEN {
            let rest = USER_MESSAGE_LEN - first_len;
            ptr::copy_nonoverlapping(
                USER_MESSAGE.as_ptr().add(first_len),
                stack_pa as *mut u8,
                rest,
            );
        }
        // 布局 iovec 数组：第一个条目跨页读取，第二个条目为 0 长度占位。
        let iov_base = data_pa as *mut usize;
        iov_base.write(USER_MESSAGE_VA);
        iov_base.add(1).write(USER_MESSAGE_LEN);
        iov_base.add(2).write(USER_DATA_VA);
        iov_base.add(3).write(0);
        // 预留 pipefd 与 pollfd 空间，pollfd 事件初始化为 POLLIN。
        let pipefd_base = (data_pa + (USER_PIPEFD_VA - USER_DATA_VA)) as *mut i32;
        pipefd_base.write(0);
        pipefd_base.add(1).write(0);
        let pollfd_base = (data_pa + (USER_POLLFD_VA - USER_DATA_VA)) as *mut UserPollFd;
        pollfd_base.write(UserPollFd {
            fd: -1,
            events: USER_POLLIN,
            revents: 0,
        });
    }
    mm::flush_icache();

    if !mm::map_user_code(root_pa, USER_CODE_VA, code_pa) {
        return None;
    }
    if !mm::map_user_data(root_pa, USER_DATA_VA, data_pa) {
        return None;
    }
    if !mm::map_user_stack(root_pa, USER_STACK_VA, stack_pa) {
        return None;
    }
    mm::flush_tlb();

    Some(UserContext {
        entry: USER_CODE_VA,
        user_sp: USER_STACK_VA + USER_STACK_SIZE,
        satp: mm::satp_for_root(root_pa),
    })
}
