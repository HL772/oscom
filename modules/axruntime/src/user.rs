#![allow(dead_code)]

use core::cmp::min;
use core::mem::size_of;
use core::ptr;

use crate::{config, mm};
use crate::syscall::Errno;

pub struct UserContext {
    pub entry: usize,
    pub user_sp: usize,
    pub root_pa: usize,
    pub satp: usize,
    pub argc: usize,
    pub argv: usize,
    pub envp: usize,
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
const USER_PPOLL_TS_VA: usize = USER_DATA_VA + 0x60;
const USER_PATH_VA: usize = USER_DATA_VA + 0x100;
const USER_ARGV_VA: usize = USER_DATA_VA + 0x120;
const USER_ENVP_VA: usize = USER_DATA_VA + 0x140;
const USER_COW_VA: usize = USER_DATA_VA + 0x180;
const USER_WAIT_STATUS_VA: usize = USER_DATA_VA + 0x190;
const USER_COW_OK_VA: usize = USER_DATA_VA + 0x1a0;
const USER_COW_BAD_VA: usize = USER_DATA_VA + 0x1b0;

const USER_MESSAGE_LEN: usize = 12;
const USER_MESSAGE: &[u8; USER_MESSAGE_LEN] = b"user: hello\n";
const USER_MESSAGE_VA: usize = USER_DATA_VA + PAGE_SIZE - 4;
const USER_MESSAGE_OFFSET: usize = USER_MESSAGE_VA - USER_DATA_VA;
const USER_MESSAGE_SPLIT: usize = PAGE_SIZE - USER_MESSAGE_OFFSET;
const USER_IOV_COUNT: usize = 2;
const USER_POLLIN: i16 = 0x001;
const USER_PATH: &[u8] = b"/init\0";
const USER_ARG0: &[u8] = b"init\0";
const USER_ENV0: &[u8] = b"TERM=vt100\0";
const USER_COW_INIT: u32 = 0x1234_5678;
const USER_COW_OK: &[u8] = b"cow: ok\n";
const USER_COW_BAD: &[u8] = b"cow: bad\n";
const USER_PPOLL_TIMEOUT_NS: i64 = 1_000_000;

const ELF_SEGMENT_OFFSET: usize = 0x1000;
const ELF_SEGMENT_ALIGN: usize = 0x1000;
const ELF_INIT_MSG_OFFSET: usize = 0x200;
const ELF_INIT_MSG: &[u8] = b"init: ok\n";
const ELF_INIT_CODE: [u8; 40] = [
    0x13, 0x05, 0x10, 0x00, 0xb7, 0x05, 0x00, 0x40, 0x93, 0x85, 0x05, 0x20, 0x13, 0x06,
    0x90, 0x00, 0x93, 0x08, 0x00, 0x04, 0x73, 0x00, 0x00, 0x00, 0x93, 0x08, 0xd0, 0x05,
    0x13, 0x05, 0x00, 0x00, 0x73, 0x00, 0x00, 0x00, 0x6f, 0x00, 0x00, 0x00,
];

const ELF_IMAGE_MAX: usize = 0x2000;
static mut INIT_ELF_IMAGE: [u8; ELF_IMAGE_MAX] = [0; ELF_IMAGE_MAX];
static mut INIT_ELF_READY: bool = false;

#[repr(C)]
#[derive(Clone, Copy)]
struct UserPollFd {
    fd: i32,
    events: i16,
    revents: i16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct UserTimespec {
    tv_sec: i64,
    tv_nsec: i64,
}

// 最小用户态程序：
//   poll(NULL, 0, 0) -> 走一次 poll 非阻塞路径
//   pipe2 + write -> 写入管道
//   ppoll(2 fds, timeout) -> 覆盖多 fd sleep-retry 超时路径
//   poll(pipefd[0], 1, 0) -> 覆盖 pipe 可读就绪路径
//   writev(1, USER_IOVEC_VA, 2) -> 控制台输出（跨页验证 UserSlice）
//   clone() -> fork 语义，子进程写入 COW 页面并 exit(42)
//   wait4(child) -> 父进程回收并验证退出码 + COW 仍保持旧值
//   execve("/init") -> 覆盖 ELF 解析与 argv/envp 栈布局
const USER_CODE: [u8; 480] = [
    0x13, 0x05, 0x00, 0x00, 0x93, 0x05, 0x00, 0x00, 0x13, 0x06, 0x00, 0x00, 0x93, 0x08, 0x70, 0x00,
    0x73, 0x00, 0x00, 0x00, 0x37, 0x15, 0x00, 0x40, 0x1b, 0x05, 0x05, 0x04, 0x93, 0x05, 0x00, 0x00,
    0x93, 0x08, 0xb0, 0x03, 0x73, 0x00, 0x00, 0x00, 0xb7, 0x12, 0x00, 0x40, 0x9b, 0x82, 0x02, 0x05,
    0x13, 0x03, 0x00, 0x00, 0x23, 0xa0, 0x62, 0x00, 0x13, 0x03, 0x10, 0x00, 0x23, 0x92, 0x62, 0x00,
    0x23, 0x93, 0x02, 0x00, 0xb7, 0x13, 0x00, 0x40, 0x9b, 0x83, 0x03, 0x04, 0x03, 0xae, 0x03, 0x00,
    0x23, 0xa4, 0xc2, 0x01, 0x13, 0x03, 0x10, 0x00, 0x23, 0x96, 0x62, 0x00, 0x23, 0x97, 0x02, 0x00,
    0x37, 0x15, 0x00, 0x40, 0x1b, 0x05, 0x05, 0x05, 0x93, 0x05, 0x20, 0x00, 0x37, 0x16, 0x00, 0x40,
    0x1b, 0x06, 0x06, 0x06, 0x93, 0x06, 0x00, 0x00, 0x13, 0x07, 0x00, 0x00, 0x93, 0x08, 0x90, 0x04,
    0x73, 0x00, 0x00, 0x00, 0x03, 0xa5, 0x43, 0x00, 0xb7, 0x15, 0x00, 0x40, 0x9b, 0x85, 0x05, 0x10,
    0x13, 0x06, 0x10, 0x00, 0x93, 0x08, 0x00, 0x04, 0x73, 0x00, 0x00, 0x00, 0xb7, 0x12, 0x00, 0x40,
    0x9b, 0x82, 0x02, 0x05, 0x23, 0xa0, 0xc2, 0x01, 0x13, 0x03, 0x10, 0x00, 0x23, 0x92, 0x62, 0x00,
    0x23, 0x93, 0x02, 0x00, 0x37, 0x15, 0x00, 0x40, 0x1b, 0x05, 0x05, 0x05, 0x93, 0x05, 0x10, 0x00,
    0x13, 0x06, 0x00, 0x00, 0x93, 0x08, 0x70, 0x00, 0x73, 0x00, 0x00, 0x00, 0x13, 0x05, 0x10, 0x00,
    0xb7, 0x15, 0x00, 0x40, 0x13, 0x06, 0x20, 0x00, 0x93, 0x08, 0x20, 0x04, 0x73, 0x00, 0x00, 0x00,
    0x13, 0x05, 0x00, 0x00, 0x93, 0x05, 0x00, 0x00, 0x13, 0x06, 0x00, 0x00, 0x93, 0x06, 0x00, 0x00,
    0x13, 0x07, 0x00, 0x00, 0x93, 0x08, 0xc0, 0x0d, 0x73, 0x00, 0x00, 0x00, 0x63, 0x0c, 0x05, 0x0a,
    0x93, 0x02, 0x05, 0x00, 0x13, 0x85, 0x02, 0x00, 0xb7, 0x15, 0x00, 0x40, 0x9b, 0x85, 0x05, 0x19,
    0x13, 0x06, 0x00, 0x00, 0x93, 0x06, 0x00, 0x00, 0x93, 0x08, 0x40, 0x10, 0x73, 0x00, 0x00, 0x00,
    0x37, 0x13, 0x00, 0x40, 0x1b, 0x03, 0x03, 0x19, 0x83, 0x23, 0x03, 0x00, 0x37, 0x3e, 0x00, 0x00,
    0x1b, 0x0e, 0x0e, 0xa0, 0x63, 0x9c, 0xc3, 0x03, 0x37, 0x13, 0x00, 0x40, 0x1b, 0x03, 0x03, 0x18,
    0x83, 0x23, 0x03, 0x00, 0x37, 0x5e, 0x34, 0x12, 0x1b, 0x0e, 0x8e, 0x67, 0x63, 0x90, 0xc3, 0x03,
    0x13, 0x05, 0x10, 0x00, 0xb7, 0x15, 0x00, 0x40, 0x9b, 0x85, 0x05, 0x1a, 0x13, 0x06, 0x80, 0x00,
    0x93, 0x08, 0x00, 0x04, 0x73, 0x00, 0x00, 0x00, 0x6f, 0x00, 0xc0, 0x01, 0x13, 0x05, 0x10, 0x00,
    0xb7, 0x15, 0x00, 0x40, 0x9b, 0x85, 0x05, 0x1b, 0x13, 0x06, 0x90, 0x00, 0x93, 0x08, 0x00, 0x04,
    0x73, 0x00, 0x00, 0x00, 0x37, 0x15, 0x00, 0x40, 0x1b, 0x05, 0x05, 0x10, 0xb7, 0x15, 0x00, 0x40,
    0x9b, 0x85, 0x05, 0x12, 0x37, 0x16, 0x00, 0x40, 0x1b, 0x06, 0x06, 0x14, 0x93, 0x08, 0xd0, 0x0d,
    0x73, 0x00, 0x00, 0x00, 0x13, 0x05, 0x00, 0x00, 0x93, 0x08, 0xd0, 0x05, 0x73, 0x00, 0x00, 0x00,
    0x6f, 0x00, 0x00, 0x00, 0xb7, 0x12, 0x00, 0x40, 0x9b, 0x82, 0x02, 0x18, 0x37, 0x23, 0x02, 0x00,
    0x1b, 0x03, 0x53, 0xd9, 0x13, 0x13, 0xe3, 0x00, 0x13, 0x03, 0x13, 0x32, 0x23, 0xa0, 0x62, 0x00,
    0x13, 0x05, 0xa0, 0x02, 0x93, 0x08, 0xd0, 0x05, 0x73, 0x00, 0x00, 0x00, 0x6f, 0x00, 0x00, 0x00,
];

pub fn prepare_user_test() -> Option<UserContext> {
    let root_pa = mm::kernel_root_pa();
    if root_pa == 0 {
        return None;
    }
    load_user_image(root_pa)
}

pub fn load_user_image(root_pa: usize) -> Option<UserContext> {
    let code_pa = ensure_user_page(root_pa, USER_CODE_VA, mm::UserAccess::Read, mm::map_user_code)?;
    let data_pa = ensure_user_page(root_pa, USER_DATA_VA, mm::UserAccess::Write, mm::map_user_data)?;
    let stack_pa = ensure_user_page(root_pa, USER_STACK_VA, mm::UserAccess::Write, mm::map_user_stack)?;

    init_user_image(code_pa, data_pa, stack_pa);
    mm::flush_icache();
    mm::flush_tlb();

    Some(UserContext {
        entry: USER_CODE_VA,
        user_sp: USER_STACK_VA + USER_STACK_SIZE,
        root_pa,
        satp: mm::satp_for_root(root_pa),
        argc: 0,
        argv: 0,
        envp: 0,
    })
}

pub fn load_exec_elf(
    old_root_pa: usize,
    image: &[u8],
    argv: usize,
    envp: usize,
) -> Result<UserContext, Errno> {
    let header = ElfHeader::parse(image)?;
    let root_pa = mm::alloc_user_root().ok_or(Errno::NoMem)?;
    if let Err(err) = load_elf_segments(root_pa, image, &header) {
        // execve 失败时释放新地址空间，避免泄漏页表页与用户页。
        mm::release_user_root(root_pa);
        return Err(err);
    }

    let stack_pa = match ensure_user_page(root_pa, USER_STACK_VA, mm::UserAccess::Write, mm::map_user_stack) {
        Some(pa) => pa,
        None => {
            mm::release_user_root(root_pa);
            return Err(Errno::Fault);
        }
    };
    // SAFETY: identity-mapped frame; zero stack page before writing.
    unsafe {
        ptr::write_bytes(stack_pa as *mut u8, 0, USER_STACK_SIZE);
    }

    let (user_sp, argc, argv_ptr, envp_ptr) = match build_user_stack(old_root_pa, root_pa, argv, envp) {
        Ok(value) => value,
        Err(err) => {
            mm::release_user_root(root_pa);
            return Err(err);
        }
    };

    mm::flush_icache();
    mm::flush_tlb();

    Ok(UserContext {
        entry: header.entry as usize,
        user_sp,
        root_pa,
        satp: mm::satp_for_root(root_pa),
        argc,
        argv: argv_ptr,
        envp: envp_ptr,
    })
}

fn build_user_stack(
    old_root_pa: usize,
    root_pa: usize,
    argv: usize,
    envp: usize,
) -> Result<(usize, usize, usize, usize), Errno> {
    const MAX_ARGS: usize = 8;
    const MAX_ENVS: usize = 8;
    const MAX_STR: usize = 128;

    let stack_base = USER_STACK_VA;
    let mut sp = USER_STACK_VA + USER_STACK_SIZE;
    let mut argc = 0usize;
    let mut envc = 0usize;
    let mut arg_ptrs = [0usize; MAX_ARGS];
    let mut env_ptrs = [0usize; MAX_ENVS];

    if argv != 0 {
        for idx in 0..MAX_ARGS {
            let ptr = read_user_usize(old_root_pa, argv + idx * size_of::<usize>())?;
            if ptr == 0 {
                break;
            }
            let mut buf = [0u8; MAX_STR];
            let len = read_user_cstr(old_root_pa, ptr, &mut buf)?;
            sp = sp.saturating_sub(len + 1);
            if sp < stack_base {
                return Err(Errno::Range);
            }
            write_user_bytes(root_pa, sp, &buf[..len])?;
            write_user_bytes(root_pa, sp + len, &[0])?;
            arg_ptrs[idx] = sp;
            argc = idx + 1;
        }
    }

    if envp != 0 {
        for idx in 0..MAX_ENVS {
            let ptr = read_user_usize(old_root_pa, envp + idx * size_of::<usize>())?;
            if ptr == 0 {
                break;
            }
            let mut buf = [0u8; MAX_STR];
            let len = read_user_cstr(old_root_pa, ptr, &mut buf)?;
            sp = sp.saturating_sub(len + 1);
            if sp < stack_base {
                return Err(Errno::Range);
            }
            write_user_bytes(root_pa, sp, &buf[..len])?;
            write_user_bytes(root_pa, sp + len, &[0])?;
            env_ptrs[idx] = sp;
            envc = idx + 1;
        }
    }

    sp &= !0xf;
    let envp_start = sp.saturating_sub((envc + 1) * size_of::<usize>());
    let argv_start = envp_start.saturating_sub((argc + 1) * size_of::<usize>());
    let argc_pos = argv_start.saturating_sub(size_of::<usize>());
    if argc_pos < stack_base {
        return Err(Errno::Range);
    }

    write_user_ptr_list(root_pa, argv_start, &arg_ptrs[..argc])?;
    write_user_ptr_list(root_pa, envp_start, &env_ptrs[..envc])?;
    write_user_usize(root_pa, argc_pos, argc)?;

    Ok((argc_pos, argc, argv_start, envp_start))
}

fn read_user_usize(root_pa: usize, addr: usize) -> Result<usize, Errno> {
    let pa = mm::translate_user_ptr(root_pa, addr, size_of::<usize>(), mm::UserAccess::Read)
        .ok_or(Errno::Fault)?;
    // SAFETY: validated user pointer.
    Ok(unsafe { *(pa as *const usize) })
}

fn read_user_cstr(root_pa: usize, addr: usize, out: &mut [u8]) -> Result<usize, Errno> {
    for i in 0..out.len() {
        let ch = read_user_byte(root_pa, addr + i)?;
        if ch == 0 {
            return Ok(i);
        }
        out[i] = ch;
    }
    Err(Errno::Range)
}

fn write_user_usize(root_pa: usize, addr: usize, value: usize) -> Result<(), Errno> {
    let pa = mm::translate_user_ptr(root_pa, addr, size_of::<usize>(), mm::UserAccess::Write)
        .ok_or(Errno::Fault)?;
    // SAFETY: validated user pointer.
    unsafe {
        *(pa as *mut usize) = value;
    }
    Ok(())
}

fn write_user_ptr_list(root_pa: usize, base: usize, ptrs: &[usize]) -> Result<(), Errno> {
    for (idx, &ptr) in ptrs.iter().enumerate() {
        write_user_usize(root_pa, base + idx * size_of::<usize>(), ptr)?;
    }
    write_user_usize(root_pa, base + ptrs.len() * size_of::<usize>(), 0)?;
    Ok(())
}

fn write_user_bytes(root_pa: usize, addr: usize, data: &[u8]) -> Result<(), Errno> {
    mm::UserSlice::new(addr, data.len())
        .copy_from_slice(root_pa, data)
        .ok_or(Errno::Fault)?;
    Ok(())
}

fn read_user_byte(root_pa: usize, addr: usize) -> Result<u8, Errno> {
    let pa = mm::translate_user_ptr(root_pa, addr, 1, mm::UserAccess::Read)
        .ok_or(Errno::Fault)?;
    // SAFETY: validated user pointer.
    Ok(unsafe { *(pa as *const u8) })
}

fn load_elf_segments(root_pa: usize, image: &[u8], header: &ElfHeader) -> Result<(), Errno> {
    for idx in 0..header.phnum {
        let ph = header.program_header(image, idx)?;
        if ph.p_type != 1 {
            continue;
        }
        if ph.p_filesz > ph.p_memsz {
            return Err(Errno::Inval);
        }
        let seg_start = align_down(ph.p_vaddr as usize, mm::PAGE_SIZE);
        let seg_end = align_up((ph.p_vaddr + ph.p_memsz) as usize, mm::PAGE_SIZE);
        let flags = mm::UserMapFlags {
            read: (ph.p_flags & 0x4) != 0,
            write: (ph.p_flags & 0x2) != 0,
            exec: (ph.p_flags & 0x1) != 0,
        };

        for va in (seg_start..seg_end).step_by(mm::PAGE_SIZE) {
            let frame = mm::alloc_frame().ok_or(Errno::MFile)?;
            let pa = frame.addr().as_usize();
            // SAFETY: identity-mapped frame; clear before mapping.
            unsafe {
                ptr::write_bytes(pa as *mut u8, 0, mm::PAGE_SIZE);
            }
            if !mm::map_user_page(root_pa, va, pa, flags) {
                return Err(Errno::Fault);
            }
        }

        let file_end = ph.p_offset as usize + ph.p_filesz as usize;
        if file_end > image.len() {
            return Err(Errno::Fault);
        }
        let file_slice = &image[ph.p_offset as usize..file_end];
        write_user_bytes(root_pa, ph.p_vaddr as usize, file_slice)?;
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct ElfHeader {
    entry: u64,
    phoff: u64,
    phentsize: u16,
    phnum: u16,
}

#[derive(Clone, Copy)]
struct ElfProgramHeader {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_filesz: u64,
    p_memsz: u64,
}

impl ElfHeader {
    fn parse(image: &[u8]) -> Result<Self, Errno> {
        if image.len() < 64 || &image[0..4] != b"\x7fELF" {
            return Err(Errno::Inval);
        }
        if image[4] != 2 || image[5] != 1 {
            return Err(Errno::Inval);
        }
        let entry = read_u64(image, 24)?;
        let phoff = read_u64(image, 32)?;
        let phentsize = read_u16(image, 54)?;
        let phnum = read_u16(image, 56)?;
        if phentsize as usize != 56 {
            return Err(Errno::Inval);
        }
        Ok(Self {
            entry,
            phoff,
            phentsize,
            phnum,
        })
    }

    fn program_header(self, image: &[u8], index: u16) -> Result<ElfProgramHeader, Errno> {
        let offset = self
            .phoff
            .checked_add((index as u64) * (self.phentsize as u64))
            .ok_or(Errno::Fault)? as usize;
        if offset + self.phentsize as usize > image.len() {
            return Err(Errno::Fault);
        }
        Ok(ElfProgramHeader {
            p_type: read_u32(image, offset)?,
            p_flags: read_u32(image, offset + 4)?,
            p_offset: read_u64(image, offset + 8)?,
            p_vaddr: read_u64(image, offset + 16)?,
            p_filesz: read_u64(image, offset + 32)?,
            p_memsz: read_u64(image, offset + 40)?,
        })
    }
}

fn read_u16(image: &[u8], offset: usize) -> Result<u16, Errno> {
    if offset + 2 > image.len() {
        return Err(Errno::Fault);
    }
    Ok(u16::from_le_bytes([image[offset], image[offset + 1]]))
}

fn read_u32(image: &[u8], offset: usize) -> Result<u32, Errno> {
    if offset + 4 > image.len() {
        return Err(Errno::Fault);
    }
    Ok(u32::from_le_bytes([
        image[offset],
        image[offset + 1],
        image[offset + 2],
        image[offset + 3],
    ]))
}

fn read_u64(image: &[u8], offset: usize) -> Result<u64, Errno> {
    if offset + 8 > image.len() {
        return Err(Errno::Fault);
    }
    Ok(u64::from_le_bytes([
        image[offset],
        image[offset + 1],
        image[offset + 2],
        image[offset + 3],
        image[offset + 4],
        image[offset + 5],
        image[offset + 6],
        image[offset + 7],
    ]))
}

fn align_down(value: usize, align: usize) -> usize {
    value & !(align - 1)
}

fn align_up(value: usize, align: usize) -> usize {
    (value + align - 1) & !(align - 1)
}

pub fn init_exec_elf_image() -> &'static [u8] {
    // SAFETY: early boot single-hart; buffer is initialized once.
    unsafe {
        if INIT_ELF_READY {
            return &INIT_ELF_IMAGE[..];
        }
        let mut offset = 0usize;
        let mut buf = &mut INIT_ELF_IMAGE[..];

        // ELF header (64-bit, little-endian).
        buf[offset..offset + 4].copy_from_slice(b"\x7fELF");
        buf[offset + 4] = 2; // ELFCLASS64
        buf[offset + 5] = 1; // ELFDATA2LSB
        buf[offset + 6] = 1; // EV_CURRENT
        buf[offset + 7] = 0; // SYSV
        buf[offset + 8] = 0;
        for i in 9..16 {
            buf[offset + i] = 0;
        }
        offset += 16;

        write_u16(&mut buf, &mut offset, 2); // ET_EXEC
        write_u16(&mut buf, &mut offset, 243); // EM_RISCV
        write_u32(&mut buf, &mut offset, 1);
        write_u64(&mut buf, &mut offset, USER_CODE_VA as u64);
        write_u64(&mut buf, &mut offset, 64); // e_phoff
        write_u64(&mut buf, &mut offset, 0);
        write_u32(&mut buf, &mut offset, 0);
        write_u16(&mut buf, &mut offset, 64); // e_ehsize
        write_u16(&mut buf, &mut offset, 56); // e_phentsize
        write_u16(&mut buf, &mut offset, 1); // e_phnum
        write_u16(&mut buf, &mut offset, 0);
        write_u16(&mut buf, &mut offset, 0);
        write_u16(&mut buf, &mut offset, 0);

        // Program header (single RXW segment).
        offset = 64;
        write_u32(&mut buf, &mut offset, 1); // PT_LOAD
        write_u32(&mut buf, &mut offset, 0x7); // PF_R|PF_W|PF_X
        write_u64(&mut buf, &mut offset, ELF_SEGMENT_OFFSET as u64);
        write_u64(&mut buf, &mut offset, USER_CODE_VA as u64);
        write_u64(&mut buf, &mut offset, USER_CODE_VA as u64);
        let segment_size = ELF_INIT_MSG_OFFSET + ELF_INIT_MSG.len();
        write_u64(&mut buf, &mut offset, segment_size as u64);
        write_u64(&mut buf, &mut offset, segment_size as u64);
        write_u64(&mut buf, &mut offset, ELF_SEGMENT_ALIGN as u64);

        // Fill segment content.
        buf[ELF_SEGMENT_OFFSET..ELF_SEGMENT_OFFSET + ELF_INIT_CODE.len()]
            .copy_from_slice(&ELF_INIT_CODE);
        let msg_start = ELF_SEGMENT_OFFSET + ELF_INIT_MSG_OFFSET;
        buf[msg_start..msg_start + ELF_INIT_MSG.len()].copy_from_slice(ELF_INIT_MSG);

        INIT_ELF_READY = true;
        &INIT_ELF_IMAGE[..ELF_SEGMENT_OFFSET + segment_size]
    }
}

fn ensure_user_page(
    root_pa: usize,
    va: usize,
    access: mm::UserAccess,
    map_fn: fn(usize, usize, usize) -> bool,
) -> Option<usize> {
    if let Some(pa) = mm::translate_user_ptr(root_pa, va, 1, access) {
        return Some(pa);
    }
    let frame = mm::alloc_frame()?;
    let pa = frame.addr().as_usize();
    if !map_fn(root_pa, va, pa) {
        return None;
    }
    Some(pa)
}

fn init_user_image(code_pa: usize, data_pa: usize, stack_pa: usize) {
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
        pollfd_base.add(1).write(UserPollFd {
            fd: -1,
            events: USER_POLLIN,
            revents: 0,
        });
        let ppoll_ts_base = (data_pa + (USER_PPOLL_TS_VA - USER_DATA_VA)) as *mut UserTimespec;
        ppoll_ts_base.write(UserTimespec {
            tv_sec: 0,
            tv_nsec: USER_PPOLL_TIMEOUT_NS,
        });
        // execve 路径字符串与 argv/envp。
        let path_base = data_pa + (USER_PATH_VA - USER_DATA_VA);
        ptr::copy_nonoverlapping(USER_PATH.as_ptr(), path_base as *mut u8, USER_PATH.len());
        let arg0_base = path_base + 8;
        ptr::copy_nonoverlapping(USER_ARG0.as_ptr(), arg0_base as *mut u8, USER_ARG0.len());
        let env0_base = arg0_base + 8;
        ptr::copy_nonoverlapping(USER_ENV0.as_ptr(), env0_base as *mut u8, USER_ENV0.len());
        let argv_base = (data_pa + (USER_ARGV_VA - USER_DATA_VA)) as *mut usize;
        argv_base.write(USER_PATH_VA);
        argv_base.add(1).write(USER_PATH_VA + 8);
        argv_base.add(2).write(0);
        let envp_base = (data_pa + (USER_ENVP_VA - USER_DATA_VA)) as *mut usize;
        envp_base.write(USER_PATH_VA + 16);
        envp_base.add(1).write(0);
        // CoW 测试数据与 wait4 状态缓冲。
        let cow_base = (data_pa + (USER_COW_VA - USER_DATA_VA)) as *mut u32;
        cow_base.write(USER_COW_INIT);
        let status_base = (data_pa + (USER_WAIT_STATUS_VA - USER_DATA_VA)) as *mut usize;
        status_base.write(0);
        let cow_ok_base = data_pa + (USER_COW_OK_VA - USER_DATA_VA);
        ptr::copy_nonoverlapping(USER_COW_OK.as_ptr(), cow_ok_base as *mut u8, USER_COW_OK.len());
        let cow_bad_base = data_pa + (USER_COW_BAD_VA - USER_DATA_VA);
        ptr::copy_nonoverlapping(
            USER_COW_BAD.as_ptr(),
            cow_bad_base as *mut u8,
            USER_COW_BAD.len(),
        );
    }
}

fn write_u16(buf: &mut [u8], offset: &mut usize, value: u16) {
    let bytes = value.to_le_bytes();
    buf[*offset..*offset + 2].copy_from_slice(&bytes);
    *offset += 2;
}

fn write_u32(buf: &mut [u8], offset: &mut usize, value: u32) {
    let bytes = value.to_le_bytes();
    buf[*offset..*offset + 4].copy_from_slice(&bytes);
    *offset += 4;
}

fn write_u64(buf: &mut [u8], offset: &mut usize, value: u64) {
    let bytes = value.to_le_bytes();
    buf[*offset..*offset + 8].copy_from_slice(&bytes);
    *offset += 8;
}
