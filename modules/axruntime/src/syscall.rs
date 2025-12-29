#![allow(dead_code)]

use core::mem::size_of;

use crate::mm::{self, UserAccess, UserPtr, UserSlice};
use crate::{sbi, time};
use crate::trap::TrapFrame;

#[repr(i32)]
#[derive(Debug, Clone, Copy)]
pub enum Errno {
    NoSys = 38,
    Fault = 14,
    Inval = 22,
    Badf = 9,
    Range = 34,
}

impl Errno {
    pub fn to_ret(self) -> usize {
        (-(self as isize)) as usize
    }
}

#[derive(Clone, Copy)]
struct SyscallContext {
    nr: usize,
    args: [usize; 6],
}

impl SyscallContext {
    fn from_trap_frame(tf: &TrapFrame) -> Self {
        Self {
            nr: tf.a7,
            args: [tf.a0, tf.a1, tf.a2, tf.a3, tf.a4, tf.a5],
        }
    }
}

pub fn handle_syscall(tf: &mut TrapFrame) {
    let ctx = SyscallContext::from_trap_frame(tf);
    let ret = dispatch(ctx);
    tf.a0 = match ret {
        Ok(value) => value,
        Err(err) => err.to_ret(),
    };
    tf.sepc = tf.sepc.wrapping_add(4);
}

fn dispatch(ctx: SyscallContext) -> Result<usize, Errno> {
    match ctx.nr {
        SYS_EXIT => sys_exit(ctx.args[0]),
        SYS_READ => sys_read(ctx.args[0], ctx.args[1], ctx.args[2]),
        SYS_WRITE => sys_write(ctx.args[0], ctx.args[1], ctx.args[2]),
        SYS_READV => sys_readv(ctx.args[0], ctx.args[1], ctx.args[2]),
        SYS_WRITEV => sys_writev(ctx.args[0], ctx.args[1], ctx.args[2]),
        SYS_CLOCK_GETTIME => sys_clock_gettime(ctx.args[0], ctx.args[1]),
        SYS_CLOCK_GETTIME64 => sys_clock_gettime(ctx.args[0], ctx.args[1]),
        SYS_GETTIMEOFDAY => sys_gettimeofday(ctx.args[0], ctx.args[1]),
        SYS_GETPID => sys_getpid(),
        SYS_GETPPID => sys_getppid(),
        SYS_GETUID => sys_getuid(),
        SYS_GETEUID => sys_geteuid(),
        SYS_GETGID => sys_getgid(),
        SYS_GETEGID => sys_getegid(),
        SYS_GETTID => sys_gettid(),
        SYS_SCHED_YIELD => sys_sched_yield(),
        SYS_SET_TID_ADDRESS => sys_set_tid_address(ctx.args[0]),
        SYS_UNAME => sys_uname(ctx.args[0]),
        SYS_EXIT_GROUP => sys_exit_group(ctx.args[0]),
        SYS_GETCWD => sys_getcwd(ctx.args[0], ctx.args[1]),
        SYS_CLOSE => sys_close(ctx.args[0]),
        SYS_GETRLIMIT => sys_getrlimit(ctx.args[0], ctx.args[1]),
        SYS_PRLIMIT64 => sys_prlimit64(ctx.args[0], ctx.args[1], ctx.args[2], ctx.args[3]),
        _ => Err(Errno::NoSys),
    }
}

const SYS_EXIT: usize = 93;
const SYS_EXIT_GROUP: usize = 94;
const SYS_READ: usize = 63;
const SYS_WRITE: usize = 64;
const SYS_READV: usize = 65;
const SYS_WRITEV: usize = 66;
const SYS_GETCWD: usize = 17;
const SYS_CLOSE: usize = 57;
const SYS_GETRLIMIT: usize = 163;
const SYS_PRLIMIT64: usize = 261;
const SYS_CLOCK_GETTIME: usize = 113;
const SYS_CLOCK_GETTIME64: usize = 403;
const SYS_GETTIMEOFDAY: usize = 169;
const SYS_GETPID: usize = 172;
const SYS_GETPPID: usize = 173;
const SYS_GETUID: usize = 174;
const SYS_GETEUID: usize = 175;
const SYS_GETGID: usize = 176;
const SYS_GETEGID: usize = 177;
const SYS_GETTID: usize = 178;
const SYS_SCHED_YIELD: usize = 124;
const SYS_SET_TID_ADDRESS: usize = 96;
const SYS_UNAME: usize = 160;

const CLOCK_REALTIME: usize = 0;
const CLOCK_MONOTONIC: usize = 1;
const IOV_MAX: usize = 1024;

#[repr(C)]
#[derive(Clone, Copy)]
struct Timespec {
    tv_sec: i64,
    tv_nsec: i64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Timeval {
    tv_sec: i64,
    tv_usec: i64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct TimeZone {
    tz_minuteswest: i32,
    tz_dsttime: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Iovec {
    iov_base: usize,
    iov_len: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Utsname {
    sysname: [u8; 65],
    nodename: [u8; 65],
    release: [u8; 65],
    version: [u8; 65],
    machine: [u8; 65],
    domainname: [u8; 65],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Rlimit {
    rlim_cur: u64,
    rlim_max: u64,
}

fn sys_exit(_code: usize) -> Result<usize, Errno> {
    crate::sbi::shutdown();
}

fn sys_exit_group(code: usize) -> Result<usize, Errno> {
    sys_exit(code)
}

fn sys_read(fd: usize, buf: usize, len: usize) -> Result<usize, Errno> {
    if len == 0 {
        return Ok(0);
    }
    if fd != 0 {
        return Err(Errno::Badf);
    }
    let root_pa = mm::current_root_pa();
    if root_pa == 0 {
        return Err(Errno::Fault);
    }

    read_console_into(root_pa, buf, len)
}

fn sys_write(fd: usize, buf: usize, len: usize) -> Result<usize, Errno> {
    if len == 0 {
        return Ok(0);
    }
    if fd != 1 && fd != 2 {
        return Err(Errno::Badf);
    }
    let root_pa = mm::current_root_pa();
    if root_pa == 0 {
        return Err(Errno::Fault);
    }

    write_console_from(root_pa, buf, len)
}

fn sys_readv(fd: usize, iov_ptr: usize, iovcnt: usize) -> Result<usize, Errno> {
    if fd != 0 {
        return Err(Errno::Badf);
    }
    if iovcnt == 0 || iovcnt > IOV_MAX {
        return Err(Errno::Inval);
    }
    if iov_ptr == 0 {
        return Err(Errno::Fault);
    }
    let root_pa = mm::current_root_pa();
    if root_pa == 0 {
        return Err(Errno::Fault);
    }

    let mut total = 0usize;
    for index in 0..iovcnt {
        let iov = load_iovec(root_pa, iov_ptr, index)?;
        if iov.iov_len == 0 {
            continue;
        }
        match read_console_into(root_pa, iov.iov_base, iov.iov_len) {
            Ok(read) => {
                total += read;
                if read < iov.iov_len {
                    break;
                }
            }
            Err(err) => {
                if total > 0 {
                    return Ok(total);
                }
                return Err(err);
            }
        }
    }
    Ok(total)
}

fn sys_writev(fd: usize, iov_ptr: usize, iovcnt: usize) -> Result<usize, Errno> {
    if fd != 1 && fd != 2 {
        return Err(Errno::Badf);
    }
    if iovcnt == 0 || iovcnt > IOV_MAX {
        return Err(Errno::Inval);
    }
    if iov_ptr == 0 {
        return Err(Errno::Fault);
    }
    let root_pa = mm::current_root_pa();
    if root_pa == 0 {
        return Err(Errno::Fault);
    }

    let mut total = 0usize;
    for index in 0..iovcnt {
        let iov = load_iovec(root_pa, iov_ptr, index)?;
        if iov.iov_len == 0 {
            continue;
        }
        match write_console_from(root_pa, iov.iov_base, iov.iov_len) {
            Ok(written) => total += written,
            Err(err) => {
                if total > 0 {
                    return Ok(total);
                }
                return Err(err);
            }
        }
    }
    Ok(total)
}

fn sys_clock_gettime(clock_id: usize, tp: usize) -> Result<usize, Errno> {
    if tp == 0 {
        return Err(Errno::Fault);
    }
    let now_ms = time::uptime_ms();
    let ts = Timespec {
        tv_sec: (now_ms / 1000) as i64,
        tv_nsec: ((now_ms % 1000) * 1_000_000) as i64,
    };
    match clock_id {
        CLOCK_REALTIME | CLOCK_MONOTONIC => {
            let root_pa = mm::current_root_pa();
            if root_pa == 0 {
                return Err(Errno::Fault);
            }
            UserPtr::new(tp).write(root_pa, ts).ok_or(Errno::Fault)?;
            Ok(0)
        }
        _ => Err(Errno::Inval),
    }
}

fn sys_gettimeofday(tv: usize, tz: usize) -> Result<usize, Errno> {
    let root_pa = mm::current_root_pa();
    if root_pa == 0 {
        return Err(Errno::Fault);
    }
    if tv != 0 {
        let now_ms = time::uptime_ms();
        let tv_val = Timeval {
            tv_sec: (now_ms / 1000) as i64,
            tv_usec: ((now_ms % 1000) * 1_000) as i64,
        };
        UserPtr::new(tv)
            .write(root_pa, tv_val)
            .ok_or(Errno::Fault)?;
    }
    if tz != 0 {
        let tz_val = TimeZone {
            tz_minuteswest: 0,
            tz_dsttime: 0,
        };
        UserPtr::new(tz)
            .write(root_pa, tz_val)
            .ok_or(Errno::Fault)?;
    }
    Ok(0)
}

fn sys_getpid() -> Result<usize, Errno> {
    Ok(1)
}

fn sys_getppid() -> Result<usize, Errno> {
    Ok(0)
}

fn sys_getuid() -> Result<usize, Errno> {
    Ok(0)
}

fn sys_geteuid() -> Result<usize, Errno> {
    Ok(0)
}

fn sys_getgid() -> Result<usize, Errno> {
    Ok(0)
}

fn sys_getegid() -> Result<usize, Errno> {
    Ok(0)
}

fn sys_gettid() -> Result<usize, Errno> {
    Ok(1)
}

fn sys_sched_yield() -> Result<usize, Errno> {
    crate::runtime::yield_now();
    Ok(0)
}

fn sys_set_tid_address(tidptr: usize) -> Result<usize, Errno> {
    if tidptr == 0 {
        return Err(Errno::Fault);
    }
    let root_pa = mm::current_root_pa();
    if root_pa == 0 {
        return Err(Errno::Fault);
    }
    let size = size_of::<usize>();
    if mm::translate_user_ptr(root_pa, tidptr, size, UserAccess::Write).is_none() {
        return Err(Errno::Fault);
    }
    Ok(1)
}

fn sys_uname(buf: usize) -> Result<usize, Errno> {
    if buf == 0 {
        return Err(Errno::Fault);
    }
    let root_pa = mm::current_root_pa();
    if root_pa == 0 {
        return Err(Errno::Fault);
    }
    let mut uts = Utsname {
        sysname: [0; 65],
        nodename: [0; 65],
        release: [0; 65],
        version: [0; 65],
        machine: [0; 65],
        domainname: [0; 65],
    };
    fill_uts_field(&mut uts.sysname, "Aurora");
    fill_uts_field(&mut uts.nodename, "aurora");
    fill_uts_field(&mut uts.release, "0.1");
    fill_uts_field(&mut uts.version, "aurora");
    fill_uts_field(&mut uts.machine, "riscv64");
    fill_uts_field(&mut uts.domainname, "localdomain");
    UserPtr::new(buf).write(root_pa, uts).ok_or(Errno::Fault)?;
    Ok(0)
}

fn sys_getcwd(buf: usize, size: usize) -> Result<usize, Errno> {
    const PATH: &[u8] = b"/\0";
    if buf == 0 {
        return Err(Errno::Fault);
    }
    if size < PATH.len() {
        return Err(Errno::Range);
    }
    let root_pa = mm::current_root_pa();
    if root_pa == 0 {
        return Err(Errno::Fault);
    }
    let slice = UserSlice::new(buf, PATH.len());
    slice
        .copy_from_slice(root_pa, PATH)
        .ok_or(Errno::Fault)?;
    Ok(PATH.len())
}

fn sys_close(fd: usize) -> Result<usize, Errno> {
    if fd <= 2 {
        return Ok(0);
    }
    Err(Errno::Badf)
}

fn sys_getrlimit(_resource: usize, rlim: usize) -> Result<usize, Errno> {
    if rlim == 0 {
        return Err(Errno::Fault);
    }
    let root_pa = mm::current_root_pa();
    if root_pa == 0 {
        return Err(Errno::Fault);
    }
    UserPtr::new(rlim)
        .write(root_pa, default_rlimit())
        .ok_or(Errno::Fault)?;
    Ok(0)
}

fn sys_prlimit64(_pid: usize, _resource: usize, new_rlim: usize, old_rlim: usize) -> Result<usize, Errno> {
    let root_pa = mm::current_root_pa();
    if root_pa == 0 {
        return Err(Errno::Fault);
    }
    if new_rlim != 0 {
        let size = size_of::<Rlimit>();
        if mm::translate_user_ptr(root_pa, new_rlim, size, UserAccess::Read).is_none() {
            return Err(Errno::Fault);
        }
    }
    if old_rlim != 0 {
        UserPtr::new(old_rlim)
            .write(root_pa, default_rlimit())
            .ok_or(Errno::Fault)?;
    }
    Ok(0)
}

fn load_iovec(root_pa: usize, iov_ptr: usize, index: usize) -> Result<Iovec, Errno> {
    let size = size_of::<Iovec>();
    let offset = index.checked_mul(size).ok_or(Errno::Fault)?;
    let addr = iov_ptr.checked_add(offset).ok_or(Errno::Fault)?;
    UserPtr::new(addr).read(root_pa).ok_or(Errno::Fault)
}

fn fill_uts_field(dst: &mut [u8; 65], src: &str) {
    let bytes = src.as_bytes();
    let len = core::cmp::min(bytes.len(), dst.len() - 1);
    dst[..len].copy_from_slice(&bytes[..len]);
    dst[len] = 0;
}

fn default_rlimit() -> Rlimit {
    Rlimit {
        rlim_cur: u64::MAX,
        rlim_max: u64::MAX,
    }
}

fn read_console_into(root_pa: usize, buf: usize, len: usize) -> Result<usize, Errno> {
    if len == 0 {
        return Ok(0);
    }
    let mut addr = buf;
    let mut remaining = len;
    let mut read = 0usize;
    while remaining > 0 {
        let page_off = addr & (mm::PAGE_SIZE - 1);
        let chunk = core::cmp::min(remaining, mm::PAGE_SIZE - page_off);
        let pa = mm::translate_user_ptr(root_pa, addr, chunk, UserAccess::Write)
            .ok_or(Errno::Fault)?;
        // SAFETY: 翻译结果确保该片段在用户态可写。
        unsafe {
            let dst = pa as *mut u8;
            for i in 0..chunk {
                match sbi::console_getchar() {
                    Some(ch) => {
                        dst.add(i).write(ch);
                        read += 1;
                    }
                    None => {
                        // 早期阶段无阻塞控制台输入；无数据则立即返回。
                        return Ok(read);
                    }
                }
            }
        }
        addr = addr.wrapping_add(chunk);
        remaining -= chunk;
    }
    Ok(read)
}

fn write_console_from(root_pa: usize, buf: usize, len: usize) -> Result<usize, Errno> {
    if len == 0 {
        return Ok(0);
    }
    let slice = UserSlice::new(buf, len);
    let mut written = 0usize;
    slice
        .for_each_chunk(root_pa, UserAccess::Read, |pa, chunk| {
            // SAFETY: 翻译结果确保该片段在用户态可读。
            unsafe {
                let src = pa as *const u8;
                for i in 0..chunk {
                    sbi::console_putchar(*src.add(i));
                }
            }
            written += chunk;
            Some(())
        })
        .ok_or(Errno::Fault)?;
    Ok(written)
}
