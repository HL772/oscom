#![allow(dead_code)]

use core::cmp::min;
use core::mem::size_of;
use core::sync::atomic::{AtomicU64, Ordering};

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
        SYS_CLOCK_GETRES => sys_clock_getres(ctx.args[0], ctx.args[1]),
        SYS_CLOCK_GETRES64 => sys_clock_getres(ctx.args[0], ctx.args[1]),
        SYS_GETTIMEOFDAY => sys_gettimeofday(ctx.args[0], ctx.args[1]),
        SYS_NANOSLEEP => sys_nanosleep(ctx.args[0], ctx.args[1]),
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
        SYS_IOCTL => sys_ioctl(ctx.args[0], ctx.args[1], ctx.args[2]),
        SYS_SYSINFO => sys_sysinfo(ctx.args[0]),
        SYS_GETRANDOM => sys_getrandom(ctx.args[0], ctx.args[1], ctx.args[2]),
        SYS_FSTAT => sys_fstat(ctx.args[0], ctx.args[1]),
        SYS_DUP => sys_dup(ctx.args[0]),
        SYS_DUP3 => sys_dup3(ctx.args[0], ctx.args[1], ctx.args[2]),
        SYS_SET_ROBUST_LIST => sys_set_robust_list(ctx.args[0], ctx.args[1]),
        SYS_GET_ROBUST_LIST => sys_get_robust_list(ctx.args[0], ctx.args[1], ctx.args[2]),
        SYS_RT_SIGACTION => sys_rt_sigaction(ctx.args[0], ctx.args[1], ctx.args[2], ctx.args[3]),
        SYS_RT_SIGPROCMASK => sys_rt_sigprocmask(ctx.args[0], ctx.args[1], ctx.args[2], ctx.args[3]),
        SYS_FCNTL => sys_fcntl(ctx.args[0], ctx.args[1], ctx.args[2]),
        SYS_UMASK => sys_umask(ctx.args[0]),
        SYS_PRCTL => sys_prctl(ctx.args[0], ctx.args[1]),
        SYS_SCHED_SETAFFINITY => sys_sched_setaffinity(ctx.args[0], ctx.args[1], ctx.args[2]),
        SYS_SCHED_GETAFFINITY => sys_sched_getaffinity(ctx.args[0], ctx.args[1], ctx.args[2]),
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
const SYS_IOCTL: usize = 29;
const SYS_GETRANDOM: usize = 278;
const SYS_FSTAT: usize = 80;
const SYS_DUP: usize = 23;
const SYS_DUP3: usize = 24;
const SYS_SET_ROBUST_LIST: usize = 99;
const SYS_GET_ROBUST_LIST: usize = 100;
const SYS_RT_SIGACTION: usize = 134;
const SYS_RT_SIGPROCMASK: usize = 135;
const SYS_FCNTL: usize = 25;
const SYS_UMASK: usize = 166;
const SYS_PRCTL: usize = 167;
const SYS_SCHED_SETAFFINITY: usize = 122;
const SYS_SCHED_GETAFFINITY: usize = 123;

const TIOCGWINSZ: usize = 0x5413;
const SYS_CLOCK_GETTIME: usize = 113;
const SYS_CLOCK_GETTIME64: usize = 403;
const SYS_CLOCK_GETRES: usize = 114;
const SYS_CLOCK_GETRES64: usize = 406;
const SYS_GETTIMEOFDAY: usize = 169;
const SYS_NANOSLEEP: usize = 101;
const SYS_GETPID: usize = 172;
const SYS_GETPPID: usize = 173;
const SYS_GETUID: usize = 174;
const SYS_GETEUID: usize = 175;
const SYS_GETGID: usize = 176;
const SYS_GETEGID: usize = 177;
const SYS_GETTID: usize = 178;
const SYS_SYSINFO: usize = 179;
const SYS_SCHED_YIELD: usize = 124;
const SYS_SET_TID_ADDRESS: usize = 96;
const SYS_UNAME: usize = 160;

const CLOCK_REALTIME: usize = 0;
const CLOCK_MONOTONIC: usize = 1;
const IOV_MAX: usize = 1024;
const S_IFCHR: u32 = 0o020000;
const O_CLOEXEC: usize = 0x80000;
const SIG_BLOCK: usize = 0;
const SIG_UNBLOCK: usize = 1;
const SIG_SETMASK: usize = 2;
const F_GETFD: usize = 1;
const F_SETFD: usize = 2;
const F_GETFL: usize = 3;
const F_SETFL: usize = 4;
const PR_SET_NAME: usize = 15;
const PR_GET_NAME: usize = 16;

static RNG_STATE: AtomicU64 = AtomicU64::new(0);
static UMASK: AtomicU64 = AtomicU64::new(0);

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

#[repr(C)]
#[derive(Clone, Copy)]
struct Sysinfo {
    uptime: i64,
    loads: [u64; 3],
    totalram: u64,
    freeram: u64,
    sharedram: u64,
    bufferram: u64,
    totalswap: u64,
    freeswap: u64,
    procs: u16,
    pad: u16,
    totalhigh: u64,
    freehigh: u64,
    mem_unit: u32,
    _pad2: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Stat {
    st_dev: usize,
    st_ino: usize,
    st_mode: u32,
    st_nlink: u32,
    st_uid: u32,
    st_gid: u32,
    st_rdev: usize,
    __pad1: usize,
    st_size: isize,
    st_blksize: i32,
    __pad2: i32,
    st_blocks: isize,
    st_atime: isize,
    st_atime_nsec: usize,
    st_mtime: isize,
    st_mtime_nsec: usize,
    st_ctime: isize,
    st_ctime_nsec: usize,
    __unused4: u32,
    __unused5: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SigAction {
    sa_handler: usize,
    sa_flags: usize,
    sa_restorer: usize,
    sa_mask: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Winsize {
    ws_row: u16,
    ws_col: u16,
    ws_xpixel: u16,
    ws_ypixel: u16,
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

fn sys_clock_getres(clock_id: usize, tp: usize) -> Result<usize, Errno> {
    if tp == 0 {
        return Ok(0);
    }
    let hz = time::tick_hz();
    let nsec = if hz == 0 {
        0
    } else {
        1_000_000_000u64 / hz
    };
    let ts = Timespec {
        tv_sec: 0,
        tv_nsec: nsec as i64,
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

fn sys_nanosleep(req: usize, rem: usize) -> Result<usize, Errno> {
    if req == 0 {
        return Err(Errno::Fault);
    }
    let root_pa = mm::current_root_pa();
    if root_pa == 0 {
        return Err(Errno::Fault);
    }
    let ts = UserPtr::<Timespec>::new(req)
        .read(root_pa)
        .ok_or(Errno::Fault)?;
    if ts.tv_sec < 0 || ts.tv_nsec < 0 || ts.tv_nsec >= 1_000_000_000 {
        return Err(Errno::Inval);
    }
    let total_ns = (ts.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(ts.tv_nsec as u64);
    let sleep_ms = total_ns.saturating_add(999_999) / 1_000_000;
    let deadline = time::uptime_ms().saturating_add(sleep_ms);
    while time::uptime_ms() < deadline {
        crate::cpu::wait_for_interrupt();
    }
    if rem != 0 {
        let zero = Timespec { tv_sec: 0, tv_nsec: 0 };
        UserPtr::new(rem).write(root_pa, zero).ok_or(Errno::Fault)?;
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

fn sys_ioctl(fd: usize, cmd: usize, arg: usize) -> Result<usize, Errno> {
    if fd > 2 {
        return Err(Errno::Badf);
    }
    if cmd != TIOCGWINSZ {
        return Err(Errno::Inval);
    }
    if arg == 0 {
        return Err(Errno::Fault);
    }
    let root_pa = mm::current_root_pa();
    if root_pa == 0 {
        return Err(Errno::Fault);
    }
    let winsz = Winsize {
        ws_row: 24,
        ws_col: 80,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    UserPtr::new(arg).write(root_pa, winsz).ok_or(Errno::Fault)?;
    Ok(0)
}

fn sys_sysinfo(info: usize) -> Result<usize, Errno> {
    if info == 0 {
        return Err(Errno::Fault);
    }
    let root_pa = mm::current_root_pa();
    if root_pa == 0 {
        return Err(Errno::Fault);
    }
    let total = mm::memory_size() as u64;
    let uptime = (time::uptime_ms() / 1000) as i64;
    let sysinfo = Sysinfo {
        uptime,
        loads: [0; 3],
        totalram: total,
        freeram: total,
        sharedram: 0,
        bufferram: 0,
        totalswap: 0,
        freeswap: 0,
        procs: 1,
        pad: 0,
        totalhigh: 0,
        freehigh: 0,
        mem_unit: 1,
        _pad2: 0,
    };
    UserPtr::new(info)
        .write(root_pa, sysinfo)
        .ok_or(Errno::Fault)?;
    Ok(0)
}

fn sys_getrandom(buf: usize, len: usize, _flags: usize) -> Result<usize, Errno> {
    if len == 0 {
        return Ok(0);
    }
    if buf == 0 {
        return Err(Errno::Fault);
    }
    let root_pa = mm::current_root_pa();
    if root_pa == 0 {
        return Err(Errno::Fault);
    }
    let slice = UserSlice::new(buf, len);
    let mut written = 0usize;
    slice
        .for_each_chunk(root_pa, UserAccess::Write, |pa, chunk| {
            let mut offset = 0usize;
            while offset < chunk {
                let rand = rng_next();
                let bytes = rand.to_le_bytes();
                let copy_len = min(bytes.len(), chunk - offset);
                // SAFETY: 翻译结果确保该片段在用户态可写。
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        bytes.as_ptr(),
                        (pa as *mut u8).add(offset),
                        copy_len,
                    );
                }
                offset += copy_len;
            }
            written += chunk;
            Some(())
        })
        .ok_or(Errno::Fault)?;
    Ok(written)
}

fn sys_fstat(fd: usize, stat_ptr: usize) -> Result<usize, Errno> {
    if stat_ptr == 0 {
        return Err(Errno::Fault);
    }
    if fd > 2 {
        return Err(Errno::Badf);
    }
    let root_pa = mm::current_root_pa();
    if root_pa == 0 {
        return Err(Errno::Fault);
    }
    let now_ms = time::uptime_ms();
    let sec = (now_ms / 1000) as isize;
    let nsec = ((now_ms % 1000) * 1_000_000) as usize;
    let stat = Stat {
        st_dev: 0,
        st_ino: 0,
        st_mode: S_IFCHR | 0o666,
        st_nlink: 1,
        st_uid: 0,
        st_gid: 0,
        st_rdev: 0,
        __pad1: 0,
        st_size: 0,
        st_blksize: 4096,
        __pad2: 0,
        st_blocks: 0,
        st_atime: sec,
        st_atime_nsec: nsec,
        st_mtime: sec,
        st_mtime_nsec: nsec,
        st_ctime: sec,
        st_ctime_nsec: nsec,
        __unused4: 0,
        __unused5: 0,
    };
    UserPtr::new(stat_ptr)
        .write(root_pa, stat)
        .ok_or(Errno::Fault)?;
    Ok(0)
}

fn sys_dup(oldfd: usize) -> Result<usize, Errno> {
    if oldfd <= 2 {
        return Ok(oldfd);
    }
    Err(Errno::Badf)
}

fn sys_dup3(oldfd: usize, newfd: usize, flags: usize) -> Result<usize, Errno> {
    if oldfd > 2 {
        return Err(Errno::Badf);
    }
    if oldfd == newfd {
        return Err(Errno::Inval);
    }
    if flags != 0 && flags != O_CLOEXEC {
        return Err(Errno::Inval);
    }
    if newfd <= 2 {
        return Ok(newfd);
    }
    Err(Errno::Badf)
}

fn sys_set_robust_list(_head: usize, _len: usize) -> Result<usize, Errno> {
    Ok(0)
}

fn sys_get_robust_list(_pid: usize, head_ptr: usize, len_ptr: usize) -> Result<usize, Errno> {
    let root_pa = mm::current_root_pa();
    if root_pa == 0 {
        return Err(Errno::Fault);
    }
    if head_ptr != 0 {
        UserPtr::<usize>::new(head_ptr)
            .write(root_pa, 0)
            .ok_or(Errno::Fault)?;
    }
    if len_ptr != 0 {
        UserPtr::<usize>::new(len_ptr)
            .write(root_pa, 0)
            .ok_or(Errno::Fault)?;
    }
    Ok(0)
}

fn sys_rt_sigaction(_sig: usize, act: usize, oldact: usize, sigsetsize: usize) -> Result<usize, Errno> {
    if sigsetsize != size_of::<usize>() {
        return Err(Errno::Inval);
    }
    let root_pa = mm::current_root_pa();
    if root_pa == 0 {
        return Err(Errno::Fault);
    }
    if act != 0 {
        let size = size_of::<SigAction>();
        if mm::translate_user_ptr(root_pa, act, size, UserAccess::Read).is_none() {
            return Err(Errno::Fault);
        }
    }
    if oldact != 0 {
        let zero = SigAction {
            sa_handler: 0,
            sa_flags: 0,
            sa_restorer: 0,
            sa_mask: 0,
        };
        UserPtr::new(oldact)
            .write(root_pa, zero)
            .ok_or(Errno::Fault)?;
    }
    Ok(0)
}

fn sys_rt_sigprocmask(how: usize, set: usize, oldset: usize, sigsetsize: usize) -> Result<usize, Errno> {
    if sigsetsize != size_of::<usize>() {
        return Err(Errno::Inval);
    }
    if how != SIG_BLOCK && how != SIG_UNBLOCK && how != SIG_SETMASK {
        return Err(Errno::Inval);
    }
    let root_pa = mm::current_root_pa();
    if root_pa == 0 {
        return Err(Errno::Fault);
    }
    if set != 0 {
        let size = size_of::<usize>();
        if mm::translate_user_ptr(root_pa, set, size, UserAccess::Read).is_none() {
            return Err(Errno::Fault);
        }
    }
    if oldset != 0 {
        UserPtr::<usize>::new(oldset)
            .write(root_pa, 0)
            .ok_or(Errno::Fault)?;
    }
    Ok(0)
}

fn sys_fcntl(fd: usize, cmd: usize, _arg: usize) -> Result<usize, Errno> {
    if fd > 2 {
        return Err(Errno::Badf);
    }
    match cmd {
        F_GETFD => Ok(0),
        F_SETFD => Ok(0),
        F_GETFL => Ok(0),
        F_SETFL => Ok(0),
        _ => Err(Errno::Inval),
    }
}

fn sys_umask(mask: usize) -> Result<usize, Errno> {
    let old = UMASK.swap((mask & 0o777) as u64, Ordering::Relaxed);
    Ok(old as usize)
}

fn sys_prctl(option: usize, arg2: usize) -> Result<usize, Errno> {
    let root_pa = mm::current_root_pa();
    if root_pa == 0 {
        return Err(Errno::Fault);
    }
    match option {
        PR_SET_NAME => {
            if arg2 == 0 {
                return Err(Errno::Fault);
            }
            if mm::translate_user_ptr(root_pa, arg2, 1, UserAccess::Read).is_none() {
                return Err(Errno::Fault);
            }
            Ok(0)
        }
        PR_GET_NAME => {
            if arg2 == 0 {
                return Err(Errno::Fault);
            }
            let mut name = [0u8; 16];
            let src = b"aurora";
            let copy_len = core::cmp::min(src.len(), name.len() - 1);
            name[..copy_len].copy_from_slice(&src[..copy_len]);
            UserSlice::new(arg2, name.len())
                .copy_from_slice(root_pa, &name)
                .ok_or(Errno::Fault)?;
            Ok(0)
        }
        _ => Err(Errno::Inval),
    }
}

fn sys_sched_setaffinity(_pid: usize, len: usize, mask: usize) -> Result<usize, Errno> {
    let size = size_of::<usize>();
    if len < size {
        return Err(Errno::Inval);
    }
    if mask == 0 {
        return Err(Errno::Fault);
    }
    let root_pa = mm::current_root_pa();
    if root_pa == 0 {
        return Err(Errno::Fault);
    }
    if mm::translate_user_ptr(root_pa, mask, size, UserAccess::Read).is_none() {
        return Err(Errno::Fault);
    }
    Ok(0)
}

fn sys_sched_getaffinity(_pid: usize, len: usize, mask: usize) -> Result<usize, Errno> {
    let size = size_of::<usize>();
    if len < size {
        return Err(Errno::Inval);
    }
    if mask == 0 {
        return Err(Errno::Fault);
    }
    let root_pa = mm::current_root_pa();
    if root_pa == 0 {
        return Err(Errno::Fault);
    }
    UserPtr::<usize>::new(mask)
        .write(root_pa, 1)
        .ok_or(Errno::Fault)?;
    Ok(size)
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

fn rng_next() -> u64 {
    let mut state = RNG_STATE.load(Ordering::Relaxed);
    if state == 0 {
        state = rng_seed();
    }
    loop {
        let mut x = state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        match RNG_STATE.compare_exchange(state, x, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return x,
            Err(cur) => {
                state = cur;
                if state == 0 {
                    state = rng_seed();
                }
            }
        }
    }
}

fn rng_seed() -> u64 {
    let tick = time::ticks();
    let addr = &RNG_STATE as *const _ as u64;
    tick ^ addr ^ (tick << 32)
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
