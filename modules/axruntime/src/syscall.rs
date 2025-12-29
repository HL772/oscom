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
    NoEnt = 2,
    Exist = 17,
    MFile = 24,
    NoSys = 38,
    Fault = 14,
    Inval = 22,
    Badf = 9,
    Pipe = 29,
    PipeBroken = 32,
    NotDir = 20,
    Range = 34,
    Again = 11,
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
        SYS_OPEN => sys_open(ctx.args[0], ctx.args[1], ctx.args[2]),
        SYS_OPENAT => sys_openat(ctx.args[0], ctx.args[1], ctx.args[2], ctx.args[3]),
        SYS_PIPE2 => sys_pipe2(ctx.args[0], ctx.args[1]),
        SYS_MKNODAT => sys_mknodat(ctx.args[0], ctx.args[1], ctx.args[2], ctx.args[3]),
        SYS_MKDIRAT => sys_mkdirat(ctx.args[0], ctx.args[1], ctx.args[2]),
        SYS_UNLINKAT => sys_unlinkat(ctx.args[0], ctx.args[1], ctx.args[2]),
        SYS_SYMLINKAT => sys_symlinkat(ctx.args[0], ctx.args[1], ctx.args[2]),
        SYS_LINKAT => sys_linkat(ctx.args[0], ctx.args[1], ctx.args[2], ctx.args[3], ctx.args[4]),
        SYS_RENAMEAT => sys_renameat(ctx.args[0], ctx.args[1], ctx.args[2], ctx.args[3]),
        SYS_RENAMEAT2 => sys_renameat2(ctx.args[0], ctx.args[1], ctx.args[2], ctx.args[3], ctx.args[4]),
        SYS_GETDENTS64 => sys_getdents64(ctx.args[0], ctx.args[1], ctx.args[2]),
        SYS_NEWFSTATAT => sys_newfstatat(ctx.args[0], ctx.args[1], ctx.args[2], ctx.args[3]),
        SYS_FACCESSAT => sys_faccessat(ctx.args[0], ctx.args[1], ctx.args[2], ctx.args[3]),
        SYS_STATX => sys_statx(ctx.args[0], ctx.args[1], ctx.args[2], ctx.args[3], ctx.args[4]),
        SYS_READLINKAT => sys_readlinkat(ctx.args[0], ctx.args[1], ctx.args[2], ctx.args[3]),
        SYS_STATFS => sys_statfs(ctx.args[0], ctx.args[1]),
        SYS_FSTATFS => sys_fstatfs(ctx.args[0], ctx.args[1]),
        SYS_FCHMODAT => sys_fchmodat(ctx.args[0], ctx.args[1], ctx.args[2], ctx.args[3]),
        SYS_FCHOWNAT => sys_fchownat(ctx.args[0], ctx.args[1], ctx.args[2], ctx.args[3], ctx.args[4]),
        SYS_UTIMENSAT => sys_utimensat(ctx.args[0], ctx.args[1], ctx.args[2], ctx.args[3]),
        SYS_PPOLL => sys_ppoll(ctx.args[0], ctx.args[1], ctx.args[2], ctx.args[3], ctx.args[4]),
        SYS_PPOLL_TIME64 => sys_ppoll(ctx.args[0], ctx.args[1], ctx.args[2], ctx.args[3], ctx.args[4]),
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
        SYS_GETRESUID => sys_getresuid(ctx.args[0], ctx.args[1], ctx.args[2]),
        SYS_GETRESGID => sys_getresgid(ctx.args[0], ctx.args[1], ctx.args[2]),
        SYS_GETTID => sys_gettid(),
        SYS_SCHED_YIELD => sys_sched_yield(),
        SYS_SET_TID_ADDRESS => sys_set_tid_address(ctx.args[0]),
        SYS_UNAME => sys_uname(ctx.args[0]),
        SYS_EXIT_GROUP => sys_exit_group(ctx.args[0]),
        SYS_GETCWD => sys_getcwd(ctx.args[0], ctx.args[1]),
        SYS_CHDIR => sys_chdir(ctx.args[0]),
        SYS_FCHDIR => sys_fchdir(ctx.args[0]),
        SYS_CLOSE => sys_close(ctx.args[0]),
        SYS_GETRLIMIT => sys_getrlimit(ctx.args[0], ctx.args[1]),
        SYS_PRLIMIT64 => sys_prlimit64(ctx.args[0], ctx.args[1], ctx.args[2], ctx.args[3]),
        SYS_IOCTL => sys_ioctl(ctx.args[0], ctx.args[1], ctx.args[2]),
        SYS_SYSINFO => sys_sysinfo(ctx.args[0]),
        SYS_GETRANDOM => sys_getrandom(ctx.args[0], ctx.args[1], ctx.args[2]),
        SYS_FSTAT => sys_fstat(ctx.args[0], ctx.args[1]),
        SYS_DUP => sys_dup(ctx.args[0]),
        SYS_DUP3 => sys_dup3(ctx.args[0], ctx.args[1], ctx.args[2]),
        SYS_LSEEK => sys_lseek(ctx.args[0], ctx.args[1], ctx.args[2]),
        SYS_SET_ROBUST_LIST => sys_set_robust_list(ctx.args[0], ctx.args[1]),
        SYS_GET_ROBUST_LIST => sys_get_robust_list(ctx.args[0], ctx.args[1], ctx.args[2]),
        SYS_RT_SIGACTION => sys_rt_sigaction(ctx.args[0], ctx.args[1], ctx.args[2], ctx.args[3]),
        SYS_RT_SIGPROCMASK => sys_rt_sigprocmask(ctx.args[0], ctx.args[1], ctx.args[2], ctx.args[3]),
        SYS_FCNTL => sys_fcntl(ctx.args[0], ctx.args[1], ctx.args[2]),
        SYS_UMASK => sys_umask(ctx.args[0]),
        SYS_PRCTL => sys_prctl(ctx.args[0], ctx.args[1]),
        SYS_SCHED_SETAFFINITY => sys_sched_setaffinity(ctx.args[0], ctx.args[1], ctx.args[2]),
        SYS_SCHED_GETAFFINITY => sys_sched_getaffinity(ctx.args[0], ctx.args[1], ctx.args[2]),
        SYS_GETRUSAGE => sys_getrusage(ctx.args[0], ctx.args[1]),
        SYS_SETPGID => sys_setpgid(ctx.args[0], ctx.args[1]),
        SYS_GETPGID => sys_getpgid(ctx.args[0]),
        SYS_SETSID => sys_setsid(),
        SYS_GETSID => sys_getsid(ctx.args[0]),
        SYS_GETPGRP => sys_getpgrp(),
        SYS_SETPGRP => sys_setpgrp(),
        SYS_GETGROUPS => sys_getgroups(ctx.args[0], ctx.args[1]),
        SYS_SETGROUPS => sys_setgroups(ctx.args[0], ctx.args[1]),
        SYS_GETCPU => sys_getcpu(ctx.args[0], ctx.args[1]),
        _ => Err(Errno::NoSys),
    }
}

const SYS_EXIT: usize = 93;
const SYS_EXIT_GROUP: usize = 94;
const SYS_READ: usize = 63;
const SYS_WRITE: usize = 64;
const SYS_READV: usize = 65;
const SYS_WRITEV: usize = 66;
const SYS_OPEN: usize = 1024;
const SYS_OPENAT: usize = 56;
const SYS_PIPE2: usize = 59;
const SYS_MKNODAT: usize = 33;
const SYS_MKDIRAT: usize = 34;
const SYS_UNLINKAT: usize = 35;
const SYS_SYMLINKAT: usize = 36;
const SYS_LINKAT: usize = 37;
const SYS_RENAMEAT: usize = 38;
const SYS_GETDENTS64: usize = 61;
const SYS_NEWFSTATAT: usize = 79;
const SYS_READLINKAT: usize = 78;
const SYS_FACCESSAT: usize = 48;
const SYS_STATX: usize = 291;
const SYS_STATFS: usize = 43;
const SYS_FSTATFS: usize = 44;
const SYS_FCHMODAT: usize = 53;
const SYS_FCHOWNAT: usize = 54;
const SYS_UTIMENSAT: usize = 88;
const SYS_RENAMEAT2: usize = 276;
const SYS_PPOLL: usize = 73;
const SYS_PPOLL_TIME64: usize = 414;
const SYS_GETCWD: usize = 17;
const SYS_CHDIR: usize = 49;
const SYS_FCHDIR: usize = 50;
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
const SYS_LSEEK: usize = 62;
const SYS_SCHED_SETAFFINITY: usize = 122;
const SYS_SCHED_GETAFFINITY: usize = 123;
const SYS_GETRUSAGE: usize = 165;
const SYS_SETPGID: usize = 154;
const SYS_GETPGID: usize = 155;
const SYS_SETSID: usize = 157;
const SYS_GETSID: usize = 156;
const SYS_GETPGRP: usize = 111;
const SYS_SETPGRP: usize = 112;
const SYS_GETGROUPS: usize = 158;
const SYS_SETGROUPS: usize = 159;
const SYS_GETCPU: usize = 309;

const TIOCGWINSZ: usize = 0x5413;
const TIOCSWINSZ: usize = 0x5414;
const TCGETS: usize = 0x5401;
const TCSETS: usize = 0x5402;
const TCSETSW: usize = 0x5403;
const TCSETSF: usize = 0x5404;
const TIOCGPGRP: usize = 0x540f;
const TIOCSPGRP: usize = 0x5410;
const TIOCSCTTY: usize = 0x540e;
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
const SYS_GETRESUID: usize = 148;
const SYS_GETRESGID: usize = 150;
const SYS_GETTID: usize = 178;
const SYS_SYSINFO: usize = 179;
const SYS_SCHED_YIELD: usize = 124;
const SYS_SET_TID_ADDRESS: usize = 96;
const SYS_UNAME: usize = 160;

const CLOCK_REALTIME: usize = 0;
const CLOCK_MONOTONIC: usize = 1;
const CLOCK_REALTIME_COARSE: usize = 5;
const CLOCK_MONOTONIC_COARSE: usize = 6;
const CLOCK_MONOTONIC_RAW: usize = 4;
const CLOCK_BOOTTIME: usize = 7;
const IOV_MAX: usize = 1024;
const S_IFCHR: u32 = 0o020000;
const O_CLOEXEC: usize = 0x80000;
const O_NONBLOCK: usize = 0x4000;
const O_RDONLY: usize = 0;
const O_WRONLY: usize = 1;
const O_RDWR: usize = 2;
const AT_FDCWD: isize = -100;
const AT_SYMLINK_NOFOLLOW: usize = 0x100;
const AT_SYMLINK_FOLLOW: usize = 0x400;
const AT_EMPTY_PATH: usize = 0x1000;
const FD_TABLE_BASE: usize = 3;
const FD_TABLE_SLOTS: usize = 16;
const PIPE_SLOTS: usize = 8;
const PIPE_BUFFER_SIZE: usize = 512;
const DEV_NULL_PATH: &[u8] = b"/dev/null";
const DEV_ZERO_PATH: &[u8] = b"/dev/zero";
const ROOT_PATH: &[u8] = b"/";
const SIG_BLOCK: usize = 0;
const SIG_UNBLOCK: usize = 1;
const SIG_SETMASK: usize = 2;
const F_GETFD: usize = 1;
const F_SETFD: usize = 2;
const F_GETFL: usize = 3;
const F_SETFL: usize = 4;
const POLLIN: u16 = 0x001;
const POLLOUT: u16 = 0x004;
const POLLERR: u16 = 0x008;
const POLLHUP: u16 = 0x010;
const POLLNVAL: u16 = 0x020;
const PR_SET_NAME: usize = 15;
const PR_GET_NAME: usize = 16;
const GRND_NONBLOCK: usize = 0x1;
const GRND_RANDOM: usize = 0x2;
const RUSAGE_SELF: isize = 0;
const RUSAGE_CHILDREN: isize = -1;
const RUSAGE_THREAD: isize = 1;
const S_IFIFO: u32 = 0o010000;

static RNG_STATE: AtomicU64 = AtomicU64::new(0);
static UMASK: AtomicU64 = AtomicU64::new(0);
const DEFAULT_PRCTL_NAME: [u8; 16] = *b"aurora\0\0\0\0\0\0\0\0\0\0";
static mut PRCTL_NAME: [u8; 16] = DEFAULT_PRCTL_NAME;

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
struct Statfs {
    f_type: u64,
    f_bsize: u64,
    f_blocks: u64,
    f_bfree: u64,
    f_bavail: u64,
    f_files: u64,
    f_ffree: u64,
    f_fsid: [i32; 2],
    f_namelen: u64,
    f_frsize: u64,
    f_flags: u64,
    f_spare: [u64; 4],
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
struct KernelTimeval {
    tv_sec: isize,
    tv_usec: isize,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Rusage {
    ru_utime: KernelTimeval,
    ru_stime: KernelTimeval,
    ru_maxrss: isize,
    ru_ixrss: isize,
    ru_idrss: isize,
    ru_isrss: isize,
    ru_minflt: isize,
    ru_majflt: isize,
    ru_nswap: isize,
    ru_inblock: isize,
    ru_oublock: isize,
    ru_msgsnd: isize,
    ru_msgrcv: isize,
    ru_nsignals: isize,
    ru_nvcsw: isize,
    ru_nivcsw: isize,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FdKind {
    Empty,
    Stdin,
    Stdout,
    Stderr,
    DevNull,
    DevZero,
    PipeRead(usize),
    PipeWrite(usize),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum KnownPath {
    Root,
    DevNull,
    DevZero,
}

#[derive(Clone, Copy)]
struct Pipe {
    used: bool,
    readers: usize,
    writers: usize,
    read_pos: usize,
    write_pos: usize,
    len: usize,
    buf: [u8; PIPE_BUFFER_SIZE],
}

const EMPTY_PIPE: Pipe = Pipe {
    used: false,
    readers: 0,
    writers: 0,
    read_pos: 0,
    write_pos: 0,
    len: 0,
    buf: [0; PIPE_BUFFER_SIZE],
};

// SAFETY: 单核早期阶段，fd 表由 syscall 串行访问。
static mut FD_TABLE: [FdKind; FD_TABLE_SLOTS] = [FdKind::Empty; FD_TABLE_SLOTS];
// SAFETY: 仅用于重定向标准 fd，单核顺序访问。
static mut STDIO_REDIRECT: [Option<FdKind>; 3] = [None, None, None];
// SAFETY: pipe 表在早期阶段串行访问。
static mut PIPES: [Pipe; PIPE_SLOTS] = [EMPTY_PIPE; PIPE_SLOTS];
// SAFETY: pipe 等待队列只在单核早期阶段访问。
static PIPE_READ_WAITERS: [crate::task_wait_queue::TaskWaitQueue; PIPE_SLOTS] = [
    crate::task_wait_queue::TaskWaitQueue::new(),
    crate::task_wait_queue::TaskWaitQueue::new(),
    crate::task_wait_queue::TaskWaitQueue::new(),
    crate::task_wait_queue::TaskWaitQueue::new(),
    crate::task_wait_queue::TaskWaitQueue::new(),
    crate::task_wait_queue::TaskWaitQueue::new(),
    crate::task_wait_queue::TaskWaitQueue::new(),
    crate::task_wait_queue::TaskWaitQueue::new(),
];
static PIPE_WRITE_WAITERS: [crate::task_wait_queue::TaskWaitQueue; PIPE_SLOTS] = [
    crate::task_wait_queue::TaskWaitQueue::new(),
    crate::task_wait_queue::TaskWaitQueue::new(),
    crate::task_wait_queue::TaskWaitQueue::new(),
    crate::task_wait_queue::TaskWaitQueue::new(),
    crate::task_wait_queue::TaskWaitQueue::new(),
    crate::task_wait_queue::TaskWaitQueue::new(),
    crate::task_wait_queue::TaskWaitQueue::new(),
    crate::task_wait_queue::TaskWaitQueue::new(),
];

#[repr(C)]
#[derive(Clone, Copy)]
struct Winsize {
    ws_row: u16,
    ws_col: u16,
    ws_xpixel: u16,
    ws_ypixel: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Termios {
    c_iflag: u32,
    c_oflag: u32,
    c_cflag: u32,
    c_lflag: u32,
    c_line: u8,
    c_cc: [u8; 19],
    c_ispeed: u32,
    c_ospeed: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct PollFd {
    fd: i32,
    events: i16,
    revents: i16,
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
    let root_pa = mm::current_root_pa();
    if root_pa == 0 {
        return Err(Errno::Fault);
    }
    let kind = resolve_fd(fd).ok_or(Errno::Badf)?;
    read_from_kind(kind, root_pa, buf, len)
}

fn sys_write(fd: usize, buf: usize, len: usize) -> Result<usize, Errno> {
    if len == 0 {
        return Ok(0);
    }
    let root_pa = mm::current_root_pa();
    if root_pa == 0 {
        return Err(Errno::Fault);
    }
    let kind = resolve_fd(fd).ok_or(Errno::Badf)?;
    write_to_kind(kind, root_pa, buf, len)
}

fn sys_readv(fd: usize, iov_ptr: usize, iovcnt: usize) -> Result<usize, Errno> {
    if iovcnt == 0 {
        return Ok(0);
    }
    if iovcnt > IOV_MAX {
        return Err(Errno::Inval);
    }
    if iov_ptr == 0 {
        return Err(Errno::Fault);
    }
    let root_pa = mm::current_root_pa();
    if root_pa == 0 {
        return Err(Errno::Fault);
    }
    let kind = resolve_fd(fd).ok_or(Errno::Badf)?;

    let mut total = 0usize;
    for index in 0..iovcnt {
        let iov = load_iovec(root_pa, iov_ptr, index)?;
        if iov.iov_len == 0 {
            continue;
        }
        match read_from_kind(kind, root_pa, iov.iov_base, iov.iov_len) {
            Ok(0) => return Ok(total),
            Ok(read) => {
                total += read;
                if read < iov.iov_len {
                    return Ok(total);
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
    if iovcnt == 0 {
        return Ok(0);
    }
    if iovcnt > IOV_MAX {
        return Err(Errno::Inval);
    }
    if iov_ptr == 0 {
        return Err(Errno::Fault);
    }
    let root_pa = mm::current_root_pa();
    if root_pa == 0 {
        return Err(Errno::Fault);
    }
    let kind = resolve_fd(fd).ok_or(Errno::Badf)?;

    let mut total = 0usize;
    for index in 0..iovcnt {
        let iov = load_iovec(root_pa, iov_ptr, index)?;
        if iov.iov_len == 0 {
            continue;
        }
        match write_to_kind(kind, root_pa, iov.iov_base, iov.iov_len) {
            Ok(written) => {
                total += written;
                if written < iov.iov_len {
                    return Ok(total);
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

fn sys_open(pathname: usize, flags: usize, mode: usize) -> Result<usize, Errno> {
    sys_openat(usize::MAX, pathname, flags, mode)
}

fn sys_pipe2(pipefd: usize, flags: usize) -> Result<usize, Errno> {
    if pipefd == 0 {
        return Err(Errno::Fault);
    }
    if flags & !(O_CLOEXEC | O_NONBLOCK) != 0 {
        return Err(Errno::Inval);
    }
    let root_pa = mm::current_root_pa();
    if root_pa == 0 {
        return Err(Errno::Fault);
    }
    // 占位 pipe：固定缓冲区，空/满时阻塞或返回 EAGAIN。
    let pipe_id = alloc_pipe().ok_or(Errno::MFile)?;
    let read_fd = match alloc_fd(FdKind::PipeRead(pipe_id)) {
        Some(fd) => fd,
        None => {
            free_pipe(pipe_id);
            return Err(Errno::MFile);
        }
    };
    let write_fd = match alloc_fd(FdKind::PipeWrite(pipe_id)) {
        Some(fd) => fd,
        None => {
            let _ = close_fd(read_fd);
            return Err(Errno::MFile);
        }
    };
    let fds = [read_fd as i32, write_fd as i32];
    if UserPtr::new(pipefd).write(root_pa, fds).is_none() {
        let _ = close_fd(read_fd);
        let _ = close_fd(write_fd);
        return Err(Errno::Fault);
    }
    Ok(0)
}

fn sys_openat(_dirfd: usize, pathname: usize, _flags: usize, _mode: usize) -> Result<usize, Errno> {
    if pathname == 0 {
        return Err(Errno::Fault);
    }
    let root_pa = mm::current_root_pa();
    if root_pa == 0 {
        return Err(Errno::Fault);
    }
    if user_path_eq(root_pa, pathname, DEV_NULL_PATH)? {
        return alloc_fd(FdKind::DevNull).ok_or(Errno::MFile);
    }
    if user_path_eq(root_pa, pathname, DEV_ZERO_PATH)? {
        return alloc_fd(FdKind::DevZero).ok_or(Errno::MFile);
    }
    Err(Errno::NoEnt)
}

fn sys_mknodat(dirfd: usize, pathname: usize, _mode: usize, _dev: usize) -> Result<usize, Errno> {
    // 占位实现：仅校验目录 fd 与路径指针，拒绝真实节点创建。
    let root_pa = mm::current_root_pa();
    if root_pa == 0 {
        return Err(Errno::Fault);
    }
    validate_at_dirfd(dirfd)?;
    validate_user_path(root_pa, pathname)?;
    match classify_path(root_pa, pathname)? {
        Some(_) => Err(Errno::Exist),
        None => Err(Errno::NoEnt),
    }
}

fn sys_mkdirat(_dirfd: usize, pathname: usize, _mode: usize) -> Result<usize, Errno> {
    if pathname == 0 {
        return Err(Errno::Fault);
    }
    let root_pa = mm::current_root_pa();
    if root_pa == 0 {
        return Err(Errno::Fault);
    }
    if user_path_eq(root_pa, pathname, ROOT_PATH)? {
        return Err(Errno::Exist);
    }
    Err(Errno::NoEnt)
}

fn sys_unlinkat(_dirfd: usize, pathname: usize, _flags: usize) -> Result<usize, Errno> {
    if pathname == 0 {
        return Err(Errno::Fault);
    }
    let root_pa = mm::current_root_pa();
    if root_pa == 0 {
        return Err(Errno::Fault);
    }
    if user_path_eq(root_pa, pathname, ROOT_PATH)? {
        return Err(Errno::Inval);
    }
    Err(Errno::NoEnt)
}

fn sys_symlinkat(oldpath: usize, newdirfd: usize, newpath: usize) -> Result<usize, Errno> {
    // 占位实现：仅验证路径指针与目标是否存在。
    let root_pa = mm::current_root_pa();
    if root_pa == 0 {
        return Err(Errno::Fault);
    }
    validate_at_dirfd(newdirfd)?;
    validate_user_path(root_pa, oldpath)?;
    validate_user_path(root_pa, newpath)?;
    match classify_path(root_pa, newpath)? {
        Some(_) => Err(Errno::Exist),
        None => Err(Errno::NoEnt),
    }
}

fn sys_linkat(
    olddirfd: usize,
    oldpath: usize,
    newdirfd: usize,
    newpath: usize,
    flags: usize,
) -> Result<usize, Errno> {
    // 占位实现：旧路径必须已知，新路径不能存在，否则返回占位错误。
    if flags & !AT_SYMLINK_FOLLOW != 0 {
        return Err(Errno::Inval);
    }
    let root_pa = mm::current_root_pa();
    if root_pa == 0 {
        return Err(Errno::Fault);
    }
    validate_at_dirfd(olddirfd)?;
    validate_at_dirfd(newdirfd)?;
    validate_user_path(root_pa, oldpath)?;
    validate_user_path(root_pa, newpath)?;
    if classify_path(root_pa, oldpath)?.is_none() {
        return Err(Errno::NoEnt);
    }
    if classify_path(root_pa, newpath)?.is_some() {
        return Err(Errno::Exist);
    }
    Err(Errno::NoEnt)
}

fn sys_renameat(olddirfd: usize, oldpath: usize, newdirfd: usize, newpath: usize) -> Result<usize, Errno> {
    sys_renameat2(olddirfd, oldpath, newdirfd, newpath, 0)
}

fn sys_renameat2(
    olddirfd: usize,
    oldpath: usize,
    newdirfd: usize,
    newpath: usize,
    flags: usize,
) -> Result<usize, Errno> {
    // 占位实现：仅支持 flags=0，且不执行真实重命名。
    if flags != 0 {
        return Err(Errno::Inval);
    }
    let root_pa = mm::current_root_pa();
    if root_pa == 0 {
        return Err(Errno::Fault);
    }
    validate_at_dirfd(olddirfd)?;
    validate_at_dirfd(newdirfd)?;
    validate_user_path(root_pa, oldpath)?;
    validate_user_path(root_pa, newpath)?;
    let old_kind = classify_path(root_pa, oldpath)?;
    let new_kind = classify_path(root_pa, newpath)?;
    match (old_kind, new_kind) {
        (Some(old), Some(new)) if old == new => Ok(0),
        (Some(_), Some(_)) => Err(Errno::Exist),
        (Some(_), None) => Err(Errno::NoEnt),
        (None, _) => Err(Errno::NoEnt),
    }
}

fn sys_getdents64(fd: usize, buf: usize, len: usize) -> Result<usize, Errno> {
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
    validate_user_write(root_pa, buf, len)?;
    if resolve_fd(fd).is_some() {
        return Err(Errno::NotDir);
    }
    Err(Errno::Badf)
}

fn sys_newfstatat(_dirfd: usize, pathname: usize, stat_ptr: usize, _flags: usize) -> Result<usize, Errno> {
    if pathname == 0 || stat_ptr == 0 {
        return Err(Errno::Fault);
    }
    let root_pa = mm::current_root_pa();
    if root_pa == 0 {
        return Err(Errno::Fault);
    }
    if mm::translate_user_ptr(root_pa, pathname, 1, UserAccess::Read).is_none() {
        return Err(Errno::Fault);
    }
    let size = size_of::<Stat>();
    if mm::translate_user_ptr(root_pa, stat_ptr, size, UserAccess::Write).is_none() {
        return Err(Errno::Fault);
    }
    Err(Errno::NoEnt)
}

fn sys_faccessat(_dirfd: usize, pathname: usize, _mode: usize, _flags: usize) -> Result<usize, Errno> {
    if pathname == 0 {
        return Err(Errno::Fault);
    }
    let root_pa = mm::current_root_pa();
    if root_pa == 0 {
        return Err(Errno::Fault);
    }
    if user_path_eq(root_pa, pathname, DEV_NULL_PATH)? || user_path_eq(root_pa, pathname, DEV_ZERO_PATH)? {
        return Ok(0);
    }
    Err(Errno::NoEnt)
}

fn sys_statx(
    _dirfd: usize,
    pathname: usize,
    _flags: usize,
    _mask: usize,
    statxbuf: usize,
) -> Result<usize, Errno> {
    if pathname == 0 || statxbuf == 0 {
        return Err(Errno::Fault);
    }
    let root_pa = mm::current_root_pa();
    if root_pa == 0 {
        return Err(Errno::Fault);
    }
    if user_path_eq(root_pa, pathname, DEV_NULL_PATH)? || user_path_eq(root_pa, pathname, DEV_ZERO_PATH)? {
        const STATX_SIZE: usize = 256;
        zero_user_write(root_pa, statxbuf, STATX_SIZE)?;
        return Ok(0);
    }
    Err(Errno::NoEnt)
}

fn sys_readlinkat(_dirfd: usize, pathname: usize, buf: usize, len: usize) -> Result<usize, Errno> {
    if pathname == 0 || buf == 0 {
        return Err(Errno::Fault);
    }
    let root_pa = mm::current_root_pa();
    if root_pa == 0 {
        return Err(Errno::Fault);
    }
    if len == 0 {
        return Ok(0);
    }
    validate_user_write(root_pa, buf, len)?;
    if user_path_eq(root_pa, pathname, DEV_NULL_PATH)? || user_path_eq(root_pa, pathname, DEV_ZERO_PATH)? {
        return Err(Errno::Inval);
    }
    Err(Errno::NoEnt)
}

fn sys_statfs(pathname: usize, buf: usize) -> Result<usize, Errno> {
    if pathname == 0 || buf == 0 {
        return Err(Errno::Fault);
    }
    let root_pa = mm::current_root_pa();
    if root_pa == 0 {
        return Err(Errno::Fault);
    }
    // 占位实现：只允许根目录与 /dev/null,/dev/zero。
    validate_user_path(root_pa, pathname)?;
    match classify_path(root_pa, pathname)? {
        Some(_) => {
            UserPtr::new(buf)
                .write(root_pa, default_statfs())
                .ok_or(Errno::Fault)?;
            Ok(0)
        }
        None => Err(Errno::NoEnt),
    }
}

fn sys_fstatfs(fd: usize, buf: usize) -> Result<usize, Errno> {
    if buf == 0 {
        return Err(Errno::Fault);
    }
    let root_pa = mm::current_root_pa();
    if root_pa == 0 {
        return Err(Errno::Fault);
    }
    // 占位实现：识别标准 fd / pseudo fd / pipe。
    if resolve_fd(fd).is_none() {
        return Err(Errno::Badf);
    }
    UserPtr::new(buf)
        .write(root_pa, default_statfs())
        .ok_or(Errno::Fault)?;
    Ok(0)
}

fn sys_fchmodat(dirfd: usize, pathname: usize, _mode: usize, flags: usize) -> Result<usize, Errno> {
    // 占位实现：仅支持 AT_FDCWD 与 AT_SYMLINK_NOFOLLOW。
    if flags & !AT_SYMLINK_NOFOLLOW != 0 {
        return Err(Errno::Inval);
    }
    let root_pa = mm::current_root_pa();
    if root_pa == 0 {
        return Err(Errno::Fault);
    }
    validate_at_dirfd(dirfd)?;
    validate_user_path(root_pa, pathname)?;
    match classify_path(root_pa, pathname)? {
        Some(_) => Ok(0),
        None => Err(Errno::NoEnt),
    }
}

fn sys_fchownat(
    dirfd: usize,
    pathname: usize,
    _owner: usize,
    _group: usize,
    flags: usize,
) -> Result<usize, Errno> {
    // 占位实现：仅支持 AT_FDCWD 与 AT_SYMLINK_NOFOLLOW。
    if flags & !AT_SYMLINK_NOFOLLOW != 0 {
        return Err(Errno::Inval);
    }
    let root_pa = mm::current_root_pa();
    if root_pa == 0 {
        return Err(Errno::Fault);
    }
    validate_at_dirfd(dirfd)?;
    validate_user_path(root_pa, pathname)?;
    match classify_path(root_pa, pathname)? {
        Some(_) => Ok(0),
        None => Err(Errno::NoEnt),
    }
}

fn sys_utimensat(dirfd: usize, pathname: usize, times: usize, flags: usize) -> Result<usize, Errno> {
    // 占位实现：忽略时间内容，仅做指针与 flags 校验。
    if flags & !AT_SYMLINK_NOFOLLOW != 0 {
        return Err(Errno::Inval);
    }
    let root_pa = mm::current_root_pa();
    if root_pa == 0 {
        return Err(Errno::Fault);
    }
    validate_at_dirfd(dirfd)?;
    validate_user_path(root_pa, pathname)?;
    if times != 0 {
        let size = size_of::<Timespec>() * 2;
        validate_user_read(root_pa, times, size)?;
    }
    match classify_path(root_pa, pathname)? {
        Some(_) => Ok(0),
        None => Err(Errno::NoEnt),
    }
}

fn sys_ppoll(fds: usize, nfds: usize, tmo: usize, _sigmask: usize, _sigsetsize: usize) -> Result<usize, Errno> {
    if nfds == 0 {
        return Ok(0);
    }
    if fds == 0 {
        return Err(Errno::Fault);
    }
    let root_pa = mm::current_root_pa();
    if root_pa == 0 {
        return Err(Errno::Fault);
    }
    let stride = size_of::<PollFd>();
    let total = nfds.checked_mul(stride).ok_or(Errno::Fault)?;
    validate_user_read(root_pa, fds, total)?;
    validate_user_write(root_pa, fds, total)?;
    let mut ready = 0usize;
    let mut single_fd = None;
    let mut single_events = 0u16;
    for index in 0..nfds {
        let base = index
            .checked_mul(stride)
            .and_then(|off| fds.checked_add(off))
            .ok_or(Errno::Fault)?;
        let mut pollfd = UserPtr::<PollFd>::new(base)
            .read(root_pa)
            .ok_or(Errno::Fault)?;
        let events = pollfd.events as u16;
        let revents = poll_revents_for_fd(pollfd.fd, events);
        if revents != 0 {
            ready += 1;
        }
        if nfds == 1 {
            single_fd = Some(pollfd.fd);
            single_events = events;
        }
        pollfd.revents = revents as i16;
        UserPtr::new(base)
            .write(root_pa, pollfd)
            .ok_or(Errno::Fault)?;
    }
    if ready > 0 || !can_block_current() || nfds != 1 {
        return Ok(ready);
    }
    let Some(fd) = single_fd else {
        return Ok(0);
    };
    let Some(queue) = ppoll_single_waiter_queue(fd, single_events) else {
        return Ok(0);
    };
    let timeout_ms = ppoll_timeout_ms(root_pa, tmo)?;
    if let Some(timeout_ms) = timeout_ms {
        if timeout_ms == 0 {
            return Ok(0);
        }
        let _ = crate::runtime::wait_timeout_ms(queue, timeout_ms);
    } else {
        crate::runtime::block_current(queue);
    }
    let base = fds;
    let mut pollfd = UserPtr::<PollFd>::new(base)
        .read(root_pa)
        .ok_or(Errno::Fault)?;
    let revents = poll_revents_for_fd(pollfd.fd, pollfd.events as u16);
    pollfd.revents = revents as i16;
    UserPtr::new(base)
        .write(root_pa, pollfd)
        .ok_or(Errno::Fault)?;
    Ok(if revents != 0 { 1 } else { 0 })
}

fn sys_clock_gettime(clock_id: usize, tp: usize) -> Result<usize, Errno> {
    if tp == 0 {
        return Err(Errno::Fault);
    }
    let now_ns = time::monotonic_ns();
    let ts = Timespec {
        tv_sec: (now_ns / 1_000_000_000) as i64,
        tv_nsec: (now_ns % 1_000_000_000) as i64,
    };
    match clock_id {
        CLOCK_REALTIME
        | CLOCK_MONOTONIC
        | CLOCK_REALTIME_COARSE
        | CLOCK_MONOTONIC_COARSE
        | CLOCK_MONOTONIC_RAW
        | CLOCK_BOOTTIME => {
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
    let hz = match time::timebase_hz() {
        0 => time::tick_hz(),
        value => value,
    };
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
        CLOCK_REALTIME
        | CLOCK_MONOTONIC
        | CLOCK_REALTIME_COARSE
        | CLOCK_MONOTONIC_COARSE
        | CLOCK_MONOTONIC_RAW
        | CLOCK_BOOTTIME => {
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
        let now_ns = time::monotonic_ns();
        let tv_val = Timeval {
            tv_sec: (now_ns / 1_000_000_000) as i64,
            tv_usec: ((now_ns % 1_000_000_000) / 1_000) as i64,
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
    if sleep_ms > 0 {
        let slept = crate::runtime::sleep_current_ms(sleep_ms);
        if !slept {
            let deadline = time::monotonic_ns().saturating_add(total_ns);
            while time::monotonic_ns() < deadline {
                crate::cpu::wait_for_interrupt();
            }
        }
    }
    if rem != 0 {
        let zero = Timespec { tv_sec: 0, tv_nsec: 0 };
        UserPtr::new(rem).write(root_pa, zero).ok_or(Errno::Fault)?;
    }
    Ok(0)
}

fn sys_getpid() -> Result<usize, Errno> {
    Ok(current_pid())
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

fn sys_getresuid(ruid: usize, euid: usize, suid: usize) -> Result<usize, Errno> {
    let root_pa = mm::current_root_pa();
    if root_pa == 0 {
        return Err(Errno::Fault);
    }
    if ruid != 0 {
        UserPtr::new(ruid).write(root_pa, 0usize).ok_or(Errno::Fault)?;
    }
    if euid != 0 {
        UserPtr::new(euid).write(root_pa, 0usize).ok_or(Errno::Fault)?;
    }
    if suid != 0 {
        UserPtr::new(suid).write(root_pa, 0usize).ok_or(Errno::Fault)?;
    }
    Ok(0)
}

fn sys_getresgid(rgid: usize, egid: usize, sgid: usize) -> Result<usize, Errno> {
    let root_pa = mm::current_root_pa();
    if root_pa == 0 {
        return Err(Errno::Fault);
    }
    if rgid != 0 {
        UserPtr::new(rgid).write(root_pa, 0usize).ok_or(Errno::Fault)?;
    }
    if egid != 0 {
        UserPtr::new(egid).write(root_pa, 0usize).ok_or(Errno::Fault)?;
    }
    if sgid != 0 {
        UserPtr::new(sgid).write(root_pa, 0usize).ok_or(Errno::Fault)?;
    }
    Ok(0)
}

fn sys_gettid() -> Result<usize, Errno> {
    Ok(current_pid())
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
    Ok(current_pid())
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

fn sys_chdir(pathname: usize) -> Result<usize, Errno> {
    if pathname == 0 {
        return Err(Errno::Fault);
    }
    let root_pa = mm::current_root_pa();
    if root_pa == 0 {
        return Err(Errno::Fault);
    }
    if user_path_eq(root_pa, pathname, ROOT_PATH)? {
        return Ok(0);
    }
    Err(Errno::NoEnt)
}

fn sys_fchdir(fd: usize) -> Result<usize, Errno> {
    if resolve_fd(fd).is_some() {
        return Err(Errno::NotDir);
    }
    Err(Errno::Badf)
}

fn sys_close(fd: usize) -> Result<usize, Errno> {
    close_fd(fd)
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
    let kind = resolve_fd(fd).ok_or(Errno::Badf)?;
    if matches!(kind, FdKind::PipeRead(_) | FdKind::PipeWrite(_)) {
        return Err(Errno::Inval);
    }
    match cmd {
        TIOCGWINSZ => {
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
        TIOCSWINSZ => {
            if arg == 0 {
                return Err(Errno::Fault);
            }
            let root_pa = mm::current_root_pa();
            if root_pa == 0 {
                return Err(Errno::Fault);
            }
            UserPtr::<Winsize>::new(arg)
                .read(root_pa)
                .ok_or(Errno::Fault)?;
            Ok(0)
        }
        TIOCGPGRP => {
            if arg == 0 {
                return Err(Errno::Fault);
            }
            let root_pa = mm::current_root_pa();
            if root_pa == 0 {
                return Err(Errno::Fault);
            }
            UserPtr::new(arg)
                .write(root_pa, current_pid())
                .ok_or(Errno::Fault)?;
            Ok(0)
        }
        TIOCSPGRP => {
            if arg == 0 {
                return Err(Errno::Fault);
            }
            let root_pa = mm::current_root_pa();
            if root_pa == 0 {
                return Err(Errno::Fault);
            }
            UserPtr::<usize>::new(arg)
                .read(root_pa)
                .ok_or(Errno::Fault)?;
            Ok(0)
        }
        TIOCSCTTY => Ok(0),
        TCGETS => {
            if arg == 0 {
                return Err(Errno::Fault);
            }
            let root_pa = mm::current_root_pa();
            if root_pa == 0 {
                return Err(Errno::Fault);
            }
            let termios = Termios {
                c_iflag: 0,
                c_oflag: 0,
                c_cflag: 0,
                c_lflag: 0,
                c_line: 0,
                c_cc: [0; 19],
                c_ispeed: 0,
                c_ospeed: 0,
            };
            UserPtr::new(arg).write(root_pa, termios).ok_or(Errno::Fault)?;
            Ok(0)
        }
        TCSETS | TCSETSW | TCSETSF => {
            if arg == 0 {
                return Err(Errno::Fault);
            }
            let root_pa = mm::current_root_pa();
            if root_pa == 0 {
                return Err(Errno::Fault);
            }
            UserPtr::<Termios>::new(arg)
                .read(root_pa)
                .ok_or(Errno::Fault)?;
            Ok(0)
        }
        _ => Err(Errno::Inval),
    }
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
    let uptime = (time::monotonic_ns() / 1_000_000_000) as i64;
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

fn sys_getrandom(buf: usize, len: usize, flags: usize) -> Result<usize, Errno> {
    if len == 0 {
        return Ok(0);
    }
    if flags & !(GRND_NONBLOCK | GRND_RANDOM) != 0 {
        return Err(Errno::Inval);
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
    let kind = resolve_fd(fd).ok_or(Errno::Badf)?;
    let root_pa = mm::current_root_pa();
    if root_pa == 0 {
        return Err(Errno::Fault);
    }
    let now_ns = time::monotonic_ns();
    let sec = (now_ns / 1_000_000_000) as isize;
    let nsec = (now_ns % 1_000_000_000) as usize;
    let mode = match kind {
        FdKind::PipeRead(_) | FdKind::PipeWrite(_) => S_IFIFO | 0o600,
        _ => S_IFCHR | 0o666,
    };
    let stat = Stat {
        st_dev: 0,
        st_ino: 0,
        st_mode: mode,
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
    let kind = resolve_fd(oldfd).ok_or(Errno::Badf)?;
    alloc_fd(kind).ok_or(Errno::MFile)
}

fn sys_dup3(oldfd: usize, newfd: usize, flags: usize) -> Result<usize, Errno> {
    let kind = resolve_fd(oldfd).ok_or(Errno::Badf)?;
    if flags != 0 && flags != O_CLOEXEC {
        return Err(Errno::Inval);
    }
    if oldfd == newfd {
        return if flags == 0 { Ok(newfd) } else { Err(Errno::Inval) };
    }
    dup_to_fd(newfd, kind)
}

fn sys_lseek(fd: usize, _offset: usize, _whence: usize) -> Result<usize, Errno> {
    if resolve_fd(fd).is_some() {
        return Err(Errno::Pipe);
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
    let kind = resolve_fd(fd).ok_or(Errno::Badf)?;
    match cmd {
        F_GETFD => Ok(0),
        F_SETFD => Ok(0),
        F_GETFL => {
            let mode = match kind {
                FdKind::Stdin | FdKind::PipeRead(_) => O_RDONLY,
                FdKind::Stdout | FdKind::Stderr | FdKind::PipeWrite(_) => O_WRONLY,
                _ => O_RDWR,
            };
            Ok(mode)
        }
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
            let mut name = [0u8; 16];
            UserSlice::new(arg2, name.len())
                .copy_to_slice(root_pa, &mut name)
                .ok_or(Errno::Fault)?;
            if let Some(pos) = name.iter().position(|&b| b == 0) {
                for byte in &mut name[pos + 1..] {
                    *byte = 0;
                }
            } else {
                name[15] = 0;
            }
            // SAFETY: single-hart early boot; process name is updated atomically.
            unsafe {
                PRCTL_NAME = name;
            }
            Ok(0)
        }
        PR_GET_NAME => {
            if arg2 == 0 {
                return Err(Errno::Fault);
            }
            // SAFETY: single-hart early boot; process name is read atomically.
            let name = unsafe { PRCTL_NAME };
            UserSlice::new(arg2, name.len()).copy_from_slice(root_pa, &name)
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
    UserSlice::new(mask, len)
        .for_each_chunk(root_pa, UserAccess::Write, |pa, chunk| {
            // SAFETY: 翻译结果确保该片段在用户态可写。
            unsafe {
                core::ptr::write_bytes(pa as *mut u8, 0, chunk);
            }
            Some(())
        })
        .ok_or(Errno::Fault)?;
    UserPtr::<usize>::new(mask)
        .write(root_pa, 1)
        .ok_or(Errno::Fault)?;
    Ok(size)
}

fn sys_getrusage(who: usize, usage: usize) -> Result<usize, Errno> {
    if usage == 0 {
        return Err(Errno::Fault);
    }
    let who = who as isize;
    if who != RUSAGE_SELF && who != RUSAGE_CHILDREN && who != RUSAGE_THREAD {
        return Err(Errno::Inval);
    }
    let root_pa = mm::current_root_pa();
    if root_pa == 0 {
        return Err(Errno::Fault);
    }
    let now_ns = time::monotonic_ns();
    let user_time = KernelTimeval {
        tv_sec: (now_ns / 1_000_000_000) as isize,
        tv_usec: ((now_ns % 1_000_000_000) / 1_000) as isize,
    };
    let zero = KernelTimeval { tv_sec: 0, tv_usec: 0 };
    let usage_val = Rusage {
        ru_utime: user_time,
        ru_stime: zero,
        ru_maxrss: 0,
        ru_ixrss: 0,
        ru_idrss: 0,
        ru_isrss: 0,
        ru_minflt: 0,
        ru_majflt: 0,
        ru_nswap: 0,
        ru_inblock: 0,
        ru_oublock: 0,
        ru_msgsnd: 0,
        ru_msgrcv: 0,
        ru_nsignals: 0,
        ru_nvcsw: 0,
        ru_nivcsw: 0,
    };
    UserPtr::new(usage)
        .write(root_pa, usage_val)
        .ok_or(Errno::Fault)?;
    Ok(0)
}

fn sys_setpgid(_pid: usize, _pgid: usize) -> Result<usize, Errno> {
    Ok(0)
}

fn sys_getpgid(_pid: usize) -> Result<usize, Errno> {
    Ok(current_pid())
}

fn sys_setsid() -> Result<usize, Errno> {
    Ok(current_pid())
}

fn sys_getsid(_pid: usize) -> Result<usize, Errno> {
    Ok(current_pid())
}

fn sys_getpgrp() -> Result<usize, Errno> {
    Ok(current_pid())
}

fn sys_setpgrp() -> Result<usize, Errno> {
    Ok(0)
}

fn sys_getgroups(size: usize, list: usize) -> Result<usize, Errno> {
    if size == 0 {
        return Ok(0);
    }
    if list == 0 {
        return Err(Errno::Fault);
    }
    let root_pa = mm::current_root_pa();
    if root_pa == 0 {
        return Err(Errno::Fault);
    }
    if mm::translate_user_ptr(root_pa, list, 1, UserAccess::Write).is_none() {
        return Err(Errno::Fault);
    }
    Ok(0)
}

fn sys_setgroups(size: usize, list: usize) -> Result<usize, Errno> {
    if size == 0 {
        return Ok(0);
    }
    if list == 0 {
        return Err(Errno::Fault);
    }
    let root_pa = mm::current_root_pa();
    if root_pa == 0 {
        return Err(Errno::Fault);
    }
    if mm::translate_user_ptr(root_pa, list, 1, UserAccess::Read).is_none() {
        return Err(Errno::Fault);
    }
    Ok(0)
}

fn sys_getcpu(cpu: usize, node: usize) -> Result<usize, Errno> {
    let root_pa = mm::current_root_pa();
    if root_pa == 0 {
        return Err(Errno::Fault);
    }
    if cpu != 0 {
        UserPtr::new(cpu).write(root_pa, 0usize).ok_or(Errno::Fault)?;
    }
    if node != 0 {
        UserPtr::new(node).write(root_pa, 0usize).ok_or(Errno::Fault)?;
    }
    Ok(0)
}

fn current_pid() -> usize {
    // Single-hart early boot uses TaskId+1 as a stable placeholder PID.
    crate::runtime::current_task_id().map(|id| id + 1).unwrap_or(1)
}

fn validate_at_dirfd(dirfd: usize) -> Result<(), Errno> {
    // 仅支持 AT_FDCWD，占位阶段不维护真实目录 fd。
    if dirfd as isize == AT_FDCWD {
        return Ok(());
    }
    if resolve_fd(dirfd).is_some() {
        return Err(Errno::NotDir);
    }
    Err(Errno::Badf)
}

fn validate_user_path(root_pa: usize, path: usize) -> Result<(), Errno> {
    if path == 0 {
        return Err(Errno::Fault);
    }
    // 只读取首字节，确保指针可访问，避免提前扫描整条路径。
    read_user_byte(root_pa, path)?;
    Ok(())
}

fn classify_path(root_pa: usize, path: usize) -> Result<Option<KnownPath>, Errno> {
    // 仅识别根目录与 /dev/null,/dev/zero，避免误判。
    if user_path_eq(root_pa, path, ROOT_PATH)? {
        return Ok(Some(KnownPath::Root));
    }
    if user_path_eq(root_pa, path, DEV_NULL_PATH)? {
        return Ok(Some(KnownPath::DevNull));
    }
    if user_path_eq(root_pa, path, DEV_ZERO_PATH)? {
        return Ok(Some(KnownPath::DevZero));
    }
    Ok(None)
}

fn can_block_current() -> bool {
    crate::runtime::current_task_id().is_some()
}

fn pipe_read_queue(pipe_id: usize) -> &'static crate::task_wait_queue::TaskWaitQueue {
    &PIPE_READ_WAITERS[pipe_id]
}

fn pipe_write_queue(pipe_id: usize) -> &'static crate::task_wait_queue::TaskWaitQueue {
    &PIPE_WRITE_WAITERS[pipe_id]
}

fn default_statfs() -> Statfs {
    // 使用内存容量填充占位 statfs，保证用户态工具有可读值。
    const TMPFS_MAGIC: u64 = 0x0102_1994;
    let bsize = 4096u64;
    let total_bytes = mm::memory_size() as u64;
    let blocks = total_bytes / bsize;
    Statfs {
        f_type: TMPFS_MAGIC,
        f_bsize: bsize,
        f_blocks: blocks,
        f_bfree: blocks,
        f_bavail: blocks,
        f_files: 0,
        f_ffree: 0,
        f_fsid: [0, 0],
        f_namelen: 255,
        f_frsize: bsize,
        f_flags: 0,
        f_spare: [0; 4],
    }
}

fn user_path_eq(root_pa: usize, ptr: usize, target: &[u8]) -> Result<bool, Errno> {
    for (idx, &expected) in target.iter().enumerate() {
        let addr = ptr.checked_add(idx).ok_or(Errno::Fault)?;
        let ch = read_user_byte(root_pa, addr)?;
        if ch == 0 || ch != expected {
            return Ok(false);
        }
    }
    let term_addr = ptr.checked_add(target.len()).ok_or(Errno::Fault)?;
    Ok(read_user_byte(root_pa, term_addr)? == 0)
}

fn stdio_kind(fd: usize) -> Option<FdKind> {
    match fd {
        0 => Some(FdKind::Stdin),
        1 => Some(FdKind::Stdout),
        2 => Some(FdKind::Stderr),
        _ => None,
    }
}

fn resolve_fd(fd: usize) -> Option<FdKind> {
    if let Some(kind) = stdio_kind(fd) {
        // SAFETY: 单核早期阶段访问重定向表。
        let redirect = unsafe { STDIO_REDIRECT[fd] };
        return Some(redirect.unwrap_or(kind));
    }
    if fd < FD_TABLE_BASE {
        return None;
    }
    let idx = fd - FD_TABLE_BASE;
    if idx >= FD_TABLE_SLOTS {
        return None;
    }
    // SAFETY: 单核早期阶段，fd 表无并发访问。
    let kind = unsafe { FD_TABLE[idx] };
    if kind == FdKind::Empty {
        None
    } else {
        Some(kind)
    }
}

fn alloc_fd(kind: FdKind) -> Option<usize> {
    if kind == FdKind::Empty {
        return None;
    }
    // SAFETY: 单核早期阶段，fd 表串行更新。
    unsafe {
        for (idx, slot) in FD_TABLE.iter_mut().enumerate() {
            if *slot == FdKind::Empty {
                *slot = kind;
                pipe_acquire(kind);
                return Some(FD_TABLE_BASE + idx);
            }
        }
    }
    None
}

fn dup_to_fd(newfd: usize, kind: FdKind) -> Result<usize, Errno> {
    if stdio_kind(newfd).is_some() {
        return set_stdio_redirect(newfd, kind);
    }
    if newfd < FD_TABLE_BASE {
        return Err(Errno::Badf);
    }
    let idx = newfd - FD_TABLE_BASE;
    if idx >= FD_TABLE_SLOTS {
        return Err(Errno::Badf);
    }
    // SAFETY: 单核早期阶段，fd 表串行更新。
    unsafe {
        let old = FD_TABLE[idx];
        if old != FdKind::Empty {
            pipe_release(old);
        }
        FD_TABLE[idx] = kind;
    }
    pipe_acquire(kind);
    Ok(newfd)
}

fn close_fd(fd: usize) -> Result<usize, Errno> {
    if stdio_kind(fd).is_some() {
        // SAFETY: 单核早期阶段访问重定向表。
        unsafe {
            if let Some(old) = STDIO_REDIRECT[fd] {
                pipe_release(old);
                STDIO_REDIRECT[fd] = None;
            }
        }
        return Ok(0);
    }
    if fd < FD_TABLE_BASE {
        return Err(Errno::Badf);
    }
    let idx = fd - FD_TABLE_BASE;
    if idx >= FD_TABLE_SLOTS {
        return Err(Errno::Badf);
    }
    // SAFETY: 单核早期阶段，fd 表串行更新。
    unsafe {
        let old = FD_TABLE[idx];
        if old == FdKind::Empty {
            return Err(Errno::Badf);
        }
        FD_TABLE[idx] = FdKind::Empty;
        pipe_release(old);
    }
    Ok(0)
}

fn set_stdio_redirect(fd: usize, kind: FdKind) -> Result<usize, Errno> {
    if stdio_kind(fd).is_none() {
        return Err(Errno::Badf);
    }
    // SAFETY: 单核早期阶段访问重定向表。
    unsafe {
        if let Some(old) = STDIO_REDIRECT[fd] {
            pipe_release(old);
        }
        STDIO_REDIRECT[fd] = Some(kind);
    }
    pipe_acquire(kind);
    Ok(fd)
}

fn alloc_pipe() -> Option<usize> {
    // SAFETY: 单核早期阶段串行更新 pipe 表。
    unsafe {
        for (idx, pipe) in PIPES.iter_mut().enumerate() {
            if !pipe.used {
                *pipe = Pipe {
                    used: true,
                    readers: 0,
                    writers: 0,
                    read_pos: 0,
                    write_pos: 0,
                    len: 0,
                    buf: [0; PIPE_BUFFER_SIZE],
                };
                return Some(idx);
            }
        }
    }
    None
}

fn free_pipe(pipe_id: usize) {
    if pipe_id >= PIPE_SLOTS {
        return;
    }
    // SAFETY: 单核早期阶段串行更新 pipe 表。
    unsafe {
        PIPES[pipe_id] = EMPTY_PIPE;
    }
}

fn pipe_acquire(kind: FdKind) {
    let (pipe_id, is_read) = match kind {
        FdKind::PipeRead(id) => (id, true),
        FdKind::PipeWrite(id) => (id, false),
        _ => return,
    };
    if pipe_id >= PIPE_SLOTS {
        return;
    }
    // SAFETY: 单核早期阶段串行更新 pipe 表。
    unsafe {
        if !PIPES[pipe_id].used {
            return;
        }
        if is_read {
            PIPES[pipe_id].readers += 1;
        } else {
            PIPES[pipe_id].writers += 1;
        }
    }
}

fn pipe_release(kind: FdKind) {
    let (pipe_id, is_read) = match kind {
        FdKind::PipeRead(id) => (id, true),
        FdKind::PipeWrite(id) => (id, false),
        _ => return,
    };
    if pipe_id >= PIPE_SLOTS {
        return;
    }
    // SAFETY: 单核早期阶段串行更新 pipe 表。
    unsafe {
        if !PIPES[pipe_id].used {
            return;
        }
        if is_read {
            if PIPES[pipe_id].readers > 0 {
                PIPES[pipe_id].readers -= 1;
            }
        } else if PIPES[pipe_id].writers > 0 {
            PIPES[pipe_id].writers -= 1;
        }
    }
    if unsafe { PIPES[pipe_id].writers == 0 } {
        let _ = crate::runtime::wake_all(pipe_read_queue(pipe_id));
    }
    if unsafe { PIPES[pipe_id].readers == 0 } {
        let _ = crate::runtime::wake_all(pipe_write_queue(pipe_id));
    }
    if unsafe { PIPES[pipe_id].readers == 0 && PIPES[pipe_id].writers == 0 } {
        unsafe {
            PIPES[pipe_id] = EMPTY_PIPE;
        }
    }
}

fn pipe_read(pipe_id: usize, root_pa: usize, buf: usize, len: usize) -> Result<usize, Errno> {
    if pipe_id >= PIPE_SLOTS {
        return Err(Errno::Badf);
    }
    if len == 0 {
        return Ok(0);
    }
    loop {
        let (used, available, writers) = unsafe {
            let pipe = &PIPES[pipe_id];
            (pipe.used, pipe.len, pipe.writers)
        };
        if !used {
            return Err(Errno::Badf);
        }
        if available == 0 {
            if writers == 0 {
                return Ok(0);
            }
            if !can_block_current() {
                return Err(Errno::Again);
            }
            crate::runtime::block_current(pipe_read_queue(pipe_id));
            continue;
        }
        break;
    }
    // SAFETY: 单核早期阶段串行访问 pipe。
    let pipe = unsafe { &mut PIPES[pipe_id] };
    let to_read = min(len, pipe.len);
    let mut remaining = to_read;
    let mut offset = 0usize;
    while remaining > 0 {
        let chunk = min(remaining, PIPE_BUFFER_SIZE - pipe.read_pos);
        let dst = buf.checked_add(offset).ok_or(Errno::Fault)?;
        let src = &pipe.buf[pipe.read_pos..pipe.read_pos + chunk];
        UserSlice::new(dst, chunk)
            .copy_from_slice(root_pa, src)
            .ok_or(Errno::Fault)?;
        pipe.read_pos = (pipe.read_pos + chunk) % PIPE_BUFFER_SIZE;
        pipe.len -= chunk;
        remaining -= chunk;
        offset += chunk;
    }
    let _ = crate::runtime::wake_one(pipe_write_queue(pipe_id));
    Ok(to_read)
}

fn pipe_write(pipe_id: usize, root_pa: usize, buf: usize, len: usize) -> Result<usize, Errno> {
    if pipe_id >= PIPE_SLOTS {
        return Err(Errno::Badf);
    }
    if len == 0 {
        return Ok(0);
    }
    loop {
        let (used, readers, used_len) = unsafe {
            let pipe = &PIPES[pipe_id];
            (pipe.used, pipe.readers, pipe.len)
        };
        if !used {
            return Err(Errno::Badf);
        }
        if readers == 0 {
            return Err(Errno::PipeBroken);
        }
        let avail = PIPE_BUFFER_SIZE.saturating_sub(used_len);
        if avail == 0 {
            if !can_block_current() {
                return Err(Errno::Again);
            }
            crate::runtime::block_current(pipe_write_queue(pipe_id));
            continue;
        }
        break;
    }
    // SAFETY: 单核早期阶段串行访问 pipe。
    let pipe = unsafe { &mut PIPES[pipe_id] };
    let avail = PIPE_BUFFER_SIZE.saturating_sub(pipe.len);
    let to_write = min(len, avail);
    let mut remaining = to_write;
    let mut offset = 0usize;
    while remaining > 0 {
        let chunk = min(remaining, PIPE_BUFFER_SIZE - pipe.write_pos);
        let src = buf.checked_add(offset).ok_or(Errno::Fault)?;
        let dst = &mut pipe.buf[pipe.write_pos..pipe.write_pos + chunk];
        UserSlice::new(src, chunk)
            .copy_to_slice(root_pa, dst)
            .ok_or(Errno::Fault)?;
        pipe.write_pos = (pipe.write_pos + chunk) % PIPE_BUFFER_SIZE;
        pipe.len += chunk;
        remaining -= chunk;
        offset += chunk;
    }
    let _ = crate::runtime::wake_one(pipe_read_queue(pipe_id));
    Ok(to_write)
}

fn pipe_snapshot(pipe_id: usize) -> Option<(usize, usize, usize)> {
    if pipe_id >= PIPE_SLOTS {
        return None;
    }
    // SAFETY: 单核早期阶段串行读取 pipe 状态。
    let pipe = unsafe { &PIPES[pipe_id] };
    if !pipe.used {
        return None;
    }
    Some((pipe.len, pipe.readers, pipe.writers))
}

fn poll_revents_for_fd(fd: i32, events: u16) -> u16 {
    if fd < 0 {
        return POLLNVAL;
    }
    let fd = fd as usize;
    let kind = match resolve_fd(fd) {
        Some(kind) => kind,
        None => return POLLNVAL,
    };
    match kind {
        FdKind::PipeRead(pipe_id) => {
            let (len, _readers, writers) = match pipe_snapshot(pipe_id) {
                Some(state) => state,
                None => return POLLNVAL,
            };
            let mut revents = 0u16;
            if (events & POLLIN) != 0 && len > 0 {
                revents |= POLLIN;
            }
            if writers == 0 {
                revents |= POLLHUP;
                if (events & POLLIN) != 0 {
                    revents |= POLLIN;
                }
            }
            revents
        }
        FdKind::PipeWrite(pipe_id) => {
            let (len, readers, _writers) = match pipe_snapshot(pipe_id) {
                Some(state) => state,
                None => return POLLNVAL,
            };
            let mut revents = 0u16;
            if readers == 0 {
                revents |= POLLERR | POLLHUP;
                return revents;
            }
            let avail = PIPE_BUFFER_SIZE.saturating_sub(len);
            if (events & POLLOUT) != 0 && avail > 0 {
                revents |= POLLOUT;
            }
            revents
        }
        FdKind::Stdout | FdKind::Stderr => {
            if (events & POLLOUT) != 0 {
                POLLOUT
            } else {
                0
            }
        }
        FdKind::DevNull | FdKind::DevZero => {
            let mut revents = 0u16;
            if (events & POLLIN) != 0 {
                revents |= POLLIN;
            }
            if (events & POLLOUT) != 0 {
                revents |= POLLOUT;
            }
            revents
        }
        _ => 0,
    }
}

fn ppoll_timeout_ms(root_pa: usize, tmo: usize) -> Result<Option<u64>, Errno> {
    if tmo == 0 {
        return Ok(None);
    }
    let ts = UserPtr::<Timespec>::new(tmo)
        .read(root_pa)
        .ok_or(Errno::Fault)?;
    if ts.tv_sec < 0 || ts.tv_nsec < 0 || ts.tv_nsec >= 1_000_000_000 {
        return Err(Errno::Inval);
    }
    let total_ns = (ts.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(ts.tv_nsec as u64);
    let timeout_ms = total_ns.saturating_add(999_999) / 1_000_000;
    Ok(Some(timeout_ms))
}

fn ppoll_single_waiter_queue(fd: i32, events: u16) -> Option<&'static crate::task_wait_queue::TaskWaitQueue> {
    if fd < 0 {
        return None;
    }
    let kind = resolve_fd(fd as usize)?;
    match kind {
        FdKind::PipeRead(pipe_id) if (events & POLLIN) != 0 => Some(pipe_read_queue(pipe_id)),
        FdKind::PipeWrite(pipe_id) if (events & POLLOUT) != 0 => Some(pipe_write_queue(pipe_id)),
        _ => None,
    }
}

fn read_from_kind(kind: FdKind, root_pa: usize, buf: usize, len: usize) -> Result<usize, Errno> {
    match kind {
        FdKind::Stdin => read_console_into(root_pa, buf, len),
        FdKind::DevNull => Ok(0),
        FdKind::DevZero => {
            zero_user_write(root_pa, buf, len)?;
            Ok(len)
        }
        FdKind::PipeRead(pipe_id) => pipe_read(pipe_id, root_pa, buf, len),
        FdKind::Stdout | FdKind::Stderr | FdKind::PipeWrite(_) => Err(Errno::Badf),
        FdKind::Empty => Err(Errno::Badf),
    }
}

fn write_to_kind(kind: FdKind, root_pa: usize, buf: usize, len: usize) -> Result<usize, Errno> {
    match kind {
        FdKind::Stdout | FdKind::Stderr => write_console_from(root_pa, buf, len),
        FdKind::DevNull | FdKind::DevZero => {
            validate_user_read(root_pa, buf, len)?;
            Ok(len)
        }
        FdKind::PipeWrite(pipe_id) => pipe_write(pipe_id, root_pa, buf, len),
        FdKind::Stdin | FdKind::PipeRead(_) => Err(Errno::Badf),
        FdKind::Empty => Err(Errno::Badf),
    }
}

fn read_user_byte(root_pa: usize, addr: usize) -> Result<u8, Errno> {
    let pa = mm::translate_user_ptr(root_pa, addr, 1, UserAccess::Read)
        .ok_or(Errno::Fault)?;
    // SAFETY: 已验证用户态权限与范围。
    Ok(unsafe { *(pa as *const u8) })
}

fn validate_user_read(root_pa: usize, addr: usize, len: usize) -> Result<(), Errno> {
    UserSlice::new(addr, len)
        .for_each_chunk(root_pa, UserAccess::Read, |_, _| Some(()))
        .ok_or(Errno::Fault)?;
    Ok(())
}

fn validate_user_write(root_pa: usize, addr: usize, len: usize) -> Result<(), Errno> {
    UserSlice::new(addr, len)
        .for_each_chunk(root_pa, UserAccess::Write, |_, _| Some(()))
        .ok_or(Errno::Fault)?;
    Ok(())
}

fn zero_user_write(root_pa: usize, addr: usize, len: usize) -> Result<(), Errno> {
    UserSlice::new(addr, len)
        .for_each_chunk(root_pa, UserAccess::Write, |pa, chunk| {
            // SAFETY: 翻译结果确保该片段在用户态可写。
            unsafe {
                core::ptr::write_bytes(pa as *mut u8, 0, chunk);
            }
            Some(())
        })
        .ok_or(Errno::Fault)?;
    Ok(())
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
                        return if read == 0 { Err(Errno::Again) } else { Ok(read) };
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
