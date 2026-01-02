#![allow(dead_code)]

use core::cmp::min;
use core::mem::{size_of, MaybeUninit};
use core::sync::atomic::{AtomicU64, AtomicU8, Ordering};

use axfs::{devfs, ext4, fat32, memfs, procfs, DirEntry, FileType, InodeId, VfsError, VfsOps};
use axfs::mount::{MountId, MountPoint, MountTable};
use crate::futex;
use crate::mm::{self, UserAccess, UserPtr, UserSlice};
use crate::{sbi, time};
use crate::task::TaskId;
use crate::trap::TrapFrame;

#[repr(i32)]
#[derive(Debug, Clone, Copy)]
pub enum Errno {
    NoEnt = 2,
    Exist = 17,
    IsDir = 21,
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
    NoMem = 12,
    Child = 10,
    NetUnreach = 101,
    IsConn = 106,
    NotConn = 107,
    ConnRefused = 111,
    TimedOut = 110,
    InProgress = 115,
}

impl Errno {
    pub fn to_ret(self) -> usize {
        (-(self as isize)) as usize
    }
}

const ROOTFS_LOG_EXT4: u8 = 1 << 0;
const ROOTFS_LOG_FAT32: u8 = 1 << 1;
const ROOTFS_LOG_MEMFS: u8 = 1 << 2;
const ROOTFS_KIND_UNKNOWN: u8 = 0;
const ROOTFS_KIND_EXT4: u8 = 1;
const ROOTFS_KIND_FAT32: u8 = 2;
const ROOTFS_KIND_MEMFS: u8 = 3;

// Avoid repeated rootfs log spam across per-syscall mount table creation.
static ROOTFS_LOGGED: AtomicU8 = AtomicU8::new(0);
// Rootfs kind is initialized once and reused to keep block cache state stable.
static ROOTFS_KIND: AtomicU8 = AtomicU8::new(ROOTFS_KIND_UNKNOWN);
static EXT4_WRITE_DONE: AtomicU8 = AtomicU8::new(0);
// SAFETY: rootfs instances are initialized once in single-core boot and then shared read-only.
static mut ROOTFS_EXT4: MaybeUninit<ext4::Ext4Fs<'static>> = MaybeUninit::uninit();
// SAFETY: rootfs instances are initialized once in single-core boot and then shared read-only.
static mut ROOTFS_FAT32: MaybeUninit<fat32::Fat32Fs<'static>> = MaybeUninit::uninit();
// SAFETY: rootfs instances are initialized once in single-core boot and then shared read-only.
static mut ROOTFS_MEMFS: MaybeUninit<memfs::MemFs<'static>> = MaybeUninit::uninit();
static DEVFS: devfs::DevFs = devfs::DevFs::new();
static PROCFS: procfs::ProcFs = procfs::ProcFs::new();
static TCP_CONNECT_LOGGED: AtomicU8 = AtomicU8::new(0);
static TCP_ACCEPT_LOGGED: AtomicU8 = AtomicU8::new(0);
static TCP_RECV_LOGGED: AtomicU8 = AtomicU8::new(0);

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
    let ret = dispatch(tf, ctx);
    tf.a0 = match ret {
        Ok(value) => value,
        Err(err) => err.to_ret(),
    };
    tf.sepc = tf.sepc.wrapping_add(4);
}

fn dispatch(tf: &mut TrapFrame, ctx: SyscallContext) -> Result<usize, Errno> {
    match ctx.nr {
        SYS_EVENTFD2 => sys_eventfd2(ctx.args[0], ctx.args[1]),
        SYS_EPOLL_CREATE1 => sys_epoll_create1(ctx.args[0]),
        SYS_EPOLL_CTL => sys_epoll_ctl(ctx.args[0], ctx.args[1], ctx.args[2], ctx.args[3]),
        SYS_EPOLL_PWAIT => sys_epoll_pwait(
            ctx.args[0],
            ctx.args[1],
            ctx.args[2],
            ctx.args[3],
            ctx.args[4],
            ctx.args[5],
        ),
        SYS_EPOLL_PWAIT2 => sys_epoll_pwait2(
            ctx.args[0],
            ctx.args[1],
            ctx.args[2],
            ctx.args[3],
            ctx.args[4],
            ctx.args[5],
        ),
        SYS_TIMERFD_CREATE => sys_timerfd_create(ctx.args[0], ctx.args[1]),
        SYS_TIMERFD_SETTIME => sys_timerfd_settime(ctx.args[0], ctx.args[1], ctx.args[2], ctx.args[3]),
        SYS_TIMERFD_GETTIME => sys_timerfd_gettime(ctx.args[0], ctx.args[1]),
        SYS_TIMERFD_SETTIME64 => sys_timerfd_settime(ctx.args[0], ctx.args[1], ctx.args[2], ctx.args[3]),
        SYS_TIMERFD_GETTIME64 => sys_timerfd_gettime(ctx.args[0], ctx.args[1]),
        SYS_EXIT => sys_exit(ctx.args[0]),
        SYS_EXECVE => sys_execve(tf, ctx.args[0], ctx.args[1], ctx.args[2]),
        SYS_CLONE => sys_clone(tf, ctx.args[0], ctx.args[1], ctx.args[2], ctx.args[3], ctx.args[4]),
        SYS_BRK => sys_brk(ctx.args[0]),
        SYS_MMAP => sys_mmap(
            ctx.args[0],
            ctx.args[1],
            ctx.args[2],
            ctx.args[3],
            ctx.args[4],
            ctx.args[5],
        ),
        SYS_MUNMAP => sys_munmap(ctx.args[0], ctx.args[1]),
        SYS_MPROTECT => sys_mprotect(ctx.args[0], ctx.args[1], ctx.args[2]),
        SYS_MADVISE => sys_madvise(ctx.args[0], ctx.args[1], ctx.args[2]),
        SYS_RSEQ => sys_rseq(ctx.args[0], ctx.args[1], ctx.args[2], ctx.args[3]),
        SYS_READ => sys_read(ctx.args[0], ctx.args[1], ctx.args[2]),
        SYS_PREAD64 => sys_pread64(ctx.args[0], ctx.args[1], ctx.args[2], ctx.args[3]),
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
        SYS_READLINK => sys_readlink(ctx.args[0], ctx.args[1], ctx.args[2]),
        SYS_READLINKAT => sys_readlinkat(ctx.args[0], ctx.args[1], ctx.args[2], ctx.args[3]),
        SYS_STATFS => sys_statfs(ctx.args[0], ctx.args[1]),
        SYS_FSTATFS => sys_fstatfs(ctx.args[0], ctx.args[1]),
        SYS_FTRUNCATE => sys_ftruncate(ctx.args[0], ctx.args[1]),
        SYS_FCHMODAT => sys_fchmodat(ctx.args[0], ctx.args[1], ctx.args[2], ctx.args[3]),
        SYS_FCHOWNAT => sys_fchownat(ctx.args[0], ctx.args[1], ctx.args[2], ctx.args[3], ctx.args[4]),
        SYS_UTIMENSAT => sys_utimensat(ctx.args[0], ctx.args[1], ctx.args[2], ctx.args[3]),
        SYS_POLL => sys_poll(ctx.args[0], ctx.args[1], ctx.args[2]),
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
        SYS_FUTEX => sys_futex(ctx.args[0], ctx.args[1], ctx.args[2], ctx.args[3], ctx.args[4], ctx.args[5]),
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
        SYS_WAIT4 => sys_wait4(ctx.args[0], ctx.args[1], ctx.args[2], ctx.args[3]),
        SYS_SOCKET => sys_socket(ctx.args[0], ctx.args[1], ctx.args[2]),
        SYS_BIND => sys_bind(ctx.args[0], ctx.args[1], ctx.args[2]),
        SYS_GETSOCKNAME => sys_getsockname(ctx.args[0], ctx.args[1], ctx.args[2]),
        SYS_GETPEERNAME => sys_getpeername(ctx.args[0], ctx.args[1], ctx.args[2]),
        SYS_CONNECT => sys_connect(ctx.args[0], ctx.args[1], ctx.args[2]),
        SYS_SETSOCKOPT => sys_setsockopt(ctx.args[0], ctx.args[1], ctx.args[2], ctx.args[3], ctx.args[4]),
        SYS_GETSOCKOPT => sys_getsockopt(ctx.args[0], ctx.args[1], ctx.args[2], ctx.args[3], ctx.args[4]),
        SYS_SHUTDOWN => sys_shutdown(ctx.args[0], ctx.args[1]),
        SYS_LISTEN => sys_listen(ctx.args[0], ctx.args[1]),
        SYS_ACCEPT => sys_accept(ctx.args[0], ctx.args[1], ctx.args[2]),
        SYS_SENDTO => sys_sendto(ctx.args[0], ctx.args[1], ctx.args[2], ctx.args[3], ctx.args[4], ctx.args[5]),
        SYS_RECVFROM => sys_recvfrom(ctx.args[0], ctx.args[1], ctx.args[2], ctx.args[3], ctx.args[4], ctx.args[5]),
        SYS_SENDMSG => sys_sendmsg(ctx.args[0], ctx.args[1], ctx.args[2]),
        SYS_RECVMSG => sys_recvmsg(ctx.args[0], ctx.args[1], ctx.args[2]),
        SYS_SENDMMSG => sys_sendmmsg(ctx.args[0], ctx.args[1], ctx.args[2], ctx.args[3]),
        SYS_RECVMMSG => sys_recvmmsg(ctx.args[0], ctx.args[1], ctx.args[2], ctx.args[3], ctx.args[4]),
        _ => Err(Errno::NoSys),
    }
}

const SYS_EXIT: usize = 93;
const SYS_EXIT_GROUP: usize = 94;
const SYS_CLONE: usize = 220;
const SYS_EXECVE: usize = 221;
const SYS_BRK: usize = 214;
const SYS_MUNMAP: usize = 215;
const SYS_MMAP: usize = 222;
const SYS_MPROTECT: usize = 226;
const SYS_MADVISE: usize = 233;
const SYS_RSEQ: usize = 293;
const SYS_EVENTFD2: usize = 19;
const SYS_EPOLL_CREATE1: usize = 20;
const SYS_EPOLL_CTL: usize = 21;
const SYS_EPOLL_PWAIT: usize = 22;
const SYS_TIMERFD_CREATE: usize = 85;
const SYS_TIMERFD_SETTIME: usize = 86;
const SYS_TIMERFD_GETTIME: usize = 87;
const SYS_TIMERFD_GETTIME64: usize = 410;
const SYS_TIMERFD_SETTIME64: usize = 411;
const SYS_EPOLL_PWAIT2: usize = 441;
const SYS_READ: usize = 63;
const SYS_PREAD64: usize = 67;
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
const SYS_READLINK: usize = 89;
const SYS_READLINKAT: usize = 78;
const SYS_FACCESSAT: usize = 48;
const SYS_STATX: usize = 291;
const SYS_STATFS: usize = 43;
const SYS_FSTATFS: usize = 44;
const SYS_FTRUNCATE: usize = 46;
const SYS_FCHMODAT: usize = 53;
const SYS_FCHOWNAT: usize = 54;
const SYS_UTIMENSAT: usize = 88;
const SYS_RENAMEAT2: usize = 276;
const SYS_POLL: usize = 7;
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
const SYS_FUTEX: usize = 98;
const SYS_DUP: usize = 23;
const SYS_DUP3: usize = 24;
const SYS_SET_ROBUST_LIST: usize = 99;
const SYS_GET_ROBUST_LIST: usize = 100;
const SYS_RT_SIGACTION: usize = 134;
const SYS_RT_SIGPROCMASK: usize = 135;
const SYS_FCNTL: usize = 25;
const SYS_UMASK: usize = 166;
const SYS_PRCTL: usize = 167;
const SYS_SOCKET: usize = 198;
const SYS_BIND: usize = 200;
const SYS_GETSOCKNAME: usize = 204;
const SYS_GETPEERNAME: usize = 205;
const SYS_LISTEN: usize = 201;
const SYS_ACCEPT: usize = 202;
const SYS_CONNECT: usize = 203;
const SYS_SETSOCKOPT: usize = 208;
const SYS_GETSOCKOPT: usize = 209;
const SYS_SHUTDOWN: usize = 210;
const SYS_SENDTO: usize = 206;
const SYS_RECVFROM: usize = 207;
const SYS_SENDMSG: usize = 211;
const SYS_RECVMSG: usize = 212;
const SYS_SENDMMSG: usize = 269;
const SYS_RECVMMSG: usize = 243;
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
const SYS_WAIT4: usize = 260;

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

const PROT_READ: usize = 0x1;
const PROT_WRITE: usize = 0x2;
const PROT_EXEC: usize = 0x4;
const MAP_SHARED: usize = 0x01;
const MAP_PRIVATE: usize = 0x02;
const MAP_FIXED: usize = 0x10;
const MAP_ANON: usize = 0x20;
const S_IFCHR: u32 = 0o020000;
const S_IFBLK: u32 = 0o060000;
const S_IFDIR: u32 = 0o040000;
const S_IFREG: u32 = 0o100000;
const O_CLOEXEC: usize = 0x80000;
const O_NONBLOCK: usize = 0x4000;
const O_CREAT: usize = 0x40;
const O_EXCL: usize = 0x80;
const O_TRUNC: usize = 0x200;
const O_APPEND: usize = 0x400;
const O_RDONLY: usize = 0;
const O_WRONLY: usize = 1;
const O_RDWR: usize = 2;
const O_ACCMODE: usize = 3;
const SOL_SOCKET: usize = 1;
const SO_REUSEADDR: usize = 2;
const SO_ERROR: usize = 4;
const SO_RCVTIMEO: usize = 20;
const SO_SNDTIMEO: usize = 21;
const SHUT_RD: usize = 0;
const SHUT_WR: usize = 1;
const SHUT_RDWR: usize = 2;
const AT_FDCWD: isize = -100;
const AT_SYMLINK_NOFOLLOW: usize = 0x100;
const AT_SYMLINK_FOLLOW: usize = 0x400;
const AT_EMPTY_PATH: usize = 0x1000;
const FD_TABLE_BASE: usize = 3;
const FD_TABLE_SLOTS: usize = 16;
const MAX_PROCS: usize = crate::config::MAX_TASKS;
const PIPE_SLOTS: usize = 8;
const PIPE_BUFFER_SIZE: usize = 512;
const EVENTFD_SLOTS: usize = 16;
const TIMERFD_SLOTS: usize = 16;
const EPOLL_SLOTS: usize = 16;
const EPOLL_ITEM_SLOTS: usize = 64;
const MAX_PATH_LEN: usize = 128;
const VFS_MOUNT_COUNT: usize = 3;
const SIG_BLOCK: usize = 0;
const SIG_UNBLOCK: usize = 1;
const SIG_SETMASK: usize = 2;
const F_GETFD: usize = 1;
const F_SETFD: usize = 2;
const F_GETFL: usize = 3;
const F_SETFL: usize = 4;
const SEEK_SET: usize = 0;
const SEEK_CUR: usize = 1;
const SEEK_END: usize = 2;
const EPOLL_CTL_ADD: usize = 1;
const EPOLL_CTL_DEL: usize = 2;
const EPOLL_CTL_MOD: usize = 3;
const EPOLLIN: u32 = 0x001;
const EPOLLOUT: u32 = 0x004;
const EPOLLERR: u32 = 0x008;
const EPOLLHUP: u32 = 0x010;
const EPOLL_CLOEXEC: usize = 0x80000;
const EFD_SEMAPHORE: usize = 0x1;
const EFD_NONBLOCK: usize = 0x800;
const EFD_CLOEXEC: usize = 0x80000;
const TFD_NONBLOCK: usize = 0x800;
const TFD_CLOEXEC: usize = 0x80000;
const TFD_TIMER_ABSTIME: usize = 0x1;
const POLLIN: u16 = 0x001;
const POLLOUT: u16 = 0x004;
const POLLERR: u16 = 0x008;
const POLLHUP: u16 = 0x010;
const POLLNVAL: u16 = 0x020;
const PPOLL_RETRY_SLEEP_MS: u64 = 10;
const EPOLL_RETRY_SLEEP_MS: u64 = 10;
const PR_SET_NAME: usize = 15;
const PR_GET_NAME: usize = 16;
const GRND_NONBLOCK: usize = 0x1;
const GRND_RANDOM: usize = 0x2;
const RUSAGE_SELF: isize = 0;
const RUSAGE_CHILDREN: isize = -1;
const RUSAGE_THREAD: isize = 1;
const S_IFIFO: u32 = 0o010000;

static RNG_STATE: AtomicU64 = AtomicU64::new(0);
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
struct Itimerspec {
    it_interval: Timespec,
    it_value: Timespec,
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
struct MsgHdr {
    msg_name: usize,
    msg_namelen: u32,
    msg_namelen_pad: u32,
    msg_iov: usize,
    msg_iovlen: usize,
    msg_control: usize,
    msg_controllen: usize,
    msg_flags: i32,
    msg_flags_pad: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct MMsgHdr {
    msg_hdr: MsgHdr,
    msg_len: u32,
    msg_len_pad: u32,
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
struct VfsHandle {
    mount: MountId,
    inode: InodeId,
    file_type: FileType,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FdKind {
    Empty,
    Stdin,
    Stdout,
    Stderr,
    Vfs(VfsHandle),
    PipeRead(usize),
    PipeWrite(usize),
    Socket(axnet::SocketId),
    Eventfd(usize),
    Timerfd(usize),
    Epoll(usize),
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct FdEntry {
    kind: FdKind,
    flags: usize,
    offset: usize,
    recv_timeout_ms: u64,
    send_timeout_ms: u64,
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

#[derive(Clone, Copy)]
struct EventFd {
    used: bool,
    refs: usize,
    counter: u64,
    flags: usize,
}

#[derive(Clone, Copy)]
struct TimerFd {
    used: bool,
    refs: usize,
    next_ns: u64,
    interval_ns: u64,
    flags: usize,
}

#[derive(Clone, Copy)]
struct EpollItem {
    used: bool,
    fd: i32,
    events: u32,
    data: u64,
}

#[derive(Clone, Copy)]
struct EpollInstance {
    used: bool,
    refs: usize,
    flags: usize,
    items: [EpollItem; EPOLL_ITEM_SLOTS],
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

const EMPTY_EVENTFD: EventFd = EventFd {
    used: false,
    refs: 0,
    counter: 0,
    flags: 0,
};

const EMPTY_TIMERFD: TimerFd = TimerFd {
    used: false,
    refs: 0,
    next_ns: 0,
    interval_ns: 0,
    flags: 0,
};

const EMPTY_EPOLL_ITEM: EpollItem = EpollItem {
    used: false,
    fd: -1,
    events: 0,
    data: 0,
};

const EMPTY_EPOLL: EpollInstance = EpollInstance {
    used: false,
    refs: 0,
    flags: 0,
    items: [EMPTY_EPOLL_ITEM; EPOLL_ITEM_SLOTS],
};

const EMPTY_FD_ENTRY: FdEntry = FdEntry {
    kind: FdKind::Empty,
    flags: 0,
    offset: 0,
    recv_timeout_ms: 0,
    send_timeout_ms: 0,
};

// SAFETY: 单核早期阶段，fd 表按进程索引串行访问。
static mut FD_TABLES: [[FdEntry; FD_TABLE_SLOTS]; MAX_PROCS] = [[EMPTY_FD_ENTRY; FD_TABLE_SLOTS]; MAX_PROCS];
// SAFETY: 仅用于重定向标准 fd，单核阶段按进程顺序访问。
static mut STDIO_REDIRECT: [[Option<FdEntry>; 3]; MAX_PROCS] = [[None; 3]; MAX_PROCS];
// SAFETY: 标准 fd 的状态标志在单核阶段按进程顺序访问。
static mut STDIO_FLAGS: [[usize; 3]; MAX_PROCS] = [[0; 3]; MAX_PROCS];
// SAFETY: 当前工作目录缓存按进程顺序访问。
static mut PROC_CWD: [[u8; MAX_PATH_LEN]; MAX_PROCS] = [[0; MAX_PATH_LEN]; MAX_PROCS];
// SAFETY: 当前工作目录长度按进程顺序访问。
static mut PROC_CWD_LEN: [usize; MAX_PROCS] = [0; MAX_PROCS];
// SAFETY: umask 按进程顺序访问。
static mut PROC_UMASK: [u16; MAX_PROCS] = [0; MAX_PROCS];
// SAFETY: 控制台输入缓存仅在单核阶段顺序访问。
static mut CONSOLE_STASH: i16 = -1;
// SAFETY: pipe 表在早期阶段串行访问。
static mut PIPES: [Pipe; PIPE_SLOTS] = [EMPTY_PIPE; PIPE_SLOTS];
// SAFETY: eventfd 表在早期阶段串行访问。
static mut EVENTFDS: [EventFd; EVENTFD_SLOTS] = [EMPTY_EVENTFD; EVENTFD_SLOTS];
// SAFETY: timerfd 表在早期阶段串行访问。
static mut TIMERFDS: [TimerFd; TIMERFD_SLOTS] = [EMPTY_TIMERFD; TIMERFD_SLOTS];
// SAFETY: epoll 表在早期阶段串行访问。
static mut EPOLLS: [EpollInstance; EPOLL_SLOTS] = [EMPTY_EPOLL; EPOLL_SLOTS];
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
// SAFETY: eventfd 等待队列只在单核早期阶段访问。
static EVENTFD_WAITERS: [crate::task_wait_queue::TaskWaitQueue; EVENTFD_SLOTS] = [
    crate::task_wait_queue::TaskWaitQueue::new(),
    crate::task_wait_queue::TaskWaitQueue::new(),
    crate::task_wait_queue::TaskWaitQueue::new(),
    crate::task_wait_queue::TaskWaitQueue::new(),
    crate::task_wait_queue::TaskWaitQueue::new(),
    crate::task_wait_queue::TaskWaitQueue::new(),
    crate::task_wait_queue::TaskWaitQueue::new(),
    crate::task_wait_queue::TaskWaitQueue::new(),
    crate::task_wait_queue::TaskWaitQueue::new(),
    crate::task_wait_queue::TaskWaitQueue::new(),
    crate::task_wait_queue::TaskWaitQueue::new(),
    crate::task_wait_queue::TaskWaitQueue::new(),
    crate::task_wait_queue::TaskWaitQueue::new(),
    crate::task_wait_queue::TaskWaitQueue::new(),
    crate::task_wait_queue::TaskWaitQueue::new(),
    crate::task_wait_queue::TaskWaitQueue::new(),
];
// SAFETY: timerfd 等待队列只在单核早期阶段访问。
static TIMERFD_WAITERS: [crate::task_wait_queue::TaskWaitQueue; TIMERFD_SLOTS] = [
    crate::task_wait_queue::TaskWaitQueue::new(),
    crate::task_wait_queue::TaskWaitQueue::new(),
    crate::task_wait_queue::TaskWaitQueue::new(),
    crate::task_wait_queue::TaskWaitQueue::new(),
    crate::task_wait_queue::TaskWaitQueue::new(),
    crate::task_wait_queue::TaskWaitQueue::new(),
    crate::task_wait_queue::TaskWaitQueue::new(),
    crate::task_wait_queue::TaskWaitQueue::new(),
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
// SAFETY: poll/ppoll 共享等待队列在单核阶段顺序访问。
static POLL_WAITERS: crate::task_wait_queue::TaskWaitQueue = crate::task_wait_queue::TaskWaitQueue::new();

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

#[repr(C)]
#[derive(Clone, Copy)]
struct EpollEvent {
    events: u32,
    data: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SockAddrIn {
    sin_family: u16,
    sin_port: u16,
    sin_addr: u32,
    sin_zero: [u8; 8],
}

const AF_INET: u16 = 2;
const SOCK_STREAM: usize = 1;
const SOCK_DGRAM: usize = 2;
const SOCK_NONBLOCK: usize = 0x800;

fn sys_exit(_code: usize) -> Result<usize, Errno> {
    let pid = crate::process::current_pid().unwrap_or(1);
    if pid == 1 {
        crate::sbi::shutdown();
    }
    if crate::process::exit_current(_code as i32) {
        crate::runtime::exit_current();
    }
    crate::sbi::shutdown();
}

fn sys_exit_group(code: usize) -> Result<usize, Errno> {
    sys_exit(code)
}

fn sys_execve(tf: &mut TrapFrame, pathname: usize, argv: usize, envp: usize) -> Result<usize, Errno> {
    if pathname == 0 {
        return Err(Errno::Fault);
    }
    let root_pa = mm::current_root_pa();
    if root_pa == 0 {
        return Err(Errno::Fault);
    }
    if cfg!(feature = "user-tcp-echo") {
        let mut buf = [0u8; 128];
        match read_user_path_str(root_pa, pathname, &mut buf) {
            Ok(path) => crate::println!("sys_execve: trying {}", path),
            Err(_) => crate::println!("sys_execve: trying <invalid path>"),
        }
    }
    validate_user_path(root_pa, pathname)?;
    validate_user_ptr_list(root_pa, argv)?;
    validate_user_ptr_list(root_pa, envp)?;
    // 通过 VFS 读取目标 ELF 镜像，统一路径与加载链路。
    let image = match execve_vfs_image(root_pa, pathname) {
        Ok(image) => image,
        Err(err) => {
            if cfg!(feature = "user-tcp-echo") {
                crate::println!("sys_execve: read image failed ({:?})", err);
            }
            return Err(err);
        }
    };
    let ctx = match crate::user::load_exec_elf(root_pa, image, argv, envp) {
        Ok(ctx) => ctx,
        Err(err) => {
            if cfg!(feature = "user-tcp-echo") {
                crate::println!("sys_execve: load elf failed ({:?})", err);
            }
            return Err(err);
        }
    };
    if cfg!(feature = "user-tcp-echo") {
        crate::println!("sys_execve: success entry={:#x} sp={:#x}", ctx.entry, ctx.user_sp);
    }
    // execve 成功后不返回，更新入口与用户栈并清理参数寄存器。
    tf.sepc = ctx.entry.wrapping_sub(4);
    tf.a0 = ctx.argc;
    tf.a1 = ctx.argv;
    tf.a2 = ctx.envp;
    mm::switch_root(ctx.root_pa);
    tf.user_sp = ctx.user_sp;
    if let Some(task_id) = crate::runtime::current_task_id() {
        let _ = crate::task::set_user_context(task_id, ctx.root_pa, ctx.entry, ctx.user_sp);
        let _ = crate::task::set_heap_top(task_id, ctx.heap_top);
    }
    let _ = crate::process::update_current_root(ctx.root_pa);
    if ctx.root_pa != root_pa {
        crate::mm::release_user_root(root_pa);
    }
    Ok(ctx.argc)
}

fn sys_brk(addr: usize) -> Result<usize, Errno> {
    let task_id = crate::runtime::current_task_id().ok_or(Errno::Fault)?;
    let old_brk = crate::task::heap_top(task_id).ok_or(Errno::Fault)?;
    if addr == 0 {
        return Ok(old_brk);
    }
    if addr <= old_brk {
        return Ok(old_brk);
    }
    let root_pa = mm::current_root_pa();
    if root_pa == 0 {
        return Err(Errno::Fault);
    }
    let new_brk = align_up(addr, mm::PAGE_SIZE);
    let start = align_up(old_brk, mm::PAGE_SIZE);
    if start < new_brk {
        let flags = mm::UserMapFlags {
            read: true,
            write: true,
            exec: false,
        };
        for va in (start..new_brk).step_by(mm::PAGE_SIZE) {
            let frame = mm::alloc_frame().ok_or(Errno::NoMem)?;
            let pa = frame.addr().as_usize();
            // SAFETY: fresh frame; zero before mapping into user space.
            unsafe {
                core::ptr::write_bytes(pa as *mut u8, 0, mm::PAGE_SIZE);
            }
            if !mm::map_user_page(root_pa, va, pa, flags) {
                return Err(Errno::NoMem);
            }
        }
    }
    crate::task::set_heap_top(task_id, new_brk);
    Ok(new_brk)
}

fn sys_mmap(
    addr: usize,
    len: usize,
    prot: usize,
    flags: usize,
    fd: usize,
    offset: usize,
) -> Result<usize, Errno> {
    if len == 0 {
        return Err(Errno::Inval);
    }
    if (flags & MAP_ANON) == 0 || (flags & MAP_PRIVATE) == 0 || (flags & MAP_SHARED) != 0 {
        return Err(Errno::Inval);
    }
    if fd != usize::MAX || offset != 0 {
        return Err(Errno::Inval);
    }
    let task_id = crate::runtime::current_task_id().ok_or(Errno::Fault)?;
    let heap_top = crate::task::heap_top(task_id).ok_or(Errno::Fault)?;
    let fixed = (flags & MAP_FIXED) != 0;
    if fixed {
        if addr == 0 || (addr & (mm::PAGE_SIZE - 1)) != 0 {
            return Err(Errno::Inval);
        }
    }
    let start = if addr != 0 {
        align_up(addr, mm::PAGE_SIZE)
    } else {
        align_up(heap_top, mm::PAGE_SIZE)
    };
    let map_len = align_up(len, mm::PAGE_SIZE);
    if map_len == 0 {
        return Err(Errno::Inval);
    }
    let end = start.checked_add(map_len).ok_or(Errno::Inval)?;
    let flags_map = mm::UserMapFlags {
        read: (prot & PROT_READ) != 0,
        write: (prot & PROT_WRITE) != 0,
        exec: (prot & PROT_EXEC) != 0,
    };
    let mut flags_map = flags_map;
    if !flags_map.read && !flags_map.write && !flags_map.exec {
        return Err(Errno::Inval);
    }
    if flags_map.exec && !flags_map.read {
        flags_map.read = true;
    }
    let root_pa = mm::current_root_pa();
    if root_pa == 0 {
        return Err(Errno::Fault);
    }
    if fixed {
        let mut va = start;
        while va < end {
            let _ = mm::unmap_user_page(root_pa, va);
            va = va.wrapping_add(mm::PAGE_SIZE);
        }
    }

    let mut va = start;
    while va < end {
        if mm::user_page_mapped(root_pa, va) {
            return Err(Errno::Inval);
        }
        let frame = mm::alloc_frame().ok_or(Errno::NoMem)?;
        let pa = frame.addr().as_usize();
        unsafe {
            core::ptr::write_bytes(pa as *mut u8, 0, mm::PAGE_SIZE);
        }
        if !mm::map_user_page(root_pa, va, pa, flags_map) {
            return Err(Errno::NoMem);
        }
        va = va.wrapping_add(mm::PAGE_SIZE);
    }
    if !fixed && end > heap_top {
        let _ = crate::task::set_heap_top(task_id, end);
    }
    Ok(start)
}

fn sys_munmap(addr: usize, len: usize) -> Result<usize, Errno> {
    if len == 0 || (addr & (mm::PAGE_SIZE - 1)) != 0 {
        return Err(Errno::Inval);
    }
    let root_pa = mm::current_root_pa();
    if root_pa == 0 {
        return Err(Errno::Fault);
    }
    let end = addr.checked_add(align_up(len, mm::PAGE_SIZE)).ok_or(Errno::Inval)?;
    let mut va = addr;
    while va < end {
        let _ = mm::unmap_user_page(root_pa, va);
        va = va.wrapping_add(mm::PAGE_SIZE);
    }
    mm::flush_tlb();
    Ok(0)
}

fn sys_mprotect(addr: usize, len: usize, prot: usize) -> Result<usize, Errno> {
    if len == 0 || (addr & (mm::PAGE_SIZE - 1)) != 0 {
        return Err(Errno::Inval);
    }
    if (prot & (PROT_READ | PROT_WRITE | PROT_EXEC)) == 0 {
        return Err(Errno::Inval);
    }
    let root_pa = mm::current_root_pa();
    if root_pa == 0 {
        return Err(Errno::Fault);
    }
    let mut flags_map = mm::UserMapFlags {
        read: (prot & PROT_READ) != 0,
        write: (prot & PROT_WRITE) != 0,
        exec: (prot & PROT_EXEC) != 0,
    };
    if flags_map.exec && !flags_map.read {
        flags_map.read = true;
    }
    let end = addr.checked_add(align_up(len, mm::PAGE_SIZE)).ok_or(Errno::Inval)?;
    let mut va = addr;
    while va < end {
        let _ = mm::protect_user_page(root_pa, va, flags_map);
        va = va.wrapping_add(mm::PAGE_SIZE);
    }
    mm::flush_tlb();
    Ok(0)
}

fn sys_madvise(_addr: usize, len: usize, _advice: usize) -> Result<usize, Errno> {
    if len == 0 {
        return Err(Errno::Inval);
    }
    if mm::current_root_pa() == 0 {
        return Err(Errno::Fault);
    }
    Ok(0)
}

fn sys_rseq(_rseq: usize, _rseq_len: usize, _flags: usize, _sig: usize) -> Result<usize, Errno> {
    Err(Errno::NoSys)
}

fn sys_eventfd2(initval: usize, flags: usize) -> Result<usize, Errno> {
    if flags & !(EFD_SEMAPHORE | EFD_NONBLOCK | EFD_CLOEXEC) != 0 {
        return Err(Errno::Inval);
    }
    let initval = initval as u64;
    let event_id = alloc_eventfd(initval, flags).ok_or(Errno::MFile)?;
    let entry = FdEntry {
        kind: FdKind::Eventfd(event_id),
        flags: if (flags & EFD_NONBLOCK) != 0 { O_NONBLOCK } else { 0 },
        offset: 0,
        recv_timeout_ms: 0,
        send_timeout_ms: 0,
    };
    let fd = alloc_fd(entry).ok_or(Errno::MFile)?;
    Ok(fd)
}

fn sys_epoll_create1(flags: usize) -> Result<usize, Errno> {
    if flags & !EPOLL_CLOEXEC != 0 {
        return Err(Errno::Inval);
    }
    let epoll_id = alloc_epoll(flags).ok_or(Errno::MFile)?;
    let entry = FdEntry {
        kind: FdKind::Epoll(epoll_id),
        flags: 0,
        offset: 0,
        recv_timeout_ms: 0,
        send_timeout_ms: 0,
    };
    let fd = alloc_fd(entry).ok_or(Errno::MFile)?;
    Ok(fd)
}

fn sys_epoll_ctl(epfd: usize, op: usize, fd: usize, event_ptr: usize) -> Result<usize, Errno> {
    let entry = resolve_fd(epfd).ok_or(Errno::Badf)?;
    let epoll_id = match entry.kind {
        FdKind::Epoll(id) => id,
        _ => return Err(Errno::Badf),
    };
    if resolve_fd(fd).is_none() {
        return Err(Errno::Badf);
    }
    let mut event = EpollEvent { events: 0, data: 0 };
    if matches!(op, EPOLL_CTL_ADD | EPOLL_CTL_MOD) {
        if event_ptr == 0 {
            return Err(Errno::Fault);
        }
        let root_pa = mm::current_root_pa();
        if root_pa == 0 {
            return Err(Errno::Fault);
        }
        event = UserPtr::<EpollEvent>::new(event_ptr)
            .read(root_pa)
            .ok_or(Errno::Fault)?;
    }
    // SAFETY: 单核早期阶段，epoll 表串行更新。
    unsafe {
        let epoll = EPOLLS.get_mut(epoll_id).ok_or(Errno::Badf)?;
        if !epoll.used {
            return Err(Errno::Badf);
        }
        match op {
            EPOLL_CTL_ADD => {
                for item in epoll.items.iter() {
                    if item.used && item.fd == fd as i32 {
                        return Err(Errno::Exist);
                    }
                }
                if let Some(slot) = epoll.items.iter_mut().find(|item| !item.used) {
                    *slot = EpollItem {
                        used: true,
                        fd: fd as i32,
                        events: event.events,
                        data: event.data,
                    };
                    return Ok(0);
                }
                Err(Errno::MFile)
            }
            EPOLL_CTL_MOD => {
                for item in epoll.items.iter_mut() {
                    if item.used && item.fd == fd as i32 {
                        item.events = event.events;
                        item.data = event.data;
                        return Ok(0);
                    }
                }
                Err(Errno::NoEnt)
            }
            EPOLL_CTL_DEL => {
                for item in epoll.items.iter_mut() {
                    if item.used && item.fd == fd as i32 {
                        *item = EMPTY_EPOLL_ITEM;
                        return Ok(0);
                    }
                }
                Err(Errno::NoEnt)
            }
            _ => Err(Errno::Inval),
        }
    }
}

fn sys_epoll_pwait(
    epfd: usize,
    events_ptr: usize,
    maxevents: usize,
    timeout: usize,
    _sigmask: usize,
    _sigsetsize: usize,
) -> Result<usize, Errno> {
    let timeout = timeout as isize;
    let timeout_ms = if timeout < 0 { None } else { Some(timeout as u64) };
    epoll_wait(epfd, events_ptr, maxevents, timeout_ms)
}

fn sys_epoll_pwait2(
    epfd: usize,
    events_ptr: usize,
    maxevents: usize,
    timeout: usize,
    _sigmask: usize,
    _sigsetsize: usize,
) -> Result<usize, Errno> {
    let timeout_ms = epoll_timeout_ms(timeout)?;
    epoll_wait(epfd, events_ptr, maxevents, timeout_ms)
}

fn sys_timerfd_create(clockid: usize, flags: usize) -> Result<usize, Errno> {
    if clockid != CLOCK_MONOTONIC && clockid != CLOCK_BOOTTIME {
        return Err(Errno::Inval);
    }
    if flags & !(TFD_NONBLOCK | TFD_CLOEXEC) != 0 {
        return Err(Errno::Inval);
    }
    let timer_id = alloc_timerfd(flags).ok_or(Errno::MFile)?;
    let entry = FdEntry {
        kind: FdKind::Timerfd(timer_id),
        flags: if (flags & TFD_NONBLOCK) != 0 { O_NONBLOCK } else { 0 },
        offset: 0,
        recv_timeout_ms: 0,
        send_timeout_ms: 0,
    };
    let fd = alloc_fd(entry).ok_or(Errno::MFile)?;
    Ok(fd)
}

fn sys_timerfd_settime(fd: usize, flags: usize, new_ptr: usize, old_ptr: usize) -> Result<usize, Errno> {
    if flags & !TFD_TIMER_ABSTIME != 0 {
        return Err(Errno::Inval);
    }
    if new_ptr == 0 {
        return Err(Errno::Fault);
    }
    let root_pa = mm::current_root_pa();
    if root_pa == 0 {
        return Err(Errno::Fault);
    }
    let entry = resolve_fd(fd).ok_or(Errno::Badf)?;
    let timer_id = match entry.kind {
        FdKind::Timerfd(id) => id,
        _ => return Err(Errno::Badf),
    };
    let new_value = UserPtr::<Itimerspec>::new(new_ptr)
        .read(root_pa)
        .ok_or(Errno::Fault)?;
    if old_ptr != 0 {
        let old = timerfd_current_spec(timer_id)?;
        UserPtr::new(old_ptr).write(root_pa, old).ok_or(Errno::Fault)?;
    }
    let value_ns = timespec_to_ns(new_value.it_value)?;
    let interval_ns = timespec_to_ns(new_value.it_interval)?;
    let now = time::monotonic_ns();
    let next_ns = if value_ns == 0 {
        0
    } else if (flags & TFD_TIMER_ABSTIME) != 0 {
        value_ns
    } else {
        now.saturating_add(value_ns)
    };
    // SAFETY: 单核早期阶段串行更新 timerfd。
    unsafe {
        if let Some(timer) = TIMERFDS.get_mut(timer_id) {
            if !timer.used {
                return Err(Errno::Badf);
            }
            timer.next_ns = next_ns;
            timer.interval_ns = interval_ns;
        } else {
            return Err(Errno::Badf);
        }
    }
    let _ = crate::runtime::wake_all(timerfd_queue(timer_id));
    Ok(0)
}

fn sys_timerfd_gettime(fd: usize, curr_ptr: usize) -> Result<usize, Errno> {
    if curr_ptr == 0 {
        return Err(Errno::Fault);
    }
    let root_pa = mm::current_root_pa();
    if root_pa == 0 {
        return Err(Errno::Fault);
    }
    let entry = resolve_fd(fd).ok_or(Errno::Badf)?;
    let timer_id = match entry.kind {
        FdKind::Timerfd(id) => id,
        _ => return Err(Errno::Badf),
    };
    let current = timerfd_current_spec(timer_id)?;
    UserPtr::new(curr_ptr)
        .write(root_pa, current)
        .ok_or(Errno::Fault)?;
    Ok(0)
}

const EXECVE_IMAGE_MAX: usize = 0x100000;
// SAFETY: 单核 execve 过程复用该缓冲区读取 ELF 镜像。
static mut EXECVE_IMAGE: [u8; EXECVE_IMAGE_MAX] = [0; EXECVE_IMAGE_MAX];

fn execve_vfs_image(root_pa: usize, pathname: usize) -> Result<&'static [u8], Errno> {
    let (mount, inode) = vfs_lookup_inode(root_pa, pathname)?;
    with_mounts(|mounts| {
        let fs = mounts.fs_for(mount).ok_or(Errno::NoEnt)?;
        let meta = fs.metadata(inode).map_err(map_vfs_err)?;
        if meta.file_type != FileType::File {
            return Err(Errno::NoEnt);
        }
        let size = meta.size as usize;
        if size == 0 || size > EXECVE_IMAGE_MAX {
            return Err(Errno::NoMem);
        }
        // SAFETY: 单核 execve 路径，缓冲区只在此处写入。
        unsafe {
            let buf = &mut EXECVE_IMAGE[..size];
            let mut offset = 0usize;
            while offset < size {
                let read = fs
                    .read_at(inode, offset as u64, &mut buf[offset..])
                    .map_err(map_vfs_err)?;
                if read == 0 {
                    break;
                }
                offset += read;
            }
            if offset != size {
                return Err(Errno::Inval);
            }
            Ok(&EXECVE_IMAGE[..size])
        }
    })
}

fn sys_clone(
    tf: &TrapFrame,
    flags: usize,
    stack: usize,
    ptid: usize,
    _tls: usize,
    ctid: usize,
) -> Result<usize, Errno> {
    const CLONE_SIGNAL_MASK: usize = 0xff;
    const CLONE_PARENT_SETTID: usize = 0x0010_0000;
    const CLONE_CHILD_CLEARTID: usize = 0x0020_0000;
    const CLONE_CHILD_SETTID: usize = 0x0100_0000;
    const CLONE_SUPPORTED: usize =
        CLONE_SIGNAL_MASK | CLONE_PARENT_SETTID | CLONE_CHILD_CLEARTID | CLONE_CHILD_SETTID;

    // clone 目前按 fork 语义处理：仅支持最小 tid 写回标志位。
    if (flags & !CLONE_SUPPORTED) != 0 {
        return Err(Errno::Inval);
    }
    let root_pa = mm::current_root_pa();
    if root_pa == 0 {
        return Err(Errno::Fault);
    }
    if (flags & CLONE_PARENT_SETTID) != 0 {
        if ptid == 0
            || mm::translate_user_ptr(root_pa, ptid, size_of::<usize>(), mm::UserAccess::Write)
                .is_none()
        {
            return Err(Errno::Fault);
        }
    }
    if (flags & (CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID)) != 0 {
        if ctid == 0
            || mm::translate_user_ptr(root_pa, ctid, size_of::<usize>(), mm::UserAccess::Write)
                .is_none()
        {
            return Err(Errno::Fault);
        }
    }
    let user_sp = if stack != 0 {
        stack
    } else {
        let task_id = crate::runtime::current_task_id().ok_or(Errno::Fault)?;
        crate::task::user_sp(task_id).ok_or(Errno::Fault)?
    };
    let child_root = mm::clone_user_root(root_pa).ok_or(Errno::NoMem)?;
    let pid = crate::runtime::spawn_forked_user(tf, child_root, user_sp).ok_or(Errno::NoMem)?;
    if (flags & CLONE_PARENT_SETTID) != 0 {
        mm::UserPtr::new(ptid)
            .write(root_pa, pid)
            .ok_or(Errno::Fault)?;
    }
    if (flags & CLONE_CHILD_SETTID) != 0 {
        mm::UserPtr::new(ctid)
            .write(child_root, pid)
            .ok_or(Errno::Fault)?;
    }
    if (flags & CLONE_CHILD_CLEARTID) != 0 {
        let _ = crate::process::set_clear_tid(pid, ctid);
    }
    Ok(pid)
}

fn sys_read(fd: usize, buf: usize, len: usize) -> Result<usize, Errno> {
    if len == 0 {
        return Ok(0);
    }
    let root_pa = mm::current_root_pa();
    if root_pa == 0 {
        return Err(Errno::Fault);
    }
    let entry = resolve_fd(fd).ok_or(Errno::Badf)?;
    read_from_entry(fd, entry, root_pa, buf, len)
}

fn sys_pread64(fd: usize, buf: usize, len: usize, offset: usize) -> Result<usize, Errno> {
    if len == 0 {
        return Ok(0);
    }
    let root_pa = mm::current_root_pa();
    if root_pa == 0 {
        return Err(Errno::Fault);
    }
    let entry = resolve_fd(fd).ok_or(Errno::Badf)?;
    match entry.kind {
        FdKind::Vfs(handle) => {
            if handle.file_type == FileType::Dir {
                return Err(Errno::IsDir);
            }
            with_mounts(|mounts| {
                let fs = mounts.fs_for(handle.mount).ok_or(Errno::NoEnt)?;
                read_vfs_at(root_pa, fs, handle.inode, offset, buf, len)
            })
        }
        FdKind::Stdin
        | FdKind::Stdout
        | FdKind::Stderr
        | FdKind::PipeRead(_)
        | FdKind::PipeWrite(_)
        | FdKind::Socket(_)
        | FdKind::Eventfd(_)
        | FdKind::Timerfd(_)
        | FdKind::Epoll(_) => Err(Errno::Pipe),
        FdKind::Empty => Err(Errno::Badf),
    }
}

fn sys_write(fd: usize, buf: usize, len: usize) -> Result<usize, Errno> {
    if len == 0 {
        return Ok(0);
    }
    let root_pa = mm::current_root_pa();
    if root_pa == 0 {
        return Err(Errno::Fault);
    }
    let entry = resolve_fd(fd).ok_or(Errno::Badf)?;
    write_to_entry(fd, entry, root_pa, buf, len)
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
    let entry = resolve_fd(fd).ok_or(Errno::Badf)?;

    let mut total = 0usize;
    for index in 0..iovcnt {
        let iov = load_iovec(root_pa, iov_ptr, index)?;
        if iov.iov_len == 0 {
            continue;
        }
        match read_from_entry(fd, entry, root_pa, iov.iov_base, iov.iov_len) {
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
    let entry = resolve_fd(fd).ok_or(Errno::Badf)?;

    let mut total = 0usize;
    for index in 0..iovcnt {
        let iov = load_iovec(root_pa, iov_ptr, index)?;
        if iov.iov_len == 0 {
            continue;
        }
        match write_to_entry(fd, entry, root_pa, iov.iov_base, iov.iov_len) {
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

fn sys_access(pathname: usize, mode: usize) -> Result<usize, Errno> {
    sys_faccessat(AT_FDCWD as usize, pathname, mode, 0)
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
    let status_flags = if (flags & O_NONBLOCK) != 0 { O_NONBLOCK } else { 0 };
    let read_fd = match alloc_fd(FdEntry {
        kind: FdKind::PipeRead(pipe_id),
        flags: status_flags,
        offset: 0,
        recv_timeout_ms: 0,
        send_timeout_ms: 0,
    }) {
        Some(fd) => fd,
        None => {
            free_pipe(pipe_id);
            return Err(Errno::MFile);
        }
    };
    let write_fd = match alloc_fd(FdEntry {
        kind: FdKind::PipeWrite(pipe_id),
        flags: status_flags,
        offset: 0,
        recv_timeout_ms: 0,
        send_timeout_ms: 0,
    }) {
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

fn sys_socket(domain: usize, sock_type: usize, protocol: usize) -> Result<usize, Errno> {
    let socket_id = axnet::socket_create(domain as i32, sock_type as i32, protocol as i32)
        .map_err(map_net_err)?;
    let flags = if (sock_type & SOCK_NONBLOCK) != 0 {
        O_NONBLOCK
    } else {
        0
    };
    let entry = FdEntry {
        kind: FdKind::Socket(socket_id),
        flags,
        offset: 0,
        recv_timeout_ms: 0,
        send_timeout_ms: 0,
    };
    alloc_fd(entry).ok_or(Errno::MFile)
}

fn sys_bind(fd: usize, addr: usize, len: usize) -> Result<usize, Errno> {
    let root_pa = mm::current_root_pa();
    let socket_id = resolve_socket_fd(fd)?;
    let (ip, port) = parse_sockaddr_in(root_pa, addr, len)?;
    axnet::socket_bind(socket_id, ip, port).map_err(map_net_err)?;
    Ok(0)
}

fn sys_getsockname(fd: usize, addr: usize, addrlen: usize) -> Result<usize, Errno> {
    let root_pa = mm::current_root_pa();
    let socket_id = resolve_socket_fd(fd)?;
    let (ip, port) = axnet::socket_local_endpoint(socket_id).map_err(map_net_err)?;
    write_sockaddr_in(root_pa, addr, addrlen, Some((ip, port)))?;
    Ok(0)
}

fn sys_getpeername(fd: usize, addr: usize, addrlen: usize) -> Result<usize, Errno> {
    let root_pa = mm::current_root_pa();
    let socket_id = resolve_socket_fd(fd)?;
    let endpoint = axnet::socket_remote_endpoint(socket_id).map_err(map_net_err)?;
    let Some((ip, port)) = endpoint else {
        return Err(Errno::NotConn);
    };
    write_sockaddr_in(root_pa, addr, addrlen, Some((ip, port)))?;
    Ok(0)
}

fn sys_connect(fd: usize, addr: usize, len: usize) -> Result<usize, Errno> {
    let root_pa = mm::current_root_pa();
    let (socket_id, entry) = resolve_socket_entry(fd)?;
    let nonblock = (entry.flags & O_NONBLOCK) != 0;
    let timeout_ms = entry.send_timeout_ms;
    if cfg!(feature = "user-tcp-echo") && TCP_CONNECT_LOGGED.swap(1, Ordering::Relaxed) == 0 {
        crate::println!("sys_connect: fd={} nonblock={}", fd, nonblock);
    }
    let (ip, port) = parse_sockaddr_in(root_pa, addr, len)?;
    match axnet::socket_connect(socket_id, ip, port) {
        Ok(()) => {}
        Err(axnet::NetError::InProgress) => {
            if nonblock || !can_block_current() {
                return Err(Errno::InProgress);
            }
        }
        Err(axnet::NetError::IsConnected) => return Err(Errno::IsConn),
        Err(err) => return Err(map_net_err(err)),
    }

    if nonblock {
        let revents = axnet::socket_poll(socket_id, POLLOUT | POLLHUP).map_err(map_net_err)?;
        if (revents & POLLOUT) != 0 {
            return Ok(0);
        }
        if (revents & POLLHUP) != 0 {
            return Err(connect_hup_error(socket_id));
        }
        return Err(Errno::InProgress);
    }

    loop {
        let revents = axnet::socket_poll(socket_id, POLLOUT | POLLHUP).map_err(map_net_err)?;
        if (revents & POLLOUT) != 0 {
            return Ok(0);
        }
        if (revents & POLLHUP) != 0 {
            return Err(connect_hup_error(socket_id));
        }
        if !can_block_current() {
            return Err(Errno::Again);
        }
        if cfg!(feature = "user-tcp-echo") && TCP_CONNECT_LOGGED.swap(2, Ordering::Relaxed) == 1 {
            crate::println!("sys_connect: blocking");
        }
        if timeout_ms == 0 {
            crate::runtime::block_current(crate::runtime::net_wait_queue());
        } else if crate::runtime::wait_timeout_ms(crate::runtime::net_wait_queue(), timeout_ms)
            == crate::wait::WaitResult::Timeout
        {
            return Err(Errno::TimedOut);
        }
    }
}

fn connect_hup_error(socket_id: axnet::SocketId) -> Errno {
    match axnet::socket_take_error(socket_id) {
        Ok(Some(err)) => map_net_err(err),
        _ => Errno::ConnRefused,
    }
}

fn read_timeval_ms(root_pa: usize, ptr: usize, len: usize) -> Result<u64, Errno> {
    if ptr == 0 || len < size_of::<Timeval>() {
        return Err(Errno::Inval);
    }
    let tv = UserPtr::<Timeval>::new(ptr)
        .read(root_pa)
        .ok_or(Errno::Fault)?;
    if tv.tv_sec < 0 || tv.tv_usec < 0 || tv.tv_usec >= 1_000_000 {
        return Err(Errno::Inval);
    }
    let ms = (tv.tv_sec as u64)
        .saturating_mul(1000)
        .saturating_add((tv.tv_usec as u64 + 999) / 1000);
    Ok(ms)
}

fn write_timeval_ms(root_pa: usize, ptr: usize, len_ptr: usize, ms: u64) -> Result<(), Errno> {
    if ptr == 0 || len_ptr == 0 {
        return Err(Errno::Fault);
    }
    let mut len = UserPtr::<u32>::new(len_ptr)
        .read(root_pa)
        .ok_or(Errno::Fault)? as usize;
    if len < size_of::<Timeval>() {
        return Err(Errno::Inval);
    }
    let tv = Timeval {
        tv_sec: (ms / 1000) as i64,
        tv_usec: ((ms % 1000) * 1000) as i64,
    };
    UserPtr::new(ptr).write(root_pa, tv).ok_or(Errno::Fault)?;
    len = size_of::<Timeval>();
    UserPtr::new(len_ptr)
        .write(root_pa, len as u32)
        .ok_or(Errno::Fault)?;
    Ok(())
}

fn sys_setsockopt(
    fd: usize,
    level: usize,
    optname: usize,
    optval: usize,
    optlen: usize,
) -> Result<usize, Errno> {
    let root_pa = mm::current_root_pa();
    let _socket_id = resolve_socket_fd(fd)?;
    if level != SOL_SOCKET {
        return Err(Errno::Inval);
    }
    match optname {
        SO_REUSEADDR => {
            if optlen < size_of::<u32>() || optval == 0 {
                return Err(Errno::Inval);
            }
            UserPtr::<u32>::new(optval)
                .read(root_pa)
                .ok_or(Errno::Fault)?;
            Ok(0)
        }
        SO_RCVTIMEO => {
            let timeout_ms = read_timeval_ms(root_pa, optval, optlen)?;
            set_socket_timeout(fd, Some(timeout_ms), None)
        }
        SO_SNDTIMEO => {
            let timeout_ms = read_timeval_ms(root_pa, optval, optlen)?;
            set_socket_timeout(fd, None, Some(timeout_ms))
        }
        _ => Err(Errno::Inval),
    }
}

fn sys_getsockopt(
    fd: usize,
    level: usize,
    optname: usize,
    optval: usize,
    optlen: usize,
) -> Result<usize, Errno> {
    let root_pa = mm::current_root_pa();
    let socket_id = resolve_socket_fd(fd)?;
    if level != SOL_SOCKET {
        return Err(Errno::Inval);
    }
    if optlen == 0 {
        return Err(Errno::Fault);
    }
    match optname {
        SO_ERROR => {
            let len = UserPtr::<u32>::new(optlen)
                .read(root_pa)
                .ok_or(Errno::Fault)? as usize;
            if len < size_of::<u32>() || optval == 0 {
                return Err(Errno::Inval);
            }
            let value = if let Some(err) = axnet::socket_take_error(socket_id).map_err(map_net_err)? {
                map_net_err(err) as i32
            } else if axnet::socket_connecting(socket_id).map_err(map_net_err)? {
                Errno::InProgress as i32
            } else {
                0
            };
            UserPtr::new(optval)
                .write(root_pa, value as u32)
                .ok_or(Errno::Fault)?;
            UserPtr::new(optlen)
                .write(root_pa, size_of::<u32>() as u32)
                .ok_or(Errno::Fault)?;
            Ok(0)
        }
        SO_REUSEADDR => {
            let len = UserPtr::<u32>::new(optlen)
                .read(root_pa)
                .ok_or(Errno::Fault)? as usize;
            if len < size_of::<u32>() || optval == 0 {
                return Err(Errno::Inval);
            }
            UserPtr::new(optval)
                .write(root_pa, 0u32)
                .ok_or(Errno::Fault)?;
            UserPtr::new(optlen)
                .write(root_pa, size_of::<u32>() as u32)
                .ok_or(Errno::Fault)?;
            Ok(0)
        }
        SO_RCVTIMEO => {
            let (recv_ms, _) = socket_timeouts(fd)?;
            write_timeval_ms(root_pa, optval, optlen, recv_ms)?;
            Ok(0)
        }
        SO_SNDTIMEO => {
            let (_, send_ms) = socket_timeouts(fd)?;
            write_timeval_ms(root_pa, optval, optlen, send_ms)?;
            Ok(0)
        }
        _ => Err(Errno::Inval),
    }
}

fn sys_shutdown(fd: usize, how: usize) -> Result<usize, Errno> {
    let socket_id = resolve_socket_fd(fd)?;
    if how != SHUT_RD && how != SHUT_WR && how != SHUT_RDWR {
        return Err(Errno::Inval);
    }
    axnet::socket_shutdown(socket_id, how).map_err(map_net_err)?;
    Ok(0)
}

fn sys_listen(fd: usize, backlog: usize) -> Result<usize, Errno> {
    let socket_id = resolve_socket_fd(fd)?;
    axnet::socket_listen(socket_id, backlog).map_err(map_net_err)?;
    Ok(0)
}

fn sys_accept(fd: usize, addr: usize, addrlen: usize) -> Result<usize, Errno> {
    let (socket_id, entry) = resolve_socket_entry(fd)?;
    let nonblock = (entry.flags & O_NONBLOCK) != 0;
    let timeout_ms = entry.recv_timeout_ms;
    if cfg!(feature = "user-tcp-echo") && TCP_ACCEPT_LOGGED.swap(1, Ordering::Relaxed) == 0 {
        crate::println!("sys_accept: fd={} nonblock={}", fd, nonblock);
    }
    loop {
        match axnet::socket_accept(socket_id) {
            Ok((accepted_id, listener_id, remote)) => {
                replace_socket_fd(fd, listener_id)?;
                let entry = FdEntry {
                    kind: FdKind::Socket(accepted_id),
                    flags: entry.flags & O_NONBLOCK,
                    offset: 0,
                    recv_timeout_ms: entry.recv_timeout_ms,
                    send_timeout_ms: entry.send_timeout_ms,
                };
                let newfd = alloc_fd(entry).ok_or(Errno::MFile)?;
                write_sockaddr_in(mm::current_root_pa(), addr, addrlen, remote)?;
                return Ok(newfd);
            }
            Err(axnet::NetError::WouldBlock) => {
                if nonblock || !can_block_current() {
                    return Err(Errno::Again);
                }
                if cfg!(feature = "user-tcp-echo") && TCP_ACCEPT_LOGGED.swap(2, Ordering::Relaxed) == 1 {
                    crate::println!("sys_accept: blocking");
                }
                if timeout_ms == 0 {
                    crate::runtime::block_current(crate::runtime::net_wait_queue());
                } else if crate::runtime::wait_timeout_ms(crate::runtime::net_wait_queue(), timeout_ms)
                    == crate::wait::WaitResult::Timeout
                {
                    return Err(Errno::TimedOut);
                }
            }
            Err(err) => return Err(map_net_err(err)),
        }
    }
}

fn sys_sendto(
    fd: usize,
    buf: usize,
    len: usize,
    _flags: usize,
    addr: usize,
    addrlen: usize,
) -> Result<usize, Errno> {
    let root_pa = mm::current_root_pa();
    let (socket_id, entry) = resolve_socket_entry(fd)?;
    let nonblock = (entry.flags & O_NONBLOCK) != 0;
    let timeout_ms = entry.send_timeout_ms;
    let endpoint = if addr != 0 {
        let (ip, port) = parse_sockaddr_in(root_pa, addr, addrlen)?;
        Some((ip, port))
    } else {
        None
    };
    if len == 0 {
        return Ok(0);
    }
    let mut total = 0usize;
    let mut remaining = len;
    let mut scratch = [0u8; 512];
    while remaining > 0 {
        let chunk = core::cmp::min(remaining, scratch.len());
        let src = buf.checked_add(total).ok_or(Errno::Fault)?;
        UserSlice::new(src, chunk)
            .copy_to_slice(root_pa, &mut scratch[..chunk])
            .ok_or(Errno::Fault)?;
        let sent = match axnet::socket_send(socket_id, &scratch[..chunk], endpoint) {
            Ok(sent) => sent,
            Err(axnet::NetError::WouldBlock) => {
                if total > 0 {
                    break;
                }
                if nonblock || !can_block_current() {
                    return Err(Errno::Again);
                }
                if timeout_ms == 0 {
                    crate::runtime::block_current(crate::runtime::net_wait_queue());
                } else if crate::runtime::wait_timeout_ms(crate::runtime::net_wait_queue(), timeout_ms)
                    == crate::wait::WaitResult::Timeout
                {
                    return Err(Errno::TimedOut);
                }
                continue;
            }
            Err(err) => return Err(map_net_err(err)),
        };
        total += sent;
        if sent < chunk {
            break;
        }
        remaining = remaining.saturating_sub(sent);
    }
    Ok(total)
}

fn sys_recvfrom(
    fd: usize,
    buf: usize,
    len: usize,
    _flags: usize,
    addr: usize,
    addrlen: usize,
) -> Result<usize, Errno> {
    let root_pa = mm::current_root_pa();
    let (socket_id, entry) = resolve_socket_entry(fd)?;
    let nonblock = (entry.flags & O_NONBLOCK) != 0;
    let timeout_ms = entry.recv_timeout_ms;
    if cfg!(feature = "user-tcp-echo") && TCP_RECV_LOGGED.swap(1, Ordering::Relaxed) == 0 {
        crate::println!("sys_recv: fd={} nonblock={}", fd, nonblock);
    }
    if len == 0 {
        return Ok(0);
    }
    let mut total = 0usize;
    let mut remaining = len;
    let mut scratch = [0u8; 512];
    let mut last_endpoint = None;
    while remaining > 0 {
        let chunk = core::cmp::min(remaining, scratch.len());
        log_tcp_window_event(socket_id, "pre");
        let (read, endpoint) = match axnet::socket_recv(socket_id, &mut scratch[..chunk]) {
            Ok(result) => result,
            Err(axnet::NetError::WouldBlock) => {
                if total > 0 {
                    break;
                }
                if nonblock || !can_block_current() {
                    return Err(Errno::Again);
                }
                if cfg!(feature = "user-tcp-echo") && TCP_RECV_LOGGED.swap(2, Ordering::Relaxed) == 1 {
                    crate::println!("sys_recv: blocking");
                }
                if timeout_ms == 0 {
                    crate::runtime::block_current(crate::runtime::net_wait_queue());
                } else if crate::runtime::wait_timeout_ms(crate::runtime::net_wait_queue(), timeout_ms)
                    == crate::wait::WaitResult::Timeout
                {
                    return Err(Errno::TimedOut);
                }
                continue;
            }
            Err(err) => return Err(map_net_err(err)),
        };
        log_tcp_window_event(socket_id, "post");
        let dst = buf.checked_add(total).ok_or(Errno::Fault)?;
        UserSlice::new(dst, read)
            .copy_from_slice(root_pa, &scratch[..read])
            .ok_or(Errno::Fault)?;
        total += read;
        last_endpoint = endpoint;
        if last_endpoint.is_none() {
            let _ = axnet::poll(crate::time::uptime_ms());
        }
        if read < chunk {
            break;
        }
        remaining = remaining.saturating_sub(read);
    }
    write_sockaddr_in(root_pa, addr, addrlen, last_endpoint)?;
    Ok(total)
}

fn log_tcp_window_event(socket_id: axnet::SocketId, tag: &str) {
    let Ok(Some(event)) = axnet::socket_recv_window_event(socket_id) else {
        return;
    };
    let port = axnet::socket_local_endpoint(socket_id)
        .map(|(_, port)| port)
        .unwrap_or(0);
    crate::println!(
        "tcp: recv_win {} id={} port={} win={} cap={} queued={}",
        tag,
        socket_id,
        port,
        event.window,
        event.capacity,
        event.queued
    );
}

fn sendmsg_inner(fd: usize, msg: usize, _flags: usize) -> Result<usize, Errno> {
    if msg == 0 {
        return Err(Errno::Fault);
    }
    let root_pa = mm::current_root_pa();
    let (socket_id, entry) = resolve_socket_entry(fd)?;
    let nonblock = (entry.flags & O_NONBLOCK) != 0;
    let timeout_ms = entry.send_timeout_ms;
    let hdr = UserPtr::<MsgHdr>::new(msg)
        .read(root_pa)
        .ok_or(Errno::Fault)?;
    if hdr.msg_iovlen > IOV_MAX {
        return Err(Errno::Inval);
    }
    if hdr.msg_control != 0 || hdr.msg_controllen != 0 {
        return Err(Errno::Inval);
    }
    if hdr.msg_iovlen == 0 {
        return Ok(0);
    }
    let endpoint = if hdr.msg_name != 0 {
        let namelen = hdr.msg_namelen as usize;
        let (ip, port) = parse_sockaddr_in(root_pa, hdr.msg_name, namelen)?;
        Some((ip, port))
    } else {
        None
    };
    let mut total = 0usize;
    let mut scratch = [0u8; 512];
    for idx in 0..hdr.msg_iovlen {
        let iov = load_iovec(root_pa, hdr.msg_iov, idx)?;
        if iov.iov_len == 0 {
            continue;
        }
        let mut remaining = iov.iov_len;
        while remaining > 0 {
            let chunk = core::cmp::min(remaining, scratch.len());
            let src = iov.iov_base.checked_add(iov.iov_len - remaining).ok_or(Errno::Fault)?;
            UserSlice::new(src, chunk)
                .copy_to_slice(root_pa, &mut scratch[..chunk])
                .ok_or(Errno::Fault)?;
            let sent = match axnet::socket_send(socket_id, &scratch[..chunk], endpoint) {
                Ok(sent) => sent,
                Err(axnet::NetError::WouldBlock) => {
                    if total > 0 {
                        return Ok(total);
                    }
                    if nonblock || !can_block_current() {
                        return Err(Errno::Again);
                    }
                    if timeout_ms == 0 {
                        crate::runtime::block_current(crate::runtime::net_wait_queue());
                    } else if crate::runtime::wait_timeout_ms(crate::runtime::net_wait_queue(), timeout_ms)
                        == crate::wait::WaitResult::Timeout
                    {
                        return Err(Errno::TimedOut);
                    }
                    continue;
                }
                Err(err) => return Err(map_net_err(err)),
            };
            total += sent;
            if sent < chunk {
                return Ok(total);
            }
            remaining = remaining.saturating_sub(sent);
        }
    }
    Ok(total)
}

fn recvmsg_inner(fd: usize, msg: usize, _flags: usize) -> Result<usize, Errno> {
    if msg == 0 {
        return Err(Errno::Fault);
    }
    let root_pa = mm::current_root_pa();
    let (socket_id, entry) = resolve_socket_entry(fd)?;
    let nonblock = (entry.flags & O_NONBLOCK) != 0;
    let timeout_ms = entry.recv_timeout_ms;
    let mut hdr = UserPtr::<MsgHdr>::new(msg)
        .read(root_pa)
        .ok_or(Errno::Fault)?;
    if hdr.msg_iovlen > IOV_MAX {
        return Err(Errno::Inval);
    }
    if hdr.msg_control != 0 || hdr.msg_controllen != 0 {
        return Err(Errno::Inval);
    }
    if hdr.msg_iovlen == 0 {
        return Ok(0);
    }
    let mut total = 0usize;
    let mut scratch = [0u8; 512];
    let mut last_endpoint = None;
    for idx in 0..hdr.msg_iovlen {
        let iov = load_iovec(root_pa, hdr.msg_iov, idx)?;
        if iov.iov_len == 0 {
            continue;
        }
        let mut remaining = iov.iov_len;
        while remaining > 0 {
            let chunk = core::cmp::min(remaining, scratch.len());
            let (read, endpoint) = match axnet::socket_recv(socket_id, &mut scratch[..chunk]) {
                Ok(result) => result,
                Err(axnet::NetError::WouldBlock) => {
                    if total > 0 {
                        return Ok(total);
                    }
                    if nonblock || !can_block_current() {
                        return Err(Errno::Again);
                    }
                    if timeout_ms == 0 {
                        crate::runtime::block_current(crate::runtime::net_wait_queue());
                    } else if crate::runtime::wait_timeout_ms(crate::runtime::net_wait_queue(), timeout_ms)
                        == crate::wait::WaitResult::Timeout
                    {
                        return Err(Errno::TimedOut);
                    }
                    continue;
                }
                Err(err) => return Err(map_net_err(err)),
            };
            let dst = iov
                .iov_base
                .checked_add(iov.iov_len - remaining)
                .ok_or(Errno::Fault)?;
            UserSlice::new(dst, read)
                .copy_from_slice(root_pa, &scratch[..read])
                .ok_or(Errno::Fault)?;
            total += read;
            last_endpoint = endpoint;
            if read < chunk {
                break;
            }
            remaining = remaining.saturating_sub(read);
        }
    }
    if hdr.msg_name != 0 {
        let Some((ip, port)) = last_endpoint else {
            return Ok(total);
        };
        let namelen = hdr.msg_namelen as usize;
        if namelen < size_of::<SockAddrIn>() {
            return Err(Errno::Inval);
        }
        let sock = SockAddrIn {
            sin_family: AF_INET,
            sin_port: port.to_be(),
            sin_addr: match ip {
                axnet::IpAddress::Ipv4(addr) => {
                    let bytes = addr.as_bytes();
                    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
                }
            },
            sin_zero: [0; 8],
        };
        UserPtr::new(hdr.msg_name)
            .write(root_pa, sock)
            .ok_or(Errno::Fault)?;
        hdr.msg_namelen = size_of::<SockAddrIn>() as u32;
        hdr.msg_flags = 0;
        UserPtr::new(msg).write(root_pa, hdr).ok_or(Errno::Fault)?;
    }
    Ok(total)
}

fn sys_sendmsg(fd: usize, msg: usize, flags: usize) -> Result<usize, Errno> {
    sendmsg_inner(fd, msg, flags)
}

fn sys_recvmsg(fd: usize, msg: usize, flags: usize) -> Result<usize, Errno> {
    recvmsg_inner(fd, msg, flags)
}

fn sys_sendmmsg(fd: usize, msgvec: usize, vlen: usize, flags: usize) -> Result<usize, Errno> {
    if msgvec == 0 {
        return Err(Errno::Fault);
    }
    if vlen == 0 {
        return Ok(0);
    }
    let root_pa = mm::current_root_pa();
    let count = core::cmp::min(vlen, IOV_MAX);
    let mut sent = 0usize;
    for idx in 0..count {
        let offset = idx
            .checked_mul(size_of::<MMsgHdr>())
            .ok_or(Errno::Fault)?;
        let addr = msgvec.checked_add(offset).ok_or(Errno::Fault)?;
        let mut mmsg = UserPtr::<MMsgHdr>::new(addr)
            .read(root_pa)
            .ok_or(Errno::Fault)?;
        let hdr_addr = addr;
        let n = match sendmsg_inner(fd, hdr_addr, flags) {
            Ok(n) => n,
            Err(Errno::Again) if sent > 0 => break,
            Err(err) => return Err(err),
        };
        mmsg.msg_len = n as u32;
        UserPtr::new(addr).write(root_pa, mmsg).ok_or(Errno::Fault)?;
        sent += 1;
    }
    Ok(sent)
}

fn sys_recvmmsg(
    fd: usize,
    msgvec: usize,
    vlen: usize,
    flags: usize,
    timeout: usize,
) -> Result<usize, Errno> {
    if msgvec == 0 {
        return Err(Errno::Fault);
    }
    if vlen == 0 {
        return Ok(0);
    }
    if timeout != 0 {
        let root_pa = mm::current_root_pa();
        UserPtr::<Timespec>::new(timeout)
            .read(root_pa)
            .ok_or(Errno::Fault)?;
    }
    let root_pa = mm::current_root_pa();
    let count = core::cmp::min(vlen, IOV_MAX);
    let mut recvd = 0usize;
    for idx in 0..count {
        let offset = idx
            .checked_mul(size_of::<MMsgHdr>())
            .ok_or(Errno::Fault)?;
        let addr = msgvec.checked_add(offset).ok_or(Errno::Fault)?;
        let mut mmsg = UserPtr::<MMsgHdr>::new(addr)
            .read(root_pa)
            .ok_or(Errno::Fault)?;
        let n = match recvmsg_inner(fd, addr, flags) {
            Ok(n) => n,
            Err(Errno::Again) if recvd > 0 => break,
            Err(err) => return Err(err),
        };
        mmsg.msg_len = n as u32;
        UserPtr::new(addr).write(root_pa, mmsg).ok_or(Errno::Fault)?;
        recvd += 1;
    }
    Ok(recvd)
}

fn sys_openat(_dirfd: usize, pathname: usize, flags: usize, _mode: usize) -> Result<usize, Errno> {
    if pathname == 0 {
        return Err(Errno::Fault);
    }
    let root_pa = mm::current_root_pa();
    if root_pa == 0 {
        return Err(Errno::Fault);
    }
    maybe_ext4_write_smoke();
    let status_flags = flags & (O_ACCMODE | O_NONBLOCK | O_CLOEXEC | O_APPEND);
    let accmode = flags & O_ACCMODE;
    let create_mode = (_mode as u16) & !current_umask();
    with_mounts(|mounts| {
        let mut path_buf = [0u8; MAX_PATH_LEN];
        let path = read_user_path_abs(root_pa, pathname, &mut path_buf)?;
        let mut created = false;
        let (mount, inode) = match mounts.resolve_path(path) {
            Ok((mount, inode)) => (mount, inode),
            Err(VfsError::NotFound) => {
                if (flags & O_CREAT) == 0 {
                    return Err(Errno::NoEnt);
                }
                let (mount, parent, name) = mounts.resolve_parent(path).map_err(map_vfs_err)?;
                let fs = mounts.fs_for(mount).ok_or(Errno::NoEnt)?;
                let inode = fs
                    .create(parent, name, FileType::File, create_mode)
                    .map_err(map_vfs_err)?;
                created = true;
                (mount, inode)
            }
            Err(err) => return Err(map_vfs_err(err)),
        };
        if !created && (flags & (O_CREAT | O_EXCL)) == (O_CREAT | O_EXCL) {
            return Err(Errno::Exist);
        }
        let fs = mounts.fs_for(mount).ok_or(Errno::NoEnt)?;
        let meta = fs.metadata(inode).map_err(map_vfs_err)?;
        match meta.file_type {
            FileType::Dir => {
                if accmode != O_RDONLY {
                    return Err(Errno::IsDir);
                }
            }
            FileType::Char | FileType::Block => {}
            FileType::File => {
                if accmode != O_RDONLY && (meta.mode & 0o222) == 0 {
                    return Err(Errno::Inval);
                }
            }
            _ => {
                if accmode == O_WRONLY || accmode == O_RDWR {
                    return Err(Errno::Inval);
                }
            }
        }
        if (flags & O_TRUNC) != 0 {
            if accmode == O_RDONLY {
                return Err(Errno::Inval);
            }
            match meta.file_type {
                FileType::Dir => return Err(Errno::IsDir),
                FileType::File => fs.truncate(inode, 0).map_err(map_vfs_err)?,
                _ => return Err(Errno::Inval),
            }
        }
        let handle = VfsHandle {
            mount,
            inode,
            file_type: meta.file_type,
        };
        alloc_fd(FdEntry {
            kind: FdKind::Vfs(handle),
            flags: status_flags,
            offset: 0,
            recv_timeout_ms: 0,
            send_timeout_ms: 0,
        })
        .ok_or(Errno::MFile)
    })
}

fn sys_mknodat(dirfd: usize, pathname: usize, _mode: usize, _dev: usize) -> Result<usize, Errno> {
    // 占位实现：仅校验目录 fd 与路径指针，拒绝真实节点创建。
    let root_pa = mm::current_root_pa();
    if root_pa == 0 {
        return Err(Errno::Fault);
    }
    validate_at_dirfd(dirfd)?;
    validate_user_path(root_pa, pathname)?;
    vfs_check_parent(root_pa, pathname)?;
    match vfs_lookup_inode(root_pa, pathname) {
        Ok(_) => Err(Errno::Exist),
        Err(err) => Err(err),
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
    vfs_check_parent(root_pa, pathname)?;
    match vfs_lookup_inode(root_pa, pathname) {
        Ok(_) => Err(Errno::Exist),
        Err(err) => Err(err),
    }
}

fn sys_unlinkat(_dirfd: usize, pathname: usize, _flags: usize) -> Result<usize, Errno> {
    if pathname == 0 {
        return Err(Errno::Fault);
    }
    let root_pa = mm::current_root_pa();
    if root_pa == 0 {
        return Err(Errno::Fault);
    }
    vfs_check_parent(root_pa, pathname)?;
    match vfs_lookup_inode(root_pa, pathname) {
        Ok(_) => Err(Errno::Inval),
        Err(err) => Err(err),
    }
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
    vfs_check_parent(root_pa, newpath)?;
    match vfs_lookup_inode(root_pa, newpath) {
        Ok(_) => Err(Errno::Exist),
        Err(err) => Err(err),
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
    vfs_check_parent(root_pa, newpath)?;
    if let Err(err) = vfs_lookup_inode(root_pa, oldpath) {
        return Err(err);
    }
    if vfs_lookup_inode(root_pa, newpath).is_ok() {
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
    vfs_check_parent(root_pa, newpath)?;
    let (old_mount, old_inode) = match vfs_lookup_inode(root_pa, oldpath) {
        Ok(value) => value,
        Err(err) => return Err(err),
    };
    match vfs_lookup_inode(root_pa, newpath) {
        Ok((new_mount, new_inode)) => {
            if new_mount == old_mount && new_inode == old_inode {
                Ok(0)
            } else {
                Err(Errno::Exist)
            }
        }
        Err(err) => Err(err),
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
    let entry = resolve_fd(fd).ok_or(Errno::Badf)?;
    let index = fd_offset(fd).ok_or(Errno::Badf)?;
    with_mounts(|mounts| {
        let handle = match entry.kind {
            FdKind::Vfs(handle) if handle.file_type == FileType::Dir => handle,
            _ => return Err(Errno::NotDir),
        };
        let mount_id = handle.mount;
        let inode = handle.inode;
        let fs = mounts.fs_for(mount_id).ok_or(Errno::NoEnt)?;
        let mut offset = index;
        let mut total_written = 0usize;
        let mut tmp_entries = [DirEntry::empty(); 8];
        loop {
            let count = fs.read_dir(inode, offset, &mut tmp_entries).map_err(map_vfs_err)?;
            if count == 0 {
                break;
            }
            let (written, consumed) =
                write_dirents(root_pa, buf + total_written, len - total_written, &tmp_entries[..count], offset)?;
            total_written += written;
            offset += consumed;
            if consumed < count || total_written >= len {
                break;
            }
        }
        set_fd_offset(fd, offset);
        Ok(total_written)
    })
}

fn write_dirents(
    root_pa: usize,
    buf: usize,
    len: usize,
    entries: &[DirEntry],
    base_index: usize,
) -> Result<(usize, usize), Errno> {
    const HDR_LEN: usize = 19;
    const RECORD_MAX: usize = 64;
    let mut written = 0usize;
    let mut index = 0usize;
    while index < entries.len() {
        let entry = entries[index];
        let name = entry.name();
        let name_len = name.len();
        let base_len = HDR_LEN + name_len + 1;
        let reclen = align_up(base_len, 8);
        if reclen > RECORD_MAX {
            return Err(Errno::Inval);
        }
        if written == 0 && reclen > len {
            return Err(Errno::Inval);
        }
        if written + reclen > len {
            break;
        }
        let mut record = [0u8; RECORD_MAX];
        let ino = entry.ino;
        let off = (base_index + index + 1) as i64;
        record[0..8].copy_from_slice(&ino.to_le_bytes());
        record[8..16].copy_from_slice(&off.to_le_bytes());
        record[16..18].copy_from_slice(&(reclen as u16).to_le_bytes());
        record[18] = dirent_dtype(entry.file_type);
        record[19..19 + name_len].copy_from_slice(name);
        let dst = buf.checked_add(written).ok_or(Errno::Fault)?;
        UserSlice::new(dst, reclen)
            .copy_from_slice(root_pa, &record[..reclen])
            .ok_or(Errno::Fault)?;
        written += reclen;
        index += 1;
    }
    Ok((written, index))
}

fn align_up(value: usize, align: usize) -> usize {
    (value + align - 1) & !(align - 1)
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
    let mut path_buf = [0u8; MAX_PATH_LEN];
    let path = read_user_path_abs(root_pa, pathname, &mut path_buf)?;
    with_mounts(|mounts| {
        let (mount_id, inode) = mounts.resolve_path(path).map_err(map_vfs_err)?;
        let fs = mounts.fs_for(mount_id).ok_or(Errno::NoEnt)?;
        let meta = fs.metadata(inode).map_err(map_vfs_err)?;
        let size = meta.size as usize;
        let mode = file_type_mode(meta.file_type) | meta.mode as u32;
        UserPtr::new(stat_ptr)
            .write(root_pa, build_stat(mode, size))
            .ok_or(Errno::Fault)?;
        Ok(0)
    })
}

fn sys_faccessat(_dirfd: usize, pathname: usize, _mode: usize, _flags: usize) -> Result<usize, Errno> {
    if pathname == 0 {
        return Err(Errno::Fault);
    }
    let root_pa = mm::current_root_pa();
    if root_pa == 0 {
        return Err(Errno::Fault);
    }
    let _ = vfs_lookup_inode(root_pa, pathname)?;
    Ok(0)
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
    let _ = vfs_lookup_inode(root_pa, pathname)?;
    const STATX_SIZE: usize = 256;
    zero_user_write(root_pa, statxbuf, STATX_SIZE)?;
    Ok(0)
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
    let (mount, inode) = vfs_lookup_inode(root_pa, pathname)?;
    with_mounts(|mounts| {
        let fs = mounts.fs_for(mount).ok_or(Errno::NoEnt)?;
        let meta = fs.metadata(inode).map_err(map_vfs_err)?;
        if meta.file_type != FileType::Symlink {
            return Err(Errno::Inval);
        }
        Err(Errno::Inval)
    })
}

fn sys_readlink(pathname: usize, buf: usize, len: usize) -> Result<usize, Errno> {
    sys_readlinkat(AT_FDCWD as usize, pathname, buf, len)
}

fn sys_statfs(pathname: usize, buf: usize) -> Result<usize, Errno> {
    if pathname == 0 || buf == 0 {
        return Err(Errno::Fault);
    }
    let root_pa = mm::current_root_pa();
    if root_pa == 0 {
        return Err(Errno::Fault);
    }
    // 占位实现：仅支持根目录与 /dev 伪节点。
    validate_user_path(root_pa, pathname)?;
    let _ = vfs_lookup_inode(root_pa, pathname)?;
    UserPtr::new(buf)
        .write(root_pa, default_statfs())
        .ok_or(Errno::Fault)?;
    Ok(0)
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

fn sys_ftruncate(fd: usize, len: usize) -> Result<usize, Errno> {
    let root_pa = mm::current_root_pa();
    if root_pa == 0 {
        return Err(Errno::Fault);
    }
    let entry = resolve_fd(fd).ok_or(Errno::Badf)?;
    let handle = match entry.kind {
        FdKind::Vfs(handle) => handle,
        _ => return Err(Errno::Inval),
    };
    if handle.file_type != FileType::File {
        return Err(Errno::Inval);
    }
    with_mounts(|mounts| {
        let fs = mounts.fs_for(handle.mount).ok_or(Errno::NoEnt)?;
        fs.truncate(handle.inode, len as u64).map_err(map_vfs_err)?;
        Ok(0)
    })
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
    let _ = vfs_lookup_inode(root_pa, pathname)?;
    Ok(0)
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
    let _ = vfs_lookup_inode(root_pa, pathname)?;
    Ok(0)
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
    let _ = vfs_lookup_inode(root_pa, pathname)?;
    Ok(0)
}

fn sys_poll(fds: usize, nfds: usize, timeout: usize) -> Result<usize, Errno> {
    // poll 的 timeout 为有符号毫秒，负值表示无限期等待。
    let timeout = timeout as isize;
    let timeout_ms = if timeout < 0 {
        None
    } else {
        Some(timeout as u64)
    };
    let root_pa = mm::current_root_pa();
    if root_pa == 0 {
        return Err(Errno::Fault);
    }
    ppoll_wait(root_pa, fds, nfds, timeout_ms)
}

fn sys_ppoll(fds: usize, nfds: usize, tmo: usize, _sigmask: usize, _sigsetsize: usize) -> Result<usize, Errno> {
    let root_pa = mm::current_root_pa();
    if root_pa == 0 {
        return Err(Errno::Fault);
    }
    let timeout_ms = ppoll_timeout_ms(root_pa, tmo)?;
    ppoll_wait(root_pa, fds, nfds, timeout_ms)
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
    let _ = crate::process::set_current_clear_tid(tidptr);
    Ok(current_pid())
}

fn sys_futex(
    uaddr: usize,
    op: usize,
    val: usize,
    timeout: usize,
    _uaddr2: usize,
    _val3: usize,
) -> Result<usize, Errno> {
    const FUTEX_WAIT: usize = 0;
    const FUTEX_WAKE: usize = 1;
    const FUTEX_CMD_MASK: usize = 0x7f;
    const FUTEX_PRIVATE_FLAG: usize = 0x80;

    let cmd = op & FUTEX_CMD_MASK;
    let private = (op & FUTEX_PRIVATE_FLAG) != 0;
    match cmd {
        FUTEX_WAIT => {
            let root_pa = mm::current_root_pa();
            if root_pa == 0 {
                return Err(Errno::Fault);
            }
            let timeout_ms = futex_timeout_ms(root_pa, timeout)?;
            futex::wait(root_pa, uaddr, val as u32, timeout_ms, private)
                .map(|_| 0)
                .map_err(map_futex_err)
        }
        FUTEX_WAKE => {
            let root_pa = mm::current_root_pa();
            if root_pa == 0 {
                return Err(Errno::Fault);
            }
            futex::wake(root_pa, uaddr, val, private).map_err(map_futex_err)
        }
        _ => Err(Errno::Inval),
    }
}

fn futex_timeout_ms(root_pa: usize, timeout: usize) -> Result<Option<u64>, Errno> {
    if timeout == 0 {
        return Ok(None);
    }
    let ts = UserPtr::<Timespec>::new(timeout)
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
    if buf == 0 {
        return Err(Errno::Fault);
    }
    let root_pa = mm::current_root_pa();
    if root_pa == 0 {
        return Err(Errno::Fault);
    }
    let cwd = current_cwd_str();
    let cwd_len = cwd.as_bytes().len();
    if size < cwd_len + 1 {
        return Err(Errno::Range);
    }
    UserSlice::new(buf, cwd_len)
        .copy_from_slice(root_pa, cwd.as_bytes())
        .ok_or(Errno::Fault)?;
    UserPtr::<u8>::new(buf + cwd_len)
        .write(root_pa, 0)
        .ok_or(Errno::Fault)?;
    Ok(cwd_len + 1)
}

fn sys_chdir(pathname: usize) -> Result<usize, Errno> {
    if pathname == 0 {
        return Err(Errno::Fault);
    }
    let root_pa = mm::current_root_pa();
    if root_pa == 0 {
        return Err(Errno::Fault);
    }
    let mut path_buf = [0u8; MAX_PATH_LEN];
    let path = read_user_path_abs(root_pa, pathname, &mut path_buf)?;
    with_mounts(|mounts| {
        let (mount, inode) = mounts.resolve_path(path).map_err(map_vfs_err)?;
        let fs = mounts.fs_for(mount).ok_or(Errno::NoEnt)?;
        let meta = fs.metadata(inode).map_err(map_vfs_err)?;
        if meta.file_type == FileType::Dir {
            set_current_cwd(path)?;
            Ok(0)
        } else {
            Err(Errno::NotDir)
        }
    })
}

fn sys_fchdir(fd: usize) -> Result<usize, Errno> {
    let entry = resolve_fd(fd).ok_or(Errno::Badf)?;
    match entry.kind {
        FdKind::Vfs(handle) if handle.file_type == FileType::Dir => {
            let mut updated = false;
            if handle.mount == MountId::Dev && handle.inode == devfs::ROOT_ID {
                set_current_cwd("/dev")?;
                updated = true;
            } else if handle.mount == MountId::Proc && handle.inode == procfs::ROOT_ID {
                set_current_cwd("/proc")?;
                updated = true;
            } else if handle.mount == MountId::Root {
                let root_inode = with_mounts(|mounts| {
                    let fs = mounts.fs_for(MountId::Root).ok_or(Errno::NoEnt)?;
                    fs.root().map_err(map_vfs_err)
                })?;
                if handle.inode == root_inode {
                    set_current_cwd("/")?;
                    updated = true;
                }
            }
            if !updated {
                // 未知目录路径：保持 cwd 不变。
                return Ok(0);
            }
            Ok(0)
        }
        _ => Err(Errno::NotDir),
    }
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
    let entry = resolve_fd(fd).ok_or(Errno::Badf)?;
    if matches!(entry.kind, FdKind::PipeRead(_) | FdKind::PipeWrite(_)) {
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
    let entry = resolve_fd(fd).ok_or(Errno::Badf)?;
    let root_pa = mm::current_root_pa();
    if root_pa == 0 {
        return Err(Errno::Fault);
    }
    let (mode, size) = match entry.kind {
        FdKind::PipeRead(_) | FdKind::PipeWrite(_) => (S_IFIFO | 0o600, 0),
        FdKind::Vfs(handle) => with_mounts(|mounts| {
            let fs = mounts.fs_for(handle.mount).ok_or(Errno::NoEnt)?;
            vfs_meta_for(fs, handle.inode)
        })?,
        _ => (S_IFCHR | 0o666, 0),
    };
    let stat = build_stat(mode, size);
    UserPtr::new(stat_ptr)
        .write(root_pa, stat)
        .ok_or(Errno::Fault)?;
    Ok(0)
}

fn sys_dup(oldfd: usize) -> Result<usize, Errno> {
    let entry = resolve_fd(oldfd).ok_or(Errno::Badf)?;
    let newfd = alloc_fd(entry).ok_or(Errno::MFile)?;
    if let Some(offset) = fd_offset(oldfd) {
        set_fd_offset(newfd, offset);
    }
    Ok(newfd)
}

fn sys_dup3(oldfd: usize, newfd: usize, flags: usize) -> Result<usize, Errno> {
    let entry = resolve_fd(oldfd).ok_or(Errno::Badf)?;
    if flags != 0 && flags != O_CLOEXEC {
        return Err(Errno::Inval);
    }
    if oldfd == newfd {
        return if flags == 0 { Ok(newfd) } else { Err(Errno::Inval) };
    }
    let newfd = dup_to_fd(newfd, entry)?;
    if let Some(offset) = fd_offset(oldfd) {
        set_fd_offset(newfd, offset);
    }
    Ok(newfd)
}

fn sys_lseek(fd: usize, offset: usize, whence: usize) -> Result<usize, Errno> {
    let entry = resolve_fd(fd).ok_or(Errno::Badf)?;
    let offset = offset as isize;
    if offset < 0 {
        return Err(Errno::Inval);
    }
    let offset = offset as usize;
    match entry.kind {
        FdKind::Vfs(handle) => {
            let base = match whence {
                SEEK_SET => 0,
                SEEK_CUR => fd_offset(fd).ok_or(Errno::Badf)?,
                SEEK_END => with_mounts(|mounts| {
                    let fs = mounts.fs_for(handle.mount).ok_or(Errno::NoEnt)?;
                    let (_, size) = vfs_meta_for(fs, handle.inode)?;
                    Ok(size)
                })?,
                _ => return Err(Errno::Inval),
            };
            let new_offset = base.checked_add(offset).ok_or(Errno::Inval)?;
            set_fd_offset(fd, new_offset);
            Ok(new_offset)
        }
        FdKind::Empty => Err(Errno::Badf),
        _ => Err(Errno::Pipe),
    }
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

fn sys_fcntl(fd: usize, cmd: usize, arg: usize) -> Result<usize, Errno> {
    let entry = resolve_fd(fd).ok_or(Errno::Badf)?;
    match cmd {
        F_GETFD => Ok(0),
        F_SETFD => Ok(0),
        F_GETFL => {
            let mode = match entry.kind {
                FdKind::Stdin | FdKind::PipeRead(_) => O_RDONLY,
                FdKind::Stdout | FdKind::Stderr | FdKind::PipeWrite(_) => O_WRONLY,
                FdKind::Vfs(_) => entry.flags & O_ACCMODE,
                _ => O_RDWR,
            };
            Ok(mode | (entry.flags & (O_NONBLOCK | O_APPEND)))
        }
        F_SETFL => {
            set_fd_flags(fd, arg)?;
            Ok(0)
        }
        _ => Err(Errno::Inval),
    }
}

fn sys_umask(mask: usize) -> Result<usize, Errno> {
    let old = set_current_umask((mask & 0o777) as u16)?;
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
    UserPtr::new(usage)
        .write(root_pa, default_rusage())
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

fn sys_wait4(pid: usize, status: usize, options: usize, rusage: usize) -> Result<usize, Errno> {
    let waited = crate::process::waitpid(pid as isize, status, options)?;
    if waited == 0 || rusage == 0 {
        return Ok(waited);
    }
    let root_pa = mm::current_root_pa();
    if root_pa == 0 {
        return Err(Errno::Fault);
    }
    // wait4 子进程统计占位：复用 getrusage 的最小填充。
    UserPtr::new(rusage)
        .write(root_pa, default_rusage())
        .ok_or(Errno::Fault)?;
    Ok(waited)
}

// 占位 rusage：复用单调时间作为用户态时间，其余字段清零。
fn default_rusage() -> Rusage {
    let now_ns = time::monotonic_ns();
    let user_time = KernelTimeval {
        tv_sec: (now_ns / 1_000_000_000) as isize,
        tv_usec: ((now_ns % 1_000_000_000) / 1_000) as isize,
    };
    let zero = KernelTimeval { tv_sec: 0, tv_usec: 0 };
    Rusage {
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
    }
}

fn build_stat(mode: u32, size: usize) -> Stat {
    let now_ns = time::monotonic_ns();
    let sec = (now_ns / 1_000_000_000) as isize;
    let nsec = (now_ns % 1_000_000_000) as usize;
    let blocks = (size.saturating_add(511) / 512) as isize;
    Stat {
        st_dev: 0,
        st_ino: 0,
        st_mode: mode,
        st_nlink: 1,
        st_uid: 0,
        st_gid: 0,
        st_rdev: 0,
        __pad1: 0,
        st_size: size as isize,
        st_blksize: 4096,
        __pad2: 0,
        st_blocks: blocks,
        st_atime: sec,
        st_atime_nsec: nsec,
        st_mtime: sec,
        st_mtime_nsec: nsec,
        st_ctime: sec,
        st_ctime_nsec: nsec,
        __unused4: 0,
        __unused5: 0,
    }
}

fn file_type_mode(file_type: FileType) -> u32 {
    match file_type {
        FileType::Dir => S_IFDIR,
        FileType::File => S_IFREG,
        FileType::Char => S_IFCHR,
        FileType::Block => S_IFBLK,
        FileType::Fifo => S_IFIFO,
        FileType::Socket => 0,
        FileType::Symlink => 0,
    }
}

fn dirent_dtype(file_type: FileType) -> u8 {
    match file_type {
        FileType::Dir => 4,
        FileType::File => 8,
        FileType::Char => 2,
        FileType::Block => 6,
        FileType::Fifo => 1,
        FileType::Socket => 12,
        FileType::Symlink => 10,
    }
}

fn vfs_meta_for(fs: &dyn VfsOps, inode: InodeId) -> Result<(u32, usize), Errno> {
    let meta = fs.metadata(inode).map_err(map_vfs_err)?;
    let mode = file_type_mode(meta.file_type) | meta.mode as u32;
    Ok((mode, meta.size as usize))
}

fn current_pid() -> usize {
    // Single-hart early boot uses TaskId+1 as a stable placeholder PID.
    crate::process::current_pid()
        .or_else(|| crate::runtime::current_task_id().map(|id| id + 1))
        .unwrap_or(1)
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

fn read_user_path_str<'a>(root_pa: usize, path: usize, buf: &'a mut [u8]) -> Result<&'a str, Errno> {
    for i in 0..buf.len() {
        let ch = read_user_byte(root_pa, path + i)?;
        if ch == 0 {
            return core::str::from_utf8(&buf[..i]).map_err(|_| Errno::Inval);
        }
        buf[i] = ch;
    }
    Err(Errno::Range)
}

fn log_rootfs_once(kind: &str, bit: u8) {
    if ROOTFS_LOGGED.fetch_or(bit, Ordering::AcqRel) & bit == 0 {
        crate::println!("vfs: mounted {} rootfs", kind);
    }
}

fn init_rootfs_kind() {
    if ROOTFS_KIND.load(Ordering::Acquire) != ROOTFS_KIND_UNKNOWN {
        return;
    }
    let root_dev = crate::fs::root_device();
    let root_block = root_dev.as_block_device();
    if let Ok(rootfs) = ext4::Ext4Fs::new(root_block) {
        // SAFETY: 单核初始化阶段写入 rootfs 实例。
        unsafe {
            ROOTFS_EXT4.write(rootfs);
        }
        ROOTFS_KIND.store(ROOTFS_KIND_EXT4, Ordering::Release);
        return;
    }
    if let Ok(rootfs) = fat32::Fat32Fs::new(root_block) {
        // SAFETY: 单核初始化阶段写入 rootfs 实例。
        unsafe {
            ROOTFS_FAT32.write(rootfs);
        }
        ROOTFS_KIND.store(ROOTFS_KIND_FAT32, Ordering::Release);
        return;
    }
    let rootfs = memfs::MemFs::with_init_image(init_memfile_image());
    // SAFETY: 单核初始化阶段写入 rootfs 实例。
    unsafe {
        ROOTFS_MEMFS.write(rootfs);
    }
    ROOTFS_KIND.store(ROOTFS_KIND_MEMFS, Ordering::Release);
}

fn rootfs_kind() -> u8 {
    if ROOTFS_KIND.load(Ordering::Acquire) == ROOTFS_KIND_UNKNOWN {
        // 单核启动阶段惰性初始化。
        init_rootfs_kind();
    }
    ROOTFS_KIND.load(Ordering::Acquire)
}

fn rootfs_ref(kind: u8) -> &'static dyn VfsOps {
    match kind {
        ROOTFS_KIND_EXT4 => unsafe { &*ROOTFS_EXT4.as_ptr() },
        ROOTFS_KIND_FAT32 => unsafe { &*ROOTFS_FAT32.as_ptr() },
        _ => unsafe { &*ROOTFS_MEMFS.as_ptr() },
    }
}

fn with_mounts<R>(f: impl FnOnce(&MountTable<'_, VFS_MOUNT_COUNT>) -> R) -> R {
    let kind = rootfs_kind();
    match kind {
        ROOTFS_KIND_EXT4 => log_rootfs_once("ext4", ROOTFS_LOG_EXT4),
        ROOTFS_KIND_FAT32 => log_rootfs_once("fat32", ROOTFS_LOG_FAT32),
        _ => log_rootfs_once("memfs", ROOTFS_LOG_MEMFS),
    }
    let rootfs = rootfs_ref(kind);
    let mounts = MountTable::new([
        MountPoint::new(MountId::Root, "/", rootfs),
        MountPoint::new(MountId::Dev, "/dev", &DEVFS),
        MountPoint::new(MountId::Proc, "/proc", &PROCFS),
    ]);
    f(&mounts)
}

pub fn ext4_write_smoke() {
    if rootfs_kind() != ROOTFS_KIND_EXT4 {
        crate::println!("ext4: write skip (rootfs not ext4)");
        return;
    }
    let payload = b"ext4: write ok\n";
    let result = with_mounts(|mounts| {
        let fs = mounts.fs_for(MountId::Root).ok_or(VfsError::NotFound)?;
        let root = fs.root()?;
        let name = "ext4-smoke.log";
        let inode = match fs.lookup(root, name)? {
            Some(inode) => inode,
            None => fs.create(root, name, FileType::File, 0o644)?,
        };
        let _ = fs.truncate(inode, 0);
        let written = fs.write_at(inode, 0, payload)?;
        if written != payload.len() {
            return Err(VfsError::Io);
        }
        let mut buf = [0u8; 32];
        let read = fs.read_at(inode, 0, &mut buf)?;
        if read != payload.len() || &buf[..read] != payload {
            return Err(VfsError::Io);
        }
        Ok(())
    });
    match result {
        Ok(()) => crate::println!("ext4: write ok"),
        Err(err) => crate::println!("ext4: write failed ({:?})", err),
    }
}

fn maybe_ext4_write_smoke() {
    if !crate::config::ENABLE_EXT4_WRITE_TEST {
        return;
    }
    if rootfs_kind() != ROOTFS_KIND_EXT4 {
        return;
    }
    if EXT4_WRITE_DONE.swap(1, Ordering::AcqRel) != 0 {
        return;
    }
    ext4_write_smoke();
}

fn vfs_lookup_inode(root_pa: usize, pathname: usize) -> Result<(MountId, InodeId), Errno> {
    let mut buf = [0u8; MAX_PATH_LEN];
    let path = read_user_path_abs(root_pa, pathname, &mut buf)?;
    with_mounts(|mounts| mounts.resolve_path(path).map_err(map_vfs_err))
}

fn vfs_check_parent(root_pa: usize, pathname: usize) -> Result<(), Errno> {
    let mut buf = [0u8; MAX_PATH_LEN];
    let path = read_user_path_abs(root_pa, pathname, &mut buf)?;
    with_mounts(|mounts| mounts.resolve_parent(path).map(|_| ()).map_err(map_vfs_err))
}

fn map_vfs_err(err: VfsError) -> Errno {
    match err {
        VfsError::NotFound => Errno::NoEnt,
        VfsError::NotDir => Errno::NotDir,
        VfsError::AlreadyExists => Errno::Exist,
        VfsError::Invalid => Errno::NoEnt,
        VfsError::NoMem => Errno::NoMem,
        VfsError::Permission => Errno::Inval,
        VfsError::Busy => Errno::Again,
        VfsError::NotSupported | VfsError::Io | VfsError::Unknown => Errno::Inval,
    }
}

fn map_net_err(err: axnet::NetError) -> Errno {
    match err {
        axnet::NetError::NotReady | axnet::NetError::WouldBlock => Errno::Again,
        axnet::NetError::BufferTooSmall => Errno::Range,
        axnet::NetError::Unsupported => Errno::NoSys,
        axnet::NetError::Invalid => Errno::Inval,
        axnet::NetError::NoMem => Errno::NoMem,
        axnet::NetError::InProgress => Errno::InProgress,
        axnet::NetError::IsConnected => Errno::IsConn,
        axnet::NetError::Unreachable => Errno::NetUnreach,
        axnet::NetError::ConnRefused => Errno::ConnRefused,
    }
}

fn validate_user_ptr_list(root_pa: usize, ptr: usize) -> Result<(), Errno> {
    if ptr == 0 {
        return Ok(());
    }
    let size = size_of::<usize>();
    if mm::translate_user_ptr(root_pa, ptr, size, UserAccess::Read).is_none() {
        return Err(Errno::Fault);
    }
    Ok(())
}

fn map_futex_err(err: futex::FutexError) -> Errno {
    match err {
        futex::FutexError::Fault => Errno::Fault,
        futex::FutexError::Again => Errno::Again,
        futex::FutexError::Inval => Errno::Inval,
        futex::FutexError::NoMem => Errno::NoMem,
        futex::FutexError::TimedOut => Errno::TimedOut,
    }
}

pub fn can_block_current() -> bool {
    crate::runtime::current_task_id().is_some()
}

fn pipe_read_queue(pipe_id: usize) -> &'static crate::task_wait_queue::TaskWaitQueue {
    &PIPE_READ_WAITERS[pipe_id]
}

fn pipe_write_queue(pipe_id: usize) -> &'static crate::task_wait_queue::TaskWaitQueue {
    &PIPE_WRITE_WAITERS[pipe_id]
}

fn ppoll_wait_queue() -> &'static crate::task_wait_queue::TaskWaitQueue {
    &POLL_WAITERS
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

fn current_proc_index() -> Option<usize> {
    let idx = crate::runtime::current_task_id()?;
    if idx < MAX_PROCS {
        Some(idx)
    } else {
        None
    }
}

fn current_umask() -> u16 {
    let Some(idx) = current_proc_index() else {
        return 0;
    };
    // SAFETY: 单核阶段顺序访问 umask。
    unsafe { PROC_UMASK[idx] }
}

fn set_current_umask(mask: u16) -> Result<u16, Errno> {
    let Some(idx) = current_proc_index() else {
        return Err(Errno::Fault);
    };
    // SAFETY: 单核阶段顺序访问 umask。
    let old = unsafe { PROC_UMASK[idx] };
    unsafe {
        PROC_UMASK[idx] = mask;
    }
    Ok(old)
}

fn init_proc_cwd(idx: usize) {
    if idx >= MAX_PROCS {
        return;
    }
    // SAFETY: 单核阶段顺序初始化 cwd。
    unsafe {
        PROC_CWD[idx][0] = b'/';
        PROC_CWD_LEN[idx] = 1;
    }
}

fn clone_proc_cwd(parent: usize, child: usize) {
    if parent >= MAX_PROCS || child >= MAX_PROCS {
        return;
    }
    // SAFETY: 单核阶段顺序复制 cwd。
    unsafe {
        PROC_CWD[child] = PROC_CWD[parent];
        PROC_CWD_LEN[child] = PROC_CWD_LEN[parent];
    }
}

fn clear_proc_cwd(idx: usize) {
    if idx >= MAX_PROCS {
        return;
    }
    // SAFETY: 单核阶段顺序清理 cwd。
    unsafe {
        PROC_CWD[idx] = [0; MAX_PATH_LEN];
        PROC_CWD_LEN[idx] = 0;
    }
}

fn current_cwd_str() -> &'static str {
    let Some(idx) = current_proc_index() else {
        return "/";
    };
    // SAFETY: 单核阶段顺序访问 cwd。
    let len = unsafe { PROC_CWD_LEN[idx] };
    if len == 0 || len > MAX_PATH_LEN {
        return "/";
    }
    let bytes = unsafe { &PROC_CWD[idx][..len] };
    core::str::from_utf8(bytes).unwrap_or("/")
}

fn set_current_cwd(path: &str) -> Result<(), Errno> {
    let Some(idx) = current_proc_index() else {
        return Err(Errno::Fault);
    };
    if !path.starts_with('/') {
        return Err(Errno::Inval);
    }
    if path.is_empty() || path.len() >= MAX_PATH_LEN {
        return Err(Errno::Range);
    }
    // SAFETY: 单核阶段顺序写入 cwd。
    unsafe {
        PROC_CWD[idx].fill(0);
        PROC_CWD[idx][..path.len()].copy_from_slice(path.as_bytes());
        PROC_CWD_LEN[idx] = path.len();
    }
    Ok(())
}

fn normalize_path<'a>(base: &str, path: &str, out: &'a mut [u8]) -> Result<&'a str, Errno> {
    const MAX_PATH_DEPTH: usize = axfs::mount::MAX_PATH_DEPTH;
    let mut len = 1usize;
    let mut depth = 0usize;
    let mut stack = [0usize; MAX_PATH_DEPTH];

    out.get_mut(0).ok_or(Errno::Range)?;
    out[0] = b'/';

    let mut push_segment = |seg: &str| -> Result<(), Errno> {
        if seg.is_empty() || seg == "." {
            return Ok(());
        }
        if seg == ".." {
            if depth > 0 {
                depth -= 1;
                let start = stack[depth];
                len = if start > 1 { start - 1 } else { 1 };
            }
            return Ok(());
        }
        if depth >= MAX_PATH_DEPTH {
            return Err(Errno::Range);
        }
        if len > 1 {
            if len >= out.len() {
                return Err(Errno::Range);
            }
            out[len] = b'/';
            len += 1;
        }
        let start = len;
        let bytes = seg.as_bytes();
        if start + bytes.len() > out.len() {
            return Err(Errno::Range);
        }
        out[start..start + bytes.len()].copy_from_slice(bytes);
        len += bytes.len();
        stack[depth] = start;
        depth += 1;
        Ok(())
    };

    if !path.starts_with('/') {
        for seg in base.split('/') {
            push_segment(seg)?;
        }
    }
    for seg in path.split('/') {
        push_segment(seg)?;
    }

    if len == 0 {
        if out.is_empty() {
            return Err(Errno::Range);
        }
        out[0] = b'/';
        len = 1;
    }
    core::str::from_utf8(&out[..len]).map_err(|_| Errno::Inval)
}

fn read_user_path_abs<'a>(root_pa: usize, path: usize, buf: &'a mut [u8]) -> Result<&'a str, Errno> {
    let mut raw_buf = [0u8; MAX_PATH_LEN];
    let raw = read_user_path_str(root_pa, path, &mut raw_buf)?;
    let base = if raw.starts_with('/') {
        "/"
    } else {
        current_cwd_str()
    };
    normalize_path(base, raw, buf)
}

fn stdio_kind(fd: usize) -> Option<FdKind> {
    match fd {
        0 => Some(FdKind::Stdin),
        1 => Some(FdKind::Stdout),
        2 => Some(FdKind::Stderr),
        _ => None,
    }
}

fn stdio_entry(fd: usize) -> Option<FdEntry> {
    let kind = stdio_kind(fd)?;
    let proc_idx = current_proc_index()?;
    // SAFETY: 单核早期阶段访问重定向表/标志。
    unsafe {
        if let Some(entry) = STDIO_REDIRECT[proc_idx][fd] {
            Some(entry)
        } else {
            Some(FdEntry {
                kind,
                flags: STDIO_FLAGS[proc_idx][fd],
                offset: 0,
                recv_timeout_ms: 0,
                send_timeout_ms: 0,
            })
        }
    }
}

fn resolve_fd(fd: usize) -> Option<FdEntry> {
    if let Some(entry) = stdio_entry(fd) {
        return Some(entry);
    }
    let proc_idx = current_proc_index()?;
    let idx = fd_table_index(fd)?;
    // SAFETY: 单核早期阶段，fd 表无并发访问。
    let entry = unsafe { FD_TABLES[proc_idx][idx] };
    if entry.kind == FdKind::Empty {
        None
    } else {
        Some(entry)
    }
}

fn fd_table_index(fd: usize) -> Option<usize> {
    if fd < FD_TABLE_BASE {
        return None;
    }
    let idx = fd - FD_TABLE_BASE;
    if idx >= FD_TABLE_SLOTS {
        None
    } else {
        Some(idx)
    }
}

fn fd_offset(fd: usize) -> Option<usize> {
    if stdio_kind(fd).is_some() {
        let proc_idx = current_proc_index()?;
        // SAFETY: 单核早期阶段访问重定向表。
        unsafe {
            if let Some(entry) = STDIO_REDIRECT[proc_idx][fd] {
                return Some(entry.offset);
            }
        }
        return Some(0);
    }
    let proc_idx = current_proc_index()?;
    let idx = fd_table_index(fd)?;
    // SAFETY: 单核早期阶段，fd 表无并发访问。
    let entry = unsafe { FD_TABLES[proc_idx][idx] };
    if entry.kind == FdKind::Empty {
        None
    } else {
        Some(entry.offset)
    }
}

fn set_fd_offset(fd: usize, offset: usize) {
    let Some(proc_idx) = current_proc_index() else {
        return;
    };
    if stdio_kind(fd).is_some() {
        // SAFETY: 单核早期阶段访问重定向表。
        unsafe {
            if let Some(mut entry) = STDIO_REDIRECT[proc_idx][fd] {
                entry.offset = offset;
                STDIO_REDIRECT[proc_idx][fd] = Some(entry);
            }
        }
        return;
    }
    let Some(idx) = fd_table_index(fd) else {
        return;
    };
    // SAFETY: 单核早期阶段，偏移顺序访问。
    unsafe {
        if FD_TABLES[proc_idx][idx].kind == FdKind::Empty {
            return;
        }
        FD_TABLES[proc_idx][idx].offset = offset;
    }
}

fn alloc_fd(entry: FdEntry) -> Option<usize> {
    if entry.kind == FdKind::Empty {
        return None;
    }
    let proc_idx = current_proc_index()?;
    // SAFETY: 单核早期阶段，fd 表串行更新。
    unsafe {
        for (idx, slot) in FD_TABLES[proc_idx].iter_mut().enumerate() {
            if slot.kind == FdKind::Empty {
                *slot = entry;
                pipe_acquire(entry.kind);
                return Some(FD_TABLE_BASE + idx);
            }
        }
    }
    None
}

fn dup_to_fd(newfd: usize, entry: FdEntry) -> Result<usize, Errno> {
    if stdio_kind(newfd).is_some() {
        return set_stdio_redirect(newfd, entry);
    }
    let proc_idx = current_proc_index().ok_or(Errno::Badf)?;
    let idx = fd_table_index(newfd).ok_or(Errno::Badf)?;
    // SAFETY: 单核早期阶段，fd 表串行更新。
    unsafe {
        let old = FD_TABLES[proc_idx][idx];
        if old.kind != FdKind::Empty {
            pipe_release(old.kind);
        }
        FD_TABLES[proc_idx][idx] = entry;
    }
    pipe_acquire(entry.kind);
    Ok(newfd)
}

fn replace_socket_fd(fd: usize, socket_id: axnet::SocketId) -> Result<(), Errno> {
    if stdio_kind(fd).is_some() {
        return Err(Errno::Badf);
    }
    let proc_idx = current_proc_index().ok_or(Errno::Badf)?;
    let idx = fd_table_index(fd).ok_or(Errno::Badf)?;
    // SAFETY: 单核早期阶段，fd 表串行更新。
    unsafe {
        let entry = &mut FD_TABLES[proc_idx][idx];
        if !matches!(entry.kind, FdKind::Socket(_)) {
            return Err(Errno::Badf);
        }
        entry.kind = FdKind::Socket(socket_id);
        entry.offset = 0;
    }
    Ok(())
}

fn close_fd(fd: usize) -> Result<usize, Errno> {
    let proc_idx = current_proc_index().ok_or(Errno::Badf)?;
    if stdio_kind(fd).is_some() {
        // SAFETY: 单核早期阶段访问重定向表。
        unsafe {
            if let Some(old) = STDIO_REDIRECT[proc_idx][fd] {
                pipe_release(old.kind);
                STDIO_REDIRECT[proc_idx][fd] = None;
            }
        }
        return Ok(0);
    }
    let idx = fd_table_index(fd).ok_or(Errno::Badf)?;
    // SAFETY: 单核早期阶段，fd 表串行更新。
    unsafe {
        let old = FD_TABLES[proc_idx][idx];
        if old.kind == FdKind::Empty {
            return Err(Errno::Badf);
        }
        FD_TABLES[proc_idx][idx] = EMPTY_FD_ENTRY;
        if let FdKind::Socket(socket_id) = old.kind {
            let _ = axnet::socket_close(socket_id);
        }
        pipe_release(old.kind);
    }
    Ok(0)
}

fn set_stdio_redirect(fd: usize, entry: FdEntry) -> Result<usize, Errno> {
    if stdio_kind(fd).is_none() {
        return Err(Errno::Badf);
    }
    let proc_idx = current_proc_index().ok_or(Errno::Badf)?;
    // SAFETY: 单核早期阶段访问重定向表。
    unsafe {
        if let Some(old) = STDIO_REDIRECT[proc_idx][fd] {
        if let FdKind::Socket(socket_id) = old.kind {
            let _ = axnet::socket_close(socket_id);
        }
        pipe_release(old.kind);
        }
        STDIO_REDIRECT[proc_idx][fd] = Some(entry);
    }
    pipe_acquire(entry.kind);
    Ok(fd)
}

fn set_fd_flags(fd: usize, flags: usize) -> Result<(), Errno> {
    let flags = flags & (O_NONBLOCK | O_APPEND);
    let proc_idx = current_proc_index().ok_or(Errno::Badf)?;
    if stdio_kind(fd).is_some() {
        // SAFETY: 单核早期阶段访问重定向表/标志。
        unsafe {
            if let Some(mut entry) = STDIO_REDIRECT[proc_idx][fd] {
                entry.flags = (entry.flags & O_ACCMODE) | flags;
                STDIO_REDIRECT[proc_idx][fd] = Some(entry);
            } else {
                STDIO_FLAGS[proc_idx][fd] = (STDIO_FLAGS[proc_idx][fd] & O_ACCMODE) | flags;
            }
        }
        return Ok(());
    }
    let idx = fd_table_index(fd).ok_or(Errno::Badf)?;
    // SAFETY: 单核早期阶段，fd 表串行更新。
    unsafe {
        if FD_TABLES[proc_idx][idx].kind == FdKind::Empty {
            return Err(Errno::Badf);
        }
        FD_TABLES[proc_idx][idx].flags = (FD_TABLES[proc_idx][idx].flags & O_ACCMODE) | flags;
    }
    Ok(())
}

fn clear_fd_table(idx: usize) {
    if idx >= MAX_PROCS {
        return;
    }
    // SAFETY: 单核早期阶段按进程顺序清理 fd 表。
    unsafe {
        for entry in FD_TABLES[idx].iter_mut() {
            if entry.kind != FdKind::Empty {
                pipe_release(entry.kind);
                *entry = EMPTY_FD_ENTRY;
            }
        }
        for slot in STDIO_REDIRECT[idx].iter_mut() {
            if let Some(entry) = *slot {
                pipe_release(entry.kind);
            }
            *slot = None;
        }
        for flag in STDIO_FLAGS[idx].iter_mut() {
            *flag = 0;
        }
    }
}

pub fn init_fd_table(task_id: TaskId) {
    clear_fd_table(task_id);
    init_proc_cwd(task_id);
    if task_id < MAX_PROCS {
        // SAFETY: 单核阶段顺序初始化 umask。
        unsafe {
            PROC_UMASK[task_id] = 0;
        }
    }
}

pub fn clone_fd_table(parent: TaskId, child: TaskId) {
    if parent >= MAX_PROCS || child >= MAX_PROCS {
        return;
    }
    clear_fd_table(child);
    // SAFETY: 单核早期阶段按进程顺序复制 fd 表。
    unsafe {
        FD_TABLES[child] = FD_TABLES[parent];
        STDIO_REDIRECT[child] = STDIO_REDIRECT[parent];
        STDIO_FLAGS[child] = STDIO_FLAGS[parent];
        for entry in FD_TABLES[child].iter() {
            pipe_acquire(entry.kind);
        }
        for slot in STDIO_REDIRECT[child].iter() {
            if let Some(entry) = *slot {
                pipe_acquire(entry.kind);
            }
        }
    }
    clone_proc_cwd(parent, child);
    // SAFETY: 单核阶段顺序复制 umask。
    unsafe {
        PROC_UMASK[child] = PROC_UMASK[parent];
    }
}

pub fn release_fd_table(task_id: TaskId) {
    clear_fd_table(task_id);
    clear_proc_cwd(task_id);
    if task_id < MAX_PROCS {
        // SAFETY: 单核阶段顺序清理 umask。
        unsafe {
            PROC_UMASK[task_id] = 0;
        }
    }
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

fn eventfd_queue(event_id: usize) -> &'static crate::task_wait_queue::TaskWaitQueue {
    &EVENTFD_WAITERS[event_id]
}

fn timerfd_queue(timer_id: usize) -> &'static crate::task_wait_queue::TaskWaitQueue {
    &TIMERFD_WAITERS[timer_id]
}

fn alloc_eventfd(initval: u64, flags: usize) -> Option<usize> {
    // SAFETY: 单核早期阶段串行更新 eventfd 表。
    unsafe {
        for (idx, slot) in EVENTFDS.iter_mut().enumerate() {
            if !slot.used {
                *slot = EventFd {
                    used: true,
                    refs: 1,
                    counter: initval,
                    flags,
                };
                return Some(idx);
            }
        }
    }
    None
}

fn alloc_timerfd(flags: usize) -> Option<usize> {
    // SAFETY: 单核早期阶段串行更新 timerfd 表。
    unsafe {
        for (idx, slot) in TIMERFDS.iter_mut().enumerate() {
            if !slot.used {
                *slot = TimerFd {
                    used: true,
                    refs: 1,
                    next_ns: 0,
                    interval_ns: 0,
                    flags,
                };
                return Some(idx);
            }
        }
    }
    None
}

fn alloc_epoll(flags: usize) -> Option<usize> {
    // SAFETY: 单核早期阶段串行更新 epoll 表。
    unsafe {
        for (idx, slot) in EPOLLS.iter_mut().enumerate() {
            if !slot.used {
                *slot = EpollInstance {
                    used: true,
                    refs: 1,
                    flags,
                    items: [EMPTY_EPOLL_ITEM; EPOLL_ITEM_SLOTS],
                };
                return Some(idx);
            }
        }
    }
    None
}

fn pipe_acquire(kind: FdKind) {
    let (pipe_id, is_read) = match kind {
        FdKind::PipeRead(id) => (id, true),
        FdKind::PipeWrite(id) => (id, false),
        FdKind::Eventfd(id) => {
            if id < EVENTFD_SLOTS {
                unsafe {
                    if EVENTFDS[id].used {
                        EVENTFDS[id].refs += 1;
                    }
                }
            }
            return;
        }
        FdKind::Timerfd(id) => {
            if id < TIMERFD_SLOTS {
                unsafe {
                    if TIMERFDS[id].used {
                        TIMERFDS[id].refs += 1;
                    }
                }
            }
            return;
        }
        FdKind::Epoll(id) => {
            if id < EPOLL_SLOTS {
                unsafe {
                    if EPOLLS[id].used {
                        EPOLLS[id].refs += 1;
                    }
                }
            }
            return;
        }
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
        FdKind::Eventfd(id) => {
            if id < EVENTFD_SLOTS {
                unsafe {
                    if EVENTFDS[id].used && EVENTFDS[id].refs > 0 {
                        EVENTFDS[id].refs -= 1;
                        if EVENTFDS[id].refs == 0 {
                            EVENTFDS[id] = EMPTY_EVENTFD;
                        }
                    }
                }
            }
            return;
        }
        FdKind::Timerfd(id) => {
            if id < TIMERFD_SLOTS {
                unsafe {
                    if TIMERFDS[id].used && TIMERFDS[id].refs > 0 {
                        TIMERFDS[id].refs -= 1;
                        if TIMERFDS[id].refs == 0 {
                            TIMERFDS[id] = EMPTY_TIMERFD;
                        }
                    }
                }
            }
            return;
        }
        FdKind::Epoll(id) => {
            if id < EPOLL_SLOTS {
                unsafe {
                    if EPOLLS[id].used && EPOLLS[id].refs > 0 {
                        EPOLLS[id].refs -= 1;
                        if EPOLLS[id].refs == 0 {
                            EPOLLS[id] = EMPTY_EPOLL;
                        }
                    }
                }
            }
            return;
        }
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
    // fd 关闭可能触发 HUP/ERR，唤醒 poll/ppoll 等待者。
    let _ = crate::runtime::wake_all(ppoll_wait_queue());
    if unsafe { PIPES[pipe_id].readers == 0 && PIPES[pipe_id].writers == 0 } {
        unsafe {
            PIPES[pipe_id] = EMPTY_PIPE;
        }
    }
}

fn pipe_read(pipe_id: usize, root_pa: usize, buf: usize, len: usize, nonblock: bool) -> Result<usize, Errno> {
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
            if nonblock || !can_block_current() {
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
    let _ = crate::runtime::wake_all(ppoll_wait_queue());
    Ok(to_read)
}

fn pipe_write(pipe_id: usize, root_pa: usize, buf: usize, len: usize, nonblock: bool) -> Result<usize, Errno> {
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
            if nonblock || !can_block_current() {
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
    let _ = crate::runtime::wake_all(ppoll_wait_queue());
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
    let entry = match resolve_fd(fd) {
        Some(entry) => entry,
        None => return POLLNVAL,
    };
    match entry.kind {
        FdKind::Stdin => {
            let mut revents = 0u16;
            if (events & POLLIN) != 0 && console_peek() {
                revents |= POLLIN;
            }
            revents
        }
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
        FdKind::Eventfd(event_id) => {
            if event_id >= EVENTFD_SLOTS {
                return POLLNVAL;
            }
            let mut revents = 0u16;
            let event = unsafe { &EVENTFDS[event_id] };
            if !event.used {
                return POLLNVAL;
            }
            let counter = event.counter;
            if (events & POLLIN) != 0 && counter > 0 {
                revents |= POLLIN;
            }
            if (events & POLLOUT) != 0 && counter < u64::MAX - 1 {
                revents |= POLLOUT;
            }
            revents
        }
        FdKind::Timerfd(timer_id) => {
            if timer_id >= TIMERFD_SLOTS {
                return POLLNVAL;
            }
            let mut revents = 0u16;
            let timer = unsafe { &TIMERFDS[timer_id] };
            if !timer.used {
                return POLLNVAL;
            }
            let next_ns = timer.next_ns;
            if (events & POLLIN) != 0 && next_ns != 0 && time::monotonic_ns() >= next_ns {
                revents |= POLLIN;
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
        FdKind::Epoll(epoll_id) => {
            let mut revents = 0u16;
            if (events & POLLIN) != 0 && epoll_has_ready(epoll_id) {
                revents |= POLLIN;
            }
            revents
        }
        FdKind::Vfs(handle) => {
            let mut revents = 0u16;
            if (events & POLLIN) != 0 {
                revents |= POLLIN;
            }
            if (events & POLLOUT) != 0 && handle.file_type != FileType::Dir {
                revents |= POLLOUT;
            }
            revents
        }
        FdKind::Socket(socket_id) => {
            match axnet::socket_poll(socket_id, events) {
                Ok(revents) => revents,
                Err(axnet::NetError::Invalid | axnet::NetError::NotReady) => POLLNVAL,
                Err(_) => 0,
            }
        }
        _ => 0,
    }
}

fn ppoll_wait(root_pa: usize, fds: usize, nfds: usize, timeout_ms: Option<u64>) -> Result<usize, Errno> {
    if nfds == 0 {
        return ppoll_sleep_only(timeout_ms);
    }
    if fds == 0 {
        return Err(Errno::Fault);
    }
    let stride = size_of::<PollFd>();
    let total = nfds.checked_mul(stride).ok_or(Errno::Fault)?;
    validate_user_read(root_pa, fds, total)?;
    validate_user_write(root_pa, fds, total)?;
    let (ready, single) = ppoll_scan(root_pa, fds, nfds)?;
    if ready > 0 || !can_block_current() {
        return Ok(ready);
    }
    if let Some(0) = timeout_ms {
        return Ok(0);
    }
    if nfds == 1 {
        if let Some((fd, events)) = single {
            if let Some(queue) = ppoll_single_waiter_queue(fd, events) {
                if let Some(timeout_ms) = timeout_ms {
                    let _ = crate::runtime::wait_timeout_ms(queue, timeout_ms);
                } else {
                    crate::runtime::block_current(queue);
                }
                let (ready_after, _) = ppoll_scan(root_pa, fds, nfds)?;
                return Ok(ready_after);
            }
        }
    }
    // 多 fd 情况用简单 sleep-retry 轮询：定时睡眠后重新扫描。
    let mut remaining_ms = timeout_ms;
    loop {
        let sleep_ms = match remaining_ms {
            Some(0) => return Ok(0),
            Some(ms) => core::cmp::min(ms, PPOLL_RETRY_SLEEP_MS),
            None => PPOLL_RETRY_SLEEP_MS,
        };
        if sleep_ms == 0 {
            return Ok(0);
        }
        ppoll_sleep_ms(sleep_ms);
        if let Some(ms) = remaining_ms {
            remaining_ms = Some(ms.saturating_sub(sleep_ms));
        }
        let (ready_retry, _) = ppoll_scan(root_pa, fds, nfds)?;
        if ready_retry > 0 {
            return Ok(ready_retry);
        }
        if !can_block_current() {
            return Ok(0);
        }
    }
}

fn ppoll_sleep_only(timeout_ms: Option<u64>) -> Result<usize, Errno> {
    // nfds=0 作为睡眠路径，复用调度器的定时阻塞能力。
    if let Some(0) = timeout_ms {
        return Ok(0);
    }
    if !can_block_current() {
        return Ok(0);
    }
    let mut remaining_ms = timeout_ms;
    loop {
        let sleep_ms = match remaining_ms {
            Some(0) => return Ok(0),
            Some(ms) => core::cmp::min(ms, PPOLL_RETRY_SLEEP_MS),
            None => PPOLL_RETRY_SLEEP_MS,
        };
        if sleep_ms == 0 {
            return Ok(0);
        }
        ppoll_sleep_ms(sleep_ms);
        if let Some(ms) = remaining_ms {
            remaining_ms = Some(ms.saturating_sub(sleep_ms));
        }
    }
}

fn ppoll_sleep_ms(sleep_ms: u64) {
    if sleep_ms == 0 {
        return;
    }
    if crate::runtime::sleep_current_ms(sleep_ms) {
        return;
    }
    // 调度器不可用时，回退到 timebase 忙等避免超时过早结束。
    let deadline = time::monotonic_ns()
        .saturating_add(sleep_ms.saturating_mul(1_000_000));
    while time::monotonic_ns() < deadline {
        crate::cpu::wait_for_interrupt();
    }
}

fn epoll_wait(
    epfd: usize,
    events_ptr: usize,
    maxevents: usize,
    timeout_ms: Option<u64>,
) -> Result<usize, Errno> {
    if maxevents == 0 || maxevents > EPOLL_ITEM_SLOTS {
        return Err(Errno::Inval);
    }
    if events_ptr == 0 {
        return Err(Errno::Fault);
    }
    let root_pa = mm::current_root_pa();
    if root_pa == 0 {
        return Err(Errno::Fault);
    }
    let total = maxevents
        .checked_mul(size_of::<EpollEvent>())
        .ok_or(Errno::Fault)?;
    validate_user_write(root_pa, events_ptr, total)?;
    let ready = epoll_scan(epfd, root_pa, events_ptr, maxevents)?;
    if ready > 0 || !can_block_current() {
        return Ok(ready);
    }
    if let Some(0) = timeout_ms {
        return Ok(0);
    }
    let mut remaining_ms = timeout_ms;
    loop {
        let sleep_ms = match remaining_ms {
            Some(0) => return Ok(0),
            Some(ms) => core::cmp::min(ms, EPOLL_RETRY_SLEEP_MS),
            None => EPOLL_RETRY_SLEEP_MS,
        };
        if sleep_ms == 0 {
            return Ok(0);
        }
        ppoll_sleep_ms(sleep_ms);
        if let Some(ms) = remaining_ms {
            remaining_ms = Some(ms.saturating_sub(sleep_ms));
        }
        let ready_retry = epoll_scan(epfd, root_pa, events_ptr, maxevents)?;
        if ready_retry > 0 {
            return Ok(ready_retry);
        }
        if !can_block_current() {
            return Ok(0);
        }
    }
}

fn ppoll_scan(root_pa: usize, fds: usize, nfds: usize) -> Result<(usize, Option<(i32, u16)>), Errno> {
    let stride = size_of::<PollFd>();
    let mut ready = 0usize;
    let mut single = None;
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
            single = Some((pollfd.fd, events));
        }
        // 每次扫描都回写 revents，确保用户态可直接读取最新状态。
        pollfd.revents = revents as i16;
        UserPtr::new(base)
            .write(root_pa, pollfd)
            .ok_or(Errno::Fault)?;
    }
    Ok((ready, single))
}

fn epoll_scan(epfd: usize, root_pa: usize, events_ptr: usize, maxevents: usize) -> Result<usize, Errno> {
    let entry = resolve_fd(epfd).ok_or(Errno::Badf)?;
    let epoll_id = match entry.kind {
        FdKind::Epoll(id) => id,
        _ => return Err(Errno::Badf),
    };
    let mut ready = 0usize;
    // SAFETY: 单核早期阶段串行读取 epoll 表。
    unsafe {
        let epoll = EPOLLS.get(epoll_id).ok_or(Errno::Badf)?;
        if !epoll.used {
            return Err(Errno::Badf);
        }
        for item in epoll.items.iter() {
            if !item.used {
                continue;
            }
            let revents = poll_revents_for_fd(item.fd, item.events as u16);
            if revents == 0 {
                continue;
            }
            if ready >= maxevents {
                break;
            }
            let out = EpollEvent {
                events: revents as u32,
                data: item.data,
            };
            let base = events_ptr
                .checked_add(ready * size_of::<EpollEvent>())
                .ok_or(Errno::Fault)?;
            UserPtr::new(base).write(root_pa, out).ok_or(Errno::Fault)?;
            ready += 1;
        }
    }
    Ok(ready)
}

fn epoll_has_ready(epoll_id: usize) -> bool {
    // SAFETY: 单核早期阶段串行读取 epoll 表。
    unsafe {
        let Some(epoll) = EPOLLS.get(epoll_id) else {
            return false;
        };
        if !epoll.used {
            return false;
        }
        for item in epoll.items.iter() {
            if !item.used {
                continue;
            }
            let revents = poll_revents_for_fd(item.fd, item.events as u16);
            if revents != 0 {
                return true;
            }
        }
    }
    false
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

fn epoll_timeout_ms(tmo: usize) -> Result<Option<u64>, Errno> {
    if tmo == 0 {
        return Ok(None);
    }
    let root_pa = mm::current_root_pa();
    if root_pa == 0 {
        return Err(Errno::Fault);
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

fn timespec_to_ns(ts: Timespec) -> Result<u64, Errno> {
    if ts.tv_sec < 0 || ts.tv_nsec < 0 || ts.tv_nsec >= 1_000_000_000 {
        return Err(Errno::Inval);
    }
    Ok((ts.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(ts.tv_nsec as u64))
}

fn ns_to_timespec(ns: u64) -> Timespec {
    let sec = ns / 1_000_000_000;
    let nsec = ns % 1_000_000_000;
    Timespec {
        tv_sec: sec as i64,
        tv_nsec: nsec as i64,
    }
}

fn ppoll_single_waiter_queue(fd: i32, events: u16) -> Option<&'static crate::task_wait_queue::TaskWaitQueue> {
    if fd < 0 {
        return None;
    }
    let entry = resolve_fd(fd as usize)?;
    match entry.kind {
        FdKind::PipeRead(pipe_id) if (events & POLLIN) != 0 => Some(pipe_read_queue(pipe_id)),
        FdKind::PipeWrite(pipe_id) if (events & POLLOUT) != 0 => Some(pipe_write_queue(pipe_id)),
        FdKind::Eventfd(event_id) if (events & POLLIN) != 0 => Some(eventfd_queue(event_id)),
        FdKind::Timerfd(timer_id) if (events & POLLIN) != 0 => Some(timerfd_queue(timer_id)),
        FdKind::Socket(_) if (events & (POLLIN | POLLOUT)) != 0 => Some(crate::runtime::net_wait_queue()),
        _ => None,
    }
}

fn resolve_socket_fd(fd: usize) -> Result<axnet::SocketId, Errno> {
    let entry = resolve_fd(fd).ok_or(Errno::Badf)?;
    match entry.kind {
        FdKind::Socket(id) => Ok(id),
        _ => Err(Errno::Badf),
    }
}

fn resolve_socket_entry(fd: usize) -> Result<(axnet::SocketId, FdEntry), Errno> {
    let entry = resolve_fd(fd).ok_or(Errno::Badf)?;
    match entry.kind {
        FdKind::Socket(id) => Ok((id, entry)),
        _ => Err(Errno::Badf),
    }
}

fn socket_timeouts(fd: usize) -> Result<(u64, u64), Errno> {
    let entry = resolve_fd(fd).ok_or(Errno::Badf)?;
    if !matches!(entry.kind, FdKind::Socket(_)) {
        return Err(Errno::Badf);
    }
    Ok((entry.recv_timeout_ms, entry.send_timeout_ms))
}

fn set_socket_timeout(
    fd: usize,
    recv_timeout_ms: Option<u64>,
    send_timeout_ms: Option<u64>,
) -> Result<usize, Errno> {
    let proc_idx = current_proc_index().ok_or(Errno::Badf)?;
    if stdio_kind(fd).is_some() {
        // SAFETY: 单核早期阶段访问重定向表。
        unsafe {
            if let Some(mut entry) = STDIO_REDIRECT[proc_idx][fd] {
                if !matches!(entry.kind, FdKind::Socket(_)) {
                    return Err(Errno::Badf);
                }
                if let Some(value) = recv_timeout_ms {
                    entry.recv_timeout_ms = value;
                }
                if let Some(value) = send_timeout_ms {
                    entry.send_timeout_ms = value;
                }
                STDIO_REDIRECT[proc_idx][fd] = Some(entry);
                return Ok(0);
            }
        }
        return Err(Errno::Badf);
    }
    let idx = fd_table_index(fd).ok_or(Errno::Badf)?;
    // SAFETY: 单核早期阶段，fd 表串行更新。
    unsafe {
        let entry = &mut FD_TABLES[proc_idx][idx];
        if entry.kind == FdKind::Empty || !matches!(entry.kind, FdKind::Socket(_)) {
            return Err(Errno::Badf);
        }
        if let Some(value) = recv_timeout_ms {
            entry.recv_timeout_ms = value;
        }
        if let Some(value) = send_timeout_ms {
            entry.send_timeout_ms = value;
        }
    }
    Ok(0)
}

fn parse_sockaddr_in(root_pa: usize, addr: usize, len: usize) -> Result<(axnet::IpAddress, u16), Errno> {
    if addr == 0 || len < size_of::<SockAddrIn>() {
        return Err(Errno::Inval);
    }
    let sock = UserPtr::<SockAddrIn>::new(addr)
        .read(root_pa)
        .ok_or(Errno::Fault)?;
    if sock.sin_family != AF_INET {
        return Err(Errno::Inval);
    }
    let port = u16::from_be(sock.sin_port);
    let ip_bytes = sock.sin_addr.to_be_bytes();
    let ip = axnet::Ipv4Address::new(ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);
    Ok((axnet::IpAddress::Ipv4(ip), port))
}

fn write_sockaddr_in(
    root_pa: usize,
    addr: usize,
    addrlen: usize,
    endpoint: Option<(axnet::IpAddress, u16)>,
) -> Result<(), Errno> {
    if addr == 0 || addrlen == 0 {
        return Ok(());
    }
    let Some((ip, port)) = endpoint else {
        return Ok(());
    };
    let mut len = UserPtr::<u32>::new(addrlen)
        .read(root_pa)
        .ok_or(Errno::Fault)? as usize;
    let expected = size_of::<SockAddrIn>();
    if len < expected {
        return Err(Errno::Inval);
    }
    let ip = match ip {
        axnet::IpAddress::Ipv4(addr) => addr,
    };
    let bytes = ip.as_bytes();
    let sock = SockAddrIn {
        sin_family: AF_INET,
        sin_port: port.to_be(),
        sin_addr: u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        sin_zero: [0; 8],
    };
    UserPtr::new(addr).write(root_pa, sock).ok_or(Errno::Fault)?;
    len = expected;
    UserPtr::new(addrlen)
        .write(root_pa, len as u32)
        .ok_or(Errno::Fault)?;
    Ok(())
}

fn eventfd_read(event_id: usize, root_pa: usize, buf: usize, len: usize, nonblock: bool) -> Result<usize, Errno> {
    if event_id >= EVENTFD_SLOTS {
        return Err(Errno::Badf);
    }
    if len < size_of::<u64>() {
        return Err(Errno::Inval);
    }
    loop {
        let (used, counter, flags) = unsafe {
            let event = &EVENTFDS[event_id];
            (event.used, event.counter, event.flags)
        };
        if !used {
            return Err(Errno::Badf);
        }
        if counter == 0 {
            if nonblock || !can_block_current() {
                return Err(Errno::Again);
            }
            crate::runtime::block_current(eventfd_queue(event_id));
            continue;
        }
        let value = if (flags & EFD_SEMAPHORE) != 0 { 1 } else { counter };
        // SAFETY: 单核早期阶段串行更新 eventfd。
        unsafe {
            let event = &mut EVENTFDS[event_id];
            if (flags & EFD_SEMAPHORE) != 0 {
                event.counter = event.counter.saturating_sub(1);
            } else {
                event.counter = 0;
            }
        }
        UserPtr::new(buf)
            .write(root_pa, value)
            .ok_or(Errno::Fault)?;
        return Ok(size_of::<u64>());
    }
}

fn eventfd_write(event_id: usize, root_pa: usize, buf: usize, len: usize, nonblock: bool) -> Result<usize, Errno> {
    if event_id >= EVENTFD_SLOTS {
        return Err(Errno::Badf);
    }
    if len < size_of::<u64>() {
        return Err(Errno::Inval);
    }
    let value = UserPtr::<u64>::new(buf)
        .read(root_pa)
        .ok_or(Errno::Fault)?;
    if value == 0 || value == u64::MAX {
        return Err(Errno::Inval);
    }
    loop {
        let (used, counter) = unsafe {
            let event = &EVENTFDS[event_id];
            (event.used, event.counter)
        };
        if !used {
            return Err(Errno::Badf);
        }
        if counter > u64::MAX - value {
            if nonblock || !can_block_current() {
                return Err(Errno::Again);
            }
            crate::runtime::block_current(eventfd_queue(event_id));
            continue;
        }
        unsafe {
            let event = &mut EVENTFDS[event_id];
            event.counter = event.counter.saturating_add(value);
        }
        let _ = crate::runtime::wake_all(eventfd_queue(event_id));
        return Ok(size_of::<u64>());
    }
}

fn timerfd_current_spec(timer_id: usize) -> Result<Itimerspec, Errno> {
    if timer_id >= TIMERFD_SLOTS {
        return Err(Errno::Badf);
    }
    let now = time::monotonic_ns();
    // SAFETY: 单核早期阶段串行读取 timerfd。
    unsafe {
        let timer = TIMERFDS.get(timer_id).ok_or(Errno::Badf)?;
        if !timer.used {
            return Err(Errno::Badf);
        }
        let remaining = if timer.next_ns == 0 || now >= timer.next_ns {
            0
        } else {
            timer.next_ns - now
        };
        Ok(Itimerspec {
            it_interval: ns_to_timespec(timer.interval_ns),
            it_value: ns_to_timespec(remaining),
        })
    }
}

fn timerfd_read(timer_id: usize, root_pa: usize, buf: usize, len: usize, nonblock: bool) -> Result<usize, Errno> {
    if timer_id >= TIMERFD_SLOTS {
        return Err(Errno::Badf);
    }
    if len < size_of::<u64>() {
        return Err(Errno::Inval);
    }
    loop {
        let (used, next_ns, interval_ns) = unsafe {
            let timer = &TIMERFDS[timer_id];
            (timer.used, timer.next_ns, timer.interval_ns)
        };
        if !used {
            return Err(Errno::Badf);
        }
        if next_ns == 0 {
            if nonblock || !can_block_current() {
                return Err(Errno::Again);
            }
            crate::runtime::block_current(timerfd_queue(timer_id));
            continue;
        }
        let now = time::monotonic_ns();
        if now < next_ns {
            if nonblock || !can_block_current() {
                return Err(Errno::Again);
            }
            let delta_ns = next_ns - now;
            let mut sleep_ms = delta_ns / 1_000_000;
            if sleep_ms == 0 {
                sleep_ms = 1;
            }
            let _ = crate::runtime::wait_timeout_ms(timerfd_queue(timer_id), sleep_ms);
            continue;
        }
        let mut expirations = 1u64;
        let mut new_next = 0u64;
        if interval_ns != 0 {
            let missed = (now - next_ns) / interval_ns;
            expirations = expirations.saturating_add(missed);
            new_next = next_ns.saturating_add(expirations.saturating_mul(interval_ns));
        }
        // SAFETY: 单核早期阶段串行更新 timerfd。
        unsafe {
            if let Some(timer) = TIMERFDS.get_mut(timer_id) {
                if interval_ns == 0 {
                    timer.next_ns = 0;
                } else {
                    timer.next_ns = new_next;
                }
            }
        }
        UserPtr::new(buf)
            .write(root_pa, expirations)
            .ok_or(Errno::Fault)?;
        return Ok(size_of::<u64>());
    }
}

fn read_from_entry(fd: usize, entry: FdEntry, root_pa: usize, buf: usize, len: usize) -> Result<usize, Errno> {
    match entry.kind {
        FdKind::Stdin => {
            let nonblock = (entry.flags & O_NONBLOCK) != 0;
            read_console_into(root_pa, buf, len, nonblock)
        }
        FdKind::Vfs(handle) => {
            if handle.file_type == FileType::Dir {
                return Err(Errno::IsDir);
            }
            read_vfs_fd(fd, root_pa, handle.mount, handle.inode, buf, len)
        }
        FdKind::PipeRead(pipe_id) => {
            let nonblock = (entry.flags & O_NONBLOCK) != 0;
            pipe_read(pipe_id, root_pa, buf, len, nonblock)
        }
        FdKind::Socket(socket_id) => {
            let nonblock = (entry.flags & O_NONBLOCK) != 0;
            read_socket(root_pa, socket_id, buf, len, nonblock)
        }
        FdKind::Eventfd(event_id) => {
            let nonblock = (entry.flags & O_NONBLOCK) != 0;
            eventfd_read(event_id, root_pa, buf, len, nonblock)
        }
        FdKind::Timerfd(timer_id) => {
            let nonblock = (entry.flags & O_NONBLOCK) != 0;
            timerfd_read(timer_id, root_pa, buf, len, nonblock)
        }
        FdKind::Stdout | FdKind::Stderr | FdKind::PipeWrite(_) => Err(Errno::Badf),
        FdKind::Epoll(_) => Err(Errno::Inval),
        FdKind::Empty => Err(Errno::Badf),
    }
}

fn init_memfile_image() -> &'static [u8] {
    crate::user::init_exec_elf_image()
}

fn read_vfs_fd(
    fd: usize,
    root_pa: usize,
    mount: MountId,
    inode: InodeId,
    buf: usize,
    len: usize,
) -> Result<usize, Errno> {
    with_mounts(|mounts| {
        let fs = mounts.fs_for(mount).ok_or(Errno::NoEnt)?;
        let offset = fd_offset(fd).ok_or(Errno::Badf)?;
        let read = read_vfs_at(root_pa, fs, inode, offset, buf, len)?;
        set_fd_offset(fd, offset + read);
        Ok(read)
    })
}

fn read_vfs_at(
    root_pa: usize,
    fs: &dyn VfsOps,
    inode: InodeId,
    offset: usize,
    buf: usize,
    len: usize,
) -> Result<usize, Errno> {
    let mut total = 0usize;
    let mut remaining = len;
    // Match FAT32 sector size to avoid partial-sector RMW issues.
    let mut scratch = [0u8; 512];
    while remaining > 0 {
        let chunk = min(remaining, scratch.len());
        let read = fs
            .read_at(inode, (offset + total) as u64, &mut scratch[..chunk])
            .map_err(map_vfs_err)?;
        if read == 0 {
            break;
        }
        let dst = buf.checked_add(total).ok_or(Errno::Fault)?;
        UserSlice::new(dst, read)
            .copy_from_slice(root_pa, &scratch[..read])
            .ok_or(Errno::Fault)?;
        total += read;
        remaining = remaining.saturating_sub(read);
    }
    Ok(total)
}

fn write_vfs_fd(
    fd: usize,
    root_pa: usize,
    mount: MountId,
    inode: InodeId,
    buf: usize,
    len: usize,
) -> Result<usize, Errno> {
    with_mounts(|mounts| {
        let fs = mounts.fs_for(mount).ok_or(Errno::NoEnt)?;
        let offset = fd_offset(fd).ok_or(Errno::Badf)?;
        let written = write_vfs_at(root_pa, fs, inode, offset, buf, len)?;
        set_fd_offset(fd, offset + written);
        Ok(written)
    })
}

fn write_vfs_at(
    root_pa: usize,
    fs: &dyn VfsOps,
    inode: InodeId,
    offset: usize,
    buf: usize,
    len: usize,
) -> Result<usize, Errno> {
    if len == 0 {
        return Ok(0);
    }
    let mut total = 0usize;
    let mut remaining = len;
    // Match FAT32 sector size to avoid partial-sector RMW issues.
    let mut scratch = [0u8; 512];
    while remaining > 0 {
        let chunk = min(remaining, scratch.len());
        let src = buf.checked_add(total).ok_or(Errno::Fault)?;
        UserSlice::new(src, chunk)
            .copy_to_slice(root_pa, &mut scratch[..chunk])
            .ok_or(Errno::Fault)?;
        let written = fs
            .write_at(inode, (offset + total) as u64, &scratch[..chunk])
            .map_err(map_vfs_err)?;
        total += written;
        if written < chunk {
            break;
        }
        remaining = remaining.saturating_sub(chunk);
    }
    Ok(total)
}

fn write_to_entry(fd: usize, entry: FdEntry, root_pa: usize, buf: usize, len: usize) -> Result<usize, Errno> {
    match entry.kind {
        FdKind::Stdout | FdKind::Stderr => write_console_from(root_pa, buf, len),
        FdKind::Vfs(handle) => {
            if handle.file_type == FileType::Dir {
                return Err(Errno::IsDir);
            }
            if (entry.flags & O_APPEND) != 0 {
                return with_mounts(|mounts| {
                    let fs = mounts.fs_for(handle.mount).ok_or(Errno::NoEnt)?;
                    let (_, size) = vfs_meta_for(fs, handle.inode)?;
                    let written = write_vfs_at(root_pa, fs, handle.inode, size, buf, len)?;
                    let new_offset = size.checked_add(written).ok_or(Errno::Inval)?;
                    set_fd_offset(fd, new_offset);
                    Ok(written)
                });
            }
            write_vfs_fd(fd, root_pa, handle.mount, handle.inode, buf, len)
        }
        FdKind::PipeWrite(pipe_id) => {
            let nonblock = (entry.flags & O_NONBLOCK) != 0;
            pipe_write(pipe_id, root_pa, buf, len, nonblock)
        }
        FdKind::Socket(socket_id) => {
            let nonblock = (entry.flags & O_NONBLOCK) != 0;
            write_socket(root_pa, socket_id, buf, len, nonblock)
        }
        FdKind::Eventfd(event_id) => {
            let nonblock = (entry.flags & O_NONBLOCK) != 0;
            eventfd_write(event_id, root_pa, buf, len, nonblock)
        }
        FdKind::Timerfd(_) | FdKind::Epoll(_) => Err(Errno::Inval),
        FdKind::Stdin | FdKind::PipeRead(_) => Err(Errno::Badf),
        FdKind::Empty => Err(Errno::Badf),
    }
}

fn read_socket(
    root_pa: usize,
    socket_id: axnet::SocketId,
    buf: usize,
    len: usize,
    nonblock: bool,
) -> Result<usize, Errno> {
    if len == 0 {
        return Ok(0);
    }
    let mut total = 0usize;
    let mut remaining = len;
    let mut scratch = [0u8; 512];
    while remaining > 0 {
        let chunk = core::cmp::min(remaining, scratch.len());
        let (read, _) = match axnet::socket_recv(socket_id, &mut scratch[..chunk]) {
            Ok(result) => result,
            Err(axnet::NetError::WouldBlock) => {
                if total > 0 {
                    break;
                }
                if nonblock || !can_block_current() {
                    return Err(Errno::Again);
                }
                crate::runtime::block_current(crate::runtime::net_wait_queue());
                continue;
            }
            Err(err) => return Err(map_net_err(err)),
        };
        let dst = buf.checked_add(total).ok_or(Errno::Fault)?;
        UserSlice::new(dst, read)
            .copy_from_slice(root_pa, &scratch[..read])
            .ok_or(Errno::Fault)?;
        total += read;
        if read < chunk {
            break;
        }
        remaining = remaining.saturating_sub(read);
    }
    Ok(total)
}

fn write_socket(
    root_pa: usize,
    socket_id: axnet::SocketId,
    buf: usize,
    len: usize,
    nonblock: bool,
) -> Result<usize, Errno> {
    if len == 0 {
        return Ok(0);
    }
    let mut total = 0usize;
    let mut remaining = len;
    let mut scratch = [0u8; 512];
    while remaining > 0 {
        let chunk = core::cmp::min(remaining, scratch.len());
        let src = buf.checked_add(total).ok_or(Errno::Fault)?;
        UserSlice::new(src, chunk)
            .copy_to_slice(root_pa, &mut scratch[..chunk])
            .ok_or(Errno::Fault)?;
        let sent = match axnet::socket_send(socket_id, &scratch[..chunk], None) {
            Ok(sent) => sent,
            Err(axnet::NetError::WouldBlock) => {
                if total > 0 {
                    break;
                }
                if nonblock || !can_block_current() {
                    return Err(Errno::Again);
                }
                crate::runtime::block_current(crate::runtime::net_wait_queue());
                continue;
            }
            Err(err) => return Err(map_net_err(err)),
        };
        total += sent;
        if sent < chunk {
            break;
        }
        remaining = remaining.saturating_sub(sent);
    }
    Ok(total)
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

fn read_console_into(root_pa: usize, buf: usize, len: usize, nonblock: bool) -> Result<usize, Errno> {
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
            let mut i = 0usize;
            while i < chunk {
                match console_take() {
                    Some(ch) => {
                        dst.add(i).write(ch);
                        read += 1;
                        i += 1;
                    }
                    None => {
                        if read > 0 {
                            return Ok(read);
                        }
                        if nonblock || !can_block_current() {
                            return Err(Errno::Again);
                        }
                        if !crate::runtime::sleep_current_ms(PPOLL_RETRY_SLEEP_MS) {
                            return Err(Errno::Again);
                        }
                    }
                }
            }
        }
        addr = addr.wrapping_add(chunk);
        remaining -= chunk;
    }
    Ok(read)
}

fn console_peek() -> bool {
    // SAFETY: 单核早期阶段顺序访问控制台缓存。
    unsafe {
        if CONSOLE_STASH >= 0 {
            return true;
        }
        if let Some(ch) = sbi::console_getchar() {
            CONSOLE_STASH = ch as i16;
            let _ = crate::runtime::wake_all(ppoll_wait_queue());
            return true;
        }
    }
    false
}

fn console_take() -> Option<u8> {
    // SAFETY: 单核早期阶段顺序访问控制台缓存。
    unsafe {
        if CONSOLE_STASH >= 0 {
            let ch = CONSOLE_STASH as u8;
            CONSOLE_STASH = -1;
            return Some(ch);
        }
    }
    let ch = sbi::console_getchar();
    if ch.is_some() {
        let _ = crate::runtime::wake_all(ppoll_wait_queue());
    }
    ch
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
