#![no_std]
#![no_main]

use core::arch::asm;

const SYS_WRITE: usize = 64;
const SYS_EXIT: usize = 93;
const SYS_OPENAT: usize = 56;
const SYS_CLOSE: usize = 57;
const SYS_READ: usize = 63;
const SYS_LSEEK: usize = 62;
const SYS_PREAD64: usize = 67;
const SYS_PWRITE64: usize = 68;
const SYS_FTRUNCATE: usize = 46;

const AT_FDCWD: isize = -100;

const O_RDONLY: usize = 0;
const O_WRONLY: usize = 1;
const O_RDWR: usize = 2;
const O_CREAT: usize = 0x40;
const O_TRUNC: usize = 0x200;
const O_APPEND: usize = 0x400;

const SEEK_SET: usize = 0;
const SEEK_END: usize = 2;

const PATH: &[u8] = b"/fs_smoke.txt\0";
const OK_MSG: &[u8] = b"fs-smoke: ok\n";
const FAIL_MSG: &[u8] = b"fs-smoke: fail\n";
const HELLO: &[u8] = b"hello";
const PATCH: &[u8] = b"XY";
const APPEND: &[u8] = b"++";

#[inline(always)]
unsafe fn syscall6(
    n: usize,
    a0: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
) -> isize {
    let ret: isize;
    asm!(
        "ecall",
        inlateout("a0") a0 as isize => ret,
        in("a1") a1 as isize,
        in("a2") a2 as isize,
        in("a3") a3 as isize,
        in("a4") a4 as isize,
        in("a5") a5 as isize,
        in("a7") n as isize,
    );
    ret
}

fn write_stdout(msg: &[u8]) {
    unsafe {
        let _ = syscall6(SYS_WRITE, 1, msg.as_ptr() as usize, msg.len(), 0, 0, 0);
    }
}

fn exit(code: i32) -> ! {
    unsafe {
        let _ = syscall6(SYS_EXIT, code as usize, 0, 0, 0, 0, 0);
    }
    loop {
        unsafe { asm!("wfi") };
    }
}

fn fail() -> ! {
    write_stdout(FAIL_MSG);
    exit(1);
}

fn check(ret: isize) -> usize {
    if ret < 0 {
        fail();
    }
    ret as usize
}

fn check_eq(got: usize, expected: usize) {
    if got != expected {
        fail();
    }
}

fn syscall_openat(path: &[u8], flags: usize, mode: usize) -> usize {
    check(unsafe {
        syscall6(
            SYS_OPENAT,
            AT_FDCWD as usize,
            path.as_ptr() as usize,
            flags,
            mode,
            0,
            0,
        )
    })
}

fn syscall_close(fd: usize) {
    check(unsafe { syscall6(SYS_CLOSE, fd, 0, 0, 0, 0, 0) });
}

fn syscall_write(fd: usize, buf: &[u8]) -> usize {
    check(unsafe { syscall6(SYS_WRITE, fd, buf.as_ptr() as usize, buf.len(), 0, 0, 0) })
}

fn syscall_read(fd: usize, buf: &mut [u8]) -> usize {
    check(unsafe { syscall6(SYS_READ, fd, buf.as_mut_ptr() as usize, buf.len(), 0, 0, 0) })
}

fn syscall_lseek(fd: usize, offset: usize, whence: usize) -> usize {
    check(unsafe { syscall6(SYS_LSEEK, fd, offset, whence, 0, 0, 0) })
}

fn syscall_pread64(fd: usize, buf: &mut [u8], offset: usize) -> usize {
    check(unsafe { syscall6(SYS_PREAD64, fd, buf.as_mut_ptr() as usize, buf.len(), offset, 0, 0) })
}

fn syscall_pwrite64(fd: usize, buf: &[u8], offset: usize) -> usize {
    check(unsafe { syscall6(SYS_PWRITE64, fd, buf.as_ptr() as usize, buf.len(), offset, 0, 0) })
}

fn syscall_ftruncate(fd: usize, len: usize) {
    check(unsafe { syscall6(SYS_FTRUNCATE, fd, len, 0, 0, 0, 0) });
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let fd = syscall_openat(PATH, O_CREAT | O_TRUNC | O_RDWR, 0o644);
    check_eq(syscall_write(fd, HELLO), HELLO.len());
    check_eq(syscall_lseek(fd, 0, SEEK_SET), 0);
    let mut buf = [0u8; 8];
    check_eq(syscall_read(fd, &mut buf[..HELLO.len()]), HELLO.len());
    if &buf[..HELLO.len()] != HELLO {
        fail();
    }

    check_eq(syscall_pwrite64(fd, PATCH, 1), PATCH.len());
    check_eq(syscall_lseek(fd, 0, SEEK_SET), 0);
    check_eq(syscall_read(fd, &mut buf[..HELLO.len()]), HELLO.len());
    if &buf[..HELLO.len()] != b"hXYlo" {
        fail();
    }
    syscall_close(fd);

    let fd_append = syscall_openat(PATH, O_WRONLY | O_APPEND, 0);
    check_eq(syscall_write(fd_append, APPEND), APPEND.len());
    syscall_close(fd_append);

    let fd_rw = syscall_openat(PATH, O_RDWR, 0);
    check_eq(syscall_lseek(fd_rw, 0, SEEK_END), 7);
    let mut pread_buf = [0u8; 5];
    check_eq(syscall_pread64(fd_rw, &mut pread_buf, 0), 5);
    if &pread_buf != b"hXYlo" {
        fail();
    }
    syscall_ftruncate(fd_rw, 4);
    check_eq(syscall_lseek(fd_rw, 0, SEEK_END), 4);
    syscall_close(fd_rw);

    let fd_ro = syscall_openat(PATH, O_RDONLY, 0);
    check_eq(syscall_lseek(fd_ro, 0, SEEK_END), 4);
    check_eq(syscall_lseek(fd_ro, 5, SEEK_SET), 5);
    check_eq(syscall_read(fd_ro, &mut buf[..APPEND.len()]), 0);
    syscall_close(fd_ro);

    write_stdout(OK_MSG);
    exit(0);
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    fail();
}
