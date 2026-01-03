#![no_std]
#![no_main]
//! Minimal interactive shell for Aurora user space.

use core::arch::asm;
use core::cmp::min;

const SYS_READ: usize = 63;
const SYS_WRITE: usize = 64;
const SYS_EXIT: usize = 93;
const SYS_OPENAT: usize = 56;
const SYS_GETDENTS64: usize = 61;
const SYS_CLOSE: usize = 57;
const SYS_CHDIR: usize = 49;
const SYS_GETCWD: usize = 17;

const AT_FDCWD: isize = -100;
const O_RDONLY: usize = 0;

const PROMPT: &[u8] = b"aurora> ";
const BANNER: &[u8] = b"\n\
\x1b[36;1m    ___                       \x1b[0m  Aurora OS / shell\n\
\x1b[36;1m   /   | __  __ _________  ___\x1b[0m  OS:       Aurora OS\n\
\x1b[34;1m  / /| |/ / / // ___/ __ \\/ _ \\\x1b[0m  Arch:     riscv64\n\
\x1b[35;1m / ___ / /_/ // /  / /_/ / // /\x1b[0m  Platform: qemu-virt\n\
\x1b[35;1m/_/  |_|\\__,_//_/   \\____/_//_/ \x1b[0m  Kernel:   axruntime\n\
                                 RootFS:   ext4\n\
                                 Net:      virtio-net\n\
                                 Shell:    aurora-sh\n\
\n\
Type 'help' for commands.\n";
const HELP_TEXT: &[u8] = b"commands: help echo ls cat cd pwd exit\n";

const MAX_LINE: usize = 256;
const MAX_ARGS: usize = 8;
const DENT_BUF_LEN: usize = 512;
const IO_BUF_LEN: usize = 256;
const DIRENT_HEADER_LEN: usize = 19;

#[derive(Clone, Copy)]
struct Arg {
    start: usize,
    len: usize,
}

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
    if msg.is_empty() {
        return;
    }
    // SAFETY: syscall arguments follow the expected ABI and pointers are valid.
    unsafe {
        let _ = syscall6(SYS_WRITE, 1, msg.as_ptr() as usize, msg.len(), 0, 0, 0);
    }
}

fn write_num(mut value: usize) {
    let mut buf = [0u8; 20];
    let mut idx = buf.len();
    if value == 0 {
        write_stdout(b"0");
        return;
    }
    while value > 0 {
        let digit = (value % 10) as u8;
        value /= 10;
        idx -= 1;
        buf[idx] = b'0' + digit;
    }
    write_stdout(&buf[idx..]);
}

fn write_errno(ret: isize) {
    if ret >= 0 {
        return;
    }
    write_stdout(b" (errno=");
    write_num((-ret) as usize);
    write_stdout(b")\n");
}

fn read_byte() -> Option<u8> {
    let mut ch = 0u8;
    // SAFETY: syscall arguments follow the expected ABI and pointers are valid.
    let ret = unsafe { syscall6(SYS_READ, 0, &mut ch as *mut u8 as usize, 1, 0, 0, 0) };
    if ret <= 0 {
        return None;
    }
    Some(ch)
}

static mut SKIP_LF: bool = false;

fn read_line(buf: &mut [u8]) -> usize {
    let mut len = 0usize;
    loop {
        let Some(ch) = read_byte() else {
            continue;
        };
        // SAFETY: single-threaded user shell input handling.
        unsafe {
            if SKIP_LF {
                SKIP_LF = false;
                if ch == b'\n' {
                    continue;
                }
            }
        }
        match ch {
            b'\r' => {
                write_stdout(b"\n");
                // SAFETY: single-threaded user shell input handling.
                unsafe {
                    SKIP_LF = true;
                }
                break;
            }
            b'\n' => {
                write_stdout(b"\n");
                break;
            }
            0x08 | 0x7f => {
                if len > 0 {
                    len -= 1;
                    write_stdout(b"\x08 \x08");
                }
            }
            _ => {
                if len + 1 < buf.len() {
                    buf[len] = ch;
                    len += 1;
                    write_stdout(&[ch]);
                }
            }
        }
    }
    len
}

fn is_space(ch: u8) -> bool {
    ch == b' ' || ch == b'\t'
}

fn parse_args(line: &[u8], len: usize, args: &mut [Arg; MAX_ARGS]) -> usize {
    let mut argc = 0usize;
    let mut i = 0usize;
    while i < len {
        while i < len && is_space(line[i]) {
            i += 1;
        }
        if i >= len {
            break;
        }
        let start = i;
        while i < len && !is_space(line[i]) {
            i += 1;
        }
        let end = i;
        if argc < MAX_ARGS {
            args[argc] = Arg {
                start,
                len: end - start,
            };
            argc += 1;
        }
    }
    argc
}

fn arg_eq(line: &[u8], arg: Arg, lit: &[u8]) -> bool {
    if arg.len != lit.len() {
        return false;
    }
    let slice = &line[arg.start..arg.start + arg.len];
    slice == lit
}

fn arg_to_cstr(line: &[u8], arg: Arg, out: &mut [u8]) -> *const u8 {
    let copy_len = min(arg.len, out.len().saturating_sub(1));
    out[..copy_len].copy_from_slice(&line[arg.start..arg.start + copy_len]);
    out[copy_len] = 0;
    out.as_ptr()
}

fn cmd_help() {
    write_stdout(HELP_TEXT);
}

fn cmd_echo(line: &[u8], args: &[Arg], argc: usize) {
    if argc <= 1 {
        write_stdout(b"\n");
        return;
    }
    for idx in 1..argc {
        let arg = args[idx];
        let slice = &line[arg.start..arg.start + arg.len];
        write_stdout(slice);
        if idx + 1 < argc {
            write_stdout(b" ");
        }
    }
    write_stdout(b"\n");
}

fn cmd_pwd() {
    let mut buf = [0u8; IO_BUF_LEN];
    // SAFETY: syscall arguments follow the expected ABI and pointers are valid.
    let ret = unsafe { syscall6(SYS_GETCWD, buf.as_mut_ptr() as usize, buf.len(), 0, 0, 0, 0) };
    if ret < 0 {
        write_stdout(b"pwd: failed");
        write_errno(ret);
        return;
    }
    let len = ret.saturating_sub(1) as usize;
    let len = min(len, buf.len());
    write_stdout(&buf[..len]);
    if len == 0 || buf[len.saturating_sub(1)] != b'\n' {
        write_stdout(b"\n");
    }
}

fn cmd_cd(line: &[u8], args: &[Arg], argc: usize) {
    if argc < 2 {
        write_stdout(b"cd: missing path\n");
        return;
    }
    let mut path_buf = [0u8; IO_BUF_LEN];
    let path = arg_to_cstr(line, args[1], &mut path_buf);
    // SAFETY: syscall arguments follow the expected ABI and pointers are valid.
    let ret = unsafe { syscall6(SYS_CHDIR, path as usize, 0, 0, 0, 0, 0) };
    if ret < 0 {
        write_stdout(b"cd: failed");
        write_errno(ret);
    }
}

fn cmd_ls(line: &[u8], args: &[Arg], argc: usize) {
    let mut path_buf = [0u8; IO_BUF_LEN];
    let path_ptr = if argc >= 2 {
        arg_to_cstr(line, args[1], &mut path_buf)
    } else {
        b".\0".as_ptr()
    };
    // SAFETY: syscall arguments follow the expected ABI and pointers are valid.
    let fd = unsafe {
        syscall6(
            SYS_OPENAT,
            AT_FDCWD as usize,
            path_ptr as usize,
            O_RDONLY,
            0,
            0,
            0,
        )
    };
    if fd < 0 {
        write_stdout(b"ls: open failed");
        write_errno(fd);
        return;
    }

    let mut dent_buf = [0u8; DENT_BUF_LEN];
    loop {
        // SAFETY: syscall arguments follow the expected ABI and pointers are valid.
        let nread = unsafe {
            syscall6(
                SYS_GETDENTS64,
                fd as usize,
                dent_buf.as_mut_ptr() as usize,
                dent_buf.len(),
                0,
                0,
                0,
            )
        };
        if nread < 0 {
            write_stdout(b"ls: getdents failed");
            write_errno(nread);
            break;
        }
        if nread == 0 {
            break;
        }
        let mut offset = 0usize;
        let total = nread as usize;
        while offset + DIRENT_HEADER_LEN <= total {
            let reclen = u16::from_le_bytes([
                dent_buf[offset + 16],
                dent_buf[offset + 17],
            ]) as usize;
            if reclen == 0 || offset + reclen > total {
                break;
            }
            let name_start = offset + DIRENT_HEADER_LEN;
            let name_end = min(offset + reclen, total);
            let mut name_len = 0usize;
            while name_start + name_len < name_end {
                if dent_buf[name_start + name_len] == 0 {
                    break;
                }
                name_len += 1;
            }
            if name_len > 0 {
                write_stdout(&dent_buf[name_start..name_start + name_len]);
                write_stdout(b"\n");
            }
            offset += reclen;
        }
    }

    // SAFETY: syscall arguments follow the expected ABI and pointers are valid.
    unsafe {
        let _ = syscall6(SYS_CLOSE, fd as usize, 0, 0, 0, 0, 0);
    }
}

fn cmd_cat(line: &[u8], args: &[Arg], argc: usize) {
    if argc < 2 {
        write_stdout(b"cat: missing path\n");
        return;
    }
    let mut path_buf = [0u8; IO_BUF_LEN];
    let path_ptr = arg_to_cstr(line, args[1], &mut path_buf);
    // SAFETY: syscall arguments follow the expected ABI and pointers are valid.
    let fd = unsafe {
        syscall6(
            SYS_OPENAT,
            AT_FDCWD as usize,
            path_ptr as usize,
            O_RDONLY,
            0,
            0,
            0,
        )
    };
    if fd < 0 {
        write_stdout(b"cat: open failed");
        write_errno(fd);
        return;
    }
    let mut buf = [0u8; IO_BUF_LEN];
    loop {
        // SAFETY: syscall arguments follow the expected ABI and pointers are valid.
        let nread = unsafe {
            syscall6(
                SYS_READ,
                fd as usize,
                buf.as_mut_ptr() as usize,
                buf.len(),
                0,
                0,
                0,
            )
        };
        if nread < 0 {
            write_stdout(b"cat: read failed");
            write_errno(nread);
            break;
        }
        if nread == 0 {
            break;
        }
        write_stdout(&buf[..nread as usize]);
    }
    // SAFETY: syscall arguments follow the expected ABI and pointers are valid.
    unsafe {
        let _ = syscall6(SYS_CLOSE, fd as usize, 0, 0, 0, 0, 0);
    }
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    write_stdout(BANNER);
    loop {
        write_stdout(PROMPT);
        let mut line = [0u8; MAX_LINE];
        let len = read_line(&mut line);
        if len == 0 {
            continue;
        }
        let mut args = [Arg { start: 0, len: 0 }; MAX_ARGS];
        let argc = parse_args(&line, len, &mut args);
        if argc == 0 {
            continue;
        }
        let cmd = args[0];
        if arg_eq(&line, cmd, b"help") {
            cmd_help();
        } else if arg_eq(&line, cmd, b"echo") {
            cmd_echo(&line, &args, argc);
        } else if arg_eq(&line, cmd, b"ls") {
            cmd_ls(&line, &args, argc);
        } else if arg_eq(&line, cmd, b"cat") {
            cmd_cat(&line, &args, argc);
        } else if arg_eq(&line, cmd, b"cd") {
            cmd_cd(&line, &args, argc);
        } else if arg_eq(&line, cmd, b"pwd") {
            cmd_pwd();
        } else if arg_eq(&line, cmd, b"exit") {
            // SAFETY: syscall arguments follow the expected ABI and pointers are valid.
            unsafe {
                let _ = syscall6(SYS_EXIT, 0, 0, 0, 0, 0, 0);
            }
            loop {
                // SAFETY: wfi halts until the next interrupt.
                unsafe { asm!("wfi") };
            }
        } else {
            write_stdout(b"unknown command: ");
            write_stdout(&line[cmd.start..cmd.start + cmd.len]);
            write_stdout(b"\n");
        }
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    // SAFETY: syscall arguments follow the expected ABI and pointers are valid.
    unsafe {
        let _ = syscall6(SYS_EXIT, 1, 0, 0, 0, 0, 0);
    }
    loop {
        // SAFETY: wfi halts until the next interrupt.
        unsafe { asm!("wfi") };
    }
}
