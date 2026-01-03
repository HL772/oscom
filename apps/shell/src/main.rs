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
const SYS_NEWFSTATAT: usize = 79;
const SYS_NANOSLEEP: usize = 101;

const AT_FDCWD: isize = -100;
const O_RDONLY: usize = 0;
const O_WRONLY: usize = 1;
const O_CREAT: usize = 0x40;
const O_APPEND: usize = 0x400;

const PROMPT: &[u8] = b"aurora> ";
const PROMPT_PREFIX: &[u8] = b"aurora:";
const PROMPT_SUFFIX: &[u8] = b"> ";
const BANNER: &[u8] = b"\n\
\x1b[36;1m~~~~~~~~~~~~~~~~~.::::::.\x1b[0m               \n\
\x1b[36;1m~~~~~~~~~~~~~~.::::::::::::.\x1b[0m            \n\
\x1b[34;1m~~~~~~~~~~~~.::::::----::::::.\x1b[0m                               aurora@oscomp\n\
\x1b[34;1m~~~~~~~~~~.::::::--------::::::.\x1b[0m                        -----------------------\n\
\x1b[35;1m~~~~~~~~.::::::----====----::::::.\x1b[0m                      OS:       Aurora Kernel\n\
\x1b[35;1m~~~~~~.::::::----========----::::::.\x1b[0m                    Arch:     riscv64gc\n\
\x1b[35;1m~~~~.::::::----==========----::::::.\x1b[0m                    Platform: QEMU virt\n\
\x1b[35;1m~~~::::::----====++++====----::::::\x1b[0m                     Kernel:   axruntime\n\
\x1b[35;1m~~~'::::----====++++====----::::'\x1b[0m                       FS:       ext4 / fat32\n\
\x1b[35;1m~~~~~'::----====++++====----::'\x1b[0m                         Net:      virtio-net + smoltcp\n\
\x1b[34;1m~~~~~~~'--====++++++++====--'\x1b[0m                           Shell:    aurora-sh\n\
\x1b[36;1m~~~~~~~~~~~'==++++++++=='\x1b[0m                   \n\
\x1b[36;1m~~~~~~~~~~~~~~~'===='\x1b[0m                       \n\
\n\
Type 'help' for commands.\n";
const HELP_TEXT: &[u8] = b"commands: help echo ls cat cd pwd exit clear head tail wc stat sleep hexdump touch append\n";

const MAX_LINE: usize = 256;
const MAX_ARGS: usize = 8;
const DENT_BUF_LEN: usize = 512;
const IO_BUF_LEN: usize = 256;
const DIRENT_HEADER_LEN: usize = 19;
const LINE_BUF_LEN: usize = 160;
const HEX_WIDTH: usize = 16;

const S_IFMT: u32 = 0o170000;
const S_IFDIR: u32 = 0o040000;
const S_IFLNK: u32 = 0o120000;

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
struct Timespec {
    tv_sec: i64,
    tv_nsec: i64,
}

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

fn hex_digit(value: u8) -> u8 {
    match value {
        0..=9 => b'0' + value,
        _ => b'a' + (value - 10),
    }
}

fn write_hex(value: usize, width: usize) {
    let mut buf = [b'0'; 16];
    let width = min(width, buf.len());
    let mut shift = (width.saturating_sub(1)) * 4;
    for i in 0..width {
        let digit = ((value >> shift) & 0xf) as u8;
        buf[i] = hex_digit(digit);
        if shift >= 4 {
            shift -= 4;
        } else {
            shift = 0;
        }
    }
    write_stdout(&buf[..width]);
}

fn write_hex_byte(value: u8) {
    let hi = hex_digit(value >> 4);
    let lo = hex_digit(value & 0xf);
    write_stdout(&[hi, lo]);
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
                write_stdout(b"\r\n");
                // SAFETY: single-threaded user shell input handling.
                unsafe {
                    SKIP_LF = true;
                }
                break;
            }
            b'\n' => {
                write_stdout(b"\r\n");
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

fn parse_u32(line: &[u8], arg: Arg) -> Option<u32> {
    let slice = &line[arg.start..arg.start + arg.len];
    if slice.is_empty() {
        return None;
    }
    let mut value: u32 = 0;
    for &ch in slice {
        if ch < b'0' || ch > b'9' {
            return None;
        }
        value = value.saturating_mul(10).saturating_add((ch - b'0') as u32);
    }
    Some(value)
}

fn open_path(path_ptr: *const u8, flags: usize) -> isize {
    // SAFETY: syscall arguments follow the expected ABI and pointers are valid.
    unsafe {
        syscall6(
            SYS_OPENAT,
            AT_FDCWD as usize,
            path_ptr as usize,
            flags,
            0o644,
            0,
            0,
        )
    }
}

fn stat_path(path_ptr: *const u8, stat: &mut Stat) -> isize {
    // SAFETY: syscall arguments follow the expected ABI and pointers are valid.
    unsafe {
        syscall6(
            SYS_NEWFSTATAT,
            AT_FDCWD as usize,
            path_ptr as usize,
            stat as *mut Stat as usize,
            0,
            0,
            0,
        )
    }
}

fn join_path(base: &[u8], name: &[u8], out: &mut [u8]) -> Option<*const u8> {
    let mut idx = 0usize;
    if base == b"." {
        // use name directly
    } else {
        if idx + base.len() >= out.len() {
            return None;
        }
        out[idx..idx + base.len()].copy_from_slice(base);
        idx += base.len();
        if idx == 0 || out[idx - 1] != b'/' {
            if idx + 1 >= out.len() {
                return None;
            }
            out[idx] = b'/';
            idx += 1;
        }
    }
    if idx + name.len() >= out.len() {
        return None;
    }
    out[idx..idx + name.len()].copy_from_slice(name);
    idx += name.len();
    if idx >= out.len() {
        return None;
    }
    out[idx] = 0;
    Some(out.as_ptr())
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

fn cmd_clear() {
    write_stdout(b"\x1b[2J\x1b[H");
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
        if ret == -20 {
            write_stdout(b"cd: not a directory\n");
            return;
        }
        write_stdout(b"cd: failed");
        write_errno(ret);
    }
}

fn cmd_ls(line: &[u8], args: &[Arg], argc: usize) {
    let mut path_buf = [0u8; IO_BUF_LEN];
    let mut long = false;
    let mut path_arg: Option<Arg> = None;
    if argc >= 2 && arg_eq(line, args[1], b"-l") {
        long = true;
        if argc >= 3 {
            path_arg = Some(args[2]);
        }
    } else if argc >= 3 && arg_eq(line, args[2], b"-l") {
        long = true;
        path_arg = Some(args[1]);
    } else if argc >= 2 {
        path_arg = Some(args[1]);
    }
    let base_ptr = if let Some(arg) = path_arg {
        arg_to_cstr(line, arg, &mut path_buf)
    } else {
        b".\0".as_ptr()
    };
    // SAFETY: syscall arguments follow the expected ABI and pointers are valid.
    let fd = open_path(base_ptr, O_RDONLY);
    if fd < 0 {
        write_stdout(b"ls: open failed");
        write_errno(fd);
        return;
    }

    let mut dent_buf = [0u8; DENT_BUF_LEN];
    let base_slice = if let Some(arg) = path_arg {
        &line[arg.start..arg.start + arg.len]
    } else {
        b"."
    };
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
                let name = &dent_buf[name_start..name_start + name_len];
                if long {
                    let mut full_buf = [0u8; IO_BUF_LEN];
                    let path_ptr = join_path(base_slice, name, &mut full_buf);
                    let mut st = Stat {
                        st_dev: 0,
                        st_ino: 0,
                        st_mode: 0,
                        st_nlink: 0,
                        st_uid: 0,
                        st_gid: 0,
                        st_rdev: 0,
                        __pad1: 0,
                        st_size: 0,
                        st_blksize: 0,
                        __pad2: 0,
                        st_blocks: 0,
                        st_atime: 0,
                        st_atime_nsec: 0,
                        st_mtime: 0,
                        st_mtime_nsec: 0,
                        st_ctime: 0,
                        st_ctime_nsec: 0,
                        __unused4: 0,
                        __unused5: 0,
                    };
                    if let Some(ptr) = path_ptr {
                        let ret = stat_path(ptr, &mut st);
                        if ret < 0 {
                            write_stdout(b"? ");
                        } else {
                            let mode = st.st_mode & S_IFMT;
                            let prefix = if mode == S_IFDIR {
                                b"d"
                            } else if mode == S_IFLNK {
                                b"l"
                            } else {
                                b"-"
                            };
                            write_stdout(prefix);
                            write_stdout(b" ");
                            write_num(st.st_size.max(0) as usize);
                            write_stdout(b" ");
                        }
                    }
                    write_stdout(name);
                    write_stdout(b"\r\n");
                } else {
                    write_stdout(name);
                    write_stdout(b"\r\n");
                }
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
    let mut numbered = false;
    let mut path_arg = args[1];
    if arg_eq(line, args[1], b"-n") {
        if argc < 3 {
            write_stdout(b"cat: missing path\n");
            return;
        }
        numbered = true;
        path_arg = args[2];
    }
    let mut path_buf = [0u8; IO_BUF_LEN];
    let path_ptr = arg_to_cstr(line, path_arg, &mut path_buf);
    // SAFETY: syscall arguments follow the expected ABI and pointers are valid.
    let fd = open_path(path_ptr, O_RDONLY);
    if fd < 0 {
        write_stdout(b"cat: open failed");
        write_errno(fd);
        return;
    }
    let mut buf = [0u8; IO_BUF_LEN];
    let mut line_no = 1usize;
    let mut line_start = true;
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
        if numbered {
            for &ch in &buf[..nread as usize] {
                if line_start {
                    write_num(line_no);
                    write_stdout(b": ");
                    line_start = false;
                }
                write_stdout(&[ch]);
                if ch == b'\n' {
                    line_no += 1;
                    line_start = true;
                }
            }
        } else {
            write_stdout(&buf[..nread as usize]);
        }
    }
    // SAFETY: syscall arguments follow the expected ABI and pointers are valid.
    unsafe {
        let _ = syscall6(SYS_CLOSE, fd as usize, 0, 0, 0, 0, 0);
    }
}

fn cmd_head_tail(line: &[u8], args: &[Arg], argc: usize, tail: bool) {
    if argc < 2 {
        if tail {
            write_stdout(b"tail: missing path\r\n");
        } else {
            write_stdout(b"head: missing path\r\n");
        }
        return;
    }
    let mut count = 10u32;
    let mut path_arg = args[1];
    if arg_eq(line, args[1], b"-n") && argc >= 4 {
        if let Some(val) = parse_u32(line, args[2]) {
            count = val;
        }
        path_arg = args[3];
    }
    let mut path_buf = [0u8; IO_BUF_LEN];
    let path_ptr = arg_to_cstr(line, path_arg, &mut path_buf);
    let fd = open_path(path_ptr, O_RDONLY);
    if fd < 0 {
        write_stdout(if tail { b"tail: open failed" } else { b"head: open failed" });
        write_errno(fd);
        return;
    }
    let mut buf = [0u8; IO_BUF_LEN];
    if !tail {
        let mut lines = 0u32;
        'outer: loop {
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
            if nread <= 0 {
                break;
            }
            for &ch in &buf[..nread as usize] {
                write_stdout(&[ch]);
                if ch == b'\n' {
                    lines += 1;
                    if lines >= count {
                        break 'outer;
                    }
                }
            }
        }
    } else {
        let mut lines = [[0u8; LINE_BUF_LEN]; 16];
        let mut lengths = [0usize; 16];
        let mut line_count = 0usize;
        let mut cur = [0u8; LINE_BUF_LEN];
        let mut cur_len = 0usize;
        loop {
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
            if nread <= 0 {
                break;
            }
            for &ch in &buf[..nread as usize] {
                if cur_len < cur.len() {
                    cur[cur_len] = ch;
                    cur_len += 1;
                }
                if ch == b'\n' {
                    let slot = line_count % lines.len();
                    let copy_len = min(cur_len, lines[slot].len());
                    lines[slot][..copy_len].copy_from_slice(&cur[..copy_len]);
                    lengths[slot] = copy_len;
                    line_count += 1;
                    cur_len = 0;
                }
            }
        }
        if cur_len > 0 {
            let slot = line_count % lines.len();
            let copy_len = min(cur_len, lines[slot].len());
            lines[slot][..copy_len].copy_from_slice(&cur[..copy_len]);
            lengths[slot] = copy_len;
            line_count += 1;
        }
        let max = min(count as usize, lines.len());
        let start = line_count.saturating_sub(max);
        for idx in 0..max {
            let slot = (start + idx) % lines.len();
            if lengths[slot] > 0 {
                write_stdout(&lines[slot][..lengths[slot]]);
                if lines[slot][lengths[slot] - 1] != b'\n' {
                    write_stdout(b"\r\n");
                }
            }
        }
    }
    unsafe {
        let _ = syscall6(SYS_CLOSE, fd as usize, 0, 0, 0, 0, 0);
    }
}

fn cmd_wc(line: &[u8], args: &[Arg], argc: usize) {
    if argc < 2 {
        write_stdout(b"wc: missing path\r\n");
        return;
    }
    let mut path_buf = [0u8; IO_BUF_LEN];
    let path_ptr = arg_to_cstr(line, args[1], &mut path_buf);
    let fd = open_path(path_ptr, O_RDONLY);
    if fd < 0 {
        write_stdout(b"wc: open failed");
        write_errno(fd);
        return;
    }
    let mut buf = [0u8; IO_BUF_LEN];
    let mut bytes = 0usize;
    let mut lines = 0usize;
    let mut words = 0usize;
    let mut in_word = false;
    loop {
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
        if nread <= 0 {
            break;
        }
        let nread = nread as usize;
        bytes += nread;
        for &ch in &buf[..nread] {
            if ch == b'\n' {
                lines += 1;
            }
            if is_space(ch) || ch == b'\n' {
                if in_word {
                    words += 1;
                    in_word = false;
                }
            } else if !in_word {
                in_word = true;
            }
        }
    }
    if in_word {
        words += 1;
    }
    write_num(lines);
    write_stdout(b" ");
    write_num(words);
    write_stdout(b" ");
    write_num(bytes);
    write_stdout(b"\r\n");
    unsafe {
        let _ = syscall6(SYS_CLOSE, fd as usize, 0, 0, 0, 0, 0);
    }
}

fn cmd_stat(line: &[u8], args: &[Arg], argc: usize) {
    if argc < 2 {
        write_stdout(b"stat: missing path\r\n");
        return;
    }
    let mut path_buf = [0u8; IO_BUF_LEN];
    let path_ptr = arg_to_cstr(line, args[1], &mut path_buf);
    let mut st = Stat {
        st_dev: 0,
        st_ino: 0,
        st_mode: 0,
        st_nlink: 0,
        st_uid: 0,
        st_gid: 0,
        st_rdev: 0,
        __pad1: 0,
        st_size: 0,
        st_blksize: 0,
        __pad2: 0,
        st_blocks: 0,
        st_atime: 0,
        st_atime_nsec: 0,
        st_mtime: 0,
        st_mtime_nsec: 0,
        st_ctime: 0,
        st_ctime_nsec: 0,
        __unused4: 0,
        __unused5: 0,
    };
    let ret = stat_path(path_ptr, &mut st);
    if ret < 0 {
        write_stdout(b"stat: failed");
        write_errno(ret);
        return;
    }
    write_stdout(b"type: ");
    let mode = st.st_mode & S_IFMT;
    if mode == S_IFDIR {
        write_stdout(b"dir");
    } else if mode == S_IFLNK {
        write_stdout(b"link");
    } else {
        write_stdout(b"file");
    }
    write_stdout(b" size: ");
    write_num(st.st_size.max(0) as usize);
    write_stdout(b"\r\n");
}

fn cmd_sleep(line: &[u8], args: &[Arg], argc: usize) {
    let secs = if argc >= 2 {
        parse_u32(line, args[1]).unwrap_or(1)
    } else {
        1
    };
    let ts = Timespec {
        tv_sec: secs as i64,
        tv_nsec: 0,
    };
    // SAFETY: syscall arguments follow the expected ABI and pointers are valid.
    unsafe {
        let _ = syscall6(
            SYS_NANOSLEEP,
            &ts as *const Timespec as usize,
            0,
            0,
            0,
            0,
            0,
        );
    }
}

fn cmd_hexdump(line: &[u8], args: &[Arg], argc: usize) {
    if argc < 2 {
        write_stdout(b"hexdump: missing path\r\n");
        return;
    }
    let mut path_buf = [0u8; IO_BUF_LEN];
    let path_ptr = arg_to_cstr(line, args[1], &mut path_buf);
    let fd = open_path(path_ptr, O_RDONLY);
    if fd < 0 {
        write_stdout(b"hexdump: open failed");
        write_errno(fd);
        return;
    }
    let mut buf = [0u8; HEX_WIDTH];
    let mut offset = 0usize;
    loop {
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
        if nread <= 0 {
            break;
        }
        let nread = nread as usize;
        write_hex(offset, 8);
        write_stdout(b": ");
        for idx in 0..HEX_WIDTH {
            if idx < nread {
                write_hex_byte(buf[idx]);
            } else {
                write_stdout(b"  ");
            }
            if idx + 1 < HEX_WIDTH {
                write_stdout(b" ");
            }
        }
        write_stdout(b"  |");
        for idx in 0..nread {
            let ch = buf[idx];
            let out = if ch.is_ascii_graphic() || ch == b' ' { ch } else { b'.' };
            write_stdout(&[out]);
        }
        write_stdout(b"|\r\n");
        offset += nread;
    }
    unsafe {
        let _ = syscall6(SYS_CLOSE, fd as usize, 0, 0, 0, 0, 0);
    }
}

fn cmd_touch_append(line: &[u8], args: &[Arg], argc: usize, append: bool) {
    if argc < 2 {
        if append {
            write_stdout(b"append: missing path\r\n");
        } else {
            write_stdout(b"touch: missing path\r\n");
        }
        return;
    }
    let mut path_buf = [0u8; IO_BUF_LEN];
    let path_ptr = arg_to_cstr(line, args[1], &mut path_buf);
    let mut flags = O_WRONLY | O_CREAT;
    if append {
        flags |= O_APPEND;
    }
    let fd = open_path(path_ptr, flags);
    if fd < 0 {
        write_stdout(if append { b"append: open failed" } else { b"touch: open failed" });
        write_errno(fd);
        return;
    }
    if append && argc > 2 {
        for idx in 2..argc {
            let arg = args[idx];
            let slice = &line[arg.start..arg.start + arg.len];
            // SAFETY: syscall arguments follow the expected ABI and pointers are valid.
            unsafe {
                let _ = syscall6(SYS_WRITE, fd as usize, slice.as_ptr() as usize, slice.len(), 0, 0, 0);
            }
            if idx + 1 < argc {
                // SAFETY: syscall arguments follow the expected ABI and pointers are valid.
                unsafe {
                    let _ = syscall6(SYS_WRITE, fd as usize, b" ".as_ptr() as usize, 1, 0, 0, 0);
                }
            }
        }
        // SAFETY: syscall arguments follow the expected ABI and pointers are valid.
        unsafe {
            let _ = syscall6(SYS_WRITE, fd as usize, b"\r\n".as_ptr() as usize, 2, 0, 0, 0);
        }
    }
    unsafe {
        let _ = syscall6(SYS_CLOSE, fd as usize, 0, 0, 0, 0, 0);
    }
}

fn write_prompt() {
    let mut buf = [0u8; IO_BUF_LEN];
    write_stdout(b"\r");
    // SAFETY: syscall arguments follow the expected ABI and pointers are valid.
    let ret = unsafe { syscall6(SYS_GETCWD, buf.as_mut_ptr() as usize, buf.len(), 0, 0, 0, 0) };
    if ret > 1 {
        let len = (ret - 1) as usize;
        if len <= buf.len() {
            write_stdout(PROMPT_PREFIX);
            write_stdout(&buf[..len]);
            write_stdout(PROMPT_SUFFIX);
            return;
        }
    }
    write_stdout(PROMPT);
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    write_stdout(BANNER);
    loop {
        write_prompt();
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
        } else if arg_eq(&line, cmd, b"clear") {
            cmd_clear();
        } else if arg_eq(&line, cmd, b"head") {
            cmd_head_tail(&line, &args, argc, false);
        } else if arg_eq(&line, cmd, b"tail") {
            cmd_head_tail(&line, &args, argc, true);
        } else if arg_eq(&line, cmd, b"wc") {
            cmd_wc(&line, &args, argc);
        } else if arg_eq(&line, cmd, b"stat") {
            cmd_stat(&line, &args, argc);
        } else if arg_eq(&line, cmd, b"sleep") {
            cmd_sleep(&line, &args, argc);
        } else if arg_eq(&line, cmd, b"hexdump") {
            cmd_hexdump(&line, &args, argc);
        } else if arg_eq(&line, cmd, b"touch") {
            cmd_touch_append(&line, &args, argc, false);
        } else if arg_eq(&line, cmd, b"append") {
            cmd_touch_append(&line, &args, argc, true);
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
