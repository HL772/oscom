#![no_std]
#![no_main]
//! TCP receive benchmark used by net-perf harness.

use core::arch::asm;

const SYS_WRITE: usize = 64;
const SYS_EXIT: usize = 93;
const SYS_SOCKET: usize = 198;
const SYS_BIND: usize = 200;
const SYS_LISTEN: usize = 201;
const SYS_ACCEPT: usize = 202;
const SYS_RECVFROM: usize = 207;
const SYS_CLOSE: usize = 57;

const AF_INET: u16 = 2;
const SOCK_STREAM: usize = 1;

const LOCAL_IP: [u8; 4] = [10, 0, 2, 15];
const PORT: u16 = 5201;

const READY_MSG: &[u8] = b"net-bench: ready\n";
const ACCEPT_MSG: &[u8] = b"net-bench: accept\n";
const FAIL_MSG: &[u8] = b"net-bench: fail\n";
const RX_PREFIX: &[u8] = b"net-bench: rx_bytes=";
const RX_SUFFIX: &[u8] = b"\n";
const TARGET_PREFIX: &[u8] = b"net-bench: target=";

#[repr(C)]
struct SockAddrIn {
    sin_family: u16,
    sin_port: u16,
    sin_addr: u32,
    sin_zero: [u8; 8],
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

fn sockaddr(ip: [u8; 4], port: u16) -> SockAddrIn {
    SockAddrIn {
        sin_family: AF_INET,
        sin_port: port.to_be(),
        sin_addr: u32::from_be_bytes(ip),
        sin_zero: [0; 8],
    }
}

fn write_u64(mut val: u64) {
    let mut buf = [0u8; 20];
    let mut idx = buf.len();
    if val == 0 {
        idx -= 1;
        buf[idx] = b'0';
    } else {
        while val != 0 {
            let digit = (val % 10) as u8;
            idx -= 1;
            buf[idx] = b'0' + digit;
            val /= 10;
        }
    }
    write_stdout(&buf[idx..]);
}

fn recv_exact(fd: usize, buf: &mut [u8]) -> bool {
    let mut offset = 0usize;
    while offset < buf.len() {
        let n = unsafe {
            syscall6(
                SYS_RECVFROM,
                fd,
                buf[offset..].as_mut_ptr() as usize,
                buf.len() - offset,
                0,
                0,
                0,
            )
        };
        if n <= 0 {
            return false;
        }
        offset += n as usize;
    }
    true
}

#[no_mangle]
/// Program entry point invoked by the kernel loader.
pub extern "C" fn _start() -> ! {
    let server = check(unsafe { syscall6(SYS_SOCKET, AF_INET as usize, SOCK_STREAM, 0, 0, 0, 0) });
    let addr = sockaddr(LOCAL_IP, PORT);
    check(unsafe {
        syscall6(
            SYS_BIND,
            server,
            &addr as *const SockAddrIn as usize,
            core::mem::size_of::<SockAddrIn>(),
            0,
            0,
            0,
        )
    });
    check(unsafe { syscall6(SYS_LISTEN, server, 16, 0, 0, 0, 0) });

    write_stdout(READY_MSG);

    loop {
        let client = check(unsafe { syscall6(SYS_ACCEPT, server, 0, 0, 0, 0, 0) });
        write_stdout(ACCEPT_MSG);
        let mut header = [0u8; 8];
        if !recv_exact(client, &mut header) {
            fail();
        }
        let target = u64::from_be_bytes(header);
        write_stdout(TARGET_PREFIX);
        write_u64(target);
        write_stdout(RX_SUFFIX);
        let mut buf = [0u8; 4096];
        let mut total: u64 = 0;
        while total < target {
            let n = unsafe {
                syscall6(
                    SYS_RECVFROM,
                    client,
                    buf.as_mut_ptr() as usize,
                    buf.len(),
                    0,
                    0,
                    0,
                )
            };
            if n <= 0 {
                fail();
            }
            total += n as u64;
        }

        let _ = unsafe { syscall6(SYS_CLOSE, client, 0, 0, 0, 0, 0) };
        write_stdout(RX_PREFIX);
        write_u64(total);
        write_stdout(RX_SUFFIX);
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    fail();
}
