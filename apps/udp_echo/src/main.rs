#![no_std]
#![no_main]

use core::arch::asm;

const SYS_WRITE: usize = 64;
const SYS_EXIT: usize = 93;
const SYS_SOCKET: usize = 198;
const SYS_BIND: usize = 200;
const SYS_SENDTO: usize = 206;
const SYS_RECVFROM: usize = 207;
const SYS_CLOSE: usize = 57;

const AF_INET: u16 = 2;
const SOCK_DGRAM: usize = 2;

const LOCAL_IP: [u8; 4] = [10, 0, 2, 15];
const SERVER_PORT: u16 = 22445;
const CLIENT_PORT: u16 = 22446;

const OK_MSG: &[u8] = b"udp-echo: ok\n";
const FAIL_MSG: &[u8] = b"udp-echo: fail\n";
const SEND_MSG: &[u8] = b"ping";
const REPLY_MSG: &[u8] = b"pong";

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

fn syscall_socket(domain: u16, sock_type: usize, protocol: usize) -> usize {
    check(unsafe { syscall6(SYS_SOCKET, domain as usize, sock_type, protocol, 0, 0, 0) })
}

fn syscall_bind(fd: usize, addr: &SockAddrIn) {
    check(unsafe {
        syscall6(
            SYS_BIND,
            fd,
            addr as *const SockAddrIn as usize,
            core::mem::size_of::<SockAddrIn>(),
            0,
            0,
            0,
        )
    });
}

fn syscall_sendto(fd: usize, buf: &[u8], addr: &SockAddrIn) -> usize {
    check(unsafe {
        syscall6(
            SYS_SENDTO,
            fd,
            buf.as_ptr() as usize,
            buf.len(),
            0,
            addr as *const SockAddrIn as usize,
            core::mem::size_of::<SockAddrIn>(),
        )
    })
}

fn syscall_recvfrom(fd: usize, buf: &mut [u8], addr: &mut SockAddrIn, addrlen: &mut u32) -> usize {
    check(unsafe {
        syscall6(
            SYS_RECVFROM,
            fd,
            buf.as_mut_ptr() as usize,
            buf.len(),
            0,
            addr as *mut SockAddrIn as usize,
            addrlen as *mut u32 as usize,
        )
    })
}

fn syscall_close(fd: usize) {
    let _ = unsafe { syscall6(SYS_CLOSE, fd, 0, 0, 0, 0, 0) };
}

fn sockaddr(ip: [u8; 4], port: u16) -> SockAddrIn {
    SockAddrIn {
        sin_family: AF_INET,
        sin_port: port.to_be(),
        sin_addr: u32::from_be_bytes(ip),
        sin_zero: [0; 8],
    }
}

fn slices_equal(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    for (idx, byte) in a.iter().enumerate() {
        if *byte != b[idx] {
            return false;
        }
    }
    true
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let server = syscall_socket(AF_INET, SOCK_DGRAM, 0);
    let client = syscall_socket(AF_INET, SOCK_DGRAM, 0);

    let server_addr = sockaddr(LOCAL_IP, SERVER_PORT);
    let client_addr = sockaddr(LOCAL_IP, CLIENT_PORT);

    syscall_bind(server, &server_addr);
    syscall_bind(client, &client_addr);

    let sent = syscall_sendto(client, SEND_MSG, &server_addr);
    if sent != SEND_MSG.len() {
        fail();
    }

    let mut buf = [0u8; 16];
    let mut from_addr = SockAddrIn {
        sin_family: 0,
        sin_port: 0,
        sin_addr: 0,
        sin_zero: [0; 8],
    };
    let mut from_len = core::mem::size_of::<SockAddrIn>() as u32;
    let received = syscall_recvfrom(server, &mut buf, &mut from_addr, &mut from_len);
    if !slices_equal(&buf[..received], SEND_MSG) {
        fail();
    }
    if from_len as usize != core::mem::size_of::<SockAddrIn>() {
        fail();
    }
    if from_addr.sin_family != AF_INET
        || from_addr.sin_port != CLIENT_PORT.to_be()
        || from_addr.sin_addr != u32::from_be_bytes(LOCAL_IP)
    {
        fail();
    }

    let sent = syscall_sendto(server, REPLY_MSG, &client_addr);
    if sent != REPLY_MSG.len() {
        fail();
    }

    let mut reply_addr = SockAddrIn {
        sin_family: 0,
        sin_port: 0,
        sin_addr: 0,
        sin_zero: [0; 8],
    };
    let mut reply_len = core::mem::size_of::<SockAddrIn>() as u32;
    let received = syscall_recvfrom(client, &mut buf, &mut reply_addr, &mut reply_len);
    if !slices_equal(&buf[..received], REPLY_MSG) {
        fail();
    }
    if reply_len as usize != core::mem::size_of::<SockAddrIn>() {
        fail();
    }
    if reply_addr.sin_family != AF_INET
        || reply_addr.sin_port != SERVER_PORT.to_be()
        || reply_addr.sin_addr != u32::from_be_bytes(LOCAL_IP)
    {
        fail();
    }

    syscall_close(client);
    syscall_close(server);

    write_stdout(OK_MSG);
    exit(0);
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    fail();
}
