#![no_std]
#![no_main]

use core::arch::asm;

const SYS_WRITE: usize = 64;
const SYS_EXIT: usize = 93;
const SYS_SOCKET: usize = 198;
const SYS_BIND: usize = 200;
const SYS_LISTEN: usize = 201;
const SYS_ACCEPT: usize = 202;
const SYS_CONNECT: usize = 203;
const SYS_SENDMSG: usize = 211;
const SYS_RECVMSG: usize = 212;
const SYS_GETSOCKNAME: usize = 204;
const SYS_GETPEERNAME: usize = 205;
const SYS_PPOLL: usize = 73;
const SYS_GETSOCKOPT: usize = 209;
const SYS_FCNTL: usize = 25;
const SYS_CLOSE: usize = 57;

const AF_INET: u16 = 2;
const SOCK_STREAM: usize = 1;

const F_SETFL: usize = 4;
const O_NONBLOCK: usize = 0x800;
const SOL_SOCKET: usize = 1;
const SO_ERROR: usize = 4;

const EINPROGRESS: isize = -115;
const ECONNREFUSED: isize = -111;
const ENETUNREACH: isize = -101;

const LOCAL_IP: [u8; 4] = [10, 0, 2, 15];
const SERVER_PORT: u16 = 22345;
const CLIENT_PORT: u16 = 22346;
const FAIL_PORT: u16 = 22347;

const OK_MSG: &[u8] = b"tcp-echo: ok\n";
const FAIL_MSG: &[u8] = b"tcp-echo: fail\n";
const SEND_MSG: &[u8] = b"ping";
const REPLY_MSG: &[u8] = b"pong";

const POLLOUT: i16 = 0x004;

#[repr(C)]
struct SockAddrIn {
    sin_family: u16,
    sin_port: u16,
    sin_addr: u32,
    sin_zero: [u8; 8],
}

#[repr(C)]
struct PollFd {
    fd: i32,
    events: i16,
    revents: i16,
}

#[repr(C)]
struct Timespec {
    tv_sec: i64,
    tv_nsec: i64,
}

#[repr(C)]
struct Iovec {
    iov_base: usize,
    iov_len: usize,
}

#[repr(C)]
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

fn syscall_listen(fd: usize, backlog: usize) {
    check(unsafe { syscall6(SYS_LISTEN, fd, backlog, 0, 0, 0, 0) });
}

fn syscall_accept(fd: usize) -> usize {
    check(unsafe { syscall6(SYS_ACCEPT, fd, 0, 0, 0, 0, 0) })
}

fn syscall_connect_nonblock(fd: usize, addr: &SockAddrIn) {
    let ret = unsafe {
        syscall6(
            SYS_CONNECT,
            fd,
            addr as *const SockAddrIn as usize,
            core::mem::size_of::<SockAddrIn>(),
            0,
            0,
            0,
        )
    };
    if ret == EINPROGRESS {
        return;
    }
    if ret < 0 {
        fail();
    }
}

fn syscall_connect(fd: usize, addr: &SockAddrIn) -> isize {
    unsafe {
        syscall6(
            SYS_CONNECT,
            fd,
            addr as *const SockAddrIn as usize,
            core::mem::size_of::<SockAddrIn>(),
            0,
            0,
            0,
        )
    }
}

fn syscall_sendmsg(fd: usize, iovs: &mut [Iovec]) -> usize {
    let msg = MsgHdr {
        msg_name: 0,
        msg_namelen: 0,
        msg_namelen_pad: 0,
        msg_iov: iovs.as_ptr() as usize,
        msg_iovlen: iovs.len(),
        msg_control: 0,
        msg_controllen: 0,
        msg_flags: 0,
        msg_flags_pad: 0,
    };
    check(unsafe { syscall6(SYS_SENDMSG, fd, &msg as *const MsgHdr as usize, 0, 0, 0, 0) })
}

fn syscall_recvmsg(fd: usize, iovs: &mut [Iovec]) -> usize {
    let mut msg = MsgHdr {
        msg_name: 0,
        msg_namelen: 0,
        msg_namelen_pad: 0,
        msg_iov: iovs.as_mut_ptr() as usize,
        msg_iovlen: iovs.len(),
        msg_control: 0,
        msg_controllen: 0,
        msg_flags: 0,
        msg_flags_pad: 0,
    };
    check(unsafe { syscall6(SYS_RECVMSG, fd, &mut msg as *mut MsgHdr as usize, 0, 0, 0, 0) })
}

fn syscall_ppoll(fds: &mut [PollFd], timeout: &Timespec) -> isize {
    unsafe {
        syscall6(
            SYS_PPOLL,
            fds.as_mut_ptr() as usize,
            fds.len(),
            timeout as *const Timespec as usize,
            0,
            0,
            0,
        )
    }
}

fn syscall_getsockname(fd: usize, addr: &mut SockAddrIn) {
    let mut len = core::mem::size_of::<SockAddrIn>();
    let ret = unsafe {
        syscall6(
            SYS_GETSOCKNAME,
            fd,
            addr as *mut SockAddrIn as usize,
            &mut len as *mut usize as usize,
            0,
            0,
            0,
        )
    };
    if ret < 0 || len < core::mem::size_of::<SockAddrIn>() {
        fail();
    }
}

fn syscall_getpeername(fd: usize, addr: &mut SockAddrIn) {
    let mut len = core::mem::size_of::<SockAddrIn>();
    let ret = unsafe {
        syscall6(
            SYS_GETPEERNAME,
            fd,
            addr as *mut SockAddrIn as usize,
            &mut len as *mut usize as usize,
            0,
            0,
            0,
        )
    };
    if ret < 0 || len < core::mem::size_of::<SockAddrIn>() {
        fail();
    }
}

fn syscall_getsockopt(fd: usize, level: usize, opt: usize, val: &mut i32, len: &mut usize) {
    let ret = unsafe {
        syscall6(
            SYS_GETSOCKOPT,
            fd,
            level,
            opt,
            val as *mut i32 as usize,
            len as *mut usize as usize,
            0,
        )
    };
    if ret < 0 {
        fail();
    }
}

fn syscall_fcntl(fd: usize, cmd: usize, arg: usize) {
    check(unsafe { syscall6(SYS_FCNTL, fd, cmd, arg, 0, 0, 0) });
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

fn iov_matches(a: &[u8], b: &[u8], expected: &[u8]) -> bool {
    if expected.len() != a.len() + b.len() {
        return false;
    }
    if !slices_equal(a, &expected[..a.len()]) {
        return false;
    }
    slices_equal(b, &expected[a.len()..])
}

fn sockaddr_matches(addr: &SockAddrIn, ip: [u8; 4], port: u16) -> bool {
    addr.sin_family == AF_INET
        && addr.sin_port == port.to_be()
        && addr.sin_addr == u32::from_be_bytes(ip)
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let server = syscall_socket(AF_INET, SOCK_STREAM, 0);
    let client = syscall_socket(AF_INET, SOCK_STREAM, 0);
    let fail_client = syscall_socket(AF_INET, SOCK_STREAM, 0);

    let server_addr = sockaddr(LOCAL_IP, SERVER_PORT);
    let client_addr = sockaddr(LOCAL_IP, CLIENT_PORT);
    let fail_addr = sockaddr(LOCAL_IP, FAIL_PORT);

    syscall_bind(server, &server_addr);
    syscall_listen(server, 1);
    syscall_bind(client, &client_addr);

    syscall_fcntl(fail_client, F_SETFL, O_NONBLOCK);
    let ret = syscall_connect(fail_client, &fail_addr);
    if ret == EINPROGRESS {
        let mut fail_poll = [PollFd {
            fd: fail_client as i32,
            events: POLLOUT,
            revents: 0,
        }];
        let timeout = Timespec {
            tv_sec: 1,
            tv_nsec: 0,
        };
        let polled = syscall_ppoll(&mut fail_poll, &timeout);
        if polled <= 0 {
            fail();
        }
        let mut so_error: i32 = -1;
        let mut so_len = core::mem::size_of::<i32>();
        syscall_getsockopt(fail_client, SOL_SOCKET, SO_ERROR, &mut so_error, &mut so_len);
        if so_error != -ECONNREFUSED as i32 && so_error != -ENETUNREACH as i32 {
            fail();
        }
    } else if ret < 0 {
        if ret != ECONNREFUSED && ret != ENETUNREACH {
            fail();
        }
    } else {
        fail();
    }
    syscall_close(fail_client);

    syscall_fcntl(client, F_SETFL, O_NONBLOCK);
    syscall_connect_nonblock(client, &server_addr);

    let mut pollfd = [PollFd {
        fd: client as i32,
        events: POLLOUT,
        revents: 0,
    }];
    let timeout = Timespec {
        tv_sec: 2,
        tv_nsec: 0,
    };
    let polled = syscall_ppoll(&mut pollfd, &timeout);
    if polled <= 0 {
        fail();
    }
    if (pollfd[0].revents & POLLOUT) == 0 {
        fail();
    }

    let mut so_error: i32 = -1;
    let mut so_len = core::mem::size_of::<i32>();
    syscall_getsockopt(client, SOL_SOCKET, SO_ERROR, &mut so_error, &mut so_len);
    if so_error != 0 {
        fail();
    }
    syscall_fcntl(client, F_SETFL, 0);

    let accepted = syscall_accept(server);

    let mut addr = SockAddrIn {
        sin_family: 0,
        sin_port: 0,
        sin_addr: 0,
        sin_zero: [0; 8],
    };
    syscall_getsockname(client, &mut addr);
    if !sockaddr_matches(&addr, LOCAL_IP, CLIENT_PORT) {
        fail();
    }
    syscall_getpeername(client, &mut addr);
    if !sockaddr_matches(&addr, LOCAL_IP, SERVER_PORT) {
        fail();
    }
    syscall_getsockname(accepted, &mut addr);
    if !sockaddr_matches(&addr, LOCAL_IP, SERVER_PORT) {
        fail();
    }
    syscall_getpeername(accepted, &mut addr);
    if !sockaddr_matches(&addr, LOCAL_IP, CLIENT_PORT) {
        fail();
    }

    let mut send_iov = [
        Iovec {
            iov_base: SEND_MSG[..2].as_ptr() as usize,
            iov_len: 2,
        },
        Iovec {
            iov_base: SEND_MSG[2..].as_ptr() as usize,
            iov_len: SEND_MSG.len() - 2,
        },
    ];
    let sent = syscall_sendmsg(client, &mut send_iov);
    if sent != SEND_MSG.len() {
        fail();
    }

    let mut recv_left = [0u8; 2];
    let mut recv_right = [0u8; 2];
    let mut recv_iov = [
        Iovec {
            iov_base: recv_left.as_mut_ptr() as usize,
            iov_len: recv_left.len(),
        },
        Iovec {
            iov_base: recv_right.as_mut_ptr() as usize,
            iov_len: recv_right.len(),
        },
    ];
    let received = syscall_recvmsg(accepted, &mut recv_iov);
    if received != SEND_MSG.len() || !iov_matches(&recv_left, &recv_right, SEND_MSG) {
        fail();
    }

    let mut reply_iov = [
        Iovec {
            iov_base: REPLY_MSG[..2].as_ptr() as usize,
            iov_len: 2,
        },
        Iovec {
            iov_base: REPLY_MSG[2..].as_ptr() as usize,
            iov_len: REPLY_MSG.len() - 2,
        },
    ];
    let sent = syscall_sendmsg(accepted, &mut reply_iov);
    if sent != REPLY_MSG.len() {
        fail();
    }

    let mut recv_left = [0u8; 2];
    let mut recv_right = [0u8; 2];
    let mut recv_iov = [
        Iovec {
            iov_base: recv_left.as_mut_ptr() as usize,
            iov_len: recv_left.len(),
        },
        Iovec {
            iov_base: recv_right.as_mut_ptr() as usize,
            iov_len: recv_right.len(),
        },
    ];
    let received = syscall_recvmsg(client, &mut recv_iov);
    if received != REPLY_MSG.len() || !iov_matches(&recv_left, &recv_right, REPLY_MSG) {
        fail();
    }

    syscall_close(accepted);
    syscall_close(client);
    syscall_close(server);

    write_stdout(OK_MSG);
    exit(0);
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    fail();
}
