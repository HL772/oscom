#![no_std]
#![no_main]

use core::arch::asm;

const SYS_WRITE: usize = 64;
const SYS_EXIT: usize = 93;
const SYS_SOCKET: usize = 198;
const SYS_BIND: usize = 200;
const SYS_SENDTO: usize = 206;
const SYS_RECVFROM: usize = 207;
const SYS_SETSOCKOPT: usize = 208;
const SYS_GETSOCKOPT: usize = 209;
const SYS_SENDMSG: usize = 211;
const SYS_RECVMSG: usize = 212;
const SYS_SENDMMSG: usize = 269;
const SYS_RECVMMSG: usize = 243;
const SYS_CLOSE: usize = 57;

const AF_INET: u16 = 2;
const SOCK_DGRAM: usize = 2;
const SOL_SOCKET: usize = 1;
const SO_RCVTIMEO: usize = 20;
const SO_SNDTIMEO: usize = 21;
const ETIMEDOUT: isize = -110;
const EAGAIN: isize = -11;

const LOCAL_IP: [u8; 4] = [10, 0, 2, 15];
const SERVER_PORT: u16 = 22445;
const CLIENT_PORT: u16 = 22446;

const OK_MSG: &[u8] = b"udp-echo: ok\n";
const FAIL_MSG: &[u8] = b"udp-echo: fail\n";
const SEND_MSG: &[u8] = b"ping";
const REPLY_MSG: &[u8] = b"pong";
const MMSG_A: &[u8] = b"aa";
const MMSG_B: &[u8] = b"bb";

#[repr(C)]
struct SockAddrIn {
    sin_family: u16,
    sin_port: u16,
    sin_addr: u32,
    sin_zero: [u8; 8],
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

#[repr(C)]
struct MMsgHdr {
    msg_hdr: MsgHdr,
    msg_len: u32,
    msg_len_pad: u32,
}

#[repr(C)]
struct Timeval {
    tv_sec: i64,
    tv_usec: i64,
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

#[allow(dead_code)]
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

#[allow(dead_code)]
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

fn syscall_sendmsg(fd: usize, msg: &MsgHdr) -> usize {
    check(unsafe { syscall6(SYS_SENDMSG, fd, msg as *const MsgHdr as usize, 0, 0, 0, 0) })
}

fn syscall_recvmsg(fd: usize, msg: &mut MsgHdr) -> usize {
    check(unsafe { syscall6(SYS_RECVMSG, fd, msg as *mut MsgHdr as usize, 0, 0, 0, 0) })
}

fn syscall_recvmsg_ret(fd: usize, msg: &mut MsgHdr) -> isize {
    unsafe { syscall6(SYS_RECVMSG, fd, msg as *mut MsgHdr as usize, 0, 0, 0, 0) }
}

fn syscall_sendmmsg(fd: usize, msgvec: &mut [MMsgHdr]) -> usize {
    check(unsafe {
        syscall6(
            SYS_SENDMMSG,
            fd,
            msgvec.as_mut_ptr() as usize,
            msgvec.len(),
            0,
            0,
            0,
        )
    })
}

fn syscall_recvmmsg(fd: usize, msgvec: &mut [MMsgHdr]) -> usize {
    check(unsafe {
        syscall6(
            SYS_RECVMMSG,
            fd,
            msgvec.as_mut_ptr() as usize,
            msgvec.len(),
            0,
            0,
            0,
        )
    })
}

fn syscall_setsockopt(fd: usize, level: usize, optname: usize, optval: &Timeval) {
    let ret = unsafe {
        syscall6(
            SYS_SETSOCKOPT,
            fd,
            level,
            optname,
            optval as *const Timeval as usize,
            core::mem::size_of::<Timeval>(),
            0,
        )
    };
    if ret < 0 {
        fail();
    }
}

fn syscall_getsockopt(fd: usize, level: usize, optname: usize, optval: &mut Timeval) {
    let mut len = core::mem::size_of::<Timeval>() as u32;
    let ret = unsafe {
        syscall6(
            SYS_GETSOCKOPT,
            fd,
            level,
            optname,
            optval as *mut Timeval as usize,
            &mut len as *mut u32 as usize,
            0,
        )
    };
    if ret < 0 || len as usize != core::mem::size_of::<Timeval>() {
        fail();
    }
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

fn check_addr(addr: &SockAddrIn, port: u16) {
    if addr.sin_family != AF_INET
        || addr.sin_port != port.to_be()
        || addr.sin_addr != u32::from_be_bytes(LOCAL_IP)
    {
        fail();
    }
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let server = syscall_socket(AF_INET, SOCK_DGRAM, 0);
    let client = syscall_socket(AF_INET, SOCK_DGRAM, 0);

    let server_addr = sockaddr(LOCAL_IP, SERVER_PORT);
    let client_addr = sockaddr(LOCAL_IP, CLIENT_PORT);

    syscall_bind(server, &server_addr);
    syscall_bind(client, &client_addr);

    let timeout = Timeval {
        tv_sec: 0,
        tv_usec: 200_000,
    };
    syscall_setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout);
    let mut timeout_buf = [0u8; 8];
    let mut timeout_addr = SockAddrIn {
        sin_family: 0,
        sin_port: 0,
        sin_addr: 0,
        sin_zero: [0; 8],
    };
    let mut timeout_iov = [Iovec {
        iov_base: timeout_buf.as_mut_ptr() as usize,
        iov_len: timeout_buf.len(),
    }];
    let mut timeout_msg = MsgHdr {
        msg_name: &mut timeout_addr as *mut SockAddrIn as usize,
        msg_namelen: core::mem::size_of::<SockAddrIn>() as u32,
        msg_namelen_pad: 0,
        msg_iov: timeout_iov.as_mut_ptr() as usize,
        msg_iovlen: timeout_iov.len(),
        msg_control: 0,
        msg_controllen: 0,
        msg_flags: 0,
        msg_flags_pad: 0,
    };
    let ret = syscall_recvmsg_ret(client, &mut timeout_msg);
    if ret >= 0 {
        fail();
    }
    if ret != ETIMEDOUT && ret != EAGAIN {
        fail();
    }
    let timeout_off = Timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    syscall_setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout_off);

    let send_timeout = Timeval {
        tv_sec: 0,
        tv_usec: 150_000,
    };
    syscall_setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, &send_timeout);
    let mut read_timeout = Timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    syscall_getsockopt(client, SOL_SOCKET, SO_SNDTIMEO, &mut read_timeout);
    if read_timeout.tv_sec != send_timeout.tv_sec || read_timeout.tv_usec != send_timeout.tv_usec {
        fail();
    }

    let mut send_iov = [Iovec {
        iov_base: SEND_MSG.as_ptr() as usize,
        iov_len: SEND_MSG.len(),
    }];
    let send_msg = MsgHdr {
        msg_name: &server_addr as *const SockAddrIn as usize,
        msg_namelen: core::mem::size_of::<SockAddrIn>() as u32,
        msg_namelen_pad: 0,
        msg_iov: send_iov.as_ptr() as usize,
        msg_iovlen: send_iov.len(),
        msg_control: 0,
        msg_controllen: 0,
        msg_flags: 0,
        msg_flags_pad: 0,
    };
    let sent = syscall_sendmsg(client, &send_msg);
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
    let mut recv_iov = [Iovec {
        iov_base: buf.as_mut_ptr() as usize,
        iov_len: buf.len(),
    }];
    let mut recv_msg = MsgHdr {
        msg_name: &mut from_addr as *mut SockAddrIn as usize,
        msg_namelen: core::mem::size_of::<SockAddrIn>() as u32,
        msg_namelen_pad: 0,
        msg_iov: recv_iov.as_mut_ptr() as usize,
        msg_iovlen: recv_iov.len(),
        msg_control: 0,
        msg_controllen: 0,
        msg_flags: 0,
        msg_flags_pad: 0,
    };
    let received = syscall_recvmsg(server, &mut recv_msg);
    if !slices_equal(&buf[..received], SEND_MSG) {
        fail();
    }
    if recv_msg.msg_namelen as usize != core::mem::size_of::<SockAddrIn>() {
        fail();
    }
    check_addr(&from_addr, CLIENT_PORT);

    send_iov[0] = Iovec {
        iov_base: REPLY_MSG.as_ptr() as usize,
        iov_len: REPLY_MSG.len(),
    };
    let send_reply = MsgHdr {
        msg_name: &client_addr as *const SockAddrIn as usize,
        msg_namelen: core::mem::size_of::<SockAddrIn>() as u32,
        msg_namelen_pad: 0,
        msg_iov: send_iov.as_ptr() as usize,
        msg_iovlen: send_iov.len(),
        msg_control: 0,
        msg_controllen: 0,
        msg_flags: 0,
        msg_flags_pad: 0,
    };
    let sent = syscall_sendmsg(server, &send_reply);
    if sent != REPLY_MSG.len() {
        fail();
    }

    let mut reply_addr = SockAddrIn {
        sin_family: 0,
        sin_port: 0,
        sin_addr: 0,
        sin_zero: [0; 8],
    };
    recv_iov[0] = Iovec {
        iov_base: buf.as_mut_ptr() as usize,
        iov_len: buf.len(),
    };
    let mut recv_reply = MsgHdr {
        msg_name: &mut reply_addr as *mut SockAddrIn as usize,
        msg_namelen: core::mem::size_of::<SockAddrIn>() as u32,
        msg_namelen_pad: 0,
        msg_iov: recv_iov.as_mut_ptr() as usize,
        msg_iovlen: recv_iov.len(),
        msg_control: 0,
        msg_controllen: 0,
        msg_flags: 0,
        msg_flags_pad: 0,
    };
    let received = syscall_recvmsg(client, &mut recv_reply);
    if !slices_equal(&buf[..received], REPLY_MSG) {
        fail();
    }
    if recv_reply.msg_namelen as usize != core::mem::size_of::<SockAddrIn>() {
        fail();
    }
    check_addr(&reply_addr, SERVER_PORT);

    let mut recv_a = [0u8; 8];
    let mut recv_b = [0u8; 8];
    let mut from_a = SockAddrIn {
        sin_family: 0,
        sin_port: 0,
        sin_addr: 0,
        sin_zero: [0; 8],
    };
    let mut from_b = SockAddrIn {
        sin_family: 0,
        sin_port: 0,
        sin_addr: 0,
        sin_zero: [0; 8],
    };

    let send_a_iov = [Iovec {
        iov_base: MMSG_A.as_ptr() as usize,
        iov_len: MMSG_A.len(),
    }];
    let send_b_iov = [Iovec {
        iov_base: MMSG_B.as_ptr() as usize,
        iov_len: MMSG_B.len(),
    }];
    let mut send_vec = [
        MMsgHdr {
            msg_hdr: MsgHdr {
                msg_name: &server_addr as *const SockAddrIn as usize,
                msg_namelen: core::mem::size_of::<SockAddrIn>() as u32,
                msg_namelen_pad: 0,
                msg_iov: send_a_iov.as_ptr() as usize,
                msg_iovlen: send_a_iov.len(),
                msg_control: 0,
                msg_controllen: 0,
                msg_flags: 0,
                msg_flags_pad: 0,
            },
            msg_len: 0,
            msg_len_pad: 0,
        },
        MMsgHdr {
            msg_hdr: MsgHdr {
                msg_name: &server_addr as *const SockAddrIn as usize,
                msg_namelen: core::mem::size_of::<SockAddrIn>() as u32,
                msg_namelen_pad: 0,
                msg_iov: send_b_iov.as_ptr() as usize,
                msg_iovlen: send_b_iov.len(),
                msg_control: 0,
                msg_controllen: 0,
                msg_flags: 0,
                msg_flags_pad: 0,
            },
            msg_len: 0,
            msg_len_pad: 0,
        },
    ];
    let sent = syscall_sendmmsg(client, &mut send_vec);
    if sent != 2 || send_vec[0].msg_len != MMSG_A.len() as u32 || send_vec[1].msg_len != MMSG_B.len() as u32 {
        fail();
    }

    let mut recv_a_iov = [Iovec {
        iov_base: recv_a.as_mut_ptr() as usize,
        iov_len: recv_a.len(),
    }];
    let mut recv_b_iov = [Iovec {
        iov_base: recv_b.as_mut_ptr() as usize,
        iov_len: recv_b.len(),
    }];
    let mut recv_vec = [
        MMsgHdr {
            msg_hdr: MsgHdr {
                msg_name: &mut from_a as *mut SockAddrIn as usize,
                msg_namelen: core::mem::size_of::<SockAddrIn>() as u32,
                msg_namelen_pad: 0,
                msg_iov: recv_a_iov.as_mut_ptr() as usize,
                msg_iovlen: recv_a_iov.len(),
                msg_control: 0,
                msg_controllen: 0,
                msg_flags: 0,
                msg_flags_pad: 0,
            },
            msg_len: 0,
            msg_len_pad: 0,
        },
        MMsgHdr {
            msg_hdr: MsgHdr {
                msg_name: &mut from_b as *mut SockAddrIn as usize,
                msg_namelen: core::mem::size_of::<SockAddrIn>() as u32,
                msg_namelen_pad: 0,
                msg_iov: recv_b_iov.as_mut_ptr() as usize,
                msg_iovlen: recv_b_iov.len(),
                msg_control: 0,
                msg_controllen: 0,
                msg_flags: 0,
                msg_flags_pad: 0,
            },
            msg_len: 0,
            msg_len_pad: 0,
        },
    ];
    let recvd = syscall_recvmmsg(server, &mut recv_vec);
    if recvd != 2 {
        fail();
    }
    if recv_vec[0].msg_len != MMSG_A.len() as u32 || recv_vec[1].msg_len != MMSG_B.len() as u32 {
        fail();
    }
    if !slices_equal(&recv_a[..MMSG_A.len()], MMSG_A) || !slices_equal(&recv_b[..MMSG_B.len()], MMSG_B) {
        fail();
    }
    check_addr(&from_a, CLIENT_PORT);
    check_addr(&from_b, CLIENT_PORT);

    syscall_close(client);
    syscall_close(server);

    write_stdout(OK_MSG);
    exit(0);
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    fail();
}
