#![allow(dead_code)]

use crate::trap::TrapFrame;

#[repr(i32)]
#[derive(Debug, Clone, Copy)]
pub enum Errno {
    NoSys = 38,
    Fault = 14,
    Inval = 22,
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
        SYS_WRITE => sys_write(ctx.args[0], ctx.args[1], ctx.args[2]),
        _ => Err(Errno::NoSys),
    }
}

const SYS_EXIT: usize = 93;
const SYS_WRITE: usize = 64;

fn sys_exit(_code: usize) -> Result<usize, Errno> {
    crate::sbi::shutdown();
}

fn sys_write(_fd: usize, _buf: usize, _len: usize) -> Result<usize, Errno> {
    // User memory access is not wired up yet.
    Err(Errno::NoSys)
}
