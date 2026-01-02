//! SBI (Supervisor Binary Interface) wrappers.

use core::arch::asm;

const SBI_CONSOLE_PUTCHAR: usize = 1;
const SBI_CONSOLE_GETCHAR: usize = 2;
const SBI_SHUTDOWN: usize = 8;

const SBI_LEGACY_SET_TIMER: usize = 0;

const SBI_EXT_SRST: usize = 0x53525354;
const SBI_SRST_RESET_TYPE_SHUTDOWN: usize = 0;
const SBI_SRST_RESET_REASON_NONE: usize = 0;
const SBI_EXT_TIME: usize = 0x54494D45;

#[inline(always)]
fn sbi_call_legacy(which: usize, arg0: usize, arg1: usize, arg2: usize) -> usize {
    let ret: usize;
    // Safety: ecall follows the SBI legacy calling convention on RISC-V.
    unsafe {
        asm!(
            "ecall",
            inlateout("a0") arg0 => ret,
            in("a1") arg1,
            in("a2") arg2,
            in("a7") which,
        );
    }
    ret
}

#[inline(always)]
fn sbi_call(eid: usize, fid: usize, arg0: usize, arg1: usize, arg2: usize) -> (usize, usize) {
    let error: usize;
    let value: usize;
    // Safety: ecall follows the SBI v0.2+ calling convention on RISC-V.
    unsafe {
        asm!(
            "ecall",
            inlateout("a0") arg0 => error,
            inlateout("a1") arg1 => value,
            in("a2") arg2,
            in("a6") fid,
            in("a7") eid,
        );
    }
    (error, value)
}

/// Write a byte to the SBI console.
pub fn console_putchar(ch: u8) {
    let _ = sbi_call_legacy(SBI_CONSOLE_PUTCHAR, ch as usize, 0, 0);
}

/// Read a byte from the SBI console if available.
pub fn console_getchar() -> Option<u8> {
    let ret = sbi_call_legacy(SBI_CONSOLE_GETCHAR, 0, 0, 0);
    if ret == usize::MAX {
        // Legacy SBI returns -1 when no input is available.
        return None;
    }
    Some(ret as u8)
}

/// Program the SBI timer with an absolute time value.
pub fn set_timer(stime_value: u64) {
    let (err, _) = sbi_call(SBI_EXT_TIME, 0, stime_value as usize, 0, 0);
    if err != 0 {
        let _ = sbi_call_legacy(SBI_LEGACY_SET_TIMER, stime_value as usize, 0, 0);
    }
}

/// Power off the system via SBI.
pub fn shutdown() -> ! {
    let (err, _) = sbi_call(
        SBI_EXT_SRST,
        0,
        SBI_SRST_RESET_TYPE_SHUTDOWN,
        SBI_SRST_RESET_REASON_NONE,
        0,
    );
    if err != 0 {
        let _ = sbi_call_legacy(SBI_SHUTDOWN, 0, 0, 0);
    }
    loop {
        // If shutdown is not supported, halt the CPU.
        // Safety: wfi only halts the current hart until the next interrupt.
        unsafe { asm!("wfi"); }
    }
}
