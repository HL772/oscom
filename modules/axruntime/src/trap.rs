#![allow(dead_code)]

use core::arch::asm;
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::{mm, runtime, sbi, time};

// Trap/interrupt helpers are scaffolded for upcoming scheduler/timer work.

#[repr(C)]
pub struct TrapFrame {
    pub ra: usize,
    pub gp: usize,
    pub tp: usize,
    pub t0: usize,
    pub t1: usize,
    pub t2: usize,
    pub s0: usize,
    pub s1: usize,
    pub a0: usize,
    pub a1: usize,
    pub a2: usize,
    pub a3: usize,
    pub a4: usize,
    pub a5: usize,
    pub a6: usize,
    pub a7: usize,
    pub s2: usize,
    pub s3: usize,
    pub s4: usize,
    pub s5: usize,
    pub s6: usize,
    pub s7: usize,
    pub s8: usize,
    pub s9: usize,
    pub s10: usize,
    pub s11: usize,
    pub t3: usize,
    pub t4: usize,
    pub t5: usize,
    pub t6: usize,
    pub sstatus: usize,
    pub sepc: usize,
    pub scause: usize,
    pub stval: usize,
    pub user_sp: usize,
    pub pad: usize,
}

extern "C" {
    fn __trap_vector();
    fn __trap_return();
}

const SSTATUS_SIE: usize = 1 << 1;
const SSTATUS_SPIE: usize = 1 << 5;
const SSTATUS_SPP: usize = 1 << 8;
const SIE_STIE: usize = 1 << 5;
const SIE_SEIE: usize = 1 << 9;

const SCAUSE_INTERRUPT_BIT: usize = 1usize << (usize::BITS as usize - 1);
const SCAUSE_SUPERVISOR_TIMER: usize = 5;
const SCAUSE_SUPERVISOR_EXTERNAL: usize = 9;
const SCAUSE_USER_ECALL: usize = 8;
const SCAUSE_SUPERVISOR_ECALL: usize = 9;
const SCAUSE_ILLEGAL_INSTRUCTION: usize = 2;
const SCAUSE_INST_PAGE_FAULT: usize = 12;
const SCAUSE_LOAD_PAGE_FAULT: usize = 13;
const SCAUSE_STORE_PAGE_FAULT: usize = 15;

static TIMER_INTERVAL: AtomicU64 = AtomicU64::new(0);
static TRAP_LOG_ONCE: AtomicBool = AtomicBool::new(false);
static mut CURRENT_TRAP_FRAME: *mut TrapFrame = ptr::null_mut();

pub struct TrapFrameGuard;

pub fn enter_trap(tf: &mut TrapFrame) -> TrapFrameGuard {
    // Safety: single-hart early boot; the trap frame lives on the current stack.
    unsafe {
        CURRENT_TRAP_FRAME = tf as *mut TrapFrame;
    }
    runtime::on_trap_entry(tf);
    TrapFrameGuard
}

impl Drop for TrapFrameGuard {
    fn drop(&mut self) {
        // Safety: trap handler exits with interrupts disabled; clear the pointer.
        runtime::on_trap_exit();
        unsafe {
            CURRENT_TRAP_FRAME = ptr::null_mut();
        }
    }
}

pub fn current_trap_frame() -> Option<&'static mut TrapFrame> {
    // Safety: only valid while handling a trap on the current hart.
    unsafe {
        if CURRENT_TRAP_FRAME.is_null() {
            None
        } else {
            Some(&mut *CURRENT_TRAP_FRAME)
        }
    }
}

pub fn init() {
    unsafe {
        write_stvec(__trap_vector as usize);
        write_sscratch(0);
    }
}

pub fn enable_timer_interrupt(interval_ticks: u64) {
    TIMER_INTERVAL.store(interval_ticks, Ordering::Relaxed);
    let now = read_time();
    sbi::set_timer(now + interval_ticks);
    unsafe {
        write_sie(read_sie() | SIE_STIE);
        write_sstatus(read_sstatus() | SSTATUS_SIE);
    }
}

pub fn enable_external_interrupts() {
    // SAFETY: external interrupts are needed for device IRQ wakeups.
    unsafe {
        write_sie(read_sie() | SIE_SEIE);
        write_sstatus(read_sstatus() | SSTATUS_SIE);
    }
}

pub fn enable_interrupts() {
    // SAFETY: enabling S-mode interrupts is required for idle sleep to receive timer IRQs.
    unsafe {
        write_sstatus(read_sstatus() | SSTATUS_SIE);
    }
}

/// # Safety
/// Caller must provide a valid user page table and user stack pointer.
pub unsafe fn enter_user(entry: usize, user_sp: usize, satp: usize) -> ! {
    // SAFETY: caller must provide a valid user page table and user stack.
    unsafe {
        asm!(
            "csrw satp, {satp}",
            "sfence.vma",
            "csrw sepc, {entry}",
            "csrw sscratch, sp",
            "mv sp, {sp}",
            "csrc sstatus, {spp_mask}",
            "csrs sstatus, {spie_mask}",
            "sret",
            satp = in(reg) satp,
            entry = in(reg) entry,
            sp = in(reg) user_sp,
            spp_mask = in(reg) SSTATUS_SPP,
            spie_mask = in(reg) SSTATUS_SPIE,
            clobber_abi("C"),
            options(noreturn)
        );
    }
}

pub fn return_to_user(trap_frame: usize) -> ! {
    // SAFETY: caller provides a valid trap frame pointer on the kernel stack.
    unsafe {
        asm!(
            "mv sp, {0}",
            "j __trap_return",
            in(reg) trap_frame,
            options(noreturn)
        );
    }
}

pub fn current_sp() -> usize {
    read_sp()
}

pub fn read_user_stack() -> usize {
    // SAFETY: reading sscratch does not modify machine state.
    unsafe { read_sscratch() }
}

#[no_mangle]
extern "C" fn trap_handler(tf: &mut TrapFrame) {
    let _guard = enter_trap(tf);
    let scause = tf.scause;
    let stval = tf.stval;
    let sepc = tf.sepc;

    let is_interrupt = (scause & SCAUSE_INTERRUPT_BIT) != 0;
    let code = scause & !SCAUSE_INTERRUPT_BIT;
    if !is_interrupt && code == SCAUSE_ILLEGAL_INSTRUCTION {
        if !TRAP_LOG_ONCE.swap(true, Ordering::Relaxed) {
            crate::println!(
                "trap: illegal insn sepc={:#x} stval={:#x} sp={:#x} sscratch={:#x} sstatus={:#x} ra={:#x} user_sp={:#x}",
                sepc,
                stval,
                read_sp(),
                unsafe { read_sscratch() },
                tf.sstatus,
                tf.ra,
                tf.user_sp
            );
        }
    }
    if !is_interrupt && code == SCAUSE_STORE_PAGE_FAULT {
        if !TRAP_LOG_ONCE.swap(true, Ordering::Relaxed) {
            crate::println!(
                "trap: store fault sepc={:#x} stval={:#x} sp={:#x} sscratch={:#x} sstatus={:#x} satp={:#x}",
                sepc,
                stval,
                read_sp(),
                unsafe { read_sscratch() },
                tf.sstatus,
                mm::current_root_pa()
            );
        }
    }

    if is_interrupt {
        if code == SCAUSE_SUPERVISOR_TIMER {
            let interval = TIMER_INTERVAL.load(Ordering::Relaxed);
            if interval != 0 {
                let now = read_time();
                sbi::set_timer(now + interval);
            }
            let ticks = time::tick();
            runtime::on_tick(ticks);
            runtime::maybe_schedule(ticks, crate::config::SCHED_INTERVAL_TICKS);
            if (tf.sstatus & SSTATUS_SPP) == 0 {
                runtime::preempt_current();
            }
            return;
        } else if code == SCAUSE_SUPERVISOR_EXTERNAL {
            let current_root = mm::current_root_pa();
            let kernel_root = mm::kernel_root_pa();
            if kernel_root != 0 && current_root != kernel_root {
                mm::switch_root(kernel_root);
            }
            loop {
                let Some(irq) = crate::plic::claim() else {
                    break;
                };
                let _handled = crate::virtio_blk::handle_irq(irq);
                let _handled = crate::virtio_net::handle_irq(irq);
                crate::plic::complete(irq);
            }
            if kernel_root != 0 && current_root != kernel_root {
                mm::switch_root(current_root);
            }
            return;
        }
    } else if code == SCAUSE_USER_ECALL {
        crate::syscall::handle_syscall(tf);
        return;
    } else if code == SCAUSE_SUPERVISOR_ECALL {
        tf.sepc = sepc.wrapping_add(4);
        return;
    } else if code == SCAUSE_STORE_PAGE_FAULT || code == SCAUSE_LOAD_PAGE_FAULT || code == SCAUSE_INST_PAGE_FAULT {
        let root_pa = crate::mm::current_root_pa();
        if root_pa != 0 && crate::mm::handle_cow_fault(root_pa, stval) {
            return;
        }
    }

    crate::println!(
        "Unhandled trap: scause={:#x} sepc={:#x} stval={:#x}",
        scause,
        sepc,
        stval
    );
    sbi::shutdown();
}

#[inline]
fn read_time() -> u64 {
    let value: u64;
    // Safety: rdtime reads the monotonic time CSR.
    unsafe { asm!("rdtime {0}", out(reg) value) };
    value
}

#[inline]
unsafe fn write_stvec(addr: usize) {
    asm!("csrw stvec, {0}", in(reg) addr);
}

#[inline]
unsafe fn write_sstatus(value: usize) {
    asm!("csrw sstatus, {0}", in(reg) value);
}

#[inline]
unsafe fn write_sie(value: usize) {
    asm!("csrw sie, {0}", in(reg) value);
}

#[inline]
unsafe fn write_sscratch(value: usize) {
    asm!("csrw sscratch, {0}", in(reg) value);
}

#[inline]
unsafe fn read_sstatus() -> usize {
    let value: usize;
    asm!("csrr {0}, sstatus", out(reg) value);
    value
}

#[inline]
unsafe fn read_sscratch() -> usize {
    let value: usize;
    asm!("csrr {0}, sscratch", out(reg) value);
    value
}

#[inline]
unsafe fn read_sie() -> usize {
    let value: usize;
    asm!("csrr {0}, sie", out(reg) value);
    value
}

#[inline]
fn read_sp() -> usize {
    let value: usize;
    // Safety: reading sp does not modify machine state.
    unsafe {
        asm!("mv {0}, sp", out(reg) value);
    }
    value
}
