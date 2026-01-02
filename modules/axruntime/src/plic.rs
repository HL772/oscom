//! PLIC (platform-level interrupt controller) helpers.

use core::ptr;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::mm::MemoryRegion;

const PLIC_PRIORITY_BASE: usize = 0x0;
const PLIC_ENABLE_BASE: usize = 0x2000;
const PLIC_CONTEXT_BASE: usize = 0x200000;
const PLIC_ENABLE_STRIDE: usize = 0x80;
const PLIC_CONTEXT_STRIDE: usize = 0x1000;
const PLIC_CONTEXT_S: usize = 1;

static PLIC_BASE: AtomicUsize = AtomicUsize::new(0);

/// Initialize the PLIC mapping from the device tree.
pub fn init(region: Option<MemoryRegion>) {
    if let Some(region) = region {
        let base = region.base as usize;
        PLIC_BASE.store(base, Ordering::Release);
        // Safety: mapped device MMIO registers, single-hart early init.
        unsafe {
            ptr::write_volatile(
                (base + PLIC_CONTEXT_BASE + PLIC_CONTEXT_S * PLIC_CONTEXT_STRIDE) as *mut u32,
                0,
            );
        }
    }
}

/// Enable a specific IRQ in the PLIC.
pub fn enable(irq: u32) {
    let base = PLIC_BASE.load(Ordering::Acquire);
    if base == 0 || irq == 0 {
        return;
    }
    let irq = irq as usize;
    let priority_addr = base + PLIC_PRIORITY_BASE + irq * 4;
    let enable_addr = base
        + PLIC_ENABLE_BASE
        + PLIC_CONTEXT_S * PLIC_ENABLE_STRIDE
        + (irq / 32) * 4;
    let enable_bit = 1u32 << (irq % 32);
    unsafe {
        ptr::write_volatile(priority_addr as *mut u32, 1);
        let current = ptr::read_volatile(enable_addr as *const u32);
        ptr::write_volatile(enable_addr as *mut u32, current | enable_bit);
    }
}

/// Claim the next pending IRQ.
pub fn claim() -> Option<u32> {
    let base = PLIC_BASE.load(Ordering::Acquire);
    if base == 0 {
        return None;
    }
    let claim_addr = base + PLIC_CONTEXT_BASE + PLIC_CONTEXT_S * PLIC_CONTEXT_STRIDE + 4;
    let irq = unsafe { ptr::read_volatile(claim_addr as *const u32) };
    if irq == 0 {
        None
    } else {
        Some(irq)
    }
}

/// Complete handling of a claimed IRQ.
pub fn complete(irq: u32) {
    let base = PLIC_BASE.load(Ordering::Acquire);
    if base == 0 || irq == 0 {
        return;
    }
    let claim_addr = base + PLIC_CONTEXT_BASE + PLIC_CONTEXT_S * PLIC_CONTEXT_STRIDE + 4;
    unsafe {
        ptr::write_volatile(claim_addr as *mut u32, irq);
    }
}
