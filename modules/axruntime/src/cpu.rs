//! CPU helpers and low-level instructions.

use core::arch::asm;

#[inline]
/// Enter low-power wait-for-interrupt state.
pub fn wait_for_interrupt() {
    // Safety: wfi only suspends the hart until the next interrupt.
    unsafe { asm!("wfi"); }
}
