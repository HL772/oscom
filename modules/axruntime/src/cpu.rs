use core::arch::asm;

#[inline]
pub fn wait_for_interrupt() {
    // Safety: wfi only suspends the hart until the next interrupt.
    unsafe { asm!("wfi"); }
}
