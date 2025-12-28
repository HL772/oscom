use core::arch::asm;

pub fn idle_loop() -> ! {
    loop {
        // Safety: wfi only suspends the hart until the next interrupt.
        unsafe { asm!("wfi"); }
    }
}
