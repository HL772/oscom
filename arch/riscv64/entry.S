.section .text.entry
.globl _start
_start:
    # Disable interrupts during early boot.
    csrw sie, zero

    # Clear BSS without using stack (stack lives in .bss.stack).
    la t0, sbss
    la t1, ebss
1:
    bgeu t0, t1, 2f
    sd zero, 0(t0)
    addi t0, t0, 8
    j 1b
2:
    # Set early stack and jump to Rust entry.
    la sp, boot_stack_top
    call rust_main

3:
    wfi
    j 3b

.section .bss.stack
.align 12
.globl boot_stack
boot_stack:
    .space 4096 * 16
.globl boot_stack_top
boot_stack_top:
