OUTPUT_ARCH(riscv)
ENTRY(_start)

BASE_ADDRESS = 0x80200000;

SECTIONS {
    . = BASE_ADDRESS;

    .text : ALIGN(0x1000) {
        *(.text.entry)
        *(.text .text.*)
    }

    .rodata : ALIGN(0x1000) {
        *(.rodata .rodata.*)
    }

    .data : ALIGN(0x1000) {
        *(.data .data.*)
    }

    .bss : ALIGN(0x1000) {
        sbss = .;
        *(.bss .bss.*)
        *(.sbss .sbss.*)
        *(.bss.stack)
        . = ALIGN(8);
        ebss = .;
    }

    /DISCARD/ : {
        *(.eh_frame)
        *(.comment)
    }
}
