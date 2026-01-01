ENTRY(_start)

PHDRS
{
  all PT_LOAD FLAGS(0x7);
}

SECTIONS
{
  . = 0x40000000;
  .text : { *(.text .text.*) } :all
  .rodata : { *(.rodata .rodata.*) } :all
  .data : { *(.data .data.*) } :all
  .bss : { *(.bss .bss.* COMMON) } :all
}
