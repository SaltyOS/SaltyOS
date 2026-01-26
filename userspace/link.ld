ENTRY(_start)

PHDRS
{
  text PT_LOAD FLAGS(5);
  data PT_LOAD FLAGS(6);
}

SECTIONS
{
  . = 0;

  .text : {
    *(.text*)
  } :text

  .rodata : {
    *(.rodata*)
  } :text

  .data : {
    *(.data*)
  } :data

  .bss : {
    *(.bss*)
    *(COMMON)
  } :data
}
