# SaltyOS x86_64 kernel entry point
# This is the first code that runs after bootloader handoff
# Placed in .text._start section so linker script can KEEP it first

.section .text._start
.global _start
.type _start, @function

_start:
    # BootInfo is in RDI (System V AMD64 ABI)
    # Save it for later use
    movq %rdi, %rbx

    # Setup stack
    # Allocate stack space
    lea stack_top(%rip), %rsp
    andq $-16, %rsp  # Align stack to 16 bytes

    # Pass bootinfo pointer as first argument
    movq %rbx, %rdi

    # Use CALL to satisfy SysV stack alignment expectations
    call kernel_main

.hang:
    hlt
    jmp .hang

_start_end:
    .size _start, _start_end - _start

.section .bss
.align 16
.global stack
stack:
    .skip 16384  # 16KB stack
stack_top:
