//! AArch64 boot entry point
//!
//! SPDX-License-Identifier: GPL-2.0-only

use core::arch::global_asm;

// Boot entry point: set SP, zero BSS, call kmain with x0 (BootInfo ptr)
global_asm!(
    r#"
    .section .text.boot, "ax"
    .global _start
    .type _start, @function
_start:
    // x0 = pointer to BootInfo (passed by bootloader)

    // Mask all exceptions during early boot
    msr     DAIFSet, #0xF

    // Set up kernel stack (use a static boot stack)
    adrp    x1, _boot_stack_top
    add     x1, x1, :lo12:_boot_stack_top
    mov     sp, x1

    // Zero BSS section
    adrp    x1, _bss_start
    add     x1, x1, :lo12:_bss_start
    adrp    x2, _bss_end
    add     x2, x2, :lo12:_bss_end
1:
    cmp     x1, x2
    b.ge    2f
    str     xzr, [x1], #8
    b       1b
2:
    // x0 still holds BootInfo pointer from bootloader
    bl      kmain

    // kmain should never return
3:
    wfi
    b       3b

    .section .bss
    .align 16
_boot_stack_bottom:
    .space  16384       // 16 KiB boot stack
    .global _boot_stack_top
_boot_stack_top:
"#,
);
