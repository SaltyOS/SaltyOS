/* SaltyOS Runtime Dynamic Linker - AArch64 PLT Lazy Resolver Trampoline
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * AArch64 ELF PLT ABI used by the linker:
 * - PLT[n] enters PLT0 with x16 = &GOT[n]
 * - PLT0 pushes {x16, x30}, then overwrites x16 = &GOT[2], x17 = resolver
 * - GOT[1] holds link_map*, GOT[2] holds _dl_runtime_resolve
 *
 * Reconstruct the relocation index from the saved GOT slot address on the
 * stack and load link_map from GOT[1].
 */

.text
.globl _dl_runtime_resolve
.type _dl_runtime_resolve, @function

_dl_runtime_resolve:
    /* Recover lazy-binding inputs before we touch the stack.
     *   [sp]     = saved x16 = &GOT[n]
     *   [sp, #8] = saved x30 = caller return address
     *   x16      = &GOT[2]
     */
    ldr     x9, [sp]          /* saved GOT[n] address */
    ldr     x10, [x16, #-8]   /* GOT[1] = link_map* */
    sub     x11, x9, x16      /* GOT[n] - GOT[2] */
    sub     x11, x11, #8      /* convert to index from GOT[3] */
    lsr     x11, x11, #3      /* 8-byte GOT entries -> relocation index */

    stp     x0, x1, [sp, #-16]!
    stp     x2, x3, [sp, #-16]!
    stp     x4, x5, [sp, #-16]!
    stp     x6, x7, [sp, #-16]!
    stp     x8, x9, [sp, #-16]!
    stp     x10, x11, [sp, #-16]!
    stp     x12, x13, [sp, #-16]!
    stp     x14, x15, [sp, #-16]!
    /* _dl_fixup is a normal C call, so preserve all callee-saved GPRs. */
    stp     x19, x20, [sp, #-16]!
    stp     x21, x22, [sp, #-16]!
    stp     x23, x24, [sp, #-16]!
    stp     x25, x26, [sp, #-16]!
    stp     x27, x28, [sp, #-16]!
    stp     x29, x30, [sp, #-16]!

    mov     x0, x10
    mov     x1, x11
    bl      _dl_fixup
    mov     x16, x0

    ldp     x29, x30, [sp], #16
    ldp     x27, x28, [sp], #16
    ldp     x25, x26, [sp], #16
    ldp     x23, x24, [sp], #16
    ldp     x21, x22, [sp], #16
    ldp     x19, x20, [sp], #16
    ldp     x14, x15, [sp], #16
    ldp     x12, x13, [sp], #16
    ldp     x10, x11, [sp], #16
    ldp     x8, x9, [sp], #16
    ldp     x6, x7, [sp], #16
    ldp     x4, x5, [sp], #16
    ldp     x2, x3, [sp], #16
    ldp     x0, x1, [sp], #16

    /* Drop PLT0's {x16, x30} frame before tail-branching to the target. */
    add     sp, sp, #16

    br      x16

.size _dl_runtime_resolve, . - _dl_runtime_resolve

/* TLSDESC static resolver for statically-allocated TLS.
 *
 * On entry:  x0 = address of the 2-word descriptor {resolver, arg}
 * On return: x0 = TP-relative offset of the TLS variable
 * All other registers (x1-x30, NZCV, d0-d31) must be preserved.
 */
.globl _tlsdesc_static_resolver
.type _tlsdesc_static_resolver, @function

_tlsdesc_static_resolver:
    ldr     x0, [x0, #8]
    ret

.size _tlsdesc_static_resolver, . - _tlsdesc_static_resolver

/*
 * rtld_jump_entry - transfer control to the executable entry point.
 *
 * Arguments: x0 = sp, x1 = entry.  Does not return.
 */
.globl rtld_jump_entry
.type rtld_jump_entry, @function

rtld_jump_entry:
    dsb     ish
    isb
    mov     sp, x0
    mov     x29, xzr
    mov     x30, xzr
    br      x1

.size rtld_jump_entry, . - rtld_jump_entry
