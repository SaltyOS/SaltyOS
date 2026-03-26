/* SaltyOS Runtime Dynamic Linker - x86_64 PLT Lazy Resolver Trampoline
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Saves all caller-saved GPRs AND XMM0-XMM7 so that lazy resolution
 * is transparent to the calling code even when it uses SSE registers
 * (e.g. memcpy with inline SIMD, float arguments).
 *
 * Stack layout after full save (offsets from RSP):
 *   0-127  : XMM0-XMM7 (8 * 16 bytes)
 *   128-199: GPRs r11,r10,r9,r8,rdi,rsi,rdx,rcx,rax (9 * 8 bytes)
 *   200    : link_map*    (pushed by PLT[0])
 *   208    : reloc_index  (pushed by PLT[N] stub)
 *   216    : return addr  (pushed by original call)
 */

.text
.globl _dl_runtime_resolve
.type _dl_runtime_resolve, @function

_dl_runtime_resolve:
    /* Save caller-saved GPRs */
    pushq %rax
    pushq %rcx
    pushq %rdx
    pushq %rsi
    pushq %rdi
    pushq %r8
    pushq %r9
    pushq %r10
    pushq %r11

    /* Save XMM0-XMM7 (128 bytes, stack is 16-byte aligned here) */
    subq $128, %rsp
    movdqu %xmm0,   0(%rsp)
    movdqu %xmm1,  16(%rsp)
    movdqu %xmm2,  32(%rsp)
    movdqu %xmm3,  48(%rsp)
    movdqu %xmm4,  64(%rsp)
    movdqu %xmm5,  80(%rsp)
    movdqu %xmm6,  96(%rsp)
    movdqu %xmm7, 112(%rsp)

    movq 200(%rsp), %rdi
    movq 208(%rsp), %rsi

    call _dl_fixup

    movq %rax, 200(%rsp)

    /* Restore XMM0-XMM7 */
    movdqu   0(%rsp), %xmm0
    movdqu  16(%rsp), %xmm1
    movdqu  32(%rsp), %xmm2
    movdqu  48(%rsp), %xmm3
    movdqu  64(%rsp), %xmm4
    movdqu  80(%rsp), %xmm5
    movdqu  96(%rsp), %xmm6
    movdqu 112(%rsp), %xmm7
    addq $128, %rsp

    /* Restore GPRs */
    popq %r11
    popq %r10
    popq %r9
    popq %r8
    popq %rdi
    popq %rsi
    popq %rdx
    popq %rcx
    popq %rax

    ret $8

.size _dl_runtime_resolve, . - _dl_runtime_resolve

/*
 * rtld_jump_entry - transfer control to the executable entry point.
 *
 * Standalone assembly so the compiler cannot interfere via inlining,
 * register allocation, or reordering around inline asm.
 *
 * Arguments: rdi = sp, rsi = entry.  Does not return.
 */
.globl rtld_jump_entry
.type rtld_jump_entry, @function

rtld_jump_entry:
    movq %rdi, %rsp
    xorq %rbp, %rbp
    jmpq *%rsi

.size rtld_jump_entry, . - rtld_jump_entry
