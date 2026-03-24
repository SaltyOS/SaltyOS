/* SaltyOS Runtime Dynamic Linker - x86_64 PLT Lazy Resolver Trampoline
 * SPDX-License-Identifier: GPL-2.0-only
 */

.text
.globl _dl_runtime_resolve
.type _dl_runtime_resolve, @function

_dl_runtime_resolve:
    pushq %rax
    pushq %rcx
    pushq %rdx
    pushq %rsi
    pushq %rdi
    pushq %r8
    pushq %r9
    pushq %r10
    pushq %r11

    movq 72(%rsp), %rdi
    movq 80(%rsp), %rsi

    call _dl_fixup

    movq %rax, 72(%rsp)

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
