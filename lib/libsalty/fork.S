/* SaltyOS fork() assembly trampoline
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * posix_fork() saves callee-saved GPRs and (when enabled) XMM0-15 on the
 * stack, then calls
 * _posix_fork_impl() which sends PM_FORK to procmgr with the current
 * RSP and the address of fork_child_entry.
 *
 * Parent path: _posix_fork_impl returns child PID, we pop saved regs,
 * return the PID to the caller.
 *
 * Child path: procmgr sets the child's RIP to fork_child_entry with
 * the same RSP the parent had after pushing regs. The child pops the
 * saved registers and returns 0.
 */

.text
.global posix_fork
.global fork_child_entry
.hidden fork_child_entry

posix_fork:
    /* Save callee-saved GPRs */
    pushq   %rbp
    pushq   %rbx
    pushq   %r12
    pushq   %r13
    pushq   %r14
    pushq   %r15

#ifdef SALTY_X86_SIMD
    /* Save caller-clobbered XMM regs so fork() preserves SIMD state */
    subq    $256, %rsp
    movdqu  %xmm0,   0(%rsp)
    movdqu  %xmm1,  16(%rsp)
    movdqu  %xmm2,  32(%rsp)
    movdqu  %xmm3,  48(%rsp)
    movdqu  %xmm4,  64(%rsp)
    movdqu  %xmm5,  80(%rsp)
    movdqu  %xmm6,  96(%rsp)
    movdqu  %xmm7, 112(%rsp)
    movdqu  %xmm8, 128(%rsp)
    movdqu  %xmm9, 144(%rsp)
    movdqu  %xmm10, 160(%rsp)
    movdqu  %xmm11, 176(%rsp)
    movdqu  %xmm12, 192(%rsp)
    movdqu  %xmm13, 208(%rsp)
    movdqu  %xmm14, 224(%rsp)
    movdqu  %xmm15, 240(%rsp)
#endif

    /* Keep SysV stack alignment (16-byte) across the call.
     * Entry RSP is 8 mod 16; after six pushes it's still 8 mod 16. */
    subq    $8, %rsp

    /* Call _posix_fork_impl(saved_rsp, child_entry) */
#ifdef SALTY_X86_SIMD
    leaq    264(%rsp), %rdi         /* arg0 = saved RSP (after pushes) */
#else
    leaq    8(%rsp), %rdi           /* arg0 = saved RSP (after pushes) */
#endif
    leaq    fork_child_entry(%rip), %rsi  /* arg1 = child entry address */
    call    _posix_fork_impl@PLT
    addq    $8, %rsp

#ifdef SALTY_X86_SIMD
    /* Parent: restore XMM regs */
    movdqu    0(%rsp), %xmm0
    movdqu   16(%rsp), %xmm1
    movdqu   32(%rsp), %xmm2
    movdqu   48(%rsp), %xmm3
    movdqu   64(%rsp), %xmm4
    movdqu   80(%rsp), %xmm5
    movdqu   96(%rsp), %xmm6
    movdqu  112(%rsp), %xmm7
    movdqu  128(%rsp), %xmm8
    movdqu  144(%rsp), %xmm9
    movdqu  160(%rsp), %xmm10
    movdqu  176(%rsp), %xmm11
    movdqu  192(%rsp), %xmm12
    movdqu  208(%rsp), %xmm13
    movdqu  224(%rsp), %xmm14
    movdqu  240(%rsp), %xmm15
    addq    $256, %rsp
#endif

    /* Parent returns here with child PID in %eax (or -1 on error) */
    popq    %r15
    popq    %r14
    popq    %r13
    popq    %r12
    popq    %rbx
    popq    %rbp
    ret

fork_child_entry:
#ifdef SALTY_X86_SIMD
    /* Child starts here with RSP pointing to saved GPRs.
     * Restore XMM regs from the saved block below, then pop GPRs. */
    movdqu  -256(%rsp), %xmm0
    movdqu  -240(%rsp), %xmm1
    movdqu  -224(%rsp), %xmm2
    movdqu  -208(%rsp), %xmm3
    movdqu  -192(%rsp), %xmm4
    movdqu  -176(%rsp), %xmm5
    movdqu  -160(%rsp), %xmm6
    movdqu  -144(%rsp), %xmm7
    movdqu  -128(%rsp), %xmm8
    movdqu  -112(%rsp), %xmm9
    movdqu   -96(%rsp), %xmm10
    movdqu   -80(%rsp), %xmm11
    movdqu   -64(%rsp), %xmm12
    movdqu   -48(%rsp), %xmm13
    movdqu   -32(%rsp), %xmm14
    movdqu   -16(%rsp), %xmm15
#endif
    popq    %r15
    popq    %r14
    popq    %r13
    popq    %r12
    popq    %rbx
    popq    %rbp
    xorl    %eax, %eax              /* return 0 = child */
    ret
