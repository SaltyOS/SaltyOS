/* saltyc setjmp/longjmp for x86_64
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * jmp_buf layout (8 * 8 = 64 bytes):
 *   [0] rbx  [1] rbp  [2] r12  [3] r13
 *   [4] r14  [5] r15  [6] rsp  [7] rip
 *
 * sigjmp_buf layout (64 + 8 + 8 = 80 bytes):
 *   [0..7] same as jmp_buf
 *   [8]    savesigs flag
 *   [9]    saved signal mask (unused for now)
 */

.section .text

/* int setjmp(jmp_buf env) */
.global setjmp
.global _setjmp
.type setjmp, @function
.type _setjmp, @function
setjmp:
_setjmp:
    movq    %rbx, 0(%rdi)
    movq    %rbp, 8(%rdi)
    movq    %r12, 16(%rdi)
    movq    %r13, 24(%rdi)
    movq    %r14, 32(%rdi)
    movq    %r15, 40(%rdi)
    leaq    8(%rsp), %rax       /* rsp as it will be after return */
    movq    %rax, 48(%rdi)
    movq    (%rsp), %rax        /* return address */
    movq    %rax, 56(%rdi)
    xorl    %eax, %eax          /* return 0 */
    ret

/* void longjmp(jmp_buf env, int val) */
.global longjmp
.global _longjmp
.type longjmp, @function
.type _longjmp, @function
longjmp:
_longjmp:
    movl    %esi, %eax          /* val */
    testl   %eax, %eax
    jnz     1f
    incl    %eax                /* val = 1 if val == 0 */
1:
    movq    0(%rdi), %rbx
    movq    8(%rdi), %rbp
    movq    16(%rdi), %r12
    movq    24(%rdi), %r13
    movq    32(%rdi), %r14
    movq    40(%rdi), %r15
    movq    48(%rdi), %rsp
    jmpq    *56(%rdi)

/* int sigsetjmp(sigjmp_buf env, int savesigs) */
.global sigsetjmp
.global __sigsetjmp
.type sigsetjmp, @function
.type __sigsetjmp, @function
sigsetjmp:
__sigsetjmp:
    movq    %rbx, 0(%rdi)
    movq    %rbp, 8(%rdi)
    movq    %r12, 16(%rdi)
    movq    %r13, 24(%rdi)
    movq    %r14, 32(%rdi)
    movq    %r15, 40(%rdi)
    leaq    8(%rsp), %rax
    movq    %rax, 48(%rdi)
    movq    (%rsp), %rax
    movq    %rax, 56(%rdi)
    movq    %rsi, 64(%rdi)      /* savesigs flag */
    movq    $0, 72(%rdi)        /* saved mask = 0 (no mask support yet) */
    xorl    %eax, %eax
    ret

/* void siglongjmp(sigjmp_buf env, int val) */
.global siglongjmp
.type siglongjmp, @function
siglongjmp:
    movl    %esi, %eax
    testl   %eax, %eax
    jnz     1f
    incl    %eax
1:
    /* Restore signal mask if savesigs was nonzero (no-op for now) */
    movq    0(%rdi), %rbx
    movq    8(%rdi), %rbp
    movq    16(%rdi), %r12
    movq    24(%rdi), %r13
    movq    32(%rdi), %r14
    movq    40(%rdi), %r15
    movq    48(%rdi), %rsp
    jmpq    *56(%rdi)
