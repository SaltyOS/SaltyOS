/* SaltyOS fork() assembly trampoline
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * posix_fork() saves callee-saved registers on the stack, then calls
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
    /* Save callee-saved registers */
    pushq   %rbp
    pushq   %rbx
    pushq   %r12
    pushq   %r13
    pushq   %r14
    pushq   %r15

    /* Keep SysV stack alignment (16-byte) across the call.
     * Entry RSP is 8 mod 16; after six pushes it's still 8 mod 16. */
    subq    $8, %rsp

    /* Call _posix_fork_impl(saved_rsp, child_entry) */
    leaq    8(%rsp), %rdi           /* arg0 = saved RSP (after pushes) */
    leaq    fork_child_entry(%rip), %rsi  /* arg1 = child entry address */
    call    _posix_fork_impl@PLT
    addq    $8, %rsp

    /* Parent returns here with child PID in %eax (or -1 on error) */
    popq    %r15
    popq    %r14
    popq    %r13
    popq    %r12
    popq    %rbx
    popq    %rbp
    ret

fork_child_entry:
    /* Child starts here with RSP pointing to the saved registers.
     * Pop them and return 0. */
    popq    %r15
    popq    %r14
    popq    %r13
    popq    %r12
    popq    %rbx
    popq    %rbp
    xorl    %eax, %eax              /* return 0 = child */
    ret
