/* saltyc CRT startup
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * _start is called by the dynamic linker (rtld) or directly for static binaries.
 * The initial stack pointer holds: argc, argv[], envp[], auxv[]
 *
 * Passes a pointer to main() and the initial stack pointer to __libc_start_main,
 * following the glibc/musl convention of receiving main as a function pointer.
 */

.section .text
.global _start
.type _start, @function

_start:
    xorl    %ebp, %ebp          /* Mark deepest stack frame */
    movq    %rsp, %rsi          /* arg2 = initial stack pointer (argc at [rsp]) */
    andq    $-16, %rsp          /* Align stack to 16 bytes */
    leaq    main(%rip), %rdi    /* arg1 = pointer to main */
    call    __libc_start_main   /* Never returns */
    ud2
