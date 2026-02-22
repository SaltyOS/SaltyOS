/* SaltyOS Runtime Dynamic Linker - PLT Lazy Resolver Trampoline
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * x86_64 PLT lazy resolution. When a PLT stub calls an unresolved function:
 *   1. The individual PLT entry pushes reloc_index onto the stack
 *   2. PLT[0] pushes GOT[1] (link_map*) and jumps to GOT[2] (here)
 *   3. We save all caller-saved registers
 *   4. Call _dl_fixup(link_map*, reloc_index) to resolve the symbol
 *   5. Restore registers and jump to the resolved address
 */

.text
.globl _dl_runtime_resolve
.type _dl_runtime_resolve, @function

_dl_runtime_resolve:
    /* Stack on entry (from PLT[0] trampoline):
     *   [RSP+0]  = link_map*    (pushed by PLT[0]: push GOT[1])
     *   [RSP+8]  = reloc_index  (pushed by individual PLT stub)
     *   [RSP+16] = return addr  (from original call instruction)
     *
     * Note: PLT[0] does: push GOT[1]; jmp *GOT[2]
     *       PLT[n] does: jmp *GOT[n+3]; push reloc_index; jmp PLT[0]
     */

    /* Save all caller-saved registers (9 regs = 72 bytes) */
    pushq %rax
    pushq %rcx
    pushq %rdx
    pushq %rsi
    pushq %rdi
    pushq %r8
    pushq %r9
    pushq %r10
    pushq %r11

    /* Call _dl_fixup(link_map*, reloc_index)
     * link_map*   is at RSP + 72 (past 9 saved regs)
     * reloc_index is at RSP + 80 (past 9 saved regs + link_map*)
     */
    movq 72(%rsp), %rdi     /* arg1: link_map* */
    movq 80(%rsp), %rsi     /* arg2: reloc_index */

    call _dl_fixup
    /* RAX = resolved function address */

    /* Store resolved address where link_map* was on the stack.
     * After restoring registers, we'll ret through it.
     */
    movq %rax, 72(%rsp)

    /* Restore all caller-saved registers */
    popq %r11
    popq %r10
    popq %r9
    popq %r8
    popq %rdi
    popq %rsi
    popq %rdx
    popq %rcx
    popq %rax

    /* Stack now:
     *   [RSP+0] = resolved_addr  (was link_map*, overwritten above)
     *   [RSP+8] = reloc_index
     *
     * ret $8: pop resolved_addr into RIP, then add 8 to RSP
     *         (skipping the reloc_index that was pushed by the PLT stub)
     */
    ret $8

.size _dl_runtime_resolve, . - _dl_runtime_resolve
