/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SaltyOS Bootloader - Mode Switch Interface (32-bit → 64-bit)
 *
 * Transitions from 32-bit protected mode to 64-bit long mode
 * and jumps directly to the kernel entry point.
 */

#ifndef BOOT_STAGE3_ARCH_X86_BIOS_MODE_SWITCH_H
#define BOOT_STAGE3_ARCH_X86_BIOS_MODE_SWITCH_H

#include "../../../../common/types.h"

/*
 * Assembly function: switch to long mode and jump to kernel
 *
 * All parameters are 32-bit because this is called from 32-bit code.
 * 64-bit values are split into low/high halves.
 */
void enter_long_mode_and_jump_asm(
    uint32_t pml4,
    uint32_t entry_lo, uint32_t entry_hi,
    uint32_t bootinfo_lo, uint32_t bootinfo_hi,
    uint32_t stack_lo, uint32_t stack_hi);

/*
 * Switch to long mode and jump to kernel
 *
 * This function enables PAE, loads the PML4, sets EFER.LME,
 * enables paging, loads a 64-bit GDT, and jumps to the kernel
 * entry point with RDI = bootinfo_addr.
 *
 * @param pml4_addr: Physical address of PML4 page table
 * @param entry_point: 64-bit kernel entry point address
 * @param bootinfo_addr: 64-bit BootInfo structure address
 * @param stack_top: 64-bit kernel stack top address
 *
 * This function does NOT return.
 */
static inline NORETURN void enter_long_mode_and_jump(
    uint32_t pml4_addr,
    uint64_t entry_point,
    uint64_t bootinfo_addr,
    uint64_t stack_top)
{
    enter_long_mode_and_jump_asm(
        pml4_addr,
        (uint32_t)entry_point, (uint32_t)(entry_point >> 32),
        (uint32_t)bootinfo_addr, (uint32_t)(bootinfo_addr >> 32),
        (uint32_t)stack_top, (uint32_t)(stack_top >> 32));

    __builtin_unreachable();
}

#endif /* BOOT_STAGE3_ARCH_X86_BIOS_MODE_SWITCH_H */
